use anyhow::{bail, ensure, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use log::{debug, warn};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// APK Signing block storage type
#[derive(Debug, Clone)]
pub struct ApkSigningBlock {
    pub data: Vec<(u32, Vec<u8>)>,
}

impl ApkSigningBlock {
    /// Load the signing block from and APK file
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let mut file = File::open(path)?;
        ApkSigningBlock::from_reader(&mut file)
    }

    /// Load the signing block from an APK file
    pub fn from_reader<R: Read + Seek>(reader: &mut R) -> Result<Self> {
        load_signing_block(reader)
    }

    /// Parse signatures from signing block
    pub fn get_signatures(&self) -> Result<Vec<ApkSignatureBlock>> {
        const V2_SIG_BLOCK_ID: u32 = 0x7109871a;
        const V3_SIG_BLOCK_ID: u32 = 0xf05368c0;

        let mut sigs = vec![];
        for (k, v) in &self.data {
            match *k {
                V2_SIG_BLOCK_ID => {
                    let v2_block = remove_prefix_layers(v)?;
                    let v2_block = get_lv_sequence(v2_block)?;
                    ensure!(
                        v2_block.len() == 3,
                        "Expected 3 elements in signing block got {}",
                        v2_block.len()
                    );
                    let signed_data = get_lv_sequence(v2_block[0])?;
                    let digests = get_sequence_kv(signed_data[0])?;
                    let certificates = get_lv_sequence(signed_data[1])?;
                    let attributes = get_sequence_kv(signed_data[2])?;

                    let signatures = get_sequence_kv(v2_block[1])?;
                    let public_key = v2_block[2];
                    let digests: HashMap<u32, &[u8]> = HashMap::from_iter(digests);
                    sigs.push(ApkSignatureBlock::V2 {
                        attributes: HashMap::from_iter(
                            attributes.into_iter().map(|(k, v)| (k, v.to_vec())),
                        ),
                        certificates: certificates.into_iter().map(|v| v.to_vec()).collect(),
                        signatures: parse_sigs(&signatures, &digests),
                        public_key: public_key.to_vec(),
                    });
                }
                V3_SIG_BLOCK_ID => {
                    let mut v = &v[4..];
                    let mut v3_block = take_lv_u32(&mut v)?;

                    let mut signed_data = take_lv_u32(&mut v3_block)?;
                    let digests = get_sequence_kv(take_lv_u32(&mut signed_data)?)?;
                    let certificates = get_lv_sequence(take_lv_u32(&mut signed_data)?)?;
                    let min_sdk_signed = u32::from_le_bytes(signed_data[..4].try_into()?);
                    let max_sdk_signed = u32::from_le_bytes(signed_data[4..8].try_into()?);
                    signed_data = &signed_data[8..];
                    let attributes = get_sequence_kv(take_lv_u32(&mut signed_data)?)?;

                    let min_sdk = u32::from_le_bytes(v3_block[..4].try_into()?);
                    let max_sdk = u32::from_le_bytes(v3_block[4..8].try_into()?);
                    v3_block = &v3_block[8..];

                    ensure!(
                        min_sdk_signed == min_sdk,
                        "Invalid min_sdk in signing block V3 {} != {}",
                        min_sdk_signed,
                        min_sdk
                    );
                    ensure!(
                        max_sdk_signed == max_sdk,
                        "Invalid max_sdk in signing block V3 {} != {}",
                        max_sdk_signed,
                        max_sdk
                    );

                    let signatures = get_sequence_kv(take_lv_u32(&mut v3_block)?)?;
                    let public_key = take_lv_u32(&mut v3_block)?;
                    let digests: HashMap<u32, &[u8]> = HashMap::from_iter(digests);

                    sigs.push(ApkSignatureBlock::V3 {
                        min_sdk,
                        max_sdk,
                        attributes: HashMap::from_iter(
                            attributes.into_iter().map(|(k, v)| (k, v.to_vec())),
                        ),
                        certificates: certificates.into_iter().map(|v| v.to_vec()).collect(),
                        signatures: parse_sigs(&signatures, &digests),
                        public_key: public_key.to_vec(),
                    });
                }
                v => debug!("Unknown block id {}", v),
            }
        }
        Ok(sigs)
    }
}

fn parse_sigs(signatures: &Vec<(u32, &[u8])>, digests: &HashMap<u32, &[u8]>) -> Vec<ApkSignature> {
    signatures
        .into_iter()
        .filter_map(|(k, v)| {
            let sig_len = u32::from_le_bytes(v[..4].try_into().ok()?) as usize;
            if sig_len > v.len() - 4 {
                warn!("Invalid signature length: {} > {}", sig_len, v.len());
                return None;
            }
            if let Ok(a) = ApkSignatureAlgo::try_from(*k) {
                Some(ApkSignature {
                    algo: a,
                    digest: digests.get(&k).map(|v| v[4..].to_vec())?,
                    signature: v[4..sig_len + 4].to_vec(),
                })
            } else {
                None
            }
        })
        .collect()
}

#[derive(Debug, Clone)]
pub enum ApkSignatureBlock {
    /// Unknown block
    Unknown { data: Vec<u8> },

    /// Android V2 Signature Block
    ///
    /// https://source.android.com/docs/security/features/apksigning/v2#apk-signature-scheme-v2-block-format
    V2 {
        signatures: Vec<ApkSignature>,
        public_key: Vec<u8>,
        certificates: Vec<Vec<u8>>,
        attributes: HashMap<u32, Vec<u8>>,
    },

    /// Android V3 Signature Block
    ///
    /// https://source.android.com/docs/security/features/apksigning/v3#format
    V3 {
        signatures: Vec<ApkSignature>,
        certificates: Vec<Vec<u8>>,
        public_key: Vec<u8>,
        attributes: HashMap<u32, Vec<u8>>,
        min_sdk: u32,
        max_sdk: u32,
    },
}

impl Display for ApkSignatureBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ApkSignatureBlock::Unknown { .. } => write!(f, "unknown"),
            ApkSignatureBlock::V2 { signatures, .. } => {
                write!(f, "v2: ")?;
                for sig in signatures {
                    write!(
                        f,
                        "algo={}, digest={}, sig={}",
                        sig.algo,
                        hex::encode(&sig.digest),
                        hex::encode(&sig.signature)
                    )?;
                }
                Ok(())
            }
            ApkSignatureBlock::V3 { signatures, .. } => {
                write!(f, "V3: ")?;
                for sig in signatures {
                    write!(
                        f,
                        "algo={}, digest={}, sig={}",
                        sig.algo,
                        hex::encode(&sig.digest),
                        hex::encode(&sig.signature)
                    )?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApkSignature {
    pub algo: ApkSignatureAlgo,
    pub signature: Vec<u8>,
    pub digest: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum ApkSignatureAlgo {
    RsaSsaPssSha256,
    RsaSsaPssSha512,
    RsaSsaPkcs1Sha256,
    RsaSsaPkcs1Sha512,
    EcdsaSha256,
    EcdsaSha512,
    DsaSha256,
}

impl Display for ApkSignatureAlgo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ApkSignatureAlgo::RsaSsaPssSha256 => write!(f, "RSASSA-PSS-SHA256"),
            ApkSignatureAlgo::RsaSsaPssSha512 => write!(f, "RSASSA-PSS-SHA512"),
            ApkSignatureAlgo::RsaSsaPkcs1Sha256 => write!(f, "RSASSA-PKCS1-SHA256"),
            ApkSignatureAlgo::RsaSsaPkcs1Sha512 => write!(f, "RSASSA-PKCS1-SHA512"),
            ApkSignatureAlgo::EcdsaSha256 => write!(f, "ECDSA-SHA256"),
            ApkSignatureAlgo::EcdsaSha512 => write!(f, "ECDSA-SHA512"),
            ApkSignatureAlgo::DsaSha256 => write!(f, "DSA-SHA256"),
        }
    }
}

impl TryFrom<u32> for ApkSignatureAlgo {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        match value {
            0x0101 => Ok(ApkSignatureAlgo::RsaSsaPssSha256),
            0x0102 => Ok(ApkSignatureAlgo::RsaSsaPssSha512),
            0x0103 => Ok(ApkSignatureAlgo::RsaSsaPkcs1Sha256),
            0x0104 => Ok(ApkSignatureAlgo::RsaSsaPkcs1Sha512),
            0x0201 => Ok(ApkSignatureAlgo::EcdsaSha256),
            0x0202 => Ok(ApkSignatureAlgo::EcdsaSha512),
            0x0301 => Ok(ApkSignatureAlgo::DsaSha256),
            _ => bail!("Unknown signature algo"),
        }
    }
}

fn load_signing_block<R>(zip: &mut R) -> Result<ApkSigningBlock>
where
    R: Read + Seek,
{
    const SIG_BLOCK_MAGIC: &[u8] = b"APK Sig Block 42";

    // scan backwards until we find the singing block
    let flen = zip.seek(SeekFrom::End(0))?;
    let mut magic_buf = [0u8; 16];
    loop {
        let magic_pos = zip.seek(SeekFrom::Current(-17))?;
        if magic_pos <= 16 {
            bail!("Failed to find signing block");
        }

        zip.read_exact(&mut magic_buf)?;
        if magic_buf == SIG_BLOCK_MAGIC {
            zip.seek(SeekFrom::Current(-(16 + 8)))?;
            let size1 = zip.read_u64::<LittleEndian>()?;
            ensure!(size1 <= flen, "Signing block is larger than entire file");

            zip.seek(SeekFrom::Current(-(size1 as i64 - 8)))?;
            let size2 = zip.read_u64::<LittleEndian>()?;
            ensure!(
                size2 == size1,
                "Invalid block sizes, {} != {}",
                size1,
                size2
            );

            let mut data_bytes = size2 - 16 - 8;
            let mut blocks = Vec::new();
            loop {
                let (k, v) = read_u64_length_prefixed_kv(zip)?;
                data_bytes -= (v.len() + 4 + 8) as u64;
                blocks.push((k, v));
                if data_bytes == 0 {
                    break;
                }
            }

            zip.seek(SeekFrom::Start(0))?;
            return Ok(ApkSigningBlock { data: blocks });
        }
    }
}

#[inline]
fn read_u64_length_prefixed_kv<T>(file: &mut T) -> Result<(u32, Vec<u8>)>
where
    T: Read + Seek,
{
    let kv_len = file.read_u64::<LittleEndian>()?;
    let k = file.read_u32::<LittleEndian>()?;
    let v_len = kv_len as usize - 4;
    let mut v = vec![0; v_len];
    file.read_exact(&mut v)?;
    Ok((k, v))
}

#[inline]
fn get_lv_u32_kv(slice: &[u8]) -> Result<(u32, &[u8])> {
    let data = get_lv_u32(slice)?;
    let k = u32::from_le_bytes(data[0..4].try_into()?);
    Ok((k, &data[4..]))
}

#[inline]
fn get_lv_u32(slice: &[u8]) -> Result<&[u8]> {
    let len = u32::from_le_bytes(slice[0..4].try_into()?);
    ensure!(
        len <= (slice.len() - 4) as u32,
        "Invalid LV sequence {} > {}",
        len,
        slice.len(),
    );
    Ok(&slice[4..4 + len as usize])
}

#[inline]
fn take_lv_u32<'a>(slice: &mut &'a[u8]) -> Result<&'a [u8]> {
    let len = u32::from_le_bytes(slice[..4].try_into()?);
    ensure!(
        len <= (slice.len() - 4) as u32,
        "Invalid LV sequence {} > {}",
        len,
        slice.len(),
    );
    let (a, b) = slice[4..].split_at(len as usize);
    *slice = b;
    Ok(a)
}

/// Remove 1 or more prefix layers
/// IDK why android needs 3 layers of prefixed lengths, maybe its just how it was written in Java,
/// but it makes no logical sense:
/// ```yaml
/// L: (1000)
///   L: (996)
///     L: V (740) - SEQ
///     L: V (252) - SEQ
/// ```
#[inline]
fn remove_prefix_layers(mut slice: &[u8]) -> Result<&[u8]> {
    let l1 = u32::from_le_bytes(slice[..4].try_into()?);
    loop {
        slice = &slice[4..];
        let l2 = u32::from_le_bytes(slice[..4].try_into()?);
        if l1 != l2 + 4 {
            return Ok(slice);
        }
    }
}

/// Read 0 or more length prefixed values until the slice is empty
#[inline]
fn get_lv_sequence(mut slice: &[u8]) -> Result<Vec<&[u8]>> {
    let mut ret = Vec::new();
    while slice.len() >= 4 {
        let data = get_lv_u32(&slice[..])?;
        let r_len = data.len() + 4;
        slice = &slice[r_len..];
        ret.push(data);
    }
    Ok(ret)
}

#[inline]
fn get_sequence_kv(slice: &[u8]) -> Result<Vec<(u32, &[u8])>> {
    let seq = get_lv_sequence(slice)?;
    Ok(seq
        .into_iter()
        .map(|s| {
            let k = u32::from_le_bytes(s[..4].try_into().unwrap());
            let v = &s[4..];
            (k, v)
        })
        .collect())
}

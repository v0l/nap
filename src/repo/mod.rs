use crate::manifest::Manifest;
use crate::repo::github::GithubRepo;
use anyhow::{anyhow, bail, ensure, Result};
use apk::res::Chunk;
use apk::zip::ZipArchive;
use apk::AndroidManifest;
use byteorder::LittleEndian;
use byteorder::ReadBytesExt;
use log::{debug, info, warn};
use nostr_sdk::prelude::{hex, Coordinate, StreamExt};
use nostr_sdk::{Event, EventBuilder, Kind, NostrSigner, Tag};
use reqwest::Url;
use semver::Version;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::env::temp_dir;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

mod github;

/// Since artifact binary / image
#[derive(Debug, Clone)]
pub struct RepoArtifact {
    /// Artifact name (filename)
    pub name: String,

    /// The size of the artifact in bytes
    pub size: u64,

    /// Where the artifact is located
    pub location: RepoResource,

    /// MIME type
    pub content_type: String,

    /// Platform this artifact runs on
    pub platform: Platform,

    /// Artifact metadata
    pub metadata: ArtifactMetadata,

    /// SHA-256 hash of the artifact
    pub hash: Option<Vec<u8>>,
}

impl Display for RepoArtifact {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} platform={} metadata={}",
            self.name, self.platform, self.metadata
        )
    }
}

/// Converts a repo artifact into a NIP-94 event
impl TryInto<EventBuilder> for RepoArtifact {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<EventBuilder, Self::Error> {
        let mut b = EventBuilder::new(Kind::FileMetadata, "").tags([
            Tag::parse(["f", self.platform.to_string().as_str()])?,
            Tag::parse(["m", self.content_type.as_str()])?,
            Tag::parse(["size", self.size.to_string().as_str()])?,
        ]);
        if let RepoResource::Remote(u) = self.location {
            b = b.tag(Tag::parse(["url", u.as_str()])?);
        }
        match self.metadata {
            ArtifactMetadata::APK {
                manifest,
                signature,
            } => {
                match signature {
                    ApkSignatureBlock::None => {
                        warn!("No signature found in metadata");
                    }
                    ApkSignatureBlock::V2 { signatures, .. } => {
                        for signature in signatures {
                            b = b.tag(Tag::parse([
                                "apk_signature_hash",
                                &hex::encode(signature.digest),
                            ])?);
                        }
                    }
                    ApkSignatureBlock::V3 { signatures, .. } => {
                        for signature in signatures {
                            b = b.tag(Tag::parse([
                                "apk_signature_hash",
                                &hex::encode(signature.digest),
                            ])?);
                        }
                    }
                }
                if let Some(vn) = manifest.version_name {
                    b = b.tag(Tag::parse(["version", vn.as_str()])?);
                }
                if let Some(vc) = manifest.version_code {
                    b = b.tag(Tag::parse(["version_code", vc.to_string().as_str()])?);
                }
                if let Some(min_sdk) = manifest.sdk.min_sdk_version {
                    b = b.tag(Tag::parse([
                        "min_sdk_version",
                        min_sdk.to_string().as_str(),
                    ])?);
                }
                if let Some(target_sdk) = manifest.sdk.target_sdk_version {
                    b = b.tag(Tag::parse([
                        "target_sdk_version",
                        target_sdk.to_string().as_str(),
                    ])?);
                }
                //TODO: apk sig
            }
        }
        Ok(b)
    }
}

#[derive(Debug, Clone)]
pub enum ArtifactMetadata {
    APK {
        manifest: AndroidManifest,
        signature: ApkSignatureBlock,
    },
}

#[derive(Debug, Clone)]
pub enum ApkSignatureBlock {
    None,
    /// Android V2 Signature Block
    ///
    /// https://source.android.com/docs/security/features/apksigning/v2#apk-signature-scheme-v2-block-format
    V2 {
        signatures: Vec<ApkSignature>,
        public_key: Vec<u8>,
        certificates: Vec<Vec<u8>>,
        attributes: HashMap<u32, Vec<u8>>,
    },
    V3 {
        signatures: Vec<ApkSignature>,
        public_key: Vec<u8>,
    },
}

impl Display for ApkSignatureBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ApkSignatureBlock::None => write!(f, "none"),
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

impl Display for ArtifactMetadata {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ArtifactMetadata::APK {
                manifest,
                signature,
            } => {
                write!(
                    f,
                    "APK id={}, version={}, code={}, sig={}",
                    manifest.package.as_ref().unwrap_or(&"missing".to_string()),
                    manifest.version_name.as_ref().unwrap_or(&String::new()),
                    manifest.version_code.as_ref().unwrap_or(&0),
                    signature
                )
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum Platform {
    Android { arch: Architecture },
    IOS { arch: Architecture },
    MacOS { arch: Architecture },
    Windows { arch: Architecture },
    Linux { arch: Architecture },
    Web,
}

impl Display for Platform {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::Android { arch } => write!(
                f,
                "android-{}",
                match arch {
                    Architecture::ARMv7 => "armeabi-v7a",
                    Architecture::ARM64 => "arm64-v8a",
                    Architecture::X86 => "x86",
                    Architecture::X86_64 => "x86_64",
                }
            ),
            Platform::IOS { arch } => write!(
                f,
                "ios-{}",
                match arch {
                    Architecture::ARM64 => "arm64",
                    _ => "unknown",
                }
            ),
            Platform::MacOS { arch } => write!(
                f,
                "darwin-{}",
                match arch {
                    Architecture::ARM64 => "aarch64",
                    Architecture::X86 => "x86",
                    Architecture::X86_64 => "x86_64",
                    _ => "unknown",
                }
            ),
            Platform::Windows { arch } => write!(
                f,
                "windows-{}",
                match arch {
                    Architecture::ARM64 => "aarch64",
                    Architecture::X86 => "x86",
                    Architecture::X86_64 => "x86_64",
                    _ => "unknown",
                }
            ),
            Platform::Linux { arch } => write!(
                f,
                "linux-{}",
                match arch {
                    Architecture::ARM64 => "aarch64",
                    Architecture::X86 => "x86",
                    Architecture::X86_64 => "x86_64",
                    _ => "unknown",
                }
            ),
            Platform::Web => write!(f, "web"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Architecture {
    ARMv7,
    ARM64,
    X86,
    X86_64,
}

impl Display for Architecture {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Architecture::ARMv7 => write!(f, "armeabi-v7a"),
            Architecture::ARM64 => write!(f, "arm64-v8a"),
            Architecture::X86 => write!(f, "x86"),
            Architecture::X86_64 => write!(f, "x86_64"),
        }
    }
}

#[derive(Debug, Clone)]
/// A local/remote location where the artifact is located
pub enum RepoResource {
    Remote(String),
    Local(PathBuf),
}

#[derive(Debug, Clone)]
/// A single release with one or more artifacts
pub struct RepoRelease {
    /// Release version (semver)
    pub version: Version,

    /// Release changelog/notes
    pub description: Option<String>,

    /// URL of the release (github release page etc)
    pub url: Option<String>,

    /// List of artifacts in this release
    pub artifacts: Vec<RepoArtifact>,
}

impl RepoRelease {
    pub fn app_id(&self) -> Result<String> {
        self.artifacts
            .iter()
            .find_map(|a| match &a.metadata {
                ArtifactMetadata::APK { manifest, .. } if manifest.package.is_some() => {
                    Some(manifest.package.as_ref().unwrap().to_string())
                }
                _ => None,
            })
            .ok_or(anyhow!("no app_id found"))
    }

    /// [app_id]@[version]
    pub fn release_tag(&self) -> Result<String> {
        Ok(format!("{}@{}", self.app_id()?, self.version))
    }

    /// Create nostr release artifact list event
    pub async fn into_release_list_event<T: NostrSigner>(
        self,
        signer: &T,
        app_coord: Coordinate,
    ) -> Result<Vec<Event>> {
        let mut ret = vec![];
        let mut b = EventBuilder::new(
            Kind::Custom(30063),
            self.description.as_deref().unwrap_or(""),
        )
        .tags([
            Tag::coordinate(app_coord),
            Tag::parse(["d", &self.release_tag()?])?,
        ]);

        if let Some(url) = self.url {
            b = b.tag(Tag::parse(["url", &url])?);
        }
        for a in &self.artifacts {
            let eb: Result<EventBuilder> = a.clone().try_into();
            match eb {
                Ok(a) => {
                    let e_build = a.sign(signer).await?;
                    b = b.tag(Tag::event(e_build.id));
                    ret.push(e_build);
                }
                Err(e) => warn!("Failed to convert artifact: {} {}", a, e),
            }
        }
        ret.push(b.sign(signer).await?);
        Ok(ret)
    }
}

/// Generic artifact repository
#[async_trait::async_trait]
pub trait Repo {
    /// Get a list of release artifacts
    async fn get_releases(&self) -> Result<Vec<RepoRelease>>;
}

impl TryInto<Box<dyn Repo>> for &Manifest {
    type Error = anyhow::Error;

    fn try_into(self) -> std::result::Result<Box<dyn Repo>, Self::Error> {
        let repo = self
            .repository
            .as_ref()
            .ok_or(anyhow!("repository not found"))?;

        if !repo.starts_with("https://github.com/") {
            bail!("Only github repos are supported");
        }

        Ok(Box::new(GithubRepo::from_url(repo)?))
    }
}

/// Download an artifact and create a [RepoArtifact]
async fn load_artifact_url(url: &str) -> Result<RepoArtifact> {
    info!("Downloading artifact {}", url);
    let u = Url::parse(url)?;
    let rsp = reqwest::get(u.clone()).await?;
    let id = hex::encode(sha2::Sha256::digest(url.as_bytes()));
    let mut tmp = temp_dir().join(id);
    tmp.set_extension(
        PathBuf::from(u.path())
            .extension()
            .ok_or(anyhow!("Missing extension in URL"))?
            .to_str()
            .unwrap(),
    );
    if !tmp.exists() {
        let mut tmp_file = tokio::fs::File::create(&tmp).await?;
        let mut rsp_stream = rsp.bytes_stream();
        while let Some(data) = rsp_stream.next().await {
            if let Ok(data) = data {
                tmp_file.write_all(&data).await?;
            }
        }
    }
    let mut a = load_artifact(&tmp)?;
    // replace location back to URL for publishing
    a.location = RepoResource::Remote(url.to_string());
    Ok(a)
}

fn load_artifact(path: &Path) -> Result<RepoArtifact> {
    match path
        .extension()
        .ok_or(anyhow!("missing file extension"))?
        .to_str()
        .unwrap()
    {
        "apk" => load_apk_artifact(path),
        v => bail!("unknown file extension: {v}"),
    }
}

fn load_apk_artifact(path: &Path) -> Result<RepoArtifact> {
    let file = std::fs::File::open(path)?;
    let mut file = std::io::BufReader::new(file);
    let sig_block = load_signing_block(&mut file)?;

    let mut zip = ZipArchive::new(file)?;
    let manifest = load_manifest(&mut zip)?;

    let lib_arch: HashSet<String> = list_libs(&mut zip)
        .iter()
        .filter_map(|p| {
            PathBuf::from(p)
                .iter()
                .nth(1)
                .map(|p| p.to_str().unwrap().to_owned())
        })
        .collect();

    ensure!(lib_arch.len() == 1, "Unknown library architecture");

    Ok(RepoArtifact {
        name: path.file_name().unwrap().to_str().unwrap().to_string(),
        size: path.metadata()?.len(),
        location: RepoResource::Local(path.to_path_buf()),
        hash: Some(hash_file(path)?),
        content_type: "application/vnd.android.package-archive".to_string(),
        platform: Platform::Android {
            arch: match lib_arch.iter().next().unwrap().as_str() {
                "arm64-v8a" => Architecture::ARM64,
                "armeabi-v7a" => Architecture::ARMv7,
                "x86_64" => Architecture::X86_64,
                "x86" => Architecture::X86,
                v => bail!("unknown architecture: {v}"),
            },
        },
        metadata: ArtifactMetadata::APK {
            manifest,
            signature: sig_block.try_into()?,
        },
    })
}

fn hash_file(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::default();
    let mut buf = Vec::with_capacity(4096);
    while let Ok(r) = file.read(&mut buf) {
        if r == 0 {
            break;
        }
        hash.update(&buf[..r]);
    }
    Ok(hash.finalize().to_vec())
}

fn load_manifest<T>(zip: &mut ZipArchive<T>) -> Result<AndroidManifest>
where
    T: Read + Seek,
{
    const ANDROID_MANIFEST: &str = "AndroidManifest.xml";

    let mut f = zip.by_name(ANDROID_MANIFEST)?;
    let mut manifest_data = Vec::with_capacity(8192);
    let r = f.read_to_end(&mut manifest_data)?;
    let res: AndroidManifest = parse_android_manifest(&manifest_data[..r])?;
    Ok(res)
}

#[derive(Debug, Clone)]
struct ApkSigningBlock {
    pub data: Vec<(u32, Vec<u8>)>,
}

impl TryInto<ApkSignatureBlock> for ApkSigningBlock {
    type Error = anyhow::Error;

    fn try_into(self) -> std::result::Result<ApkSignatureBlock, Self::Error> {
        const V2_SIG_BLOCK_ID: u32 = 0x7109871a;
        const V3_SIG_BLOCK_ID: u32 = 0xf05368c0;

        if let Some(v3) =
            self.data
                .iter()
                .find_map(|(k, v)| if *k == V3_SIG_BLOCK_ID { Some(v) } else { None })
        {
            todo!("Not done yet")
        }
        if let Some(v2) =
            self.data
                .iter()
                .find_map(|(k, v)| if *k == V2_SIG_BLOCK_ID { Some(v) } else { None })
        {
            let v2 = get_length_prefixed_u32_sequence(&v2[4..])?;
            let signed_data = get_sequence(v2[0])?;
            let digests = get_sequence_kv(signed_data[0])?;
            let certificates = get_sequence(signed_data[1])?;
            let attributes = get_sequence_kv(signed_data[2])?;
            let signatures = get_sequence_kv(v2[1])?;
            let public_key = v2[2];
            let digests: HashMap<u32, &[u8]> = HashMap::from_iter(digests);
            return Ok(ApkSignatureBlock::V2 {
                attributes: HashMap::from_iter(
                    attributes.into_iter().map(|(k, v)| (k, v.to_vec())),
                ),
                certificates: certificates.into_iter().map(|v| v.to_vec()).collect(),
                signatures: signatures
                    .into_iter()
                    .filter_map(|(k, v)| {
                        let sig_len = u32::from_le_bytes(v[..4].try_into().ok()?) as usize;
                        if sig_len > v.len() - 4 {
                            warn!("Invalid signature length: {} > {}", sig_len, v.len());
                            return None;
                        }
                        if let Ok(a) = ApkSignatureAlgo::try_from(k) {
                            Some(ApkSignature {
                                algo: a,
                                digest: digests.get(&k).map(|v| v[4..].to_vec())?,
                                signature: v[4..sig_len + 4].to_vec(),
                            })
                        } else {
                            None
                        }
                    })
                    .collect(),
                public_key: public_key.to_vec(),
            });
        }
        Ok(ApkSignatureBlock::None)
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
        if magic_pos <= 4 {
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

            let mut data_bytes = size1 - 8 - 16;
            let mut sigs = Vec::new();
            loop {
                let (k, v) = read_u64_length_prefixed_kv(zip)?;
                data_bytes -= (v.len() + 4 + 8) as u64;
                sigs.push((k, v));
                if data_bytes == 0 {
                    break;
                }
            }

            zip.seek(SeekFrom::Start(0))?;
            return Ok(ApkSigningBlock { data: sigs });
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
    file.read_exact(v.as_mut_slice())?;
    Ok((k, v))
}

#[inline]
fn get_u64_length_prefixed_kv(slice: &[u8]) -> Result<(u32, &[u8])> {
    let kv_len = u64::from_le_bytes(slice[..8].try_into()?);
    let k = u32::from_le_bytes(slice[8..12].try_into()?);
    Ok((k, &slice[12..(kv_len as usize - 12)]))
}

#[inline]
fn get_u32_length_prefixed_kv(slice: &[u8]) -> Result<(u32, &[u8])> {
    let kv_len = u32::from_le_bytes(slice[..4].try_into()?);
    let k = u32::from_le_bytes(slice[4..8].try_into()?);
    Ok((k, &slice[8..(kv_len as usize - 8)]))
}

#[inline]
fn get_length_prefixed_u32(slice: &[u8]) -> Result<&[u8]> {
    let len = u32::from_le_bytes(slice[..4].try_into()?);
    Ok(&slice[4..4 + len as usize])
}

#[inline]
fn get_length_prefixed_u32_sequence(slice: &[u8]) -> Result<Vec<&[u8]>> {
    let sequence_len = u32::from_le_bytes(slice[..4].try_into()?);
    get_sequence(&slice[4..4 + sequence_len as usize])
}

#[inline]
fn get_sequence(mut slice: &[u8]) -> Result<Vec<&[u8]>> {
    let mut ret = Vec::new();
    while slice.len() >= 4 {
        let data = get_length_prefixed_u32(slice)?;
        let r_len = data.len() + 4;
        slice = &slice[r_len..];
        ret.push(data);
    }
    Ok(ret)
}

#[inline]
fn get_sequence_kv(slice: &[u8]) -> Result<Vec<(u32, &[u8])>> {
    let seq = get_sequence(slice)?;
    Ok(seq
        .into_iter()
        .map(|s| {
            let k = u32::from_le_bytes(s[..4].try_into().unwrap());
            let v = &s[4..];
            (k, v)
        })
        .collect())
}

fn list_libs<T>(zip: &mut ZipArchive<T>) -> Vec<String>
where
    T: Read + Seek,
{
    zip.file_names()
        .filter_map(|f| {
            if f.starts_with("lib/") {
                Some(f.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn parse_android_manifest(data: &[u8]) -> Result<AndroidManifest> {
    let chunks = if let Chunk::Xml(chunks) = Chunk::parse(&mut Cursor::new(data))? {
        chunks
    } else {
        bail!("Invalid AndroidManifest file");
    };

    let strings = if let Chunk::StringPool(strings, _) = &chunks[0] {
        HashMap::from_iter(
            strings
                .iter()
                .enumerate()
                .map(|(i, s)| (s.to_string(), i as i32)),
        )
    } else {
        bail!("invalid manifest 1");
    };

    let mut res = AndroidManifest::default();
    res.package = find_value_in(&strings, &chunks, "manifest", "package");
    res.version_code =
        find_value_in(&strings, &chunks, "manifest", "versionCode").and_then(|v| v.parse().ok());
    res.version_name = find_value_in(&strings, &chunks, "manifest", "versionName");
    res.compile_sdk_version = find_value_in(&strings, &chunks, "manifest", "compileSdkVersion")
        .and_then(|v| v.parse().ok());
    res.compile_sdk_version_codename =
        find_value_in(&strings, &chunks, "manifest", "compileSdkVersionCodename")
            .and_then(|v| v.parse().ok());
    res.platform_build_version_code =
        find_value_in(&strings, &chunks, "manifest", "platformBuildVersionCode")
            .and_then(|v| v.parse().ok());
    res.platform_build_version_name =
        find_value_in(&strings, &chunks, "manifest", "platformBuildVersionName")
            .and_then(|v| v.parse().ok());

    res.sdk.min_sdk_version =
        find_value_in(&strings, &chunks, "uses-sdk", "minSdkVersion").and_then(|v| v.parse().ok());
    res.sdk.target_sdk_version = find_value_in(&strings, &chunks, "uses-sdk", "targetSdkVersion")
        .and_then(|v| v.parse().ok());
    res.sdk.max_sdk_version =
        find_value_in(&strings, &chunks, "uses-sdk", "maxSdkVersion").and_then(|v| v.parse().ok());

    res.application.theme = find_value_in(&strings, &chunks, "application", "theme");
    res.application.label = find_value_in(&strings, &chunks, "application", "label");
    res.application.icon = find_value_in(&strings, &chunks, "application", "icon");

    Ok(res)
}

fn find_value_in(
    strings: &HashMap<String, i32>,
    chunks: &Vec<Chunk>,
    node: &str,
    attr: &str,
) -> Option<String> {
    let idx_node = if let Some(i) = strings.get(node) {
        *i
    } else {
        return None;
    };

    let idx_attr = if let Some(i) = strings.get(attr) {
        *i
    } else {
        return None;
    };

    chunks.iter().find_map(|chunk| {
        if let Chunk::XmlStartElement(_, el, attrs) = chunk {
            match el.name {
                x if x == idx_node => attrs.iter().find(|e| e.name == idx_attr).and_then(|e| {
                    debug!("{}, {}, {:?}", node, attr, e);
                    match e.typed_value.data_type {
                        3 => strings
                            .iter()
                            .find(|(_, v)| **v == e.raw_value)
                            .map(|(k, _)| k.clone()),
                        16 => Some(e.typed_value.data.to_string()),
                        _ => {
                            debug!("unknown data type {},{},{:?}", node, attr, e);
                            None
                        }
                    }
                }),
                _ => None,
            }
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[test]
    fn read_apk() -> Result<()> {
        let path = "/home/kieran/Downloads/app-arm64-v8a-release.apk";

        let apk = load_apk_artifact(&PathBuf::from(path))?;
        assert!(
            matches!(&apk.platform, Platform::Android { arch } if matches!(arch, Architecture::ARM64 { .. }))
        );
        assert!(matches!(&apk.metadata,
                ArtifactMetadata::APK { signature, .. } if matches!(signature,
                    ApkSignatureBlock::V2 { signatures, .. } if signatures.len() == 1 &&
                matches!(signatures[0].algo, ApkSignatureAlgo::RsaSsaPkcs1Sha256))));

        eprint!("{}", apk);
        Ok(())
    }
}

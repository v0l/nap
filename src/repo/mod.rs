use crate::manifest::Manifest;
use crate::repo::github::GithubRepo;
use anyhow::{anyhow, bail, ensure, Result};
use apk_parser::zip::ZipArchive;
use apk_parser::{parse_android_manifest, AndroidManifest, ApkSignatureBlock, ApkSigningBlock};
use log::{info, warn};
use nostr_sdk::prelude::{hex, Coordinate, StreamExt};
use nostr_sdk::{Event, EventBuilder, Kind, NostrSigner, Tag};
use reqwest::Url;
use semver::Version;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::env::temp_dir;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{Read, Seek};
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
    pub hash: Vec<u8>,
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
            Tag::parse(["x", &hex::encode(self.hash)])?,
        ]);
        if let RepoResource::Remote(u) = self.location {
            b = b.tag(Tag::parse(["url", u.as_str()])?);
        }
        match self.metadata {
            ArtifactMetadata::APK {
                manifest,
                signatures,
            } => {
                for signature in signatures {
                    match signature {
                        ApkSignatureBlock::Unknown { .. } => {
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
            }
        }
        Ok(b)
    }
}

#[derive(Debug, Clone)]
pub enum ArtifactMetadata {
    APK {
        manifest: AndroidManifest,
        signatures: Vec<ApkSignatureBlock>,
    },
}

impl Display for ArtifactMetadata {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ArtifactMetadata::APK {
                manifest,
                signatures,
            } => {
                write!(
                    f,
                    "APK id={}, version={}, code={}, sig={}",
                    manifest.package.as_ref().unwrap_or(&"missing".to_string()),
                    manifest.version_name.as_ref().unwrap_or(&String::new()),
                    manifest.version_code.as_ref().unwrap_or(&0),
                    signatures
                        .iter()
                        .map(|b| b.to_string())
                        .collect::<Vec<String>>()
                        .join(", ")
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
    let id = hex::encode(Sha256::digest(url.as_bytes()));
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
    let file = File::open(path)?;
    let mut file = std::io::BufReader::new(file);
    let sig_block = ApkSigningBlock::from_reader(&mut file)?;

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
        hash: hash_file(path)?,
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
            signatures: sig_block.get_signatures()?,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[test]
    fn read_apk() -> Result<()> {
        let path = "/home/kieran/Downloads/snort-arm64-v8a-v0.3.0.apk";

        let apk = load_apk_artifact(&PathBuf::from(path))?;
        eprint!("{}", apk);
        Ok(())
    }
}

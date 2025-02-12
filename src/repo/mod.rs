use crate::manifest::Manifest;
use crate::repo::github::GithubRepo;
use anyhow::{anyhow, bail, Context, Result};
use apk::AndroidManifest;
use async_zip::tokio::read::seek::ZipFileReader;
use async_zip::ZipFile;
use log::info;
use nostr_sdk::async_utility::futures_util::TryStreamExt;
use nostr_sdk::prelude::{hex, StreamExt};
use reqwest::Url;
use semver::Version;
use serde::Deserialize;
use sha2::Digest;
use std::env::temp_dir;
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, BufReader};

mod github;

/// Since artifact binary / image
pub struct RepoArtifact {
    pub name: String,
    pub size: u64,
    pub location: RepoResource,
    pub content_type: String,
    pub platform: Platform,
    pub metadata: ArtifactMetadata,
}

pub enum ArtifactMetadata {
    APK { manifest: AndroidManifest },
}

pub enum Platform {
    Android { arch: Architecture },
    IOS,
    MacOS { arch: Architecture },
    Windows { arch: Architecture },
    Linux { arch: Architecture },
    Web,
}

pub enum Architecture {
    ARMv7,
    ARMv8,
    X86,
    AMD64,
    ARM64,
}

/// A local/remote location where the artifact is located
pub enum RepoResource {
    Remote(String),
    Local(PathBuf),
}

/// A single release with one or more artifacts
pub struct RepoRelease {
    pub version: Version,
    pub artifacts: Vec<RepoArtifact>,
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
        let mut tmp_file = File::create(&tmp).await?;
        let mut rsp_stream = rsp.bytes_stream();
        while let Some(data) = rsp_stream.next().await {
            if let Ok(data) = data {
                tmp_file.write_all(&data).await?;
            }
        }
    }
    load_artifact(&tmp).await
}

async fn load_artifact(path: &Path) -> Result<RepoArtifact> {
    match path
        .extension()
        .ok_or(anyhow!("missing file extension"))?
        .to_str()
        .unwrap()
    {
        "apk" => load_apk_artifact(path).await,
        _ => bail!("unknown file extension"),
    }
}

async fn load_apk_artifact(path: &Path) -> Result<RepoArtifact> {
    let file = File::open(path).await?;

    let mut zip = ZipFileReader::with_tokio(BufReader::new(file)).await?;

    const ANDROID_MANIFEST: &'static str = "AndroidManifest.xml";

    let idx = zip
        .file()
        .entries()
        .iter()
        .enumerate()
        .find_map(|(i, entry)| {
            if entry.filename().as_bytes() == ANDROID_MANIFEST.as_bytes() {
                Some(i)
            } else {
                None
            }
        })
        .ok_or(anyhow!("missing AndroidManifest file"))?;
    let mut manifest = zip.reader_with_entry(idx).await?;
    let mut manifest_data = String::with_capacity(8192);
    manifest.read_to_string_checked(&mut manifest_data).await?;
    info!("Successfully loaded AndroidManifest: {}", &manifest_data);
    let manifest: AndroidManifest = quick_xml::de::from_str(&manifest_data)?;

    Ok(RepoArtifact {
        name: path.file_name().unwrap().to_str().unwrap().to_string(),
        size: path.metadata()?.len(),
        location: RepoResource::Local(path.to_path_buf()),
        content_type: "application/apk".to_string(),
        platform: Platform::Android {
            arch: Architecture::ARMv8,
        },
        metadata: ArtifactMetadata::APK { manifest },
    })
}

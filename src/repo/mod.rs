use std::path::{Path, PathBuf};
use crate::manifest::Manifest;
use crate::repo::github::GithubRepo;
use anyhow::{anyhow, bail, Result};
use semver::Version;
use serde::Deserialize;

mod github;

/// Since artifact binary / image
pub struct RepoArtifact {
    pub name: String,
    pub size: u64,
    pub location: RepoResource,
    pub content_type: String,
    pub platform: Platform,
    pub metadata: ArtifactMetadata
}

pub enum ArtifactMetadata {
    APK {
        version_code: u32,
        min_sdk_version: u32,
        target_sdk_version: u32,
        sig_hash: String,
    }
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

async fn load_artifact_url(url: &str) -> Result<RepoArtifact> {

}

async fn load_artifact(path: &Path) -> Result<RepoArtifact> {

}
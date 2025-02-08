use crate::repo::{Repo, RepoArtifact, RepoRelease, RepoResource};
use anyhow::{anyhow, Result};
use log::{info, warn};
use nostr_sdk::Url;
use reqwest::header::{HeaderMap, ACCEPT, USER_AGENT};
use reqwest::Client;
use semver::Version;
use serde::Deserialize;

pub struct GithubRepo {
    client: Client,
    owner: String,
    repo: String,
}

impl GithubRepo {
    pub fn new(owner: String, repo: String) -> GithubRepo {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, "application/vnd.github+json".parse().unwrap());
        headers.insert(
            USER_AGENT,
            "nap/1.0 (https://github.com/v0l/nap)".parse().unwrap(),
        );

        let client = Client::builder().default_headers(headers).build().unwrap();

        GithubRepo {
            owner,
            repo,
            client,
        }
    }

    pub fn from_url(url: &str) -> Result<GithubRepo> {
        let u: Url = url.parse()?;
        let mut segs = u.path_segments().ok_or(anyhow::anyhow!("Invalid URL"))?;
        Ok(GithubRepo::new(
            segs.next().ok_or(anyhow!("Invalid URL"))?.to_string(),
            segs.next().ok_or(anyhow!("Invalid URL"))?.to_string(),
        ))
    }
}

#[derive(Deserialize)]
struct GithubRelease {
    pub tag_name: String,
    pub name: String,
    pub draft: bool,
    #[serde(rename = "prerelease")]
    pub pre_release: bool,
    pub body: String,
    pub assets: Vec<GithubReleaseArtifact>,
}

#[derive(Deserialize)]
struct GithubReleaseArtifact {
    pub name: String,
    pub size: u64,
    pub content_type: String,
    pub browser_download_url: String,
}

impl TryFrom<&GithubRelease> for RepoRelease {
    type Error = anyhow::Error;

    fn try_from(value: &GithubRelease) -> std::result::Result<Self, Self::Error> {
        Ok(RepoRelease {
            version: Version::parse(if value.tag_name.starts_with("v") {
                &value.tag_name[1..]
            } else {
                &value.tag_name
            })?,
            artifacts: value
                .assets
                .iter()
                .filter_map(|v| match RepoArtifact::try_from(v) {
                    Ok(art) => Some(art),
                    Err(e) => {
                        warn!("Failed to parse artifact {}: {}", &v.name, e);
                        None
                    }
                })
                .collect(),
        })
    }
}

impl TryFrom<&GithubReleaseArtifact> for RepoArtifact {
    type Error = anyhow::Error;

    fn try_from(value: &GithubReleaseArtifact) -> std::result::Result<Self, Self::Error> {
        Ok(RepoArtifact {
            name: value.name.clone(),
            size: value.size,
            content_type: value.content_type.clone(),
            location: RepoResource::Remote(value.browser_download_url.clone()),
        })
    }
}

#[async_trait::async_trait]
impl Repo for GithubRepo {
    async fn get_releases(&self) -> Result<Vec<RepoRelease>> {
        info!(
            "Fetching release from: github.com/{}/{}",
            self.owner, self.repo
        );
        let req = self
            .client
            .get(format!(
                "https://api.github.com/repos/{}/{}/releases",
                self.owner, self.repo
            ))
            .build()?;

        let rsp: Vec<GithubRelease> = self.client.execute(req).await?.json().await?;
        Ok(rsp
            .into_iter()
            .filter_map(|v| match RepoRelease::try_from(&v) {
                Ok(r) => Some(r),
                Err(e) => {
                    warn!("Failed to parse release: {} {}", v.tag_name, e);
                    None
                }
            })
            .collect())
    }
}

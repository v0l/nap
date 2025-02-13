use crate::repo::{
    load_artifact, load_artifact_url, Repo, RepoArtifact, RepoRelease, RepoResource,
};
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
    pub url: String,
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

        let gh_release: Vec<GithubRelease> = self.client.execute(req).await?.json().await?;

        let mut releases = vec![];
        for release in gh_release {
            let mut artifacts = vec![];
            for gh_artifact in release.assets {
                match load_artifact_url(&gh_artifact.browser_download_url).await {
                    Ok(a) => artifacts.push(a),
                    Err(e) => warn!(
                        "Failed to load artifact {}: {}",
                        gh_artifact.browser_download_url, e
                    ),
                }
            }
            if artifacts.is_empty() {
                warn!("No artifacts found for {}", release.tag_name);
                continue;
            }
            releases.push(RepoRelease {
                version: Version::parse(if release.tag_name.starts_with("v") {
                    &release.tag_name[1..]
                } else {
                    &release.tag_name
                })?,
                description: Some(release.body),
                url: Some(release.url),
                artifacts,
            });
        }
        Ok(releases)
    }
}

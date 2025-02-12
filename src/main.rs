mod manifest;
mod repo;

use crate::manifest::Manifest;
use crate::repo::Repo;
use anyhow::{anyhow, bail, Result};
use clap::Parser;
use config::{Config, File, FileSourceFile};
use log::info;
use nostr_sdk::{EventBuilder, JsonUtil, Keys};
use std::path::PathBuf;

#[derive(clap::Parser)]
#[command(version, about)]
struct Args {
    /// User specified config path
    #[arg(long, short)]
    pub config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // Set default log level to info
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    let args = Args::parse();

    let manifest: Manifest = Config::builder()
        .add_source(File::from(args.config.unwrap_or(PathBuf::from("nap.yaml"))))
        .build()
        .map_err(|e| anyhow!("Failed to load config: {}", e))?
        .try_deserialize()?;

    let repo: Box<dyn Repo> = (&manifest).try_into()?;

    let releases = repo.get_releases().await?;

    info!("Found {} release(s)", releases.len());

    if let Some(release) = releases.first() {
        info!("Starting publish of release {}", release.version);
        info!("Artifacts: ");
        for a in &release.artifacts {
            info!(" - {}", a.name);
        }
        if !dialoguer::Confirm::new()
            .default(false)
            .with_prompt(format!("Publish v{}?", release.version))
            .interact()?
        {
            return Ok(());
        }

        let key = dialoguer::Password::new()
            .with_prompt("Enter nsec:")
            .interact()?;

        let key = if let Ok(nsec) = Keys::parse(&key) {
            nsec
        } else {
            bail!("Invalid private key")
        };

        let ev: EventBuilder = (&manifest).into();

        // create release

        // publish application
        let ev = ev.build(key.public_key).sign_with_keys(&key)?;
        info!("{}", ev.as_json());
    }

    Ok(())
}

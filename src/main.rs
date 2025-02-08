mod manifest;
mod repo;

use crate::manifest::Manifest;
use crate::repo::Repo;
use anyhow::{anyhow, Result};
use clap::Parser;
use config::{Config, File, FileSourceFile};
use log::info;
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
    }

    Ok(())
}

mod manifest;
mod repo;

use crate::manifest::Manifest;
use crate::repo::Repo;
use anyhow::{anyhow, bail, Result};
use clap::Parser;
use config::{Config, File, FileSourceFile};
use log::info;
use nostr_sdk::prelude::Coordinate;
use nostr_sdk::{Client, EventBuilder, JsonUtil, Keys, Kind, Tag};
use std::path::PathBuf;

#[derive(clap::Parser)]
#[command(version, about)]
struct Args {
    /// User specified config path
    #[arg(long, short)]
    pub config: Option<PathBuf>,

    /// Relay to publish events to
    #[arg(long)]
    pub relay: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Set default log level to info
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    env_logger::init();

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
            info!(" - {}", a);
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

        let app_id = release.app_id()?;
        let app_coord = Coordinate::new(Kind::Custom(32_267), key.public_key).identifier(app_id);

        // create release
        let release_list = release
            .clone()
            .into_release_list_event(&key, app_coord)
            .await?;
        let release_coord = Coordinate::new(Kind::Custom(30_063), key.public_key)
            .identifier(release.release_tag()?);

        // publish application
        let app_ev = ev
            .tag(Tag::coordinate(release_coord))
            .tags(
                release
                    .artifacts
                    .iter()
                    .filter_map(|a| Tag::parse(["f", a.platform.to_string().as_str()]).ok()),
            )
            .sign_with_keys(&key)?;

        info!("Publishing events..");
        let client = Client::builder().build();
        for r in &args.relay {
            info!("Connecting to {}", r);
            client.add_relay(r).await?;
        }
        if args.relay.is_empty() {
            const DEFAULT_RELAY: &'static str = "wss://relay.zapstore.dev";
            info!("Connecting to default relay {DEFAULT_RELAY}");
            client.add_relay(DEFAULT_RELAY).await?;
        }
        client.connect().await;

        client.send_event(app_ev).await?;
        for ev in release_list {
            client.send_event(ev).await?;
        }

        info!("Done.");
    }

    Ok(())
}

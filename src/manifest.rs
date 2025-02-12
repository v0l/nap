use nostr_sdk::{Event, EventBuilder, Kind, Tag};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Manifest {
    /// App ID, must be unique
    pub id: String,

    /// Application display name
    pub name: String,

    /// Long app description / release notes
    pub description: Option<String>,

    /// Repo URL
    pub repository: Option<String>,

    /// SPDX license code
    pub license: Option<String>,

    /// App icon
    pub icon: Option<String>,

    /// App preview images
    pub images: Vec<String>,

    /// Tags (category / purpose)
    pub tags: Vec<String>,
}

impl Into<EventBuilder> for &Manifest {
    fn into(self) -> EventBuilder {
        let mut b = EventBuilder::new(
            Kind::Custom(32_267),
            self.description.clone().unwrap_or_default(),
        )
        .tags([
            Tag::parse(["d", &self.id]).unwrap(),
            Tag::parse(["name", &self.name]).unwrap(),
        ]);
        if let Some(icon) = &self.icon {
            b = b.tag(Tag::parse(["icon", icon]).unwrap());
        }
        if let Some(repository) = &self.repository {
            b = b.tag(Tag::parse(["repository", repository]).unwrap());
        }
        if let Some(license) = &self.license {
            b = b.tag(Tag::parse(["license", license]).unwrap());
        }
        for image in &self.images {
            b = b.tag(Tag::parse(["image", image]).unwrap());
        }
        for tag in &self.tags {
            b = b.tag(Tag::parse(["t", tag]).unwrap());
        }

        b
    }
}

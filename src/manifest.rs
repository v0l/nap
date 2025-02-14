use nostr_sdk::{EventBuilder, Kind, Tag};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Manifest {
    /// App ID, must be unique
    pub id: String,

    /// Application display name
    pub name: String,

    /// App description
    pub description: Option<String>,

    /// Long form app description (with markdown)
    pub summary: Option<String>,

    /// Repo URL
    pub repository: Option<String>,

    /// Public project website
    pub url: Option<String>,

    /// SPDX license code
    pub license: Option<String>,

    /// App icon
    pub icon: Option<String>,

    /// App preview images
    pub images: Vec<String>,

    /// Tags (category / purpose)
    pub tags: Vec<String>,
}

impl From<&Manifest> for EventBuilder {
    fn from(val: &Manifest) -> Self {
        let mut b = EventBuilder::new(Kind::Custom(32_267), val.description.as_str_or_empty())
            .tags([
                Tag::parse(["d", &val.id]).unwrap(),
                Tag::parse(["name", &val.name]).unwrap(),
                Tag::parse(["url", val.url.as_str_or_empty()]).unwrap(),
            ]);
        if let Some(s) = &val.summary {
            b = b.tag(Tag::parse(["summary", s]).unwrap());
        }
        if let Some(icon) = &val.icon {
            b = b.tag(Tag::parse(["icon", icon]).unwrap());
        }
        if let Some(repository) = &val.repository {
            b = b.tag(Tag::parse(["repository", repository]).unwrap());
        }
        if let Some(license) = &val.license {
            b = b.tag(Tag::parse(["license", license]).unwrap());
        }
        for image in &val.images {
            b = b.tag(Tag::parse(["image", image]).unwrap());
        }
        for tag in &val.tags {
            b = b.tag(Tag::parse(["t", tag]).unwrap());
        }

        b
    }
}

pub trait AsStrOrEmpty {
    fn as_str_or_empty(&self) -> &str;
}

impl AsStrOrEmpty for Option<String> {
    fn as_str_or_empty(&self) -> &str {
        self.as_ref().map(|s| s.as_str()).unwrap_or("")
    }
}

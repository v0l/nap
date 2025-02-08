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

    /// App icon
    pub icon: Option<String>,

    /// App preview images
    pub images: Vec<String>,

    /// Tags (category / purpose)
    pub tags: Vec<String>,
}

#[derive(Deserialize)]
pub enum Platform {
    Android {
        arch: Architecture
    },
    IOS,
    MacOS {
        arch: Architecture
    },
    Windows {
        arch: Architecture
    },
    Linux {
        arch: Architecture
    },
    Web
}

#[derive(Deserialize)]
pub enum Architecture {
    ARMv7,
    ARMv8,
    X86,
    AMD64,
    ARM64
}
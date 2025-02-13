# NAP

Nostr Application Publisher

## Install

Install rust toolchain with [rustup](https://rustup.rs/)

Install `nap`:
```bash
cargo install --git https://git.v0l.io/Kieran/nap
```

Create your `nap.yaml` config file:

```yaml
# Unique app id
id: "io.nostrlabs.freeflow"

# Display name of the app
name: "Freeflow"

# Human-readable long description
description: "Live in the moment"

# Application icon
icon: "https://freeflow.app/icon.png"

# Banner / Preview of the app
images:
  - "https://freeflow.app/banner.jpg"

# Public code repo or project website
repository: "https://github.com/nostrlabs-io/freeflow"

# SPDX code license
license: "MIT"

# Descriptive app tags
tags:
  - "tiktok"
  - "shorts"
```

Publish the app by running `nap` in your project folder and follow the prompts. 
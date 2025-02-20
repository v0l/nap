use anyhow::{bail, Result};
use apk::res::Chunk;
use apk::AndroidManifest;
use log::{debug, trace};
use std::collections::HashMap;
use std::fmt::Write;
use std::io::Cursor;

/// Converts [Chunk::Xml] to actual XML string
pub fn xml_chunk_to_xml(chunk: &Chunk) -> Result<String> {
    let nodes = if let Chunk::Xml(nodes) = chunk {
        nodes
    } else {
        bail!("Not an XML chunk")
    };

    let mut buf = String::with_capacity(4096);
    for node in nodes {
        match node {
            Chunk::Xml(x) => buf.write_str(&xml_chunk_to_xml(&Chunk::Xml(x.clone()))?)?,
            Chunk::XmlStartNamespace(_, _) => {}
            Chunk::XmlEndNamespace(_, _) => {}
            Chunk::XmlStartElement(_, _, _) => {}
            Chunk::XmlEndElement(_, _) => {}
            Chunk::XmlResourceMap(_) => {}
            Chunk::TablePackage(_, _) => {}
            Chunk::TableType(_, _, _) => {}
            Chunk::TableTypeSpec(_, _) => {}
            _ => trace!("Skipping chunk: {:?}", node),
        }
    }
    Ok(buf)
}
/// Parse android manifest from AndroidManifest.xml file data
pub fn parse_android_manifest(data: &[u8]) -> Result<AndroidManifest> {
    let chunks = if let Chunk::Xml(chunks) = Chunk::parse(&mut Cursor::new(data))? {
        chunks
    } else {
        bail!("Invalid AndroidManifest file");
    };

    let strings = if let Chunk::StringPool(strings, _) = &chunks[0] {
        HashMap::from_iter(
            strings
                .iter()
                .enumerate()
                .map(|(i, s)| (s.to_string(), i as i32)),
        )
    } else {
        bail!("invalid manifest 1");
    };

    let mut res = AndroidManifest::default();
    res.package = find_value_in(&strings, &chunks, "manifest", "package");
    res.version_code =
        find_value_in(&strings, &chunks, "manifest", "versionCode").and_then(|v| v.parse().ok());
    res.version_name = find_value_in(&strings, &chunks, "manifest", "versionName");
    res.compile_sdk_version = find_value_in(&strings, &chunks, "manifest", "compileSdkVersion")
        .and_then(|v| v.parse().ok());
    res.compile_sdk_version_codename =
        find_value_in(&strings, &chunks, "manifest", "compileSdkVersionCodename")
            .and_then(|v| v.parse().ok());
    res.platform_build_version_code =
        find_value_in(&strings, &chunks, "manifest", "platformBuildVersionCode")
            .and_then(|v| v.parse().ok());
    res.platform_build_version_name =
        find_value_in(&strings, &chunks, "manifest", "platformBuildVersionName")
            .and_then(|v| v.parse().ok());

    res.sdk.min_sdk_version =
        find_value_in(&strings, &chunks, "uses-sdk", "minSdkVersion").and_then(|v| v.parse().ok());
    res.sdk.target_sdk_version = find_value_in(&strings, &chunks, "uses-sdk", "targetSdkVersion")
        .and_then(|v| v.parse().ok());
    res.sdk.max_sdk_version =
        find_value_in(&strings, &chunks, "uses-sdk", "maxSdkVersion").and_then(|v| v.parse().ok());

    res.application.theme = find_value_in(&strings, &chunks, "application", "theme");
    res.application.label = find_value_in(&strings, &chunks, "application", "label");
    res.application.icon = find_value_in(&strings, &chunks, "application", "icon");

    Ok(res)
}

fn find_value_in(
    strings: &HashMap<String, i32>,
    chunks: &Vec<Chunk>,
    node: &str,
    attr: &str,
) -> Option<String> {
    let idx_node = if let Some(i) = strings.get(node) {
        *i
    } else {
        return None;
    };

    let idx_attr = if let Some(i) = strings.get(attr) {
        *i
    } else {
        return None;
    };

    chunks.iter().find_map(|chunk| {
        if let Chunk::XmlStartElement(_, el, attrs) = chunk {
            match el.name {
                x if x == idx_node => attrs.iter().find(|e| e.name == idx_attr).and_then(|e| {
                    debug!("{}, {}, {:?}", node, attr, e);
                    match e.typed_value.data_type {
                        3 => strings
                            .iter()
                            .find(|(_, v)| **v == e.raw_value)
                            .map(|(k, _)| k.clone()),
                        16 => Some(e.typed_value.data.to_string()),
                        _ => {
                            debug!("unknown data type {},{},{:?}", node, attr, e);
                            None
                        }
                    }
                }),
                _ => None,
            }
        } else {
            None
        }
    })
}

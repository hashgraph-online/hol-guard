//! Installed metadata integrity only; this never enables contributed policy.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
#[path = "bundle_metadata_compatibility.rs"]
mod compatibility_reader;
#[path = "bundle_metadata_defaults.rs"]
mod release_defaults;
#[path = "bundle_metadata_json.rs"]
mod strict_json;
pub(crate) use compatibility_reader::stream as compatibility_stream;
type Result<T> = std::result::Result<T, &'static str>;
const INVALID: &str = "installed bundle metadata invalid";

fn fields(value: &Value, names: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|v| v.len() == names.len() && names.iter().all(|k| v.contains_key(*k)))
}
fn hex(value: &Value, length: usize) -> bool {
    value.as_str().is_some_and(|s| {
        s.len() == length
            && s.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}
fn positive(value: &Value) -> bool {
    value.as_u64().is_some_and(|n| n > 0)
}
fn matches(pattern: &str, value: &str) -> bool {
    regex::Regex::new(pattern)
        .expect("fixed metadata expression")
        .is_match(value)
}

fn target(value: &Value, source: Option<&str>) -> Result<Value> {
    if !fields(value, &["tag", "asset"]) && !fields(value, &["tag", "asset", "member"]) {
        return Err(INVALID);
    }
    let name = value
        .get("member")
        .unwrap_or(&value["asset"])
        .as_str()
        .ok_or(INVALID)?;
    let (kind, digest) = if let Some(digest) = name
        .strip_prefix("object-")
        .and_then(|s| s.strip_suffix(".json"))
    {
        ("object", digest)
    } else if let Some(digest) = name
        .strip_prefix("pack-")
        .and_then(|s| s.strip_suffix(".zip"))
    {
        ("pack", digest)
    } else {
        return Err(INVALID);
    };
    let tag = value["tag"].as_str().ok_or(INVALID)?;
    if !hex(&json!(digest), 64)
        || !matches(
            r"^extension-data-[0-9a-f]{40}-[0-9]{1,20}\.[0-9]{1,10}-[0-9]{6}$",
            tag,
        )
        || source.is_some_and(|source| !tag.starts_with(&format!("extension-data-{source}-0.0-")))
    {
        return Err(INVALID);
    }
    if value.get("member").is_some() {
        let asset = value["asset"].as_str().ok_or(INVALID)?;
        let pattern = if kind == "object" {
            r"^objects-[0-9]{6}\.zip$"
        } else {
            r"^packs-[0-9]{6}\.zip$"
        };
        if !matches(pattern, asset) {
            return Err(INVALID);
        }
    }
    Ok(json!({"name":name,"digest":digest,"kind":kind}))
}

fn reference(value: &Value, located: bool, source: Option<&str>) -> Result<()> {
    let mut expected = vec!["sha256", "length", "expanded_length", "kind"];
    if located {
        expected.push("location");
    }
    if !fields(value, &expected)
        || !hex(&value["sha256"], 64)
        || !value["length"]
            .as_u64()
            .is_some_and(|n| n > 0 && n <= 65536)
        || value["expanded_length"].as_u64() != value["length"].as_u64()
        || value["kind"] != "data"
    {
        return Err(INVALID);
    }
    if located {
        let selected = target(&value["location"], source)?;
        if selected["kind"] != "object" || selected["digest"] != value["sha256"] {
            return Err(INVALID);
        }
    }
    Ok(())
}

fn compatibility(value: &Value, extensions: u64, source: Option<&str>) -> Result<()> {
    if !fields(value, &["commands", "mcp"]) {
        return Err(INVALID);
    }
    let mut total = 0u64;
    for family in ["commands", "mcp"] {
        let row = &value[family];
        let count = row["count"].as_u64().ok_or(INVALID)?;
        if !fields(row, &["count", "index"]) || count > extensions {
            return Err(INVALID);
        }
        total = total.checked_add(count).ok_or(INVALID)?;
        if count == 0 {
            if !row["index"].is_null() {
                return Err(INVALID);
            }
        } else {
            reference(&row["index"], true, source)?;
        }
    }
    if total != extensions {
        return Err(INVALID);
    }
    Ok(())
}

fn root(data: &str, source: &str, engine: &str) -> Result<Value> {
    if data.is_empty() || data.len() > 65536 || !hex(&json!(source), 40) || !hex(&json!(engine), 64)
    {
        return Err(INVALID);
    }
    let root = strict_json::decode(data.as_bytes())?;
    let mut names = vec![
        "schema",
        "source_sha",
        "engine",
        "authority_epoch",
        "publication_id",
        "policy",
    ];
    if root.get("compatibility").is_some() {
        names.push("compatibility");
    }
    if !fields(&root, &names)
        || root["schema"] != "guard.command-pack-bundle.v1"
        || root["source_sha"] != source
        || root["engine"] != engine
        || root["publication_id"] != "0.0"
        || !positive(&root["authority_epoch"])
    {
        return Err(INVALID);
    }
    let policy = &root["policy"];
    if !fields(policy, &["root", "transport", "defaults", "revocations"]) {
        return Err(INVALID);
    }
    let native = &policy["root"];
    if !fields(
        native,
        &[
            "schema",
            "kind",
            "authority",
            "engine",
            "extensions",
            "index",
            "index_fanout",
            "objects",
            "object_bytes",
            "object_bytes_limit",
        ],
    ) || native["schema"] != "guard.command-pack-release.v1"
        || native["engine"] != engine
        || native["kind"] != "root"
        || native["authority"] != "requires-authenticated-release-binding"
        || native["index_fanout"].as_u64() != Some(64)
        || native["object_bytes_limit"].as_u64() != Some(65536)
        || !["extensions", "objects", "object_bytes"]
            .iter()
            .all(|k| positive(&native[k]))
    {
        return Err(INVALID);
    }
    reference(&native["index"], false, None)?;
    reference(&policy["transport"], true, Some(source))?;
    let extensions = native["extensions"].as_u64().ok_or(INVALID)?;
    if let Some(value) = root.get("compatibility") {
        compatibility(value, extensions, Some(source))?;
    }
    for name in ["defaults", "revocations"] {
        let row = &policy[name];
        let expected = if name == "defaults" {
            vec!["count", "index"]
        } else {
            vec!["count", "index", "epoch"]
        };
        let count = row["count"].as_u64().ok_or(INVALID)?;
        if !fields(row, &expected)
            || (name == "defaults" && count > extensions)
            || (name == "revocations" && row["epoch"].as_u64().is_none())
        {
            return Err(INVALID);
        }
        if count > 0 {
            reference(&row["index"], true, Some(source))?;
        } else if !row["index"].is_null() {
            return Err(INVALID);
        }
    }
    Ok(root)
}

pub(crate) fn evaluate(bytes: &[u8]) -> Result<Value> {
    let input = strict_json::decode(bytes)?;
    match input["operation"].as_str() {
        Some("release-defaults") => release_defaults::select(&input),
        Some("installed-presence") => compatibility_reader::presence(&input),
        Some("installed-plan") => installed_plan(&input),
        Some("installed") => installed(&input),
        Some("root" | "descriptor") => {
            let data = input["data"].as_str().ok_or(INVALID)?;
            let source = input["source_sha"].as_str().ok_or(INVALID)?;
            let engine = input["engine"].as_str().ok_or(INVALID)?;
            let value = root(data, source, engine)?;
            if input["operation"] == "root" {
                Ok(value)
            } else {
                Ok(json!({"schema":"guard.command-pack-bundle.v1",
                    "path":"codex_plugin_scanner/guard/contracts/data/extensions/command-pack-bundle/command-pack-bundle.v1.json",
                    "sha256":hex::encode(Sha256::digest(data.as_bytes())),
                    "length":data.len(),"source_sha":source,"engine":engine}))
            }
        }
        Some("compatibility") => {
            compatibility(
                &input["value"],
                input["extensions"].as_u64().ok_or(INVALID)?,
                None,
            )?;
            Ok(json!({}))
        }
        _ => Err(INVALID),
    }
}

fn installed_plan(input: &Value) -> Result<Value> {
    let runtime = &input["runtime_manifest"];
    let compiler = &input["compiler_manifest"];
    if !runtime.is_object()
        || !compiler.is_object()
        || runtime["schema"] != "hol-guard-native-runtime.v1"
        || compiler["schema"] != "hol-guard-native-source-compiler.v2"
        || runtime["protocol_version"].as_u64() != Some(1)
        || compiler["protocol_version"].as_u64() != Some(1)
    {
        return Err("installed bundle native manifests differ");
    }
    for field in ["source_sha", "package_version", "target", "platform_tag"] {
        if !runtime[field].is_string() || runtime[field] != compiler[field] {
            return Err("installed bundle native manifests differ");
        }
    }
    if !matches!(
        compiler["executable"].as_str(),
        Some("hol-guard-runtime" | "hol-guard-runtime.exe")
    ) {
        return Err("installed bundle executable invalid");
    }
    let size = compiler["compiler_size"]
        .as_u64()
        .ok_or("installed bundle executable size differs")?;
    if size == 0 || size > 128 * 1024 * 1024 || runtime["runtime_size"].as_u64() != Some(size) {
        return Err("installed bundle executable size differs");
    }
    Ok(json!({"executable":compiler["executable"],"size":size}))
}

fn installed(input: &Value) -> Result<Value> {
    let plan = installed_plan(input)?;
    let runtime = &input["runtime_manifest"];
    let compiler = &input["compiler_manifest"];
    if input["binary_length"].as_u64() != plan["size"].as_u64()
        || !hex(&input["binary_digest"], 64)
        || input["binary_digest"] != runtime["runtime_sha256"]
        || input["binary_digest"] != compiler["compiler_sha256"]
    {
        return Err("installed bundle executable digest differs");
    }
    let data = input["data"].as_str().ok_or(INVALID)?;
    let source = runtime["source_sha"].as_str().ok_or(INVALID)?;
    let engine = compiler["implementation_digest"]
        .as_str()
        .ok_or("installed bundle engine identity missing")?;
    root(data, source, engine)?;
    let digest = hex::encode(Sha256::digest(data.as_bytes()));
    let descriptor = json!({"schema":"guard.command-pack-bundle.v1",
        "path":"codex_plugin_scanner/guard/contracts/data/extensions/command-pack-bundle/command-pack-bundle.v1.json",
        "sha256":digest,"length":data.len(),"source_sha":source,"engine":engine});
    if runtime["command_pack_bundle"] != descriptor || compiler["command_pack_bundle"] != descriptor
    {
        return Err("installed bundle native Root binding differs");
    }
    Ok(json!({"source_sha":source,"digest":digest,"engine":engine}))
}

#[cfg(test)]
#[path = "bundle_metadata_tests.rs"]
mod tests;

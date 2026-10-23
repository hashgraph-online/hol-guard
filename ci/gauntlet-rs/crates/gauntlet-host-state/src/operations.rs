//! Parse the pinned Python operator configuration from already-custodied bytes.
//! This module does not open the private config file or start an observer.

use crate::stable_tag;
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::fmt;
use std::path::{Component, Path};

const MAX_OPERATIONS_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationsError {
    pub reason: String,
}

impl fmt::Display for OperationsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for OperationsError {}

fn invalid(reason: impl Into<String>) -> OperationsError {
    OperationsError {
        reason: reason.into(),
    }
}

fn text<'a>(value: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn positive_integer(value: &Value) -> Option<u64> {
    value.as_u64().filter(|number| *number > 0)
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn literal_absolute_path(value: &str) -> bool {
    let path = Path::new(value);
    path.is_absolute()
        && !path.components().any(|part| part == Component::ParentDir)
        && !value.chars().any(char::is_whitespace)
}

fn repository(value: &str) -> bool {
    let Some((owner, name)) = value.split_once('/') else {
        return false;
    };
    !owner.is_empty()
        && !name.is_empty()
        && !name.contains('/')
        && owner
            .bytes()
            .chain(name.bytes())
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn vm_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=81).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'.' | b'-'))
}

/// Return Python's complete merged operations object, subject to an additional
/// 1-MiB input bound and Rust's finite integer representation. The caller must
/// independently authenticate and privately read the bytes before using them.
pub fn load_operations_bytes(raw: &[u8]) -> Result<Value, OperationsError> {
    if raw.len() > MAX_OPERATIONS_BYTES {
        return Err(invalid("operator configuration exceeds byte limit"));
    }
    let supplied: Value = serde_json::from_slice(raw)
        .map_err(|_| invalid("malformed operator configuration JSON"))?;
    let supplied = supplied
        .as_object()
        .ok_or_else(|| invalid("operator configuration must be a JSON object"))?;
    let defaults: Value = serde_json::from_str(include_str!("../operations-defaults-v1.json"))
        .expect("pinned operations defaults are valid JSON");
    let mut merged = defaults
        .as_object()
        .expect("pinned operations defaults are a JSON object")
        .clone();
    if supplied.keys().any(|key| !merged.contains_key(key)) {
        return Err(invalid("unknown operator configuration keys"));
    }
    merged.extend(supplied.clone());
    if !matches!(
        text(&merged, "discovery_mode"),
        Some("release-tags" | "pull-requests")
    ) {
        return Err(invalid("release-tags or pull-requests discovery required"));
    }
    if !matches!(
        text(&merged, "release_build_backend"),
        Some("local-vm" | "github-actions")
    ) {
        return Err(invalid(
            "local-vm or github-actions release build backend required",
        ));
    }
    let tags = merged
        .get("release_tags")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("explicit distinct stable release tags required"))?;
    if !(1..=20).contains(&tags.len()) {
        return Err(invalid("explicit distinct stable release tags required"));
    }
    let mut seen = HashSet::new();
    for tag in tags {
        let tag = tag
            .as_str()
            .ok_or_else(|| invalid("explicit distinct stable release tags required"))?;
        if !stable_tag(tag) || !seen.insert(tag) {
            return Err(invalid("explicit distinct stable release tags required"));
        }
    }
    if text(&merged, "schema") != Some("hol-gauntlet-operations.v1")
        || text(&merged, "base_branch") != Some("main")
    {
        return Err(invalid("supported schema and main base branch required"));
    }
    if !text(&merged, "repository").is_some_and(repository) {
        return Err(invalid("owner/repository required"));
    }
    if !text(&merged, "vm").is_some_and(vm_name) {
        return Err(invalid("literal Lima instance name required"));
    }
    for key in [
        "limactl",
        "gh",
        "git",
        "guest_python",
        "guest_controller",
        "candidate_root",
        "guest_output_root",
        "guest_inbox",
        "template_config",
        "template_asset_root",
        "template_controller",
        "guest_uv",
    ] {
        if !text(&merged, key).is_some_and(literal_absolute_path) {
            return Err(invalid(format!(
                "{key} must be a literal absolute path without spaces"
            )));
        }
    }
    let prefix = merged.get("staging_dependency_prefix");
    let digest = merged.get("staging_dependency_prefix_digest");
    let has_prefix = prefix.is_some_and(|value| !value.is_null());
    let has_digest = digest.is_some_and(|value| !value.is_null());
    if has_prefix != has_digest {
        return Err(invalid(
            "staging dependency prefix and digest must be supplied together",
        ));
    }
    if has_prefix
        && (!prefix
            .and_then(Value::as_str)
            .is_some_and(literal_absolute_path)
            || !digest
                .and_then(Value::as_str)
                .is_some_and(|value| lower_hex(value, 64)))
    {
        return Err(invalid(
            "pinned absolute staging dependency prefix required",
        ));
    }
    for key in [
        "poll_seconds",
        "telemetry_seconds",
        "job_timeout_seconds",
        "host_disk_floor_gib",
        "vm_disk_floor_gib",
        "vm_memory_gib",
        "vm_cpus",
        "vm_disk_gib",
        "build_memory_gib",
    ] {
        if merged.get(key).and_then(positive_integer).is_none() {
            return Err(invalid(format!("{key} must be a positive integer")));
        }
    }
    let vm_memory = merged["vm_memory_gib"].as_u64().unwrap();
    let build_memory = merged["build_memory_gib"].as_u64().unwrap();
    if vm_memory.saturating_sub(build_memory) < 2 {
        return Err(invalid(
            "reserve at least 2 GiB of VM memory outside the build container",
        ));
    }
    if merged["poll_seconds"].as_u64().unwrap() < 30
        || merged["telemetry_seconds"].as_u64().unwrap() < 5
    {
        return Err(invalid(
            "poll >=30 seconds and telemetry >=5 seconds required",
        ));
    }
    let argv = merged
        .get("prepare_argv")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid("prepare_argv must be a literal argv with an absolute executable")
        })?;
    if argv
        .iter()
        .any(|arg| arg.as_str().is_none_or(str::is_empty))
        || argv.first().is_some_and(|first| {
            !first
                .as_str()
                .is_some_and(|path| Path::new(path).is_absolute())
        })
    {
        return Err(invalid(
            "prepare_argv must be a literal argv with an absolute executable",
        ));
    }
    if text(&merged, "artifact_workflow") != Some("gauntlet-pr-artifacts.yml") {
        return Err(invalid("reviewed Gauntlet artifact workflow required"));
    }
    if !text(&merged, "template_config_digest").is_some_and(|value| lower_hex(value, 64)) {
        return Err(invalid("external baseline configuration digest required"));
    }
    if !merged.get("public_dashboard_url").is_some_and(|value| {
        value.is_null()
            || value
                .as_str()
                .is_some_and(|url| url.starts_with("https://"))
    }) {
        return Err(invalid(
            "public dashboard URL must use HTTPS, or remain null",
        ));
    }
    Ok(Value::Object(merged))
}

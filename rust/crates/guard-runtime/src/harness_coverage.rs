//! The machine registry of the harnesses each managed user installed, and the
//! aggregate coverage integrity reports from it.
//!
//! Only an administrator registers or unregisters a user, under the
//! machine-state lock the caller holds. The registry names each managed
//! artifact by its path below the user's home and the digest it had when it
//! was registered; verification reports only counts, never a home or a path.

#[path = "harness_coverage_artifacts.rs"]
mod artifacts;
#[path = "harness_coverage_registry.rs"]
mod registry;

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;

use serde_json::{json, Map, Value};

use artifacts::{
    artifact_digest, managed_manifest_paths, relative_text, resolve_lenient, Evidence,
};
use registry::{artifact_fields, read_registry, write_registry};

const SCHEMA_VERSION: &str = "hol-guard-harness-coverage-registry.v1";
const REGISTRY_NAME: &str = "harness-coverage-registry.json";
const MAX_REGISTRY_BYTES: u64 = 256 * 1024;
const MAX_USERS: usize = 256;
const MAX_HARNESSES_PER_USER: usize = 32;
const MAX_ARTIFACTS_PER_HARNESS: usize = 64;
const MAX_PATH_CHARS: usize = 4096;
const MAX_NAME_CHARS: usize = 128;

const REGISTRY_INVALID: &str = "harness_coverage_registry_invalid";
const REGISTRY_ACL_INVALID: &str = "harness_coverage_registry_acl_invalid";
const CAPACITY_EXCEEDED: &str = "harness_coverage_registry_capacity_exceeded";
const MANIFEST_INVALID: &str = "harness_coverage_manifest_invalid";
const REGISTRY_IO_FAILED: &str = "harness_coverage_registry_io_failed";

/// The Python exception a refused registry change surfaces as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorClass {
    Value,
    Permission,
    Os,
}

impl ErrorClass {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Value => "value",
            Self::Permission => "permission",
            Self::Os => "os",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CoverageError {
    pub(crate) class: ErrorClass,
    pub(crate) reason_code: &'static str,
}

const fn value_error(reason_code: &'static str) -> CoverageError {
    CoverageError {
        class: ErrorClass::Value,
        reason_code,
    }
}

const fn permission_error(reason_code: &'static str) -> CoverageError {
    CoverageError {
        class: ErrorClass::Permission,
        reason_code,
    }
}

fn os_error(_error: io::Error) -> CoverageError {
    CoverageError {
        class: ErrorClass::Os,
        reason_code: REGISTRY_IO_FAILED,
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Coverage {
    pub(crate) required: usize,
    pub(crate) protected: usize,
    pub(crate) degraded: usize,
    pub(crate) missing: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Verification {
    pub(crate) state: &'static str,
    pub(crate) reason_code: &'static str,
    /// `None` when the registry could not be read, so nothing was counted.
    pub(crate) coverage: Option<Coverage>,
}

const fn unknown(reason_code: &'static str) -> Verification {
    Verification {
        state: "unknown",
        reason_code,
        coverage: None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactState {
    Protected,
    Degraded,
    Missing,
}

/// Count every required harness of every registered user as protected,
/// degraded or missing. A registry that cannot be read proves nothing, so it
/// is unknown rather than a count.
pub(crate) fn verify(state_root: &Path, owner_uid: u32, required: &[String]) -> Verification {
    if required.is_empty() {
        return Verification {
            state: "healthy",
            reason_code: "harness_coverage_not_required",
            coverage: Some(Coverage::default()),
        };
    }
    match read_registry(state_root, owner_uid) {
        Ok(None) => unknown("harness_coverage_registry_absent"),
        Ok(Some(registry)) => project(&registry, required),
        Err(_) => unknown("harness_coverage_probe_failed"),
    }
}

fn project(registry: &Map<String, Value>, required: &[String]) -> Verification {
    let users = registry_users(registry);
    let mut coverage = Coverage {
        required: users.len() * required.len(),
        ..Coverage::default()
    };
    for user in users {
        let home = resolve_lenient(Path::new(text(user, "home")));
        let harnesses = list(user, "harnesses");
        for name in required {
            let Some(harness) = harnesses
                .iter()
                .find(|harness| harness.get("name").and_then(Value::as_str) == Some(name))
            else {
                coverage.missing += 1;
                continue;
            };
            let artifacts = list(harness, "artifacts");
            if artifacts.is_empty() {
                coverage.degraded += 1;
                continue;
            }
            let states: Vec<ArtifactState> = artifacts
                .iter()
                .map(|artifact| artifact_state(&home, artifact))
                .collect();
            if states.contains(&ArtifactState::Missing) {
                coverage.missing += 1;
            } else if states.contains(&ArtifactState::Degraded) {
                coverage.degraded += 1;
            } else {
                coverage.protected += 1;
            }
        }
    }
    let (state, reason_code) = if coverage.missing > 0 {
        ("degraded", "harness_coverage_missing")
    } else if coverage.degraded > 0 {
        ("degraded", "harness_coverage_degraded")
    } else {
        ("healthy", "harness_coverage_healthy")
    };
    Verification {
        state,
        reason_code,
        coverage: Some(coverage),
    }
}

/// How one registered artifact stands now. Its record was validated when the
/// registry was read.
fn artifact_state(home: &Path, artifact: &Map<String, Value>) -> ArtifactState {
    let Some((relative, kind, digest)) = artifact_fields(artifact) else {
        return ArtifactState::Missing;
    };
    let candidate = home.join(relative);
    if !resolve_lenient(&candidate).starts_with(home) {
        return ArtifactState::Degraded;
    }
    if kind == "mutable-file" {
        // Guard's own database changes on every run, so only its presence is
        // evidence, and its size never makes it absent.
        return match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.is_file() => ArtifactState::Protected,
            Ok(metadata) if metadata.is_dir() => ArtifactState::Degraded,
            _ => ArtifactState::Missing,
        };
    }
    match (kind, artifact_digest(&candidate)) {
        ("missing", _) | (_, None) => ArtifactState::Missing,
        ("file", Some(Evidence::File(actual)))
        | ("directory", Some(Evidence::Directory(actual)))
            if digest == Some(actual.as_str()) =>
        {
            ArtifactState::Protected
        }
        _ => ArtifactState::Degraded,
    }
}

/// Record the active harnesses `installs` names for the user at `home`,
/// replacing whatever that user had registered. `home` is already resolved.
pub(crate) fn register(
    state_root: &Path,
    owner_uid: u32,
    home: &Path,
    installs: &[Value],
) -> Result<(), CoverageError> {
    let mut registry = read_registry(state_root, owner_uid)?.unwrap_or_else(empty_registry);
    if installs.len() > MAX_HARNESSES_PER_USER {
        return Err(value_error(CAPACITY_EXCEEDED));
    }
    let home_text = home.to_str().ok_or(value_error(REGISTRY_INVALID))?;
    let mut records: Vec<(String, Value)> = Vec::new();
    let mut seen = BTreeSet::new();
    for install in installs {
        let install = install.as_object().ok_or(value_error(REGISTRY_INVALID))?;
        if !install.get("active").is_some_and(truthy) {
            continue;
        }
        let name = install.get("harness").and_then(Value::as_str);
        let manifest = install.get("manifest").and_then(Value::as_object);
        let (Some(name), Some(manifest)) = (name, manifest) else {
            return Err(value_error(REGISTRY_INVALID));
        };
        if !(1..=MAX_NAME_CHARS).contains(&name.chars().count()) || !seen.insert(name) {
            return Err(value_error(REGISTRY_INVALID));
        }
        let artifacts = harness_artifacts(home, manifest)?;
        records.push((
            name.to_owned(),
            json!({"artifacts": artifacts, "name": name}),
        ));
    }
    records.sort_by(|left, right| left.0.cmp(&right.0));
    let harnesses: Vec<Value> = records.into_iter().map(|(_, record)| record).collect();
    let users = users_mut(&mut registry);
    users.retain(|user| home_of(user) != home_text);
    users.push(json!({"harnesses": harnesses, "home": home_text}));
    if users.len() > MAX_USERS {
        return Err(value_error(CAPACITY_EXCEEDED));
    }
    users.sort_by(|left, right| home_of(left).cmp(home_of(right)));
    write_registry(state_root, &registry)
}

fn harness_artifacts(
    home: &Path,
    manifest: &Map<String, Value>,
) -> Result<Vec<Value>, CoverageError> {
    let paths = managed_manifest_paths(manifest, home, MAX_ARTIFACTS_PER_HARNESS - 1)
        .map_err(|()| value_error(MANIFEST_INVALID))?;
    let mut artifacts = Vec::with_capacity(paths.len() + 1);
    for path in paths {
        let relative = relative_text(&path, home).ok_or(value_error(MANIFEST_INVALID))?;
        artifacts.push(match artifact_digest(&path) {
            Some(Evidence::File(digest)) => {
                json!({"kind": "file", "path": relative, "sha256": digest})
            }
            Some(Evidence::Directory(digest)) => {
                json!({"kind": "directory", "path": relative, "sha256": digest})
            }
            None => json!({"kind": "missing", "path": relative}),
        });
    }
    let guard_home = home.join(".hol-guard");
    let state_path = guard_home.join("guard.db");
    if let (Ok(guard_home), Ok(state)) = (
        fs::symlink_metadata(&guard_home),
        fs::symlink_metadata(&state_path),
    ) {
        let kind = if guard_home.is_dir() && state.is_file() {
            "mutable-file"
        } else {
            "missing"
        };
        let relative = relative_text(&state_path, home).ok_or(value_error(MANIFEST_INVALID))?;
        artifacts.push(json!({"kind": kind, "path": relative}));
    }
    Ok(artifacts)
}

/// Drop the user registered at `home`, the caller's spelling of the resolved
/// home. An absent registry has no user to drop.
pub(crate) fn unregister(
    state_root: &Path,
    owner_uid: u32,
    home: &str,
) -> Result<(), CoverageError> {
    let Some(mut registry) = read_registry(state_root, owner_uid)? else {
        return Ok(());
    };
    users_mut(&mut registry).retain(|user| home_of(user) != home);
    write_registry(state_root, &registry)
}

fn empty_registry() -> Map<String, Value> {
    let mut registry = Map::new();
    registry.insert("schemaVersion".to_owned(), Value::from(SCHEMA_VERSION));
    registry.insert("users".to_owned(), Value::Array(Vec::new()));
    registry
}

fn users_mut(registry: &mut Map<String, Value>) -> &mut Vec<Value> {
    let users = registry
        .entry("users")
        .or_insert_with(|| Value::Array(Vec::new()));
    if !users.is_array() {
        *users = Value::Array(Vec::new());
    }
    match users {
        Value::Array(users) => users,
        _ => unreachable!("users was just made an array"),
    }
}

/// A validated user record's home; every record has one.
fn home_of(user: &Value) -> &str {
    user.get("home").and_then(Value::as_str).unwrap_or_default()
}

fn registry_users(registry: &Map<String, Value>) -> Vec<&Map<String, Value>> {
    registry
        .get("users")
        .and_then(Value::as_array)
        .map(|users| users.iter().filter_map(Value::as_object).collect())
        .unwrap_or_default()
}

fn list<'a>(record: &'a Map<String, Value>, key: &str) -> Vec<&'a Map<String, Value>> {
    record
        .get(key)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_object).collect())
        .unwrap_or_default()
}

fn text<'a>(record: &'a Map<String, Value>, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// Python truthiness for a JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|number| number != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(fields) => !fields.is_empty(),
    }
}

#[cfg(test)]
#[path = "harness_coverage_tests.rs"]
mod tests;

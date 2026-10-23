//! Inert v1-v7 runner declaration checks; no asset or candidate code is read.

use crate::{load_record, Record, RecordError};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;

const FILE_ROLES: &[&str] = &[
    "bun",
    "node",
    "wheel",
    "native",
    "policy",
    "compiler",
    "model_manifest",
    "provider_manifest",
];
const TREE_ROLES: &[(&str, &str)] = &[("sdk", "sdk-tree"), ("guard_prefix", "guard-prefix")];

#[derive(Debug)]
pub enum RunnerConfigError {
    InvalidPin,
    UnsupportedVersion,
    Record(RecordError),
    DigestMismatch,
    InvalidDeclaration(&'static str),
}

impl fmt::Display for RunnerConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPin => f.write_str("external runner configuration SHA-256 required"),
            Self::UnsupportedVersion => f.write_str("unsupported runner schema version"),
            Self::Record(error) => write!(f, "{error}"),
            Self::DigestMismatch => f.write_str("runner configuration differs from external pin"),
            Self::InvalidDeclaration(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for RunnerConfigError {}

impl From<RecordError> for RunnerConfigError {
    fn from(value: RecordError) -> Self {
        Self::Record(value)
    }
}

#[derive(Debug, Clone)]
pub struct RunnerDeclaration {
    pub version: u8,
    pub config_digest: String,
    pub record: Record,
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn version_kind(schema: &str) -> Option<(u8, &'static str)> {
    match schema {
        "gauntlet-ci-runner.v1" => Some((1, "ci-runner-config")),
        "gauntlet-ci-runner.v2" => Some((2, "ci-runner-private-cell-config")),
        "gauntlet-ci-runner.v3" => Some((3, "ci-runner-conformance-config")),
        "gauntlet-ci-runner.v4" => Some((4, "ci-runner-compact-config")),
        "gauntlet-ci-runner.v5" => Some((5, "ci-runner-package-config")),
        "gauntlet-ci-runner.v6" => Some((6, "ci-runner-protocol-config")),
        "gauntlet-ci-runner.v7" => Some((7, "ci-runner-agent-surface-config")),
        _ => None,
    }
}

/// Match Python `PurePosixPath`'s canonical relative declaration rule.
/// Actual no-symlink file custody is a later, descriptor-relative step.
pub fn canonical_relative_asset_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains('\0')
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn asset_role_kind(role: &str) -> &'static str {
    if role == "private_cell" {
        "cell-artifacts"
    } else if role == "zod_cache" || role == "sdk" {
        "sdk-tree"
    } else if role == "guard_prefix" {
        "guard-prefix"
    } else {
        "file"
    }
}

fn validate_declaration(value: &Value, version: u8) -> Result<(), RunnerConfigError> {
    let invalid = RunnerConfigError::InvalidDeclaration;
    let assets = value["assets"]
        .as_object()
        .ok_or(invalid("asset map is missing"))?;
    let mut required: BTreeSet<&str> = FILE_ROLES.iter().copied().collect();
    required.extend(TREE_ROLES.iter().map(|(role, _)| *role));
    if version >= 2 {
        required.insert("private_cell");
    }
    if version >= 3 {
        required.insert("conformance");
    }
    let actual: BTreeSet<&str> = assets.keys().map(String::as_str).collect();
    let mut with_cache = required.clone();
    with_cache.insert("zod_cache");
    if actual != required && actual != with_cache {
        return Err(invalid(
            "exact named file, SDK and installed-prefix pins required",
        ));
    }
    for (role, row) in assets {
        if row["kind"] != asset_role_kind(role)
            || !row["path"]
                .as_str()
                .is_some_and(canonical_relative_asset_path)
        {
            return Err(invalid("asset kind or canonical relative path is invalid"));
        }
    }
    for name in ["campaign", "policy"] {
        if !value[name]["path"]
            .as_str()
            .is_some_and(canonical_relative_asset_path)
        {
            return Err(invalid("document path is not canonical relative"));
        }
    }
    let selection = value["selection"]
        .as_array()
        .ok_or(invalid("selection is missing"))?;
    let shards = value["shards"]
        .as_u64()
        .ok_or(invalid("shard count is invalid"))?;
    if shards == 0 || shards > selection.len() as u64 {
        return Err(invalid("shard count exceeds selected episodes"));
    }
    if assets["node"]["path"]
        .as_str()
        .and_then(|path| path.rsplit('/').next())
        != Some("node")
    {
        return Err(invalid(
            "explicit Node asset must retain the node executable name",
        ));
    }
    let runtime = &value["runtime"];
    let base_url = runtime["base_url"]
        .as_str()
        .ok_or(invalid("local model endpoint is missing"))?;
    let allowed_host = [
        "host.lima.internal",
        "localhost",
        "127.0.0.1",
        "192.168.5.2",
    ];
    if !allowed_host.iter().any(|host| {
        [8001, 8002]
            .iter()
            .any(|port| base_url == format!("http://{host}:{port}/v1"))
    }) {
        return Err(invalid(
            "local model endpoint is outside the pinned allowlist",
        ));
    }
    if version >= 2 && runtime["private_cell"]["native_sha256"] != assets["native"]["sha256"] {
        return Err(invalid(
            "private-cell native digest differs from the pinned native file",
        ));
    }
    Ok(())
}

/// Check a caller-pinned config's schema and declaration before opening assets.
///
/// This deliberately stops before Python `load_config`'s document, campaign,
/// policy, reservation and asset-custody checks. It cannot authorize execution.
pub fn validate_runner_declaration(
    raw: &[u8],
    expected_digest: &str,
) -> Result<RunnerDeclaration, RunnerConfigError> {
    if !is_sha256(expected_digest) {
        return Err(RunnerConfigError::InvalidPin);
    }
    let canonical = crate::canonicalize(raw)
        .map_err(|error| RunnerConfigError::Record(RecordError::Json(error)))?;
    let value: Value =
        serde_json::from_slice(&canonical).map_err(|_| RunnerConfigError::UnsupportedVersion)?;
    let schema = value["schema"]
        .as_str()
        .ok_or(RunnerConfigError::UnsupportedVersion)?;
    let (version, kind) = version_kind(schema).ok_or(RunnerConfigError::UnsupportedVersion)?;
    let record = load_record(kind, raw)?;
    let actual_digest = format!("{:x}", Sha256::digest(record.canonical_bytes()));
    if actual_digest != expected_digest {
        return Err(RunnerConfigError::DigestMismatch);
    }
    validate_declaration(record.value(), version)?;
    Ok(RunnerDeclaration {
        version,
        config_digest: actual_digest,
        record,
    })
}

//! `inventory_contract_metadata` classification half — the deterministic
//! functions `_item_from_artifact` calls to decide an inventory item's kind,
//! capabilities, risk level and content hash, plus the strict envelope check
//! that says whether a skill directory hash may be reused.
//!
//! The filesystem half of that module (`_apply_source_of_truth_metadata`,
//! `_apply_aibom_metadata_enrichment`, `_primary_artifact_content_hash`) and
//! the trust-attestation signing `_item_from_artifact` performs are not here:
//! they reach `aibom_detection`, `aibom_symlink` and the signing keys, and
//! land with those seams.
//!
//! Three CPython behaviours decide the output:
//!
//! * `bool(value)` is not "is the JSON `true`". `envConfigurationPresent: "no"`
//!   and `has_auth_headers: [0]` are both truthy, and an item whose risk level
//!   silently dropped to `info` is a protection regression, so
//!   [`python_truthy`] ports the rule rather than reading a boolean.
//! * `_canonical_inventory_content_hash` lower-cases to *test* a bare digest
//!   but returns the value it was handed when the test fails, so a
//!   `SHA256:AB…` prefixed value keeps its original spelling.
//! * `dict` is insertion-ordered and `serde_json::Map` is sorted, so the maps
//!   here are compared by content. Every consumer of this metadata serializes
//!   it with sorted keys (`fingerprint_mapping`, `_stable_snapshot_value`,
//!   `json.dumps(sort_keys=True)`), so the order the Python builds is not
//!   observable downstream.
//!
//! `scripts/ci/generate_inventory_item_metadata_parity.py` records the corpus
//! in `testdata/inventory_item_metadata_parity.json` that pins every case.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use guard_contracts::SKILL_DIRECTORY_IDENTITY_SCHEMA;

/// `bool(value)` for a JSON value: `None`, `false`, `0`, `""`, `[]` and `{}`
/// are false and everything else is true. `0.0` is false too, and so is a
/// `Number` that is zero however it was spelled.
pub fn python_truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        // A number outside `f64` is nonzero, so the fallback cannot hide a zero.
        Some(Value::Number(number)) => number.as_f64().map(|float| float != 0.0).unwrap_or(true),
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(fields)) => !fields.is_empty(),
    }
}

/// `_item_kind(artifact_type)` — the native artifact category mapped onto the
/// inventory item-kind contract. An unmapped category is a plugin.
pub fn item_kind(artifact_type: &str) -> &'static str {
    match artifact_type {
        "skill" | "skill_file" => "skill",
        "mcp_server" => "mcp_server",
        "mcp_tool" => "mcp_tool",
        "channel" => "channel",
        "gateway_config" | "config" | "agent" => "agent",
        "hook" => "hook",
        "instruction" | "overlay" => "overlay",
        "command" | "prompt_pack" => "prompt_pack",
        "extension" | "plugin" | "plugin-file" => "plugin",
        "repository" => "repository",
        "container_image" => "container_image",
        "policy" => "policy",
        "secret_reference" => "secret_reference",
        "network_endpoint" => "network_endpoint",
        "guard_launcher_shim" => "harness",
        "package" => "package",
        "daemon_plugin" => "daemon_plugin",
        "model_provider" => "model_provider",
        _ => "plugin",
    }
}

/// `_canonical_inventory_content_hash(value)` — a bare 64-character digest
/// gains the `sha256:` prefix; anything else is returned as it arrived, in the
/// spelling it arrived in.
pub fn canonical_inventory_content_hash(value: &str) -> String {
    let normalized = value.to_lowercase();
    if normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return format!("sha256:{normalized}");
    }
    value.to_owned()
}

fn non_empty_string(value: Option<&Value>) -> Option<&str> {
    match value {
        Some(Value::String(text)) if !text.is_empty() => Some(text),
        _ => None,
    }
}

/// `_resolve_item_content_hash(metadata, semantic_text)` — a verified hash
/// from the artifact's own evidence, or the semantic fingerprint.
pub fn resolve_item_content_hash(metadata: &Map<String, Value>, semantic_text: &str) -> String {
    for key in ["content_hash", "directory_hash"] {
        if let Some(candidate) = non_empty_string(metadata.get(key)) {
            return canonical_inventory_content_hash(candidate);
        }
    }
    if let Some(Value::Object(version_info)) = metadata.get("versionInfo") {
        if let Some(version_hash) = non_empty_string(version_info.get("contentHash")) {
            return canonical_inventory_content_hash(version_hash);
        }
    }
    semantic_text.to_owned()
}

/// `_canonical_sha256(value)` from `skill_directory_identity_contract`: the
/// strict digest form, `None` for anything that is not one.
fn canonical_sha256(value: Option<&Value>) -> Option<String> {
    let Some(Value::String(text)) = value else {
        return None;
    };
    let normalized = text.trim().to_lowercase();
    let normalized = normalized.strip_prefix("sha256:").unwrap_or(&normalized);
    if normalized.len() != 64 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("sha256:{normalized}"))
}

fn positive_int(value: Option<&Value>, minimum: i64) -> bool {
    let Some(Value::Number(number)) = value else {
        return false;
    };
    if let Some(parsed) = number.as_i64() {
        return parsed >= minimum;
    }
    // CPython's `int` has no width, so an entry count or byte total wider than
    // `i64` is still an integer there. `arbitrary_precision` keeps such a
    // number as its literal text, and a literal of nothing but digits is a
    // non-negative integer above every `minimum` this contract uses.
    let literal = number.to_string();
    !literal.is_empty() && literal.bytes().all(|byte| byte.is_ascii_digit())
}

/// `validated_complete_skill_directory_hash(metadata)` — the v1 directory
/// digest, and only for an envelope that is complete, reusable, carries no
/// incomplete-state evidence, and agrees with `directory_hash` and
/// `versionInfo.contentHash`.
///
/// Every rejected shape here is a hash that must not be reused as an item's
/// public content hash, so a missing check reads as "this skill is unchanged"
/// for a directory Guard never fully read.
pub fn validated_complete_skill_directory_hash(metadata: &Map<String, Value>) -> Option<String> {
    let Some(Value::Object(identity)) = metadata.get("skillDirectoryIdentity") else {
        return None;
    };
    if identity.get("schemaVersion")
        != Some(&Value::String(SKILL_DIRECTORY_IDENTITY_SCHEMA.to_owned()))
        || identity.get("status") != Some(&Value::String("complete".to_owned()))
        || identity.get("reusable") != Some(&Value::Bool(true))
        || identity.contains_key("reason")
        || identity.contains_key("reuseNonce")
        || identity.contains_key("incompleteStateHash")
    {
        return None;
    }
    if !positive_int(identity.get("entryCount"), 1) || !positive_int(identity.get("totalBytes"), 0)
    {
        return None;
    }
    let identity_hash = canonical_sha256(identity.get("contentHash"))?;
    if canonical_sha256(metadata.get("directory_hash")).as_ref() != Some(&identity_hash) {
        return None;
    }
    let Some(Value::Object(version_info)) = metadata.get("versionInfo") else {
        return None;
    };
    if version_info.get("hashBasis") != Some(&Value::String("skill-directory-v1".to_owned())) {
        return None;
    }
    if canonical_sha256(version_info.get("contentHash")).as_ref() != Some(&identity_hash) {
        return None;
    }
    Some(identity_hash)
}

/// `_discard_unverified_skill_directory_hash(metadata)` — an envelope that
/// claims an identity it cannot prove loses its `directory_hash`, so the item
/// falls back to evidence that was verified.
pub fn discard_unverified_skill_directory_hash(
    metadata: &Map<String, Value>,
) -> Map<String, Value> {
    if !metadata.contains_key("skillDirectoryIdentity")
        || validated_complete_skill_directory_hash(metadata).is_some()
    {
        return metadata.clone();
    }
    let mut sanitized = metadata.clone();
    sanitized.remove("directory_hash");
    sanitized
}

/// `_capabilities_for_artifact(artifact_type, metadata)` — the capability
/// categories a native artifact declares, sorted, or `("unknown",)`.
pub fn capabilities_for_artifact(
    artifact_type: &str,
    metadata: &Map<String, Value>,
) -> Vec<String> {
    let mut capabilities: Vec<&str> = Vec::new();
    if matches!(artifact_type, "instruction" | "overlay" | "command") {
        capabilities.push("reads_files");
    }
    if artifact_type == "mcp_server" {
        capabilities.push("network_egress");
        if metadata.get("transport") == Some(&Value::String("stdio".to_owned())) {
            capabilities.push("runs_shell");
        }
    }
    if artifact_type == "channel" {
        capabilities.extend(["reads_messages", "posts_messages", "network_ingress"]);
    }
    if python_truthy(metadata.get("envConfigurationPresent"))
        || python_truthy(metadata.get("has_auth_headers"))
    {
        capabilities.push("reads_secrets");
    }
    if capabilities.is_empty() {
        return vec!["unknown".to_owned()];
    }
    // The Python builds a `set` and returns `tuple(sorted(...))`.
    capabilities.sort_unstable();
    capabilities.dedup();
    capabilities.into_iter().map(str::to_owned).collect()
}

/// `_bind_skill_document_evidence(metadata, primary_content_hash)` — bind the
/// hash of Guard's own full read of `SKILL.md`, and drop content evidence that
/// does not belong to it.
///
/// `documentedCapabilities` is what a skill says about itself, so it survives
/// only alongside evidence that matches the body Guard hashed, or alongside an
/// evidence record that makes no content claim at all.
pub fn bind_skill_document_evidence(
    metadata: &Map<String, Value>,
    primary_content_hash: Option<&str>,
) -> Map<String, Value> {
    let mut bound = metadata.clone();
    match primary_content_hash {
        Some(hash) => {
            bound.insert(
                "primaryContentHash".to_owned(),
                Value::String(hash.to_owned()),
            );
        }
        None => {
            bound.remove("primaryContentHash");
        }
    }
    if let (Some(Value::Object(evidence)), Some(hash)) =
        (metadata.get("contentEvidence"), primary_content_hash)
    {
        if evidence.get("contentHash") == Some(&Value::String(hash.to_owned())) {
            return bound;
        }
    }
    if let Some(Value::Object(evidence)) = metadata.get("contentEvidence") {
        if !evidence.contains_key("contentHash") {
            bound.remove("documentedCapabilities");
            return bound;
        }
    }
    bound.remove("contentEvidence");
    bound.remove("documentedCapabilities");
    bound
}

/// `_risk_level(metadata)` — the supported inventory risk level for an item's
/// evidence.
pub fn risk_level(metadata: &Map<String, Value>) -> &'static str {
    if python_truthy(metadata.get("has_auth_headers"))
        || python_truthy(metadata.get("envConfigurationPresent"))
    {
        return "high";
    }
    if metadata.get("endpointHostClass") == Some(&Value::String("remote_public".to_owned())) {
        return "medium";
    }
    "info"
}

/// `_safe_roots_for_inspection(home_dir=…, workspace_dir=…)` — the bounded
/// roots source-of-truth inspection may read, workspace first so a workspace
/// inside the home directory wins.
pub fn safe_roots_for_inspection(home_dir: &Path, workspace_dir: Option<&Path>) -> Vec<PathBuf> {
    match workspace_dir {
        Some(workspace) => vec![workspace.to_path_buf(), home_dir.to_path_buf()],
        None => vec![home_dir.to_path_buf()],
    }
}

#[cfg(test)]
#[path = "inventory_item_metadata_tests.rs"]
mod tests;

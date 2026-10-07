//! `runtime/package_intent_common.py` (:1-599) — shared package intent models,
//! manifest diff result types, and package request artifact construction.
//!
//! Also hosts the `models.py` `GuardArtifact` (:69-95) the artifact builder
//! returns, and the `_split_package_token` / URL-sanitizer helpers imported
//! there from `mcp_protection.py` (:297-381). `mcp_protection`'s Rust port can
//! re-export these rather than duplicate them.
//!
//! Dict parity note: Python `asdict`/`to_dict` returns insertion-ordered dicts;
//! `serde_json::Value::Object` (BTreeMap) is key-sorted. Persisted JSON is
//! always produced through `json.dumps(..., sort_keys=True)` downstream, so
//! serialized bytes are identical; only in-memory iteration order would differ
//! and no caller consumes it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use guard_contracts::write_json_string;
use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::command_launcher_floors::{shlex_join, shlex_split};
use crate::npm_source_spec::{parse_npm_source_spec, NpmSourceSpec};

#[allow(dead_code)]
type IntentResult<T> = Result<T, &'static str>;

static EXTRAS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?P<name>[A-Za-z0-9_.-]+)\[(?P<extras>[A-Za-z0-9_,.-]+)\]$").unwrap()
});
static EGG_FRAGMENT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|[#&])egg=([^&#]+)").unwrap());
static PYTHON_VERSION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?P<name>[^<>=!~\s]+)(?P<op>===|==|~=|!=|<=|>=|<|>|=)?(?P<version>.*)").unwrap()
});
static HTTP_SOURCE_IN_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)https?:").unwrap());
static UNSANITIZED_HTTP_SOURCE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^https?://[^/\\]").unwrap());
static SCHEME_PREFIX_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z][A-Za-z0-9+.-]*://").unwrap());

// ---------------------------------------------------------------------------
// IntentKind / EvidenceStatus literals (:19-20)
// ---------------------------------------------------------------------------

/// `IntentKind = Literal["install", "execute", "sync"]` (:19).
pub type IntentKind = &'static str;
/// `EvidenceStatus` literal (:20). Python keeps the literal as a plain str.
pub type EvidenceStatus = &'static str;

// ---------------------------------------------------------------------------
// PackageIntentTarget (:27-65)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct PackageIntentTarget {
    pub ecosystem: String,
    pub package_name: Option<String>,
    pub raw_spec: String,
    pub requested_specifier: Option<String>,
    pub source_url: Option<String>,
    pub source_kind: Option<String>,
    pub source_repository: Option<String>,
    pub source_revision_kind: Option<String>,
    pub source_identity: Option<String>,
    pub source_invalid_reason: Option<String>,
    pub alias: Option<String>,
    pub dependency_group: Option<String>,
    pub extras: Vec<String>,
    pub editable: bool,
}

impl PackageIntentTarget {
    /// `to_dict` (:44-51): dataclass field order, `raw_spec`/`source_url`
    /// sanitized + sha256'd alongside.
    pub fn to_dict(&self) -> Value {
        let mut payload = Map::new();
        payload.insert("ecosystem".to_owned(), json!(self.ecosystem));
        payload.insert("package_name".to_owned(), json!(self.package_name));
        payload.insert("raw_spec".to_owned(), json!(sanitize_url(&self.raw_spec)));
        payload.insert(
            "requested_specifier".to_owned(),
            json!(self.requested_specifier),
        );
        payload.insert("source_url".to_owned(), Value::Null);
        payload.insert("source_kind".to_owned(), json!(self.source_kind));
        payload.insert(
            "source_repository".to_owned(),
            json!(self.source_repository),
        );
        payload.insert(
            "source_revision_kind".to_owned(),
            json!(self.source_revision_kind),
        );
        payload.insert("source_identity".to_owned(), json!(self.source_identity));
        payload.insert(
            "source_invalid_reason".to_owned(),
            json!(self.source_invalid_reason),
        );
        payload.insert("alias".to_owned(), json!(self.alias));
        payload.insert("dependency_group".to_owned(), json!(self.dependency_group));
        payload.insert("extras".to_owned(), json!(self.extras));
        payload.insert("editable".to_owned(), json!(self.editable));
        payload.insert(
            "raw_spec_hash".to_owned(),
            json!(hex::encode(Sha256::digest(self.raw_spec.as_bytes()))),
        );
        if let Some(source_url) = &self.source_url {
            payload.insert("source_url".to_owned(), json!(sanitize_url(source_url)));
            payload.insert(
                "source_url_hash".to_owned(),
                json!(hex::encode(Sha256::digest(source_url.as_bytes()))),
            );
        }
        Value::Object(payload)
    }

    /// `to_execution_dict` (:53-56): exact request values for ephemeral
    /// in-process enforcement — no sanitization.
    pub fn to_execution_dict(&self) -> Value {
        let mut payload = Map::new();
        payload.insert("ecosystem".to_owned(), json!(self.ecosystem));
        payload.insert("package_name".to_owned(), json!(self.package_name));
        payload.insert("raw_spec".to_owned(), json!(self.raw_spec));
        payload.insert(
            "requested_specifier".to_owned(),
            json!(self.requested_specifier),
        );
        payload.insert("source_url".to_owned(), json!(self.source_url));
        payload.insert("source_kind".to_owned(), json!(self.source_kind));
        payload.insert(
            "source_repository".to_owned(),
            json!(self.source_repository),
        );
        payload.insert(
            "source_revision_kind".to_owned(),
            json!(self.source_revision_kind),
        );
        payload.insert("source_identity".to_owned(), json!(self.source_identity));
        payload.insert(
            "source_invalid_reason".to_owned(),
            json!(self.source_invalid_reason),
        );
        payload.insert("alias".to_owned(), json!(self.alias));
        payload.insert("dependency_group".to_owned(), json!(self.dependency_group));
        payload.insert("extras".to_owned(), json!(self.extras));
        payload.insert("editable".to_owned(), json!(self.editable));
        Value::Object(payload)
    }

    /// `to_fingerprint_dict` (:58-65): `to_dict` minus exact-spelling fields
    /// when the source is an identity-pinned git spec.
    pub fn to_fingerprint_dict(&self) -> Value {
        let mut payload = self.to_dict();
        if self.source_kind.as_deref() == Some("git") && self.source_identity.is_some() {
            if let Value::Object(map) = &mut payload {
                for field in ["raw_spec", "raw_spec_hash", "source_url", "source_url_hash"] {
                    map.remove(field);
                }
            }
        }
        payload
    }
}

// ---------------------------------------------------------------------------
// PackageExecutionFileEvidence (:68-79)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PackageExecutionFileEvidence {
    pub path: String,
    pub resolved_path: Option<String>,
    pub status: EvidenceStatus,
    pub file_identity: Option<String>,
    pub content_hash: Option<String>,
}

impl PackageExecutionFileEvidence {
    /// `to_dict` (:78-79).
    pub fn to_dict(&self) -> Value {
        let mut payload = Map::new();
        payload.insert("path".to_owned(), json!(self.path));
        payload.insert("resolved_path".to_owned(), json!(self.resolved_path));
        payload.insert("status".to_owned(), json!(self.status));
        payload.insert("file_identity".to_owned(), json!(self.file_identity));
        payload.insert("content_hash".to_owned(), json!(self.content_hash));
        Value::Object(payload)
    }
}

// ---------------------------------------------------------------------------
// LocalPackageExecutionEvidence (:82-103)
// ---------------------------------------------------------------------------

/// `typescript_launch` stays a free-form `Value` until
/// `typescript_launch_evidence.py` (:54-75) is ported — the serialized shape
/// (a 15-key flat dict) is fixed by `TypeScriptLaunchEvidence.to_dict`.
#[derive(Debug, Clone)]
pub struct LocalPackageExecutionEvidence {
    pub manager_name: String,
    pub path_source: String,
    pub effective_cwd: String,
    pub cwd_source: String,
    pub manager_is_guard_shim: bool,
    pub local_only_requested: bool,
    pub context_hash: String,
    pub package_name: Option<String>,
    pub executable_name: Option<String>,
    pub declared_version: Option<String>,
    pub manager: Option<PackageExecutionFileEvidence>,
    pub local_executable: Option<PackageExecutionFileEvidence>,
    pub manifests: Vec<PackageExecutionFileEvidence>,
    pub lockfiles: Vec<PackageExecutionFileEvidence>,
    pub typescript_launch: Option<Value>,
}

impl LocalPackageExecutionEvidence {
    /// `to_dict` (:102-103) — `asdict` recurses into nested dataclasses.
    pub fn to_dict(&self) -> Value {
        let mut payload = Map::new();
        payload.insert("manager_name".to_owned(), json!(self.manager_name));
        payload.insert("path_source".to_owned(), json!(self.path_source));
        payload.insert("effective_cwd".to_owned(), json!(self.effective_cwd));
        payload.insert("cwd_source".to_owned(), json!(self.cwd_source));
        payload.insert(
            "manager_is_guard_shim".to_owned(),
            json!(self.manager_is_guard_shim),
        );
        payload.insert(
            "local_only_requested".to_owned(),
            json!(self.local_only_requested),
        );
        payload.insert("context_hash".to_owned(), json!(self.context_hash));
        payload.insert("package_name".to_owned(), json!(self.package_name));
        payload.insert("executable_name".to_owned(), json!(self.executable_name));
        payload.insert("declared_version".to_owned(), json!(self.declared_version));
        payload.insert(
            "manager".to_owned(),
            self.manager.as_ref().map_or(Value::Null, |ev| ev.to_dict()),
        );
        payload.insert(
            "local_executable".to_owned(),
            self.local_executable
                .as_ref()
                .map_or(Value::Null, |ev| ev.to_dict()),
        );
        payload.insert(
            "manifests".to_owned(),
            Value::Array(self.manifests.iter().map(|ev| ev.to_dict()).collect()),
        );
        payload.insert(
            "lockfiles".to_owned(),
            Value::Array(self.lockfiles.iter().map(|ev| ev.to_dict()).collect()),
        );
        payload.insert(
            "typescript_launch".to_owned(),
            self.typescript_launch.clone().unwrap_or(Value::Null),
        );
        Value::Object(payload)
    }
}

// ---------------------------------------------------------------------------
// PackageIntent (:106-126)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PackageIntent {
    pub package_manager: String,
    pub intent_kind: IntentKind,
    pub command_tokens: Vec<String>,
    pub redacted_command: String,
    pub targets: Vec<PackageIntentTarget>,
    pub manifest_paths: Vec<String>,
    pub lockfile_paths: Vec<String>,
    pub flags: Vec<String>,
    pub notes: Vec<String>,
    pub local_executions: Vec<LocalPackageExecutionEvidence>,
    pub execution_context_hashes: Vec<String>,
    pub execution_context_cwds: Vec<String>,
    pub execution_context_reason_codes: Vec<String>,
}

impl PackageIntent {
    /// `to_dict` (:122-126): `command_tokens` are re-split from the redacted
    /// command so exact argv never leaves the process.
    pub fn to_dict(&self) -> Value {
        let mut payload = Map::new();
        payload.insert("package_manager".to_owned(), json!(self.package_manager));
        payload.insert("intent_kind".to_owned(), json!(self.intent_kind));
        payload.insert(
            "command_tokens".to_owned(),
            json!(shlex_split(&self.redacted_command).unwrap_or_default()),
        );
        payload.insert("redacted_command".to_owned(), json!(self.redacted_command));
        payload.insert(
            "targets".to_owned(),
            Value::Array(self.targets.iter().map(|t| t.to_dict()).collect()),
        );
        payload.insert("manifest_paths".to_owned(), json!(self.manifest_paths));
        payload.insert("lockfile_paths".to_owned(), json!(self.lockfile_paths));
        payload.insert("flags".to_owned(), json!(self.flags));
        payload.insert("notes".to_owned(), json!(self.notes));
        payload.insert(
            "local_executions".to_owned(),
            Value::Array(
                self.local_executions
                    .iter()
                    .map(|ev| ev.to_dict())
                    .collect(),
            ),
        );
        payload.insert(
            "execution_context_hashes".to_owned(),
            json!(self.execution_context_hashes),
        );
        payload.insert(
            "execution_context_cwds".to_owned(),
            json!(self.execution_context_cwds),
        );
        payload.insert(
            "execution_context_reason_codes".to_owned(),
            json!(self.execution_context_reason_codes),
        );
        Value::Object(payload)
    }
}

// ---------------------------------------------------------------------------
// Manifest diff types (:129-141) — canonical home; package_manifest_diff.rs
// imports these rather than defining its own.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestDependencyChange {
    pub manifest_path: String,
    pub package_name: String,
    pub before: Option<String>,
    pub after: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManifestParseResult {
    pub changes: Vec<ManifestDependencyChange>,
    pub truncated: bool,
    pub parse_errors: Vec<String>,
}

// ---------------------------------------------------------------------------
// GuardArtifact (models.py :69-95) — needed by build_package_request_artifact.
// Full models.py port may consolidate later; keep co-located for now.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct GuardArtifact {
    pub artifact_id: String,
    pub name: String,
    pub harness: String,
    pub artifact_type: String,
    pub source_scope: String,
    pub config_path: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub url: Option<String>,
    pub transport: Option<String>,
    pub publisher: Option<String>,
    pub metadata: Value,
    /// `runtime_private_metadata` (models.py :87): ephemeral enforcement-only
    /// values — never serialized, excluded from `to_dict`.
    pub runtime_private_metadata: Value,
}

impl GuardArtifact {
    /// `to_dict` (models.py :89-95): drops `runtime_private_metadata`,
    /// redacts args/url/metadata.
    pub fn to_dict(&self) -> Value {
        let mut payload = Map::new();
        payload.insert("artifact_id".to_owned(), json!(self.artifact_id));
        payload.insert("name".to_owned(), json!(self.name));
        payload.insert("harness".to_owned(), json!(self.harness));
        payload.insert("artifact_type".to_owned(), json!(self.artifact_type));
        payload.insert("source_scope".to_owned(), json!(self.source_scope));
        payload.insert("config_path".to_owned(), json!(self.config_path));
        payload.insert("command".to_owned(), json!(self.command));
        payload.insert(
            "args".to_owned(),
            Value::Array(self.args.iter().map(|a| json!(redact_arg(a))).collect()),
        );
        payload.insert("url".to_owned(), json!(redact_url(self.url.as_deref())));
        payload.insert("transport".to_owned(), json!(self.transport));
        payload.insert("publisher".to_owned(), json!(self.publisher));
        payload.insert("metadata".to_owned(), redact_metadata(&self.metadata, None));
        Value::Object(payload)
    }
}

/// `_redact_url` (models.py :25-40): query keys containing key/token/auth/
/// secret → `*****`, preserving other params in original order.
fn redact_url(value: Option<&str>) -> Option<String> {
    let value = value?;
    // split_url is total (Python urlsplit only raises on port access).
    let parsed = crate::npm_source_spec::split_url(value);
    if parsed.query.is_empty() {
        return Some(value.to_owned());
    }
    let redacted_pairs: Vec<(String, String)> = parse_qsl(&parsed.query)
        .into_iter()
        .map(|(key, item)| {
            let lower = key.to_lowercase();
            if ["key", "token", "auth", "secret"]
                .iter()
                .any(|t| lower.contains(t))
            {
                (key, "*****".to_owned())
            } else {
                (key, item)
            }
        })
        .collect();
    // urlunsplit((scheme, netloc, path, query, fragment)): ':' after scheme;
    // '//' iff netloc non-empty OR scheme is a `uses_netloc` member.
    let uses_netloc = [
        "file", "ftp", "ftps", "http", "https", "rtsp", "rtsps", "ws", "wss",
    ]
    .contains(&parsed.scheme.as_str());
    let mut out = String::new();
    if !parsed.scheme.is_empty() {
        out.push_str(&parsed.scheme);
        out.push(':');
    }
    if !parsed.netloc.is_empty() || (!parsed.scheme.is_empty() && uses_netloc) {
        out.push_str("//");
    }
    out.push_str(&parsed.netloc);
    out.push_str(&parsed.path);
    out.push('?');
    out.push_str(&urlencode(&redacted_pairs));
    if !parsed.fragment.is_empty() {
        out.push('#');
        out.push_str(&parsed.fragment);
    }
    Some(out)
}

/// `urllib.parse.parse_qsl(query, keep_blank_values=True)` for `redact_url`.
/// Pairs split on `&`; `;` is not a separator in modern Python. `+` decodes
/// to space; `%XX` percent-decodes (invalid sequences left literal).
fn parse_qsl(query: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for part in query.split('&') {
        if part.is_empty() {
            continue;
        }
        let (name, value) = match part.split_once('=') {
            Some((name, value)) => (name, value),
            None => (part, ""),
        };
        pairs.push((percent_decode_plus(name), percent_decode_plus(value)));
    }
    pairs
}

fn percent_decode_plus(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hi = hex_digit(bytes[index + 1]);
                let lo = hex_digit(bytes[index + 2]);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi << 4) | lo);
                    index += 3;
                } else {
                    out.push(b'%');
                    index += 1;
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// `urllib.parse.urlencode(pairs)` — `quote_plus` semantics: safe chars are
/// alnum + `_.-~`; space → `+`; everything else `%XX` uppercase.
fn urlencode(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", quote_plus(key), quote_plus(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn quote_plus(text: &str) -> String {
    let mut out = String::new();
    for &byte in text.as_bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(char::from(b"0123456789ABCDEF"[(byte >> 4) as usize]));
                out.push(char::from(b"0123456789ABCDEF"[(byte & 0xf) as usize]));
            }
        }
    }
    out
}

/// `_redact_arg` (models.py :43-51).
fn redact_arg(value: &str) -> String {
    let lower = value.to_lowercase();
    if lower.contains("authorization:") || lower.contains("api-key:") || lower.contains("bearer ") {
        let prefix = value.split(':').next().unwrap_or("");
        return format!("{prefix}: *****");
    }
    if ["apikey=", "api_key=", "api-key=", "token=", "secret="]
        .iter()
        .any(|token| lower.contains(token))
    {
        let key = value.split('=').next().unwrap_or("");
        return format!("{key}=*****");
    }
    value.to_owned()
}

/// `_redact_metadata` (models.py :54-65): `env`/`environment` dicts collapse to
/// `*****` values; keys containing secret-ish substrings redact entirely.
fn redact_metadata(value: &Value, key: Option<&str>) -> Value {
    if let Some(key) = key {
        let lower = key.to_lowercase();
        if (lower == "env" || lower == "environment") && value.is_object() {
            if let Value::Object(map) = value {
                let mut out = Map::new();
                for item_key in map.keys() {
                    out.insert(item_key.clone(), json!("*****"));
                }
                return Value::Object(out);
            }
        }
        if lower.contains("secret") || lower.contains("token") {
            return json!("*****");
        }
    }
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (item_key, item_value) in map {
                out.insert(
                    item_key.clone(),
                    redact_metadata(item_value, Some(item_key)),
                );
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| redact_metadata(item, None))
                .collect(),
        ),
        other => other.clone(),
    }
}

// ---------------------------------------------------------------------------
// build_package_request_artifact (:144-206)
// ---------------------------------------------------------------------------

/// `build_package_request_artifact` (:144-206).
pub fn build_package_request_artifact(
    harness: &str,
    intent: &PackageIntent,
    config_path: &str,
    source_scope: &str,
) -> GuardArtifact {
    let (manifest_paths, lockfile_paths) = artifact_workspace_paths(intent);
    let package_executable = if !intent.command_tokens.is_empty()
        && !intent.command_tokens.iter().any(|t| t.contains(';'))
    {
        Some(intent.command_tokens[0].clone())
    } else {
        None
    };

    let mut fingerprint_material = Map::new();
    fingerprint_material.insert("harness".to_owned(), json!(harness));
    fingerprint_material.insert("package_manager".to_owned(), json!(intent.package_manager));
    fingerprint_material.insert("intent_kind".to_owned(), json!(intent.intent_kind));
    fingerprint_material.insert(
        "redacted_command".to_owned(),
        json!(fingerprint_command_shape(intent)),
    );
    fingerprint_material.insert(
        "targets".to_owned(),
        Value::Array(
            intent
                .targets
                .iter()
                .map(|t| t.to_fingerprint_dict())
                .collect(),
        ),
    );
    fingerprint_material.insert("manifest_paths".to_owned(), json!(manifest_paths));
    fingerprint_material.insert("lockfile_paths".to_owned(), json!(lockfile_paths));
    fingerprint_material.insert(
        "local_executions".to_owned(),
        Value::Array(
            intent
                .local_executions
                .iter()
                .map(|ev| ev.to_dict())
                .collect(),
        ),
    );
    fingerprint_material.insert(
        "execution_context_hashes".to_owned(),
        json!(intent.execution_context_hashes),
    );
    fingerprint_material.insert(
        "execution_context_cwds".to_owned(),
        json!(intent.execution_context_cwds),
    );
    fingerprint_material.insert(
        "execution_context_reason_codes".to_owned(),
        json!(intent.execution_context_reason_codes),
    );
    // Python: json.dumps(material, sort_keys=True) — DEFAULT separators
    // (", ", ": "), not the canonical compact codec (:155-172).
    let mut fingerprint_json = String::new();
    write_spaced_sorted_json(&Value::Object(fingerprint_material), &mut fingerprint_json);
    let fingerprint = hex::encode(Sha256::digest(fingerprint_json.as_bytes()));

    let target_label = intent
        .targets
        .first()
        .and_then(|t| t.package_name.clone())
        .unwrap_or_else(|| intent.package_manager.clone());

    let mut metadata = Map::new();
    metadata.insert("package_manager".to_owned(), json!(intent.package_manager));
    metadata.insert("package_executable".to_owned(), json!(package_executable));
    metadata.insert("intent_kind".to_owned(), json!(intent.intent_kind));
    metadata.insert(
        "targets".to_owned(),
        Value::Array(intent.targets.iter().map(|t| t.to_dict()).collect()),
    );
    metadata.insert("manifest_paths".to_owned(), json!(manifest_paths));
    metadata.insert("lockfile_paths".to_owned(), json!(lockfile_paths));
    metadata.insert("flags".to_owned(), json!(intent.flags));
    metadata.insert("notes".to_owned(), json!(intent.notes));
    metadata.insert(
        "local_executions".to_owned(),
        Value::Array(
            intent
                .local_executions
                .iter()
                .map(|ev| ev.to_dict())
                .collect(),
        ),
    );
    metadata.insert(
        "shell_execution_context_hashes".to_owned(),
        json!(intent.execution_context_hashes),
    );
    metadata.insert(
        "shell_execution_effective_cwds".to_owned(),
        json!(intent.execution_context_cwds),
    );
    metadata.insert(
        "shell_execution_context_reason_codes".to_owned(),
        json!(intent.execution_context_reason_codes),
    );
    metadata.insert(
        "shell_execution_context_complete".to_owned(),
        json!(intent.execution_context_reason_codes.is_empty()),
    );
    metadata.insert(
        "effective_cwd".to_owned(),
        intent
            .execution_context_cwds
            .last()
            .map_or(Value::Null, |cwd| json!(cwd)),
    );
    metadata.insert(
        "redacted_command".to_owned(),
        json!(intent.redacted_command),
    );
    metadata.insert(
        "request_summary".to_owned(),
        json!(package_request_summary(intent)),
    );
    metadata.insert(
        "runtime_request_signals".to_owned(),
        json!([format!(
            "invokes a package {} request via {}",
            intent.intent_kind, intent.package_manager
        )]),
    );
    metadata.insert(
        "runtime_request_summary".to_owned(),
        json!(package_runtime_summary(intent)),
    );
    metadata.insert(
        "runtime_request_reason".to_owned(),
        json!(package_runtime_reason(intent)),
    );
    if let Value::Object(extra) = local_execution_runtime_metadata(intent) {
        for (key, value) in extra {
            metadata.insert(key, value);
        }
    }

    let mut private_metadata = Map::new();
    private_metadata.insert(
        "package_targets".to_owned(),
        Value::Array(
            intent
                .targets
                .iter()
                .map(|t| t.to_execution_dict())
                .collect(),
        ),
    );

    GuardArtifact {
        artifact_id: format!("{harness}:{source_scope}:package-request:{fingerprint}"),
        name: format!(
            "{} {} {}",
            intent.package_manager, intent.intent_kind, target_label
        ),
        harness: harness.to_owned(),
        artifact_type: "package_request".to_owned(),
        source_scope: source_scope.to_owned(),
        config_path: config_path.to_owned(),
        command: None,
        args: Vec::new(),
        url: None,
        transport: None,
        publisher: None,
        metadata: Value::Object(metadata),
        runtime_private_metadata: Value::Object(private_metadata),
    }
}

/// `json.dumps(value, sort_keys=True)` with default separators `(", ", ": ")`
/// and `ensure_ascii=True` — the non-compact sibling of the canonical codec.
/// `serde_json::Value::Object` is already key-sorted.
pub(crate) fn write_spaced_sorted_json(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => {
            // serde_json Number prints i64/u64/f64 canonically; Python floats
            // never reach these payloads (digests, paths, strings only).
            out.push_str(&number.to_string());
        }
        Value::String(text) => {
            let mut buf = Vec::with_capacity(text.len() + 2);
            write_json_string(text, &mut buf);
            out.push_str(&String::from_utf8_lossy(&buf));
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_spaced_sorted_json(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (index, (key, item)) in map.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                let mut buf = Vec::with_capacity(key.len() + 2);
                write_json_string(key, &mut buf);
                out.push_str(&String::from_utf8_lossy(&buf));
                out.push_str(": ");
                write_spaced_sorted_json(item, out);
            }
            out.push('}');
        }
    }
}

/// `_artifact_workspace_paths` (:209-212).
fn artifact_workspace_paths(intent: &PackageIntent) -> (Vec<String>, Vec<String>) {
    if is_global_package_install(intent) {
        return (Vec::new(), Vec::new());
    }
    (intent.manifest_paths.clone(), intent.lockfile_paths.clone())
}

/// `_is_global_package_install` (:215-220).
fn is_global_package_install(intent: &PackageIntent) -> bool {
    if !["npm", "pnpm", "yarn"].contains(&intent.package_manager.as_str()) {
        return false;
    }
    if intent
        .notes
        .iter()
        .any(|n| n == "multiple-package-segments")
    {
        return all_package_segments_are_global(intent);
    }
    intent.flags.iter().any(|flag| is_true_global_flag(flag))
}

/// `_all_package_segments_are_global` (:223-227).
fn all_package_segments_are_global(intent: &PackageIntent) -> bool {
    let segments: Vec<&str> = intent
        .redacted_command
        .split(" ; ")
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments.is_empty() {
        return false;
    }
    segments
        .iter()
        .all(|segment| segment_has_global_flag(segment))
}

/// `_segment_has_global_flag` (:230-235): `shlex.split` with `ValueError`
/// fallback to `str.split`.
fn segment_has_global_flag(segment: &str) -> bool {
    let tokens = shlex_split(segment)
        .unwrap_or_else(|_| segment.split_whitespace().map(str::to_owned).collect());
    tokens.iter().any(|token| is_true_global_flag(token))
}

/// `_is_true_global_flag` (:238-244).
fn is_true_global_flag(flag: &str) -> bool {
    let normalized = flag.trim().to_lowercase();
    if normalized == "-g" || normalized == "--global" {
        return true;
    }
    if let Some(rest) = normalized.strip_prefix("--global=") {
        return !["", "0", "false", "no", "off"].contains(&rest);
    }
    normalized == "--location=global"
}

/// `package_request_summary` (:247-268).
fn package_request_summary(intent: &PackageIntent) -> String {
    if let Some(execution) = intent.local_executions.first() {
        let executable = execution
            .executable_name
            .clone()
            .unwrap_or_else(|| "an unresolved executable".to_owned());
        let manager_path = execution
            .manager
            .as_ref()
            .and_then(|m| m.resolved_path.clone())
            .unwrap_or_else(|| "unresolved from the command's effective PATH".to_owned());
        return format!(
            "Requested local `{executable}` execution through `{}`. Manager: `{manager_path}`.",
            execution.manager_name
        );
    }
    if !intent.targets.is_empty() {
        let target_names = intent
            .targets
            .iter()
            .take(3)
            .map(|target| {
                target
                    .package_name
                    .clone()
                    .unwrap_or_else(|| target.raw_spec.clone())
            })
            .collect::<Vec<_>>()
            .join(", ");
        return format!(
            "Requested `{}` {} for {target_names}.",
            intent.package_manager, intent.intent_kind
        );
    }
    if !intent.lockfile_paths.is_empty() {
        return format!(
            "Requested `{}` {} using existing project manifest and lockfile context.",
            intent.package_manager, intent.intent_kind
        );
    }
    format!(
        "Requested `{}` {} using existing project manifest context.",
        intent.package_manager, intent.intent_kind
    )
}

/// `package_runtime_summary` (:271-281).
fn package_runtime_summary(intent: &PackageIntent) -> String {
    if !intent.local_executions.is_empty() {
        return format!(
            "Executes a project package through {} using an exact local execution identity.",
            intent.package_manager
        );
    }
    if intent.intent_kind == "execute" {
        return format!(
            "Executes a remote package through {} before it is trusted locally.",
            intent.package_manager
        );
    }
    if !intent.lockfile_paths.is_empty() {
        return format!(
            "Mutates project dependencies through {} using existing manifest and lockfile context.",
            intent.package_manager
        );
    }
    format!(
        "Mutates project dependencies through {}.",
        intent.package_manager
    )
}

/// `package_runtime_reason` (:283-292).
fn package_runtime_reason(intent: &PackageIntent) -> String {
    if !intent.local_executions.is_empty() {
        return "Guard requires review for the first local package-runner execution and binds reuse to the exact \
            manager, local executable, manifest, and lockfile evidence."
            .to_owned();
    }
    format!(
        "Guard parsed this command as a package {} request and kept only package metadata plus a redacted \
         command shape.",
        intent.intent_kind
    )
}

/// `_fingerprint_command_shape` (:295-306): git source spellings collapse to
/// `<canonical-git-source>` so alias/format variants share an identity.
fn fingerprint_command_shape(intent: &PackageIntent) -> String {
    if !intent
        .targets
        .iter()
        .any(|target| target.source_kind.as_deref() == Some("git"))
    {
        return intent.redacted_command.clone();
    }
    let mut tokens: Vec<String> = intent.command_tokens.clone();
    for target in &intent.targets {
        if target.source_kind.as_deref() != Some("git") {
            continue;
        }
        for source_spelling in [&target.raw_spec, target.source_url.as_deref().unwrap_or("")] {
            let source_spelling: &str = source_spelling;
            if source_spelling.is_empty() {
                continue;
            }
            tokens = tokens
                .iter()
                .map(|token| token.replace(source_spelling, "<canonical-git-source>"))
                .collect();
        }
    }
    shlex_join(&tokens)
}

/// `_local_execution_runtime_metadata` (:309-318).
fn local_execution_runtime_metadata(intent: &PackageIntent) -> Value {
    if intent.local_executions.is_empty() {
        return json!({});
    }
    json!({
        "runtime_request_reason_code": "local_package_execution_review",
        "runtime_request_remediation_hint":
            "Review the resolved manager and local executable once. Unchanged exact executions reuse that scoped \
             approval; PATH, executable, manifest, or lockfile changes require review again.",
    })
}

// ---------------------------------------------------------------------------
// Token helpers (:321-444)
// ---------------------------------------------------------------------------

/// `redacted_command` (:321-340).
pub fn redacted_command(tokens: &[String]) -> String {
    let mut redacted: Vec<String> = Vec::with_capacity(tokens.len());
    let mut skip_hash = false;
    for token in tokens {
        if skip_hash {
            redacted.push("<hash>".to_owned());
            skip_hash = false;
            continue;
        }
        if token == "--hash" {
            redacted.push(token.clone());
            skip_hash = true;
            continue;
        }
        if token.starts_with("--hash=") {
            redacted.push("--hash=<hash>".to_owned());
            continue;
        }
        if HTTP_SOURCE_IN_TOKEN_RE.is_match(token) || token.starts_with("git+") {
            redacted.push(sanitize_url(token));
            continue;
        }
        redacted.push(token.clone());
    }
    shlex_join(&redacted)
}

/// `redact_package_request_token` (:343-346).
pub fn redact_package_request_token(value: &str) -> String {
    sanitize_url(value)
}

/// `flag_tokens` (:349-364).
pub fn flag_tokens(tokens: &[String]) -> Vec<String> {
    let mut flags: Vec<String> = Vec::new();
    let mut index = 0usize;
    while index < tokens.len() {
        let token = &tokens[index];
        if token.starts_with('-') {
            if token == "--location"
                && index + 1 < tokens.len()
                && !tokens[index + 1].starts_with('-')
            {
                flags.push(format!("--location={}", tokens[index + 1]));
                index += 2;
                continue;
            }
            if token.starts_with("--global=") || token.starts_with("--location=") {
                flags.push(token.clone());
            } else {
                flags.push(if token.starts_with("--") && token.contains('=') {
                    token.split('=').next().unwrap_or(token).to_owned()
                } else {
                    token.clone()
                });
            }
        }
        index += 1;
    }
    // dict.fromkeys dedup preserving first-seen order.
    let mut seen = std::collections::HashSet::new();
    flags.retain(|flag| seen.insert(flag.clone()));
    flags
}

/// `existing_relative_paths` (:367-368) →
/// `workspace_path_guard.existing_paths_within_workspace` (:45-67).
pub fn existing_relative_paths(workspace: Option<&Path>, candidates: &[String]) -> Vec<String> {
    existing_paths_within_workspace(workspace, candidates)
}

/// `resolve_path_within_workspace` (workspace_path_guard.py :8-22):
/// absolute candidates rejected; resolved path must stay inside the
/// (expanduser'd, resolved) workspace root.
pub fn resolve_path_within_workspace(workspace_dir: &Path, relative_path: &str) -> Option<PathBuf> {
    if relative_path.is_empty() {
        return None;
    }
    let candidate = Path::new(relative_path);
    if candidate.is_absolute() {
        return None;
    }
    let workspace_root = std::fs::canonicalize(expanduser(workspace_dir)).ok()?;
    let resolved = std::fs::canonicalize(workspace_root.join(candidate)).ok()?;
    if !resolved.starts_with(&workspace_root) {
        return None;
    }
    Some(resolved)
}

/// `existing_paths_within_workspace` (workspace_path_guard.py :45-67).
pub fn existing_paths_within_workspace(
    workspace: Option<&Path>,
    candidates: &[String],
) -> Vec<String> {
    let Some(workspace) = workspace else {
        return Vec::new();
    };
    let Some(workspace_root) = std::fs::canonicalize(expanduser(workspace)).ok() else {
        return Vec::new();
    };
    let mut resolved_paths: Vec<String> = Vec::new();
    for candidate in candidates {
        if candidate.is_empty() {
            continue;
        }
        let Some(disk_path) = resolve_path_within_workspace(&workspace_root, candidate) else {
            continue;
        };
        if !disk_path.exists() {
            continue;
        }
        let Ok(relative) = disk_path.strip_prefix(&workspace_root) else {
            continue;
        };
        // `.as_posix()`: components joined with '/'; non-Unicode components
        // are lossy — Python would keep the surrogateescape form, which fails
        // closed here by dropping the path from evidence (never a silent
        // allow: missing evidence → fresh review).
        let normalized = relative
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        if !normalized.is_empty() && !resolved_paths.contains(&normalized) {
            resolved_paths.push(normalized);
        }
    }
    resolved_paths
}

/// `Path.expanduser` subset: `~` → HOME (POSIX) or USERPROFILE (Windows).
fn expanduser(path: &Path) -> PathBuf {
    let text = path.as_os_str().to_string_lossy();
    if text == "~" || text.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            if text == "~" {
                return PathBuf::from(home);
            }
            return PathBuf::from(home).join(&text[2..]);
        }
    }
    path.to_path_buf()
}

/// `first_positional` (:371-382).
pub fn first_positional(tokens: &[String], skip_value_options: &[&str]) -> Option<String> {
    let mut index = 0usize;
    while index < tokens.len() {
        let token = &tokens[index];
        if skip_value_options.contains(&token.as_str()) && index + 1 < tokens.len() {
            index += 2;
            continue;
        }
        if token.starts_with('-') {
            index += 1;
            continue;
        }
        return Some(token.clone());
    }
    None
}

/// `option_value` (:385-391).
pub fn option_value(tokens: &[String], option: &str) -> Option<String> {
    for (index, token) in tokens.iter().enumerate() {
        if token == option && index + 1 < tokens.len() {
            return Some(tokens[index + 1].clone());
        }
        if let Some(value) = token.strip_prefix(&format!("{option}=")) {
            return Some(value.to_owned());
        }
    }
    None
}

/// `property_value` (:394-399) — Maven-style `-Dname=value`.
pub fn property_value(tokens: &[String], property_name: &str) -> Option<String> {
    let prefix = format!("-D{property_name}=");
    tokens
        .iter()
        .find_map(|token| token.strip_prefix(prefix.as_str()).map(str::to_owned))
}

/// `js_target` (:402-421).
pub fn js_target(spec: &str) -> PackageIntentTarget {
    let mut alias: Option<String> = None;
    let mut normalized_spec = spec.to_owned();
    if spec.contains("@npm:") && !spec.starts_with("@npm:") {
        if let Some((alias_part, rest)) = spec.split_once("@npm:") {
            alias = Some(alias_part.to_owned());
            normalized_spec = rest.to_owned();
        }
    }
    let parsed_source = parse_npm_source_spec(Some(&normalized_spec));
    if let Some(source) = parsed_source.as_ref() {
        if is_unnamed_js_source_spec(&normalized_spec) {
            return js_source_target(spec, &normalized_spec, source, None, alias);
        }
    }
    let (named_source_package, source_url) = split_js_named_source_spec(&normalized_spec);
    if let Some(source_url) = source_url {
        let parsed_source = parse_npm_source_spec(Some(&source_url))
            .expect("named source spec validated by split_js_named_source_spec");
        return js_source_target(
            spec,
            &source_url,
            &parsed_source,
            named_source_package,
            alias,
        );
    }
    if let Some(source) = parsed_source {
        return js_source_target(spec, &normalized_spec, &source, None, alias);
    }
    let (package_name, requested_specifier) = split_package_token(&normalized_spec);
    let parsed_source = parse_npm_source_spec(requested_specifier.as_deref());
    if let (Some(specifier), Some(source)) = (requested_specifier.as_ref(), parsed_source.as_ref())
    {
        return js_source_target(spec, specifier, source, package_name, alias);
    }
    PackageIntentTarget {
        ecosystem: "npm".to_owned(),
        package_name,
        raw_spec: spec.to_owned(),
        requested_specifier,
        source_url: None,
        source_kind: None,
        source_repository: None,
        source_revision_kind: None,
        source_identity: None,
        source_invalid_reason: None,
        alias,
        dependency_group: None,
        extras: Vec::new(),
        editable: false,
    }
}

/// `_js_source_target` (:424-444).
fn js_source_target(
    raw_spec: &str,
    source_url: &str,
    source: &NpmSourceSpec,
    package_name: Option<String>,
    alias: Option<String>,
) -> PackageIntentTarget {
    PackageIntentTarget {
        ecosystem: "npm".to_owned(),
        package_name: package_name.or_else(|| source_url_package_name(source_url)),
        raw_spec: raw_spec.to_owned(),
        requested_specifier: None,
        source_url: Some(source_url.to_owned()),
        source_kind: Some(source.source_kind.as_str().to_owned()),
        source_repository: source.canonical_repository.clone(),
        source_revision_kind: Some(source.revision_kind.as_str().to_owned()),
        source_identity: Some(source.identity.clone()),
        source_invalid_reason: source.reason.clone(),
        alias,
        dependency_group: None,
        extras: Vec::new(),
        editable: false,
    }
}

/// `python_target` (:447-493).
pub fn python_target(
    spec: &str,
    editable: bool,
    dependency_group: Option<&str>,
    extras: Vec<String>,
) -> PackageIntentTarget {
    let base = |package_name: Option<String>,
                requested_specifier: Option<String>,
                source_url: Option<String>,
                extras: Vec<String>| PackageIntentTarget {
        ecosystem: "pypi".to_owned(),
        package_name,
        raw_spec: spec.to_owned(),
        requested_specifier,
        source_url,
        source_kind: None,
        source_repository: None,
        source_revision_kind: None,
        source_identity: None,
        source_invalid_reason: None,
        alias: None,
        dependency_group: dependency_group.map(str::to_owned),
        extras,
        editable,
    };
    if spec.contains(" @ ") {
        let (package_name, _, source) = split3(spec, " @ ");
        return base(
            Some(package_name.trim().to_owned()),
            None,
            Some(source.trim().to_owned()),
            Vec::new(),
        );
    }
    if spec.contains("://") || spec.starts_with("git+") {
        let package_name = EGG_FRAGMENT_RE
            .captures(spec)
            .and_then(|cap| cap.get(1).map(|m| m.as_str().to_owned()))
            .or_else(|| {
                let sanitized = sanitize_url(spec);
                let name = Path::new(&sanitized)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())?;
                Some(name.strip_suffix(".git").unwrap_or(&name).to_owned())
            });
        return base(
            package_name.filter(|n| !n.is_empty()),
            None,
            Some(spec.to_owned()),
            Vec::new(),
        );
    }
    if spec.contains('@')
        && !spec.starts_with("./")
        && !spec.starts_with("../")
        && !spec.starts_with('/')
    {
        let (package_name, _, requested_specifier) = rsplit3(spec, '@');
        let (normalized_name, detected_extras) = split_python_extras(package_name);
        return base(
            (!normalized_name.is_empty()).then_some(normalized_name),
            (!requested_specifier.is_empty()).then_some(requested_specifier.to_string()),
            None,
            if !extras.is_empty() {
                extras
            } else {
                detected_extras
            },
        );
    }
    let (normalized_name, requested_specifier) = split_python_specifier(spec);
    let (mut package_name, detected_extras) = split_python_extras(&normalized_name);
    if package_name.starts_with("./")
        || package_name.starts_with("../")
        || package_name.starts_with('/')
    {
        package_name = Path::new(&package_name)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .filter(|n| !n.is_empty())
            .unwrap_or(package_name);
    }
    base(
        (!package_name.is_empty()).then_some(package_name),
        requested_specifier,
        None,
        if !extras.is_empty() {
            extras
        } else {
            detected_extras
        },
    )
}

/// `str.partition` three-tuple: `("", sep_missing) -> (s, "", "")`.
fn split3<'a>(text: &'a str, sep: &'a str) -> (&'a str, &'a str, &'a str) {
    match text.split_once(sep) {
        Some((before, after)) => (before, sep, after),
        None => (text, "", ""),
    }
}

/// `str.rpartition` three-tuple on the last `sep` occurrence.
fn rsplit3(text: &str, sep: char) -> (&str, &str, &str) {
    match text.rfind(sep) {
        Some(index) => (&text[..index], &text[index..index + 1], &text[index + 1..]),
        None => ("", "", text),
    }
}

/// `version_target` (:496-498).
pub fn version_target(
    ecosystem: &str,
    spec: &str,
    source_url: Option<&str>,
) -> PackageIntentTarget {
    let (package_name, requested_specifier) = split_package_token(spec);
    PackageIntentTarget {
        ecosystem: ecosystem.to_owned(),
        package_name,
        raw_spec: spec.to_owned(),
        requested_specifier,
        source_url: source_url.map(str::to_owned),
        source_kind: None,
        source_repository: None,
        source_revision_kind: None,
        source_identity: None,
        source_invalid_reason: None,
        alias: None,
        dependency_group: None,
        extras: Vec::new(),
        editable: false,
    }
}

/// `coordinate_target` (:501-505) — Maven `group:artifact:version`.
pub fn coordinate_target(ecosystem: &str, spec: &str) -> PackageIntentTarget {
    let parts: Vec<&str> = spec.split(':').collect();
    let (package_name, specifier) = if parts.len() < 3 {
        (
            if spec.is_empty() {
                None
            } else {
                Some(spec.to_owned())
            },
            None,
        )
    } else {
        (
            Some(parts[..2].join(":")),
            parts
                .last()
                .filter(|p| !p.is_empty())
                .map(|p| p.to_string()),
        )
    };
    PackageIntentTarget {
        ecosystem: ecosystem.to_owned(),
        package_name,
        raw_spec: spec.to_owned(),
        requested_specifier: specifier,
        source_url: None,
        source_kind: None,
        source_repository: None,
        source_revision_kind: None,
        source_identity: None,
        source_invalid_reason: None,
        alias: None,
        dependency_group: None,
        extras: Vec::new(),
        editable: false,
    }
}

/// `composer_target` (:508-510).
pub fn composer_target(spec: &str) -> PackageIntentTarget {
    let (package_name, requested_specifier) = match spec.split_once(':') {
        Some((name, version)) => (name.to_owned(), Some(version.to_owned())),
        None => (spec.to_owned(), None),
    };
    PackageIntentTarget {
        ecosystem: "packagist".to_owned(),
        package_name: Some(package_name),
        raw_spec: spec.to_owned(),
        requested_specifier,
        source_url: None,
        source_kind: None,
        source_repository: None,
        source_revision_kind: None,
        source_identity: None,
        source_invalid_reason: None,
        alias: None,
        dependency_group: None,
        extras: Vec::new(),
        editable: false,
    }
}

/// `homebrew_target` (:513-518).
pub fn homebrew_target(spec: &str, cask: bool) -> PackageIntentTarget {
    let ecosystem = if cask { "homebrew-cask" } else { "homebrew" };
    PackageIntentTarget {
        ecosystem: ecosystem.to_owned(),
        package_name: if spec.is_empty() {
            None
        } else {
            Some(spec.to_owned())
        },
        raw_spec: spec.to_owned(),
        requested_specifier: None,
        source_url: None,
        source_kind: None,
        source_repository: None,
        source_revision_kind: None,
        source_identity: None,
        source_invalid_reason: None,
        alias: None,
        dependency_group: None,
        extras: Vec::new(),
        editable: false,
    }
}

/// `split_python_specifier` (:522-531).
pub fn split_python_specifier(spec: &str) -> (String, Option<String>) {
    let Some(matched) = PYTHON_VERSION_RE.captures(spec.trim()) else {
        return (spec.to_owned(), None);
    };
    let name = matched
        .name("name")
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| spec.to_owned());
    let operator = matched.name("op").map(|m| m.as_str());
    let version = matched
        .name("version")
        .map(|m| m.as_str().trim().to_owned())
        .unwrap_or_default();
    if operator.is_some() && !version.is_empty() {
        let op = operator.unwrap();
        let specifier = if op == "==" || op == "===" {
            version.clone()
        } else {
            format!("{op}{version}")
        };
        return (name, Some(specifier));
    }
    (name, None)
}

/// `split_python_extras` (:534-538).
pub fn split_python_extras(name: &str) -> (String, Vec<String>) {
    let Some(matched) = EXTRAS_RE.captures(name) else {
        return (name.to_owned(), Vec::new());
    };
    let extras = matched
        .name("extras")
        .map(|m| {
            m.as_str()
                .split(',')
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    (
        matched
            .name("name")
            .map(|m| m.as_str().to_owned())
            .unwrap_or_else(|| name.to_owned()),
        extras,
    )
}

/// `_sanitize_url` (:541-560). `pub(crate)`: `mcp_protection` needs it as
/// `_sanitize_package_url`-adjacent logic.
pub(crate) fn sanitize_url(value: &str) -> String {
    if let Some(http_source) = HTTP_SOURCE_IN_TOKEN_RE.find(value) {
        let source = &value[http_source.start()..];
        if !UNSANITIZED_HTTP_SOURCE_RE.is_match(source) {
            let scheme = source.partition3(':').0.to_lowercase();
            // npm treats slashless, single-slash, and backslash HTTP(S)
            // specifiers as remote URLs. They are rejected by Guard, and the
            // persisted command shape must not retain their query/userinfo.
            return format!(
                "{}{}:<redacted-source>",
                &value[..http_source.start()],
                scheme
            );
        }
    }
    if !value.contains("://") && !value.starts_with("git+") {
        return value.to_owned();
    }
    let mut scheme_split = value.splitn(2, "://");
    let scheme_part = scheme_split.next().unwrap_or("");
    let remainder = scheme_split.next();
    if let Some(remainder) = remainder {
        if remainder.split('/').next().unwrap_or("").contains('@') {
            let mut remainder_split = remainder.splitn(2, '/');
            let authority = remainder_split.next().unwrap_or("");
            let tail = remainder_split.next();
            let redacted_authority = authority.rsplit('@').next().unwrap_or("");
            let suffix = tail.map(|t| format!("/{t}")).unwrap_or_default();
            let joined = format!("{scheme_part}://{redacted_authority}{suffix}");
            return strip_query_fragment(&joined);
        }
    }
    strip_query_fragment(value)
}

trait Partition3 {
    fn partition3(&self, sep: char) -> (&str, &str, &str);
}

impl Partition3 for str {
    /// `str.partition` on a single char.
    fn partition3(&self, sep: char) -> (&str, &str, &str) {
        match self.find(sep) {
            Some(index) => (&self[..index], &self[index..index + 1], &self[index + 1..]),
            None => (self, "", ""),
        }
    }
}

fn strip_query_fragment(value: &str) -> String {
    let mut end = value.len();
    if let Some(index) = value.find('?') {
        end = end.min(index);
    }
    if let Some(index) = value.find('#') {
        end = end.min(index);
    }
    value[..end].to_owned()
}

/// `_split_js_named_source_spec` (:563-571).
fn split_js_named_source_spec(spec: &str) -> (Option<String>, Option<String>) {
    for (index, character) in spec.char_indices() {
        if character != '@' || index == 0 {
            continue;
        }
        let package_name = spec[..index].trim();
        let source_candidate = spec[index + 1..].trim();
        if !package_name.is_empty() && parse_npm_source_spec(Some(source_candidate)).is_some() {
            return (
                Some(package_name.to_owned()),
                Some(source_candidate.to_owned()),
            );
        }
    }
    (None, None)
}

/// `_is_unnamed_js_source_spec` (:574-580).
fn is_unnamed_js_source_spec(value: &str) -> bool {
    let lowered = value.to_lowercase();
    SCHEME_PREFIX_RE.is_match(value)
        || lowered.starts_with("git@")
        || lowered.starts_with("git+")
        || lowered.starts_with("github:")
        || lowered.starts_with("gitlab:")
        || lowered.starts_with("bitbucket:")
        || lowered.starts_with("file:")
        || !value.contains('@')
}

/// `_source_url_package_name` (:583-599).
fn source_url_package_name(source_url: &str) -> Option<String> {
    if let Some(parsed_source) = parse_npm_source_spec(Some(source_url)) {
        if let Some(repository) = &parsed_source.canonical_repository {
            let last = repository.rsplit('/').next().unwrap_or("");
            if !last.is_empty() {
                return Some(last.to_owned());
            }
            return None;
        }
    }
    let normalized = source_url.trim();
    let candidate = if normalized.starts_with("github:")
        || normalized.starts_with("gitlab:")
        || normalized.starts_with("bitbucket:")
        || normalized.starts_with("file:")
    {
        split3(normalized, ":").2
    } else {
        normalized
    };
    let sanitized = sanitize_url(candidate);
    let package_name = Path::new(&sanitized)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if package_name.ends_with(".tar.gz") {
        let stem = &package_name[..package_name.len() - ".tar.gz".len()];
        return Some(if stem.is_empty() {
            normalized.to_owned()
        } else {
            stem.to_owned()
        });
    }
    if package_name.ends_with(".git")
        || package_name.ends_with(".tar")
        || package_name.ends_with(".tgz")
    {
        let stem = package_name
            .rsplit_once('.')
            .map(|(stem, _)| stem)
            .unwrap_or("");
        return Some(if stem.is_empty() {
            normalized.to_owned()
        } else {
            stem.to_owned()
        });
    }
    Some(if package_name.is_empty() {
        normalized.to_owned()
    } else {
        package_name
    })
}

// ---------------------------------------------------------------------------
// mcp_protection.py helpers (:297-381) — `pub(crate)` so the mcp_protection
// port reuses them rather than duplicating.
// ---------------------------------------------------------------------------

/// `_split_package_token` (mcp_protection.py :297-314).
pub(crate) fn split_package_token(value: &str) -> (Option<String>, Option<String>) {
    let (pip_name, pip_version) = split_pip_style_specifier(value);
    if pip_name.is_some() {
        return (pip_name, pip_version);
    }
    if let Some(stripped) = value.strip_prefix('@') {
        let scoped = format!("@{stripped}");
        let (scope, slash, remainder) = partition3_str(&scoped, "/");
        if slash.is_empty() || remainder.is_empty() {
            return (Some(value.to_owned()), None);
        }
        let (name, at_sign, version) = rpartition3_str(remainder, '@');
        if at_sign.is_empty() || name.is_empty() {
            return (Some(value.to_owned()), None);
        }
        return (
            Some(format!("{scope}/{name}")),
            if version.is_empty() {
                None
            } else {
                Some(version.to_owned())
            },
        );
    }
    if value.contains("://") {
        return (Some(sanitize_package_url(value)), None);
    }
    let (name, at_sign, version) = rpartition3_str(value, '@');
    if at_sign.is_empty() || name.is_empty() {
        return (Some(value.to_owned()), None);
    }
    (
        Some(name.to_owned()),
        if version.is_empty() {
            None
        } else {
            Some(version.to_owned())
        },
    )
}

/// `_split_pip_style_specifier` (mcp_protection.py :324-338).
pub(crate) fn split_pip_style_specifier(value: &str) -> (Option<String>, Option<String>) {
    if value.contains("://") {
        return (None, None);
    }
    for separator in ["===", "==", "~=", "!=", "<=", ">=", "<", ">", "="] {
        let (name, matched, version) = partition3_str(value, separator);
        if matched.is_empty() {
            continue;
        }
        let normalized_name = name.trim();
        let normalized_version = version.trim();
        if normalized_name.is_empty() || normalized_version.is_empty() {
            continue;
        }
        if ["=", "==", "==="].contains(&separator) {
            return (
                Some(normalized_name.to_owned()),
                Some(normalized_version.to_owned()),
            );
        }
        return (
            Some(normalized_name.to_owned()),
            Some(format!("{separator}{normalized_version}")),
        );
    }
    (None, None)
}

/// `_sanitize_package_url` (mcp_protection.py :350-355): fragments and query
/// dropped first, then authority userinfo redaction via `://` bounds.
pub(crate) fn sanitize_package_url(value: &str) -> String {
    let without_fragment = value.split('#').next().unwrap_or("");
    let without_query = without_fragment.split('?').next().unwrap_or("");
    if url_authority_contains_userinfo(without_query) {
        return redact_url_userinfo(without_query);
    }
    without_query.to_owned()
}

/// `_redact_url_userinfo` (mcp_protection.py :358-368).
fn redact_url_userinfo(value: &str) -> String {
    let Some((authority_start, authority_end)) = url_authority_bounds(value) else {
        return value.to_owned();
    };
    let authority = &value[authority_start..authority_end];
    let Some(at_index) = authority.rfind('@') else {
        return value.to_owned();
    };
    let redacted_authority = &authority[at_index + 1..];
    format!(
        "{}{}{}",
        &value[..authority_start],
        redacted_authority,
        &value[authority_end..]
    )
}

/// `_url_authority_contains_userinfo` (mcp_protection.py :341-347).
fn url_authority_contains_userinfo(value: &str) -> bool {
    let Some((authority_start, authority_end)) = url_authority_bounds(value) else {
        return false;
    };
    value[authority_start..authority_end].contains('@')
}

/// `_url_authority_bounds` (mcp_protection.py :371-381). Byte offsets: the
/// scanner only looks for ASCII delimiters, so indices land on UTF-8
/// boundaries.
fn url_authority_bounds(value: &str) -> Option<(usize, usize)> {
    let scheme_index = value.find("://")?;
    let authority_start = scheme_index + 3;
    let mut authority_end = value.len();
    for delimiter in ['/', '?', '#'] {
        if let Some(delimiter_index) = value[authority_start..].find(delimiter) {
            authority_end = authority_end.min(authority_start + delimiter_index);
        }
    }
    Some((authority_start, authority_end))
}

/// `str.partition` on a substring separator.
fn partition3_str<'a>(text: &'a str, sep: &str) -> (&'a str, &'a str, &'a str) {
    match text.find(sep) {
        Some(index) => (
            &text[..index],
            &text[index..index + sep.len()],
            &text[index + sep.len()..],
        ),
        None => (text, "", ""),
    }
}

/// `str.rpartition` on a single char separator: no match → `("", "", text)`.
fn rpartition3_str(text: &str, sep: char) -> (&str, &str, &str) {
    match text.rfind(sep) {
        Some(index) => (&text[..index], &text[index..index + 1], &text[index + 1..]),
        None => ("", "", text),
    }
}

// keep BTreeMap import used in later chunks (manifest diff consolidation)
#[allow(dead_code)]
fn _unused(_: BTreeMap<String, String>) {}

/// `homebrew_tap_target` (:518-520).
pub fn homebrew_tap_target(spec: &str, source_url: Option<&str>) -> PackageIntentTarget {
    PackageIntentTarget {
        ecosystem: "homebrew-tap".to_owned(),
        package_name: if spec.is_empty() {
            None
        } else {
            Some(spec.to_owned())
        },
        raw_spec: spec.to_owned(),
        requested_specifier: None,
        source_url: source_url.map(str::to_owned),
        source_kind: None,
        source_repository: None,
        source_revision_kind: None,
        source_identity: None,
        source_invalid_reason: None,
        alias: None,
        dependency_group: None,
        extras: Vec::new(),
        editable: false,
    }
}

// ---------------------------------------------------------------------------
// mcp_protection.py command/selector helpers (:154-321, :384-499) + protect.py
// `_collect_package_specs` (:828-850) + secret_file_requests candidate helpers
// (`_SHELL_TOOL_NAMES`/`_normalize_tool_name`/`_candidate_command_texts`) —
// `pub(crate)` so `package_intent_parser` and the eventual `mcp_protection.rs`
// port can reuse them; consolidated here because they share the URL/token
// primitives above.

/// `_PACKAGE_LAUNCHERS` (mcp_protection.py :151) — narrower than
/// `package_execution_context::PACKAGE_LAUNCHERS` (launch_identity_binding.py
/// :41-58); the two sets are intentionally distinct upstream.
#[allow(dead_code)]
pub(crate) const MCP_PACKAGE_LAUNCHERS: &[&str] =
    &["bunx", "npm", "npx", "pnpm", "uvx", "yarn", "pipx"];

/// `_command_name` (mcp_protection.py :317-321):
/// `PurePath(value.replace("\\", "/")).name.lower()`, stripping
/// `.cmd`/`.exe`/`.bat`/`.ps1` suffix.
pub(crate) fn command_name(value: &str) -> String {
    let normalized = value.replace('\\', "/");
    let base = normalized.rsplit('/').next().unwrap_or("").to_lowercase();
    for suffix in [".cmd", ".exe", ".bat", ".ps1"] {
        if let Some(stem) = base.strip_suffix(suffix) {
            return stem.to_owned();
        }
    }
    base
}

/// `package_launcher_name` (mcp_protection.py :154-158).
#[allow(dead_code)]
pub(crate) fn package_launcher_name(command: &str) -> Option<String> {
    let name = command_name(command);
    if MCP_PACKAGE_LAUNCHERS.contains(&name.as_str()) {
        Some(name)
    } else {
        None
    }
}

/// `_launcher_subcommands` (mcp_protection.py :393-400).
#[allow(dead_code)]
pub(crate) fn launcher_subcommands(command_name: &str) -> &'static [&'static str] {
    match command_name {
        "npm" => &["exec", "x"],
        "pipx" => &["run"],
        "pnpm" => &["dlx"],
        "yarn" => &["dlx"],
        _ => &[],
    }
}

/// `_launcher_non_package_subcommands` (mcp_protection.py :403-409).
#[allow(dead_code)]
pub(crate) fn launcher_non_package_subcommands(command_name: &str) -> &'static [&'static str] {
    match command_name {
        "npm" => &["ci", "install", "run", "start", "stop", "restart", "test"],
        "pnpm" => &["exec", "run"],
        "yarn" => &["exec", "run"],
        _ => &[],
    }
}

/// `_package_selector_flags` (mcp_protection.py :412-419).
#[allow(dead_code)]
pub(crate) fn package_selector_flags(command_name: &str) -> &'static [&'static str] {
    match command_name {
        "bunx" => &["--package", "-p"],
        "npm" => &["--package"],
        "npx" => &["--package", "-p"],
        "pnpm" => &["--package"],
        _ => &[],
    }
}

/// `_value_options_for_command` (mcp_protection.py :422-489): `common` union
/// with the command-specific set.
#[allow(dead_code)]
pub(crate) fn value_options_for_command(command_name: &str) -> Vec<&'static str> {
    const COMMON: &[&str] = &[
        "--cache",
        "--cache-dir",
        "--call",
        "--cwd",
        "--prefix",
        "--python",
        "--registry",
        "--userconfig",
    ];
    let mut out: Vec<&'static str> = COMMON.to_vec();
    let extra: &[&str] = match command_name {
        "bunx" => &["-c", "--config", "--package"],
        "npm" => &["-c", "-w", "--workspace"],
        "npx" => &["-c", "-w", "--workspace"],
        "pipx" => &["-i", "--index-url", "--pip-args", "--suffix", "--with"],
        "pnpm" => &["-C", "--allow-build", "--dir", "--filter", "--reporter"],
        "uvx" => &[
            "-P",
            "-b",
            "-C",
            "-c",
            "-f",
            "-i",
            "-p",
            "-w",
            "--allow-insecure-host",
            "--cache-dir",
            "--color",
            "--config-file",
            "--config-setting",
            "--config-settings-package",
            "--default-index",
            "--build-constraints",
            "--constraints",
            "--directory",
            "--env-file",
            "--extra-index-url",
            "--exclude-newer",
            "--exclude-newer-package",
            "--find-links",
            "--fork-strategy",
            "--from",
            "--index",
            "--index-url",
            "--index-strategy",
            "--keyring-provider",
            "--link-mode",
            "--no-binary-package",
            "--no-build-isolation-package",
            "--no-build-package",
            "--no-sources-package",
            "--overrides",
            "--prerelease",
            "--project",
            "--python-platform",
            "--refresh-package",
            "--reinstall-package",
            "--resolution",
            "--torch-backend",
            "--upgrade-package",
            "--with",
            "--with-editable",
            "--with-requirements",
        ],
        "yarn" => &["--cwd", "--use-yarnrc"],
        _ => &[],
    };
    for flag in extra {
        if !out.contains(flag) {
            out.push(flag);
        }
    }
    out
}

/// `_option_takes_value` (mcp_protection.py :384-390).
#[allow(dead_code)]
pub(crate) fn option_takes_value(command_name: &str, option: &str) -> bool {
    let option_name = option.trim();
    if !option_name.starts_with('-') {
        return false;
    }
    if option_name.starts_with("--") && option_name.contains('=') {
        return false;
    }
    value_options_for_command(command_name).contains(&option_name)
}

/// `_looks_like_runtime_path` (mcp_protection.py :492-499).
#[allow(dead_code)]
pub(crate) fn looks_like_runtime_path(value: &str) -> bool {
    let normalized = value.trim().replace('\\', "/");
    if normalized.starts_with("./")
        || normalized.starts_with("../")
        || normalized.starts_with("~/")
        || normalized.starts_with('/')
    {
        return true;
    }
    // `PurePath(normalized).suffix.lower()` → last dotted suffix.
    let base = normalized.rsplit('/').next().unwrap_or("");
    let suffix = base
        .rfind('.')
        .map(|idx| base[idx..].to_lowercase())
        .unwrap_or_default();
    if !matches!(
        suffix.as_str(),
        ".cjs" | ".js" | ".json" | ".mjs" | ".py" | ".ts"
    ) {
        return false;
    }
    normalized.contains('/') && !normalized.starts_with('@')
}

/// `_package_token` (mcp_protection.py :244-294).
#[allow(dead_code)]
pub(crate) fn package_token(command_name: &str, args: &[String]) -> Option<String> {
    let mut index = 0usize;
    let mut positional_index = 0usize;
    let package_selector_flags = package_selector_flags(command_name);
    let mut selected_package: Option<String> = None;
    while index < args.len() {
        let value = args[index].trim();
        if value.is_empty() {
            index += 1;
            continue;
        }
        if positional_index == 0 && launcher_non_package_subcommands(command_name).contains(&value)
        {
            return None;
        }
        if positional_index == 0 && launcher_subcommands(command_name).contains(&value) {
            index += 1;
            positional_index += 1;
            continue;
        }
        if package_selector_flags.contains(&value) && index + 1 < args.len() {
            let next = args[index + 1].trim();
            if !next.is_empty() {
                selected_package = Some(next.to_owned());
            }
            index += 2;
            continue;
        }
        if package_selector_flags.contains(&"--package") && value.starts_with("--package=") {
            let package = value.split_once('=').map(|x| x.1).unwrap_or("").trim();
            if !package.is_empty() {
                selected_package = Some(package.to_owned());
            }
            index += 1;
            continue;
        }
        if option_takes_value(command_name, value) {
            index += 2;
            continue;
        }
        if value.starts_with('-') {
            index += 1;
            continue;
        }
        if positional_index == 0 && looks_like_runtime_path(value) {
            return None;
        }
        if positional_index == 0 {
            return Some(value.to_owned());
        }
        index += 1;
    }
    selected_package
}

/// `_collect_package_specs` (protect.py :828-850).
pub(crate) fn collect_package_specs(values: &[String]) -> Vec<String> {
    const VALUE_OPTIONS: &[&str] = &[
        "-r",
        "--extra-index-url",
        "--index-url",
        "--prefix",
        "--registry",
        "--requirement",
    ];
    let mut specs: Vec<String> = Vec::new();
    let mut skip_next = false;
    for (index, value) in values.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if value.starts_with('-') {
            if VALUE_OPTIONS.contains(&value.as_str()) {
                skip_next = true;
            }
            continue;
        }
        if index > 0 && matches!(values[index - 1].as_str(), "-r" | "--requirement") {
            continue;
        }
        specs.push(value.clone());
    }
    specs
}

// ---------------------------------------------------------------------------
// secret_file_requests candidate helpers — used by package_intent_parser's
// tool-action detection (:235-237). Source module lives at
// `runtime/secret_file_request_services/` (48 files); only these three
// constants/helpers are needed today.

/// `_SHELL_TOOL_NAMES` (secret_file_request_services/constants_core.py :266-280).
pub(crate) const SHELL_TOOL_NAMES: &[&str] = &[
    "ash",
    "bash",
    "cmd",
    "dash",
    "powershell",
    "pwsh",
    "run_command",
    "run_terminal_command",
    "shell",
    "sh",
    "terminal",
    "zsh",
];

/// `_normalize_tool_name` (request_models.py :277-280).
pub(crate) fn normalize_tool_name(tool_name: &str) -> Option<String> {
    let trimmed = tool_name.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_lowercase())
}

const COMMAND_KEYS: &[&str] = &[
    "command",
    "cmd",
    "shell_command",
    "shellCommand",
    "pattern",
    "query",
    "search",
    "regex",
];
const COMMAND_LIST_KEYS: &[&str] = &["argv", "command_args", "commandArgs"];
const COMMAND_SEQUENCE_KEYS: &[&str] = &["commands"];

/// `command_list_candidate_texts` (request_artifacts.py :177-189).
pub(crate) fn command_list_candidate_texts(values: &[Value], preserve_items: bool) -> Vec<String> {
    let string_values: Vec<String> = values
        .iter()
        .filter_map(|v| v.as_str())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    if string_values.is_empty() {
        return Vec::new();
    }
    if preserve_items {
        return string_values;
    }
    if string_values.len() == 1 {
        return vec![string_values[0].clone()];
    }
    vec![shlex_join(&string_values)]
}

/// `_candidate_command_texts` (request_artifacts.py :171-174).
pub(crate) fn candidate_command_texts(value: &Value) -> Vec<String> {
    let mut results: Vec<String> = Vec::new();
    collect_candidate_commands(value, &mut results, 0);
    results
}

/// `_collect_candidate_commands` (request_artifacts.py :192-220).
fn collect_candidate_commands(value: &Value, results: &mut Vec<String>, depth: usize) {
    if depth > 4 {
        return;
    }
    if let Some(s) = value.as_str() {
        let stripped = s.trim();
        if !stripped.is_empty() {
            results.push(stripped.to_owned());
        }
        return;
    }
    if let Some(list) = value.as_array() {
        results.extend(command_list_candidate_texts(list, false));
        for child in list {
            if child.is_object() || child.is_array() {
                collect_candidate_commands(child, results, depth + 1);
            }
        }
        return;
    }
    let Some(dict) = value.as_object() else {
        return;
    };
    for key in COMMAND_KEYS {
        if let Some(candidate) = dict.get(*key).and_then(|v| v.as_str()) {
            let trimmed = candidate.trim();
            if !trimmed.is_empty() {
                results.push(trimmed.to_owned());
            }
        }
    }
    for key in COMMAND_LIST_KEYS.iter().chain(COMMAND_SEQUENCE_KEYS.iter()) {
        if let Some(candidate) = dict.get(*key).and_then(|v| v.as_array()) {
            results.extend(command_list_candidate_texts(
                candidate,
                COMMAND_SEQUENCE_KEYS.contains(key),
            ));
        }
    }
    for (key, child) in dict {
        if COMMAND_LIST_KEYS.contains(&key.as_str())
            || COMMAND_SEQUENCE_KEYS.contains(&key.as_str())
        {
            continue;
        }
        if child.is_object() || child.is_array() {
            collect_candidate_commands(child, results, depth + 1);
        }
    }
}

// ---------------------------------------------------------------------------
// from_dict — RTM-020 resident-op transport.
//
// `try_execute_contained_*_with_intent` receives a pre-parsed
// `LocalPackageExecutionEvidence` produced by the Python caller. The value
// arrives as the `to_dict` output of the caller's dataclass; we reconstruct
// the Rust struct without re-running the environment probe so caller-bound
// context (workspace, PATH source, cwd) survives the transport intact.
// ---------------------------------------------------------------------------

fn _string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn _bool_field(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn _opt_string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn _file_evidence_from_dict(value: &Value) -> Option<PackageExecutionFileEvidence> {
    let path = _string_field(value, "path")?;
    let status_str = _string_field(value, "status").unwrap_or_else(|| "unknown".to_owned());
    Some(PackageExecutionFileEvidence {
        path: path.clone(),
        resolved_path: _opt_string_field(value, "resolved_path").or_else(|| Some(path.clone())),
        status: match status_str.as_str() {
            "present" => "present",
            "absent" => "absent",
            "directory" => "directory",
            _ => "unknown",
        },
        file_identity: _opt_string_field(value, "file_identity"),
        content_hash: _opt_string_field(value, "content_hash"),
    })
}

fn _file_evidence_list(value: &Value, key: &str) -> Vec<PackageExecutionFileEvidence> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(_file_evidence_from_dict).collect())
        .unwrap_or_default()
}

impl LocalPackageExecutionEvidence {
    /// Reconstruct a `LocalPackageExecutionEvidence` from the `to_dict` JSON
    /// emitted by the Python caller. Returns `None` when the payload is not an
    /// object or is missing the required scalar fields — the resident treats
    /// a `None` here exactly as the Python caller treats a `None` evidence
    /// (transport failure → Python fallback, never re-spawn).
    pub fn from_dict(value: &Value) -> Option<Self> {
        if !value.is_object() {
            return None;
        }
        let manager_name = _string_field(value, "manager_name")?;
        let path_source = _string_field(value, "path_source")?;
        let effective_cwd = _string_field(value, "effective_cwd")?;
        let cwd_source = _string_field(value, "cwd_source")?;
        let context_hash = _string_field(value, "context_hash")?;
        Some(LocalPackageExecutionEvidence {
            manager_name,
            path_source,
            effective_cwd,
            cwd_source,
            manager_is_guard_shim: _bool_field(value, "manager_is_guard_shim"),
            local_only_requested: _bool_field(value, "local_only_requested"),
            context_hash,
            package_name: _opt_string_field(value, "package_name"),
            executable_name: _opt_string_field(value, "executable_name"),
            declared_version: _opt_string_field(value, "declared_version"),
            manager: value.get("manager").and_then(_file_evidence_from_dict),
            local_executable: value
                .get("local_executable")
                .and_then(_file_evidence_from_dict),
            manifests: _file_evidence_list(value, "manifests"),
            lockfiles: _file_evidence_list(value, "lockfiles"),
            typescript_launch: value
                .get("typescript_launch")
                .filter(|v| !v.is_null())
                .cloned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_tokens_location_and_dedup() {
        // Python: flag_tokens(("npm", "--location", "global", "--save-dev",
        //                     "--save-dev", "-g"))
        // → ("--location=global", "--save-dev", "-g") — "npm" is not a flag.
        let tokens: Vec<String> = [
            "npm",
            "--location",
            "global",
            "--save-dev",
            "--save-dev",
            "-g",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            flag_tokens(&tokens),
            vec!["--location=global", "--save-dev", "-g"]
        );
    }

    #[test]
    fn flag_tokens_long_option_value_stripped() {
        let tokens: Vec<String> = ["--registry=https://x", "--dry-run", "pkg"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        // --registry=... keeps only the flag name; positional ignored.
        assert_eq!(flag_tokens(&tokens), vec!["--registry", "--dry-run"]);
    }

    #[test]
    fn split_package_token_pip_and_npm() {
        assert_eq!(
            split_package_token("requests>=2.0"),
            (Some("requests".to_owned()), Some(">=2.0".to_owned()))
        );
        assert_eq!(
            split_package_token("requests==2.31.0"),
            (Some("requests".to_owned()), Some("2.31.0".to_owned()))
        );
        assert_eq!(
            split_package_token("@scope/pkg@1.2.3"),
            (Some("@scope/pkg".to_owned()), Some("1.2.3".to_owned()))
        );
        assert_eq!(
            split_package_token("@scope"),
            (Some("@scope".to_owned()), None)
        );
        assert_eq!(
            split_package_token("pkg@latest"),
            (Some("pkg".to_owned()), Some("latest".to_owned()))
        );
        assert_eq!(
            split_package_token("lodash"),
            (Some("lodash".to_owned()), None)
        );
    }

    #[test]
    fn sanitize_url_redacts_userinfo_and_query() {
        assert_eq!(
            sanitize_url("https://user:pass@registry.example.com/pkg.tgz?token=abc#frag"),
            "https://registry.example.com/pkg.tgz"
        );
        // `git@` before the host IS userinfo — Python rsplit("@") drops it.
        assert_eq!(
            sanitize_url("git+ssh://git@github.com/owner/repo.git#semver:^1"),
            "git+ssh://github.com/owner/repo.git"
        );
        // Slashless http: → <redacted-source>
        assert_eq!(
            sanitize_url("http:registry.example.com/pkg"),
            "http:<redacted-source>"
        );
        assert_eq!(sanitize_url("plain-token"), "plain-token");
    }

    #[test]
    fn python_target_variants() {
        let target = python_target("requests[security]>=2.0", false, None, Vec::new());
        assert_eq!(target.ecosystem, "pypi");
        assert_eq!(target.package_name.as_deref(), Some("requests"));
        // `req[extra]@ver` is caught by the "@" branch first.
        let target = python_target("requests[security]@2.0", false, Some("dev"), Vec::new());
        assert_eq!(target.package_name.as_deref(), Some("requests"));
        assert_eq!(target.extras, vec!["security"]);
        assert_eq!(target.requested_specifier.as_deref(), Some("2.0"));
        assert_eq!(target.dependency_group.as_deref(), Some("dev"));

        let target = python_target(
            "requests @ https://example.com/requests.whl",
            true,
            None,
            Vec::new(),
        );
        assert_eq!(target.package_name.as_deref(), Some("requests"));
        assert_eq!(
            target.source_url.as_deref(),
            Some("https://example.com/requests.whl")
        );
        assert!(target.editable);
    }

    #[test]
    fn spaced_sorted_json_matches_python_dumps() {
        // json.dumps(material, sort_keys=True) with default separators.
        let value = json!({"b": [1, "x"], "a": {"z": true}});
        let mut out = String::new();
        write_spaced_sorted_json(&value, &mut out);
        assert_eq!(out, r#"{"a": {"z": true}, "b": [1, "x"]}"#);
    }

    #[test]
    fn fingerprint_deterministic() {
        let intent = PackageIntent {
            package_manager: "npm".to_owned(),
            intent_kind: "install",
            command_tokens: vec!["npm".to_owned(), "install".to_owned(), "lodash".to_owned()],
            redacted_command: "npm install lodash".to_owned(),
            targets: vec![PackageIntentTarget {
                ecosystem: "npm".to_owned(),
                package_name: Some("lodash".to_owned()),
                raw_spec: "lodash".to_owned(),
                requested_specifier: None,
                source_url: None,
                source_kind: None,
                source_repository: None,
                source_revision_kind: None,
                source_identity: None,
                source_invalid_reason: None,
                alias: None,
                dependency_group: None,
                extras: Vec::new(),
                editable: false,
            }],
            manifest_paths: vec!["package.json".to_owned()],
            lockfile_paths: vec!["package-lock.json".to_owned()],
            flags: vec!["--save".to_owned()],
            notes: Vec::new(),
            local_executions: Vec::new(),
            execution_context_hashes: Vec::new(),
            execution_context_cwds: Vec::new(),
            execution_context_reason_codes: Vec::new(),
        };
        let artifact =
            build_package_request_artifact("claude", &intent, "settings.json", "workspace");
        assert!(artifact
            .artifact_id
            .starts_with("claude:workspace:package-request:"));
        assert_eq!(artifact.name, "npm install lodash");
        assert_eq!(artifact.metadata["package_manager"], json!("npm"));
        assert_eq!(
            artifact.runtime_private_metadata["package_targets"][0]["raw_spec"],
            json!("lodash")
        );
        // to_dict drops the private metadata.
        assert!(
            artifact.to_dict()["metadata"]
                .get("package_targets")
                .is_none()
                || artifact.to_dict().get("runtime_private_metadata").is_none()
        );
        assert!(artifact.to_dict().get("runtime_private_metadata").is_none());
    }
}

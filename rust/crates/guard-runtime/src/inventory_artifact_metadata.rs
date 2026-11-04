//! `artifact_metadata` operation of the `inventory_export_redaction` kind: the
//! metadata an exported inventory item carries for one artifact
//! (`_safe_artifact_metadata`, `_sanitize_paths` and the copy of
//! `separate_untrusted_adapter_trust_metadata` it applied, before they moved
//! here).
//!
//! Every string in the artifact's own metadata is redacted as a URL when it
//! holds `://` and as a local path otherwise; a key that names a credential
//! keeps a boolean and masks anything else. Adapter-authored trust claims then
//! move under `unverifiedAdapterEvidence`, with proof material dropped, and
//! the artifact's config path, command, URL and transport are added in their
//! exported form. The redaction rules are the ones the resident's
//! `inventory_url_redaction` serves, so a value exports the same either way.
//!
//! `{"op": "artifact_metadata", "home_dir": str, "workspace_dir": str|null,
//! "cwd": str, "artifacts": [<JSON text>, ...], "window": null}` answers
//! `{"metadata": [<JSON text>, ...]}`, one answer per artifact. Each artifact is
//! `{"metadata": object, "artifact_type": str, "config_path": str|null,
//! "command": str|null, "url": str|null, "transport": str|null}`; it travels
//! as JSON text so its key order survives, and so a long list inside it is
//! not refused as a wide request.
//!
//! One artifact too large for its answer to fit a response is read in parts:
//! with `"window": {"start": int, "length": int}` and exactly one artifact, the
//! answer is `{"metadata": [<part>], "total": int}`, the part being the answer
//! text's characters from `start`, at most `length` of them, and `total` the
//! answer text's length in characters.

use std::path::Path;

use guard_command::inventory_path_redaction::{redact_command_value, redact_known_path};
use guard_command::inventory_redaction::{
    classify_endpoint_host, matches_sensitive_key, redact_url,
};
use serde_json::{json, Map, Value};

use super::{exact_keys, parse, text};
use crate::hook_env_stamp::{dumps, set_member as set};
use crate::pyjson::PyVal;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const KEYS: [&str; 6] = [
    "op",
    "home_dir",
    "workspace_dir",
    "cwd",
    "artifacts",
    "window",
];
const WINDOW_KEYS: [&str; 2] = ["start", "length"];
/// The most characters one window answers. Even a part made only of characters
/// JSON writes as six-byte escapes stays well inside a response.
const MAX_WINDOW: u64 = 256 * 1024;
const ARTIFACT_KEYS: [&str; 6] = [
    "metadata",
    "artifact_type",
    "config_path",
    "command",
    "url",
    "transport",
];
const MAX_ARTIFACTS: usize = 4096;
const EVIDENCE_KEY: &str = "unverifiedAdapterEvidence";
/// `_TOP_LEVEL_TRUST_KEYS`, normalized.
const TRUST_KEYS: [&str; 18] = [
    "affectsv4score",
    "attestation",
    "attestationbindings",
    "attestationref",
    "attestations",
    "attestationstatus",
    "attestationverification",
    "evidenceauthority",
    "signature",
    "signatures",
    "signedtrust",
    "trustlayer",
    "trustlayers",
    "trustresolution",
    "trustscore",
    "truststatus",
    "verification",
    "verified",
];
/// `_PROOF_KEY_MARKERS`: a key holding any of these names proof material.
const PROOF_KEY_MARKERS: [&str; 8] = [
    "attestation",
    "signature",
    "publickey",
    "privatekey",
    "fingerprintsha256",
    "keyid",
    "payloadhash",
    "signedat",
];

/// The directories a relative or home-anchored path is redacted against.
struct Roots<'a> {
    home_dir: &'a Path,
    workspace_dir: Option<&'a Path>,
    cwd: &'a Path,
}

impl Roots<'_> {
    fn known_path(&self, value: &str) -> String {
        redact_known_path(value, self.home_dir, self.workspace_dir, self.cwd)
    }

    fn command(&self, value: &str) -> String {
        redact_command_value(value, self.home_dir, self.workspace_dir, self.cwd)
    }
}

pub(super) fn dispatch(fields: &Map<String, Value>) -> KindResult {
    exact_keys(fields, &KEYS)?;
    let workspace_dir = match fields.get("workspace_dir") {
        Some(Value::Null) => None,
        Some(Value::String(dir)) => Some(Path::new(dir.as_str())),
        _ => return Err(ERR_INVALID),
    };
    let roots = Roots {
        home_dir: Path::new(text(fields, "home_dir")?),
        workspace_dir,
        cwd: Path::new(text(fields, "cwd")?),
    };
    let artifacts = fields
        .get("artifacts")
        .and_then(Value::as_array)
        .filter(|artifacts| artifacts.len() <= MAX_ARTIFACTS)
        .ok_or(ERR_INVALID)?;
    let window = match fields.get("window") {
        Some(Value::Null) => None,
        Some(Value::Object(window)) if artifacts.len() == 1 => Some(answer_window(window)?),
        _ => return Err(ERR_INVALID),
    };
    let metadata = artifacts
        .iter()
        .map(|artifact| {
            let (entry, mapped) = parse(artifact.as_str().ok_or(ERR_INVALID)?)?;
            let mut answer = String::new();
            dumps(
                &artifact_metadata(&entry, &roots)?,
                false,
                mapped,
                &mut answer,
            );
            Ok(answer)
        })
        .collect::<Result<Vec<String>, &'static str>>()?;
    let Some((start, length)) = window else {
        return Ok(json!({ "metadata": metadata }));
    };
    let text = &metadata[0];
    let part: String = text.chars().skip(start).take(length).collect();
    Ok(json!({ "metadata": [part], "total": text.chars().count() }))
}

/// The window's start and length, in characters.
fn answer_window(window: &Map<String, Value>) -> Result<(usize, usize), &'static str> {
    exact_keys(window, &WINDOW_KEYS)?;
    let start = window
        .get("start")
        .and_then(Value::as_u64)
        .ok_or(ERR_INVALID)?;
    let length = window
        .get("length")
        .and_then(Value::as_u64)
        .filter(|length| (1..=MAX_WINDOW).contains(length))
        .ok_or(ERR_INVALID)?;
    let start = usize::try_from(start).map_err(|_| ERR_INVALID)?;
    let length = usize::try_from(length).map_err(|_| ERR_INVALID)?;
    Ok((start, length))
}

/// `_safe_artifact_metadata(artifact, home_dir=..., workspace_dir=...)`.
fn artifact_metadata(entry: &PyVal, roots: &Roots<'_>) -> Result<PyVal, &'static str> {
    let PyVal::Dict(fields) = entry else {
        return Err(ERR_INVALID);
    };
    if fields.len() != ARTIFACT_KEYS.len()
        || !ARTIFACT_KEYS.iter().all(|key| get(fields, key).is_some())
    {
        return Err(ERR_INVALID);
    }
    let Some(PyVal::Dict(raw)) = get(fields, "metadata") else {
        return Err(ERR_INVALID);
    };
    let Some(PyVal::Str(artifact_type)) = get(fields, "artifact_type") else {
        return Err(ERR_INVALID);
    };
    let mut metadata = separate_untrusted_trust(sanitize_entries(raw, roots));
    if let Some(config_path) = optional_text(fields, "config_path")? {
        set(
            &mut metadata,
            "configPath",
            PyVal::Str(roots.known_path(config_path)),
        );
    }
    if let Some(command) = optional_text(fields, "command")? {
        set(&mut metadata, "command", PyVal::Str(roots.command(command)));
    }
    if let Some(url) = optional_text(fields, "url")? {
        set(&mut metadata, "url", PyVal::Str(redact_url(url)));
        let host_class = classify_endpoint_host(Some(url));
        set(
            &mut metadata,
            "endpointHostClass",
            PyVal::Str(host_class.to_owned()),
        );
    }
    if let Some(transport) = optional_text(fields, "transport")? {
        set(&mut metadata, "transport", PyVal::Str(transport.to_owned()));
    }
    set(
        &mut metadata,
        "artifactType",
        PyVal::Str(artifact_type.clone()),
    );
    Ok(PyVal::Dict(metadata))
}

/// `_sanitize_paths(value, home_dir, workspace_dir)`.
fn sanitize(value: &PyVal, roots: &Roots<'_>) -> PyVal {
    match value {
        PyVal::Dict(entries) => PyVal::Dict(sanitize_entries(entries, roots)),
        PyVal::List(items) => PyVal::List(items.iter().map(|item| sanitize(item, roots)).collect()),
        PyVal::Str(text) if text.contains("://") => PyVal::Str(redact_url(text)),
        PyVal::Str(text) => PyVal::Str(roots.known_path(text)),
        other => other.clone(),
    }
}

/// A mapping's members, each sanitized; a credential key keeps a boolean and
/// masks anything else without looking at it.
fn sanitize_entries(entries: &[(String, PyVal)], roots: &Roots<'_>) -> Vec<(String, PyVal)> {
    entries
        .iter()
        .map(|(key, item)| {
            let value = if !matches_sensitive_key(key) {
                sanitize(item, roots)
            } else if let PyVal::Bool(_) = item {
                item.clone()
            } else {
                PyVal::Str("present_redacted".to_owned())
            };
            (key.clone(), value)
        })
        .collect()
}

/// `separate_untrusted_adapter_trust_metadata(metadata)`: adapter-authored
/// trust claims move under `unverifiedAdapterEvidence` and proof material is
/// dropped. Applying it twice changes nothing.
fn separate_untrusted_trust(metadata: Vec<(String, PyVal)>) -> Vec<(String, PyVal)> {
    let mut claims = existing_unverified_claims(get(&metadata, EVIDENCE_KEY));
    let mut clean: Vec<(String, PyVal)> = Vec::with_capacity(metadata.len());
    for (key, value) in metadata {
        if key == EVIDENCE_KEY || is_prior_proof_key(&key) {
            continue;
        }
        if is_untrusted_trust_key(&key) {
            let claim = without_prior_proofs(&value);
            set(&mut claims, &key, claim);
            continue;
        }
        clean.push((key, value));
    }
    if !claims.is_empty() {
        let evidence = vec![
            (
                "source".to_owned(),
                PyVal::Str("adapter_metadata".to_owned()),
            ),
            (
                "verificationStatus".to_owned(),
                PyVal::Str("unverified".to_owned()),
            ),
            ("affectsTrustScore".to_owned(), PyVal::Bool(false)),
            ("trustClaims".to_owned(), PyVal::Dict(claims)),
        ];
        clean.push((EVIDENCE_KEY.to_owned(), PyVal::Dict(evidence)));
    }
    clean
}

/// `_existing_unverified_claims`: the claims an earlier pass already moved,
/// kept only when they carry that pass's own marking.
fn existing_unverified_claims(value: Option<&PyVal>) -> Vec<(String, PyVal)> {
    let Some(PyVal::Dict(entries)) = value else {
        return Vec::new();
    };
    if !is_text(get(entries, "source"), "adapter_metadata")
        || !is_text(get(entries, "verificationStatus"), "unverified")
    {
        return Vec::new();
    }
    let Some(PyVal::Dict(claims)) = get(entries, "trustClaims") else {
        return Vec::new();
    };
    claims
        .iter()
        .map(|(key, item)| (key.clone(), without_prior_proofs(item)))
        .collect()
}

/// `_without_prior_proofs`: the value with every proof-named key removed, at
/// any depth.
fn without_prior_proofs(value: &PyVal) -> PyVal {
    match value {
        PyVal::Dict(entries) => PyVal::Dict(
            entries
                .iter()
                .filter(|(key, _)| !is_prior_proof_key(key))
                .map(|(key, item)| (key.clone(), without_prior_proofs(item)))
                .collect(),
        ),
        PyVal::List(items) => PyVal::List(items.iter().map(without_prior_proofs).collect()),
        other => other.clone(),
    }
}

/// `_normalized_key`: `re.sub(r"[^a-z0-9]+", "", key.lower())`.
fn normalized_key(key: &str) -> String {
    key.to_lowercase()
        .chars()
        .filter(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
        .collect()
}

fn is_untrusted_trust_key(key: &str) -> bool {
    let normalized = normalized_key(key);
    TRUST_KEYS.contains(&normalized.as_str()) || normalized.starts_with("trustattestation")
}

fn is_prior_proof_key(key: &str) -> bool {
    let normalized = normalized_key(key);
    PROOF_KEY_MARKERS
        .iter()
        .any(|marker| normalized.contains(marker))
}

fn is_text(value: Option<&PyVal>, expected: &str) -> bool {
    matches!(value, Some(PyVal::Str(text)) if text == expected)
}

fn get<'a>(entries: &'a [(String, PyVal)], key: &str) -> Option<&'a PyVal> {
    entries
        .iter()
        .find(|(existing, _)| existing == key)
        .map(|(_, value)| value)
}

/// A string field the export uses only when it is a non-empty string.
fn optional_text<'a>(
    fields: &'a [(String, PyVal)],
    key: &str,
) -> Result<Option<&'a str>, &'static str> {
    match get(fields, key) {
        Some(PyVal::Null) => Ok(None),
        Some(PyVal::Str(text)) => Ok(Some(text.as_str()).filter(|text| !text.is_empty())),
        _ => Err(ERR_INVALID),
    }
}

#[cfg(test)]
#[path = "inventory_artifact_metadata_tests.rs"]
mod tests;

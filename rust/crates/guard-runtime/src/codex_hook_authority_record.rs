//! `codex-hook-authority-record --stdin`: seal and open the signed records
//! that carry Codex hook authority between processes.
//!
//! Four records share one shape, a canonical JSON object signed with the
//! Codex hook authentication key under a purpose of its own:
//!
//! - `recovery`: the pending publication inverse
//!   (`managed/codex/pending-hook-publication.json`);
//! - `receipt`: the retained authority receipt beside a hook manifest;
//! - `repair_request` and `inverse_request`: the private review artifacts
//!   a repair or publication inverse is captured in.
//!
//! The caller reads the key and the files; the runtime decides what a record
//! may contain and whether it opens. Ops:
//!
//! - `seal` signs `payload` and answers `{text}`, the record's exact bytes;
//! - `open` authenticates `text` against the expected context and answers
//!   `{payload}` without its authentication (plus `signed_at`);
//! - `receipt_manifest` checks an authenticated manifest against the
//!   receipt's context;
//! - `repair_proof` answers `{matches}` for a native verification proof
//!   against a repair record.
//!
//! A record the runtime refuses answers `{error: <reason>}`; the caller
//! raises that reason with its own error type.

use std::io::Read;
use std::path::Path;

use guard_policy_snapshot::local_authority_integrity::sign_local_authority_payload;
use serde::Deserialize;
use serde_json::{json, Map, Value};

#[path = "codex_hook_authority_open.rs"]
mod opening;
#[path = "codex_hook_authority_json.rs"]
pub(crate) mod python_json;

use opening::*;
use python_json::{parse_python_json, python_canonical_json};

use crate::codex_hook_key;
use crate::codex_hook_manifest_auth;
use crate::compound_git_paths;
use crate::local_authority_integrity_op;

const SCHEMA: &str = "codex-hook-authority-record.v1";
const MAX_REQUEST_BYTES: u64 = 64 * 1024 * 1024;
const MAX_KEY_BYTES: usize = 1024;
const MAX_SNAPSHOT: usize = 4 * 1024 * 1024;
const REVIEW_SECONDS: f64 = 300.0;
// Canonical JSON preserves each timestamp; subtracting the loaded values can
// exceed the signed window by a few ulps.
const REVIEW_TIMESTAMP_SLACK_SECONDS: f64 = 1e-6;
const REPAIR_PLAN_SCHEMA: &str = "hol-guard.codex-authority-repair-plan.v1";
const REPAIR_ACTION: &str = "apps.repair.codex-authority";
const AUTHENTICATION_FIELDS: [&str; 5] = [
    "integrity_version",
    "payload_hash",
    "payload_mac",
    "integrity_key_id",
    "signed_at",
];
const RECEIPT_FIELDS: [&str; 7] = [
    "schema",
    "guard_home",
    "config_path",
    "installation_id",
    "config_sha256",
    "manifest",
    "authentication",
];
const REQUEST_FIELDS: [&str; 9] = [
    "schema",
    "guard_home",
    "config_path",
    "installation_id",
    "created_monotonic",
    "expires_monotonic",
    "plan",
    "subject",
    "authentication",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Recovery,
    Receipt,
    RepairRequest,
    InverseRequest,
}

impl Kind {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "recovery" => Some(Self::Recovery),
            "receipt" => Some(Self::Receipt),
            "repair_request" => Some(Self::RepairRequest),
            "inverse_request" => Some(Self::InverseRequest),
            _ => None,
        }
    }

    fn schema(self) -> &'static str {
        match self {
            Self::Recovery => "hol-guard.codex-hook-recovery.v1",
            Self::Receipt => "hol-guard.codex-hook-authority-receipt.v1",
            Self::RepairRequest => "hol-guard.codex-authority-repair-request.v1",
            Self::InverseRequest => "hol-guard.codex-publication-inverse-request.v1",
        }
    }

    fn purpose(self) -> &'static str {
        match self {
            Self::Recovery => "codex-hook-publication-inverse",
            Self::Receipt => "codex-hook-authority-receipt",
            Self::RepairRequest => "codex-authority-repair-request",
            Self::InverseRequest => "codex-publication-inverse-request",
        }
    }

    fn max_bytes(self) -> usize {
        match self {
            Self::Recovery => 24 * 1024 * 1024,
            Self::Receipt => MAX_SNAPSHOT,
            Self::RepairRequest | Self::InverseRequest => 8 * 1024 * 1024,
        }
    }

    fn too_large(self) -> &'static str {
        match self {
            Self::Recovery => "record_too_large",
            Self::Receipt => "snapshot_too_large",
            Self::RepairRequest | Self::InverseRequest => "too_large",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    kind: Option<String>,
    key_hex: Option<String>,
    key_home: Option<String>,
    key_id: Option<String>,
    installation_id: Option<String>,
    payload: Option<Map<String, Value>>,
    signed_at: Option<String>,
    text: Option<String>,
    path: Option<String>,
    guard_home: Option<String>,
    config_path: Option<String>,
    #[serde(default)]
    live_config_conflict: bool,
    now_monotonic: Option<f64>,
    proof: Option<Map<String, Value>>,
    manifest: Option<Map<String, Value>>,
    spec: Option<Map<String, Value>>,
    package_roots: Option<Vec<String>>,
}

struct Secret {
    key: zeroize::Zeroizing<Vec<u8>>,
    key_id: String,
    installation_id: String,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "codex-hook-authority-record"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "codex_hook_authority_record_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("codex_hook_authority_record_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    Ok(answer(&request)?.to_string().into_bytes())
}

/// One request from inside the runtime, as `run_command` would read it.
pub(crate) fn ask(request: Value) -> Result<Value, String> {
    answer(&serde_json::from_value(request).map_err(|_| invalid())?)
}

fn answer(request: &Request) -> Result<Value, String> {
    if request.schema != SCHEMA {
        return Err(invalid());
    }
    Ok(match request.op.as_str() {
        "seal" => seal(request)?,
        "open" => open(request)?,
        "receipt_manifest" => receipt_manifest(request)?,
        "manifest_build" => match secret(request)? {
            Ok(held) => crate::codex_hook_manifest_build::answer(
                request.spec.as_ref().ok_or_else(invalid)?,
                request.manifest.as_ref(),
                request.package_roots.as_deref().unwrap_or_default(),
                &held.key,
                (&held.key_id, &held.installation_id),
            ),
            Err(reason) => refused(reason),
        },
        "manifest_load" | "manifest_authenticate" => manifest_answer(request)?,
        op @ ("key_identity" | "key_ensure" | "key_remove_if_unused") => {
            let guard_home = request.guard_home.as_deref().ok_or_else(invalid)?;
            codex_hook_key::answer(op, guard_home).ok_or_else(invalid)?
        }
        "repair_proof" => {
            let payload = request.payload.as_ref().ok_or_else(invalid)?;
            let proof = request.proof.as_ref().ok_or_else(invalid)?;
            match repair_proof_matches(payload, proof) {
                Ok(matches) => json!({"matches": matches}),
                Err(reason) => refused(reason),
            }
        }
        _ => return Err(invalid()),
    })
}

/// `load_authenticated_hook_manifest_path` (`path`) or
/// `authenticate_hook_manifest_text` (`text`, optionally under one key).
fn manifest_answer(request: &Request) -> Result<Value, String> {
    let guard_home = request.guard_home.as_deref().ok_or_else(invalid)?;
    let manifest = if request.op == "manifest_load" {
        let path = request.path.as_deref().ok_or_else(invalid)?;
        codex_hook_manifest_auth::load_path(guard_home, Path::new(path))
    } else {
        let text = request.text.as_deref().ok_or_else(invalid)?;
        codex_hook_manifest_auth::authenticate_text(
            guard_home,
            text,
            request.key_id.as_deref(),
            request.installation_id.as_deref(),
        )
    };
    Ok(match manifest {
        Ok(manifest) => json!({"manifest": manifest}),
        Err(reason) => refused(reason),
    })
}

fn invalid() -> String {
    "codex_hook_authority_record_request_invalid".to_owned()
}

fn refused(reason: &str) -> Value {
    json!({"error": reason})
}

fn kind(request: &Request) -> Result<Kind, String> {
    request
        .kind
        .as_deref()
        .and_then(Kind::parse)
        .ok_or_else(invalid)
}

/// The signing key: read from `key_home` by the runtime itself, or (for
/// older callers) passed as `key_hex`. A key the runtime cannot read, or
/// whose ids differ from the caller's, is a refusal with its reason.
fn secret(request: &Request) -> Result<Result<Secret, &'static str>, String> {
    let key_id = request.key_id.clone().ok_or_else(invalid)?;
    let installation_id = request.installation_id.clone().ok_or_else(invalid)?;
    let key = match (request.key_hex.as_deref(), request.key_home.as_deref()) {
        (Some(text), None) if text.len() <= MAX_KEY_BYTES * 2 => {
            zeroize::Zeroizing::new(hex::decode(text).map_err(|_| invalid())?)
        }
        (None, Some(home)) => {
            match codex_hook_key::read_matching(home, Some(&key_id), Some(&installation_id)) {
                Ok(held) => held.key,
                Err(reason) => return Ok(Err(reason)),
            }
        }
        _ => return Err(invalid()),
    };
    Ok(Ok(Secret {
        key,
        key_id,
        installation_id,
    }))
}

/// Sign `payload` and answer the record's exact bytes.
fn seal(request: &Request) -> Result<Value, String> {
    let kind = kind(request)?;
    let secret = match secret(request)? {
        Ok(secret) => secret,
        Err(reason) => return Ok(refused(reason)),
    };
    let mut payload = request.payload.clone().ok_or_else(invalid)?;
    if payload.contains_key("authentication")
        || text(payload.get("schema")) != Some(kind.schema())
        || text(payload.get("installation_id")) != Some(secret.installation_id.as_str())
    {
        return Err(invalid());
    }
    let signed_at = match kind {
        // A receipt is bound to the exact manifest it retains.
        Kind::Receipt => {
            if request.signed_at.is_some()
                || !keys_are(&payload, &RECEIPT_FIELDS[..RECEIPT_FIELDS.len() - 1])
            {
                return Err(invalid());
            }
            match decode(payload.get("manifest")) {
                Ok(Some(manifest)) => sha256_hex(&manifest),
                Ok(None) => return Err(invalid()),
                Err(reason) => return Ok(refused(reason)),
            }
        }
        _ => request.signed_at.clone().ok_or_else(invalid)?,
    };
    if kind == Kind::Recovery {
        if payload.contains_key("repair_plan") {
            if let Err(reason) = validate_repair_record(&payload) {
                return Ok(refused(reason));
            }
        } else if payload.contains_key("repair_publication_monotonic") {
            return Ok(refused("repair_record_invalid"));
        }
    }
    let signed = Value::Object(payload.clone());
    let fields = sign_local_authority_payload(
        &signed,
        &secret.key,
        &secret.key_id,
        kind.purpose(),
        &signed_at,
    )
    .map_err(str::to_owned)?;
    payload.insert(
        "authentication".to_owned(),
        json!({
            "integrity_version": fields.integrity_version,
            "payload_hash": fields.payload_hash,
            "payload_mac": fields.payload_mac,
            "integrity_key_id": fields.integrity_key_id,
            "signed_at": fields.signed_at,
        }),
    );
    let mut bytes = python_canonical_json(&Value::Object(payload)).ok_or_else(invalid)?;
    bytes.push('\n');
    if bytes.len() > kind.max_bytes() {
        return Ok(refused(kind.too_large()));
    }
    Ok(json!({"text": bytes}))
}

/// Authenticate a record against the context the caller expects.
fn open(request: &Request) -> Result<Value, String> {
    let kind = kind(request)?;
    let secret = match secret(request)? {
        Ok(secret) => secret,
        Err(reason) => return Ok(refused(reason)),
    };
    let raw = request.text.as_deref().ok_or_else(invalid)?;
    let guard_home = request.guard_home.as_deref().ok_or_else(invalid)?;
    let outcome = match kind {
        Kind::Recovery => open_recovery(raw, guard_home, request.live_config_conflict, &secret),
        Kind::Receipt => {
            let config = request.config_path.as_deref().ok_or_else(invalid)?;
            open_receipt(raw, guard_home, config, &secret)
        }
        Kind::RepairRequest | Kind::InverseRequest => {
            let config = request.config_path.as_deref().ok_or_else(invalid)?;
            let now = request.now_monotonic.ok_or_else(invalid)?;
            open_request(kind, raw, guard_home, config, now, &secret)
        }
    };
    Ok(match outcome {
        Ok((payload, signed_at)) => json!({"payload": payload, "signed_at": signed_at}),
        Err(reason) => refused(reason),
    })
}

/// An authenticated manifest must describe the receipt's own global config.
fn receipt_manifest(request: &Request) -> Result<Value, String> {
    let manifest = request.manifest.as_ref().ok_or_else(invalid)?;
    let installation_id = request.installation_id.as_deref().ok_or_else(invalid)?;
    let guard_home = request.guard_home.as_deref().ok_or_else(invalid)?;
    let config_path = request.config_path.as_deref().ok_or_else(invalid)?;
    let config = manifest.get("config").and_then(Value::as_object);
    let context = manifest.get("context").and_then(Value::as_object);
    let matches = text(manifest.get("harness")) == Some("codex")
        && text(manifest.get("installation_id")) == Some(installation_id)
        && config.is_some_and(|config| {
            text(config.get("scope")) == Some("global")
                && text(config.get("target")) == Some(config_path)
        })
        && context.is_some_and(|context| text(context.get("guard_home")) == Some(guard_home));
    Ok(if matches {
        json!({"ok": true})
    } else {
        refused("receipt_context_invalid")
    })
}

/// What a repair publication record must hold before and after its commit.
fn validate_repair_record(payload: &Map<String, Value>) -> Result<(), &'static str> {
    let plan = payload.get("repair_plan").and_then(Value::as_object);
    let valid = plan.is_some_and(|plan| {
        text(plan.get("schema")) == Some(REPAIR_PLAN_SCHEMA)
            && text(plan.get("action")) == Some(REPAIR_ACTION)
            && plan.get("guard_home") == payload.get("guard_home")
            && plan.get("config_path") == payload.get("config_path")
    }) && matches!(text(payload.get("phase")), Some("prepared" | "committed"))
        && payload.get("key_created") == Some(&Value::Bool(false))
        && matches!(payload.get("before_manifest"), None | Some(Value::Null))
        && matches!(payload.get("after_manifest"), Some(Value::String(_)))
        && matches!(payload.get("after_receipt"), Some(Value::String(_)))
        && payload.get("before_config") == payload.get("after_config")
        && payload.get("before_receipt") == payload.get("after_receipt")
        && real(payload.get("repair_publication_monotonic")).is_some_and(|time| time > 0.0);
    if !valid {
        return Err("repair_record_invalid");
    }
    if text(payload.get("phase")) == Some("committed") {
        match payload
            .get("native_verification")
            .and_then(Value::as_object)
        {
            Some(proof) if repair_proof_matches(payload, proof)? => {}
            _ => return Err("repair_record_invalid"),
        }
    } else if payload.contains_key("native_verification") {
        return Err("repair_record_invalid");
    }
    Ok(())
}

/// A native admission proof that saw exactly the published repair, after it.
fn repair_proof_matches(
    payload: &Map<String, Value>,
    proof: &Map<String, Value>,
) -> Result<bool, &'static str> {
    let Some(plan) = payload.get("repair_plan").and_then(Value::as_object) else {
        return Ok(false);
    };
    if !matches!(plan.get("native_runtime"), Some(Value::Object(_))) {
        return Ok(false);
    }
    let config = decode(payload.get("after_config"))?;
    let manifest = decode(payload.get("after_manifest"))?;
    let (Some(config), Some(manifest)) = (config, manifest) else {
        return Ok(false);
    };
    let Some(evidence) = proof
        .get("installed_hook_evidence")
        .and_then(Value::as_object)
    else {
        return Ok(false);
    };
    let Some(plan_bytes) = python_canonical_json(&Value::Object(plan.clone())) else {
        return Ok(false);
    };
    let generation = format!(
        "codex-authority-repair-{}",
        sha256_hex(plan_bytes.as_bytes())
    );
    let (Some(observed), Some(published)) = (
        real(proof.get("observed_monotonic")),
        real(payload.get("repair_publication_monotonic")),
    ) else {
        return Ok(false);
    };
    Ok(
        text(proof.get("schema")) == Some("hol-guard.native-protection-admission.v1")
            && proof.get("operation_id") == plan.get("operation_id")
            && text(proof.get("generation")) == Some(generation.as_str())
            && proof.get("guard_home") == payload.get("guard_home")
            && proof.get("runtime_identity") == plan.get("native_runtime")
            && text(evidence.get("harness")) == Some("codex")
            && text(evidence.get("config_sha256")) == Some(sha256_hex(&config).as_str())
            && text(evidence.get("manifest_sha256")) == Some(sha256_hex(&manifest).as_str())
            && observed >= published,
    )
}

#[cfg(test)]
#[path = "codex_hook_authority_record_tests.rs"]
mod tests;

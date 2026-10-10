//! `ApprovalReuseDiagnostic` — resident op that explains a saved-allow miss.
//!
//! Read-only: it walks the bounded near-match probes and names the first
//! reason a row could not authorize the request. A near match never grants
//! anything. Integrity evidence (state and keys) lives behind the OS keyring,
//! so when verification is needed the first reply is a `need` and the caller
//! repeats the identical request with the evidence attached.

use guard_contracts::{
    ApprovalReuseDiagnosticEvidenceV1, ApprovalReuseDiagnosticRequestV1,
    ApprovalReuseDiagnosticResultV1, APPROVAL_REUSE_DIAGNOSTIC_REQUEST_SCHEMA,
    APPROVAL_REUSE_DIAGNOSTIC_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use guard_policy_snapshot::policy_integrity::is_remote_policy_source;
use serde_json::{json, Value};

use super::context_digest_json::write_canonical_json_with_limit;
use crate::approval_reuse_diagnostic_probes::{local_rows, policy_rows};
use crate::policy_decision_lookup_op::{
    artifact_family_key, policy_integrity_result_for_row, verify_local_once, workspace_policy_key,
};

const CONTEXT_TOKEN_PREFIX: &str = "guard-approval-context:v1:";
const DEGRADED_REASONS_ALLOWED: [&str; 3] = [
    "system_keyring_unavailable",
    "policy_integrity_key_unavailable",
    "policy_integrity_control_unavailable",
];

fn request_digest(request: &ApprovalReuseDiagnosticRequestV1) -> Result<String, &'static str> {
    let material =
        serde_json::to_value(request).map_err(|_| "native_approval_reuse_diagnostic_invalid")?;
    let mut bytes = Vec::new();
    write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| "native_approval_reuse_diagnostic_invalid")?;
    Ok(format!("sha256:{}", digest_bytes(&bytes)))
}

pub(crate) fn evaluate_approval_reuse_diagnostic_request(
    request: &ApprovalReuseDiagnosticRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request).map_err(str::to_owned)?;
    let (status, code, payload) = match evaluate(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code, None),
    };
    let result = ApprovalReuseDiagnosticResultV1 {
        schema: APPROVAL_REUSE_DIAGNOSTIC_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    };
    crate::encode_response(&result)
}

fn decode_key(encoded: Option<&str>) -> Option<Vec<u8>> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::decode_vec(encoded?).ok()
}

fn text(row: &Value, key: &str) -> Option<String> {
    match row.get(key)? {
        Value::Null => None,
        Value::String(value) => Some(value.clone()),
        other => Some(other.to_string()),
    }
}

/// `_warn_only_policy_integrity_status`: only a warn-enforcement approval-gate
/// row may proceed past a failed integrity check, and only for missing
/// integrity or a degraded mode wholly explained by unavailable local trust.
fn warn_only_policy_integrity_status(status: &str, state: &Value, source: &str) -> bool {
    if state.get("enforcement").and_then(Value::as_str) != Some("warn") || source != "approval-gate"
    {
        return false;
    }
    if status == "missing_integrity" {
        return true;
    }
    if status != "degraded_mode" {
        return false;
    }
    match state.get("degraded_reasons").and_then(Value::as_array) {
        Some(reasons) if !reasons.is_empty() => reasons.iter().all(|reason| {
            reason
                .as_str()
                .is_some_and(|r| DEGRADED_REASONS_ALLOWED.contains(&r))
        }),
        _ => false,
    }
}

struct Context<'a> {
    request: &'a ApprovalReuseDiagnosticRequestV1,
    now: String,
    family: Option<String>,
    workspace_key: Option<String>,
    state: Value,
    policy_key: Option<Vec<u8>>,
}

fn evaluate(request: &ApprovalReuseDiagnosticRequestV1) -> Result<Value, String> {
    if request.schema != APPROVAL_REUSE_DIAGNOSTIC_REQUEST_SCHEMA {
        return Err("native_approval_reuse_diagnostic_schema_mismatch".to_owned());
    }
    let now = guard_contracts::canonical_utc_timestamp(&request.now)
        .ok_or_else(|| "native_approval_reuse_diagnostic_invalid".to_owned())?;
    let connection = rusqlite::Connection::open_with_flags(
        &request.store_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|_| "native_approval_reuse_diagnostic_store_unavailable".to_owned())?;
    connection
        .busy_timeout(std::time::Duration::from_millis(5000))
        .map_err(|_| "native_approval_reuse_diagnostic_store_unavailable".to_owned())?;
    diagnose(&connection, request, now)
}

/// Probe the store and name the first reason a near match did not authorize.
pub(crate) fn diagnose(
    connection: &rusqlite::Connection,
    request: &ApprovalReuseDiagnosticRequestV1,
    now: String,
) -> Result<Value, String> {
    let family = artifact_family_key(Some(&request.artifact_id));
    let (harness, artifact_id) = (request.harness.as_str(), request.artifact_id.as_str());
    let store_error = |_| "native_approval_reuse_diagnostic_store_error".to_owned();
    let local = local_rows(
        connection,
        harness,
        artifact_id,
        family.as_deref(),
        request.artifact_hash.as_deref(),
    )
    .map_err(store_error)?;
    let policy = policy_rows(
        connection,
        harness,
        artifact_id,
        family.as_deref(),
        request.artifact_hash.as_deref(),
        request.publisher.as_deref(),
    )
    .map_err(store_error)?;
    let needs_policy = policy
        .iter()
        .any(|row| !is_remote_policy_source(text(row, "source").as_deref()));
    let needs_local = !local.is_empty();
    let evidence = match (&request.evidence, needs_policy || needs_local) {
        (None, true) => {
            return Ok(json!({
                "need": "integrity_evidence",
                "policy": needs_policy,
                "local_once": needs_local,
            }));
        }
        (Some(evidence), _) => evidence.clone(),
        (None, false) => ApprovalReuseDiagnosticEvidenceV1::default(),
    };
    let context = Context {
        request,
        now,
        family,
        workspace_key: workspace_policy_key(request.workspace.as_deref()),
        state: evidence
            .integrity_state
            .clone()
            .unwrap_or_else(|| json!({})),
        policy_key: decode_key(evidence.integrity_key_b64.as_deref()),
    };
    let local_key = decode_key(evidence.local_once_integrity_key_b64.as_deref());
    if let Some(failure) = local_integrity_failure(
        &local,
        local_key.as_deref(),
        evidence.local_once_integrity_key_id.as_deref(),
    ) {
        return Ok(failure);
    }
    let policy_key_id = evidence.integrity_key_id.as_deref();
    for row in local.iter().chain(policy.iter()) {
        if let Some((reason, hash)) = diagnose_row(&context, row, policy_key_id) {
            return Ok(json!({"reason": reason, "stored_hash": hash}));
        }
    }
    Ok(json!({"reason": null, "stored_hash": null}))
}

fn local_integrity_failure(
    local: &[Value],
    key: Option<&[u8]>,
    key_id: Option<&str>,
) -> Option<Value> {
    for row in local {
        let valid = verify_local_once(row, key, key_id).status == "valid";
        if !valid || row.get("authority_kind").is_none_or(Value::is_null) {
            return Some(json!({
                "reason": "approval_reuse_integrity_failure",
                "stored_hash": text(row, "artifact_hash"),
            }));
        }
    }
    None
}

/// The first reason `row` could not authorize the request, with its stored
/// hash, or `None` when the row is unrelated.
fn diagnose_row(
    ctx: &Context<'_>,
    row: &Value,
    policy_key_id: Option<&str>,
) -> Option<(String, Option<String>)> {
    let request = ctx.request;
    if row
        .get("claimed_at")
        .is_some_and(|claimed| !claimed.is_null())
    {
        return None;
    }
    let stored_id = text(row, "artifact_id");
    let stored_hash = text(row, "artifact_hash");
    let artifact_hash = request.artifact_hash.as_deref();
    let same_identity = stored_id
        .as_deref()
        .is_some_and(|id| id == request.artifact_id || Some(id) == ctx.family.as_deref());
    let same_content = artifact_hash.is_some() && stored_hash.as_deref() == artifact_hash;
    let scope = text(row, "scope");
    let broad_scope = matches!(scope.as_deref(), Some("harness" | "global"));
    let publisher_scope = scope.as_deref() == Some("publisher")
        && text(row, "publisher").is_some_and(|p| Some(p.as_str()) == request.publisher.as_deref());
    if !(same_identity || same_content || publisher_scope || (broad_scope && stored_id.is_none())) {
        return None;
    }
    let hash = || stored_hash.clone();
    let source = text(row, "source").unwrap_or_default();
    if row.get("decision_id").is_some() && !is_remote_policy_source(Some(&source)) {
        let mode = ctx
            .state
            .get("mode")
            .and_then(Value::as_str)
            .filter(|mode| !mode.is_empty())
            .unwrap_or("degraded");
        let generation = match ctx.state.get("generation") {
            Some(Value::Number(number)) if !number.is_f64() => number.as_i64(),
            _ => None,
        };
        let result = policy_integrity_result_for_row(
            row,
            mode,
            ctx.policy_key.as_deref(),
            policy_key_id,
            generation,
        );
        if result.status != "valid"
            && !warn_only_policy_integrity_status(result.status, &ctx.state, &source)
        {
            return Some(("approval_reuse_integrity_failure".to_owned(), hash()));
        }
    }
    if text(row, "expires_at")
        .is_some_and(|expires| guard_contracts::timestamp_has_expired(&expires, &ctx.now))
    {
        return Some(("approval_reuse_expired".to_owned(), hash()));
    }
    let is_token = |value: Option<&str>| value.is_some_and(|v| v.starts_with(CONTEXT_TOKEN_PREFIX));
    if is_token(stored_hash.as_deref()) || is_token(artifact_hash) {
        let saved = stored_hash.clone().map_or(Value::Null, Value::String);
        let current = artifact_hash.map_or(Value::Null, |h| Value::String(h.to_owned()));
        if let Some(reason) = crate::context_digest::validate_context_tokens(&saved, &current) {
            return Some((reason, hash()));
        }
    }
    if let (Some(stored), Some(current)) = (stored_hash.as_deref(), artifact_hash) {
        if stored != current {
            return Some(("approval_reuse_content_changed".to_owned(), hash()));
        }
    }
    let workspace_changed = text(row, "workspace").is_some_and(|stored| {
        Some(stored.as_str()) != request.workspace.as_deref()
            && Some(stored.as_str()) != ctx.workspace_key.as_deref()
    });
    let publisher_changed = text(row, "publisher")
        .is_some_and(|stored| Some(stored.as_str()) != request.publisher.as_deref());
    if workspace_changed || publisher_changed || !same_identity {
        return Some(("approval_reuse_identity_changed".to_owned(), hash()));
    }
    None
}

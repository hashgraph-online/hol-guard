//! `PolicyDecisionLookup` — native port of
//! `StorePolicyMixin.resolve_policy_decision_lookup`.
//!
//! Rust owns the `policy_decisions` select, eligibility, integrity verify,
//! precedence ordering, `guard_events` insert, and one-shot
//! `guard_local_once_approvals` claim. Python ships the pre-op `integrity_state`
//! snapshot + `local_once_*`/`policy_integrity_*` key material as request DTOs
//! (secret procurement stays Python-side because it requires
//! `EncryptedFileSecretStore`), plus `policy_bundle_decision_identities` (needs
//! the synced bundle + device metadata Rust cannot read) and `now` (the caller's
//! `_canonical_utc_timestamp`-normalized lookup timestamp).
//!
//! Parity contract: row selection, integrity-result status, event payload
//! bytes, and the `PolicyDecisionLookupResultV1.payload` `lookup_result` dict
//! must match Python byte-for-byte.

use rusqlite::{params, params_from_iter, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use guard_command::action_lattice::guard_action_severity;
use guard_command::effect_decision::GuardAction;
use guard_contracts::{
    canonical_utc_timestamp, PolicyDecisionLookupRequestV1, PolicyDecisionLookupResultV1,
    POLICY_DECISION_LOOKUP_REQUEST_SCHEMA, POLICY_DECISION_LOOKUP_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use guard_policy_snapshot::local_authority_integrity::{
    sign_local_authority_payload, verify_local_authority_payload, LocalAuthorityVerification,
};
use guard_policy_snapshot::policy_integrity::{
    is_remote_policy_source, verify_local_policy_row, PolicyIntegrityVerification,
};

use super::context_digest_json::write_canonical_json_with_limit;
use crate::claim_reuse::approval_authority_revision;

const LOCAL_ONCE_LEGACY_AUTHORITY_KIND: &str = "legacy";
const LOCAL_ONCE_INTEGRITY_PURPOSE: &str = "guard-local-once-approval";
const NON_CONSUMING_POLICY_MATCH_LIMIT: i64 = 256;
const POLICY_LOOKUP_COLUMNS: &str = "decision_id, harness, scope, artifact_id, action, \
     artifact_hash, workspace, publisher, source, reason, owner, expires_at, updated_at, \
     integrity_version, integrity_generation, payload_hash, payload_mac, integrity_key_id, \
     signed_at";
const LOCAL_ONCE_CLAIM_COLUMNS: &str = "approval_id, request_id, harness, artifact_id, \
     artifact_hash, workspace, publisher, action, created_at, expires_at, claimed_at, \
     integrity_version, payload_hash, payload_mac, integrity_key_id, signed_at, \
     authority_kind";
const APPROVAL_GATE_POLICY_SOURCE: &str = "approval-gate";
const APPROVAL_CONTEXT_SQL_PATTERN: &str = "guard-approval-context:v1:%";
const RUNTIME_SCOPED_EXACT_MATCH_PREFIX: &str = "runtime-exact:";
const POLICY_BUNDLE_SOURCE: &str = "policy-bundle";

/// `_SCOPED_RUNTIME_EXACT_FAMILIES` (`store_base.py:317`) — the 5 families that
/// get a runtime exact-match key. `mcp`/`prompt-env-read`/`prompt-file` are
/// approval families but *not* runtime-exact: they intentionally produce no
/// key so a `family:mcp` allow row still resolves a concrete `*:mcp:*` lookup.
const SCOPED_RUNTIME_EXACT_FAMILIES: [&str; 5] = [
    "file-read",
    "mcp-tool",
    "package-request",
    "prompt",
    "tool-action",
];

/// `_SCOPED_APPROVAL_FAMILIES` (`approval_scope_support.py:25`) — the broader
/// set a scoped artifact may collapse to. `parts[2]` of `harness:scope:family:…`
/// only becomes a family key when it's an approval family; otherwise unrelated
/// namespaces would shadow family-scoped rows.
const SCOPED_APPROVAL_FAMILIES: [&str; 8] = [
    "file-read",
    "mcp",
    "mcp-tool",
    "package-request",
    "prompt",
    "prompt-env-read",
    "prompt-file",
    "tool-action",
];

/// `_artifact_family_key` (`approval_scope_support.py`): `family:`-prefixed
/// ids pass through verbatim (already canonical); otherwise the family is
/// `parts[2]` of `harness:scope:family:…`, lower-cased, gated by the scoped
/// approval families so unrelated namespaces never collapse to a family key.
fn artifact_family_key(artifact_id: Option<&str>) -> Option<String> {
    let id = artifact_id?.trim();
    if id.is_empty() {
        return None;
    }
    if let Some(rest) = id.strip_prefix("family:") {
        let family = rest.trim().to_lowercase();
        return SCOPED_APPROVAL_FAMILIES
            .contains(&family.as_str())
            .then(|| format!("family:{family}"));
    }
    let parts: Vec<&str> = id.split(':').collect();
    if parts.len() < 3 {
        return None;
    }
    let family = parts[2].trim().to_lowercase();
    SCOPED_APPROVAL_FAMILIES
        .contains(&family.as_str())
        .then(|| format!("family:{family}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// `json.dumps(..., sort_keys=True, separators=(",", ":"))`.
/// serde_json `Map` is BTreeMap-backed → keys sorted; compact writer matches.
fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

fn row_value(row: &Value, key: &str) -> Value {
    row.get(key).cloned().unwrap_or(Value::Null)
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::decode_vec(s).ok()
}

/// `_normalized_workspace_path` (`store_base.py`): strip, `\`→`/`, trim
/// trailing `/`, lowercase a `X:` drive prefix.
fn normalized_workspace_path(value: &str) -> String {
    let mut normalized = value.trim().replace('\\', "/");
    while normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }
    if normalized.len() >= 2 && normalized.as_bytes()[1] == b':' {
        normalized = normalized.to_lowercase();
    }
    normalized
}

/// `_workspace_policy_key` (`store_base.py`) — `"workspace:" +
/// sha256(normalized).hexdigest()`, full 64-hex digest. An already-keyed
/// input (`workspace:<hex>`) is returned unchanged so stored rows match.
fn workspace_policy_key(workspace: Option<&str>) -> Option<String> {
    let ws = workspace?;
    if ws.trim().is_empty() {
        return None;
    }
    if ws.starts_with("workspace:") {
        return Some(ws.to_string());
    }
    Some(format!(
        "workspace:{}",
        sha256_hex(normalized_workspace_path(ws).as_bytes())
    ))
}

fn family_key_value(family_key: &str) -> &str {
    family_key.strip_prefix("family:").unwrap_or(family_key)
}

/// `_runtime_scoped_exact_match_key` — `runtime-exact:<digest>`; `None` unless
/// the artifact is a scoped family member.
fn runtime_scoped_exact_match_key(
    artifact_id: Option<&str>,
    runtime_exact_match_context: Option<&str>,
) -> Option<String> {
    let id = artifact_id?.trim();
    if id.is_empty() || id.starts_with("family:") {
        return None;
    }
    let family_key = artifact_family_key(Some(id))?;
    if !SCOPED_RUNTIME_EXACT_FAMILIES.contains(&family_key_value(&family_key)) {
        return None;
    }
    let digest = match runtime_exact_match_context {
        None => sha256_hex(id.as_bytes()),
        Some(ctx) => sha256_hex(
            canonical_json(&json!({
                "artifact_id": id,
                "context": ctx,
                "version": 2,
            }))
            .as_bytes(),
        ),
    };
    Some(format!("{RUNTIME_SCOPED_EXACT_MATCH_PREFIX}{digest}"))
}

/// `runtime_tool_action_portable_match_context` — portable context form.
/// `runtime_tool_action_portable_match_context` (`store_base.py:1490`) — strip
/// `config_path`/`source_scope` (project-location fields) so a `harness`/`global`
/// broad rule matches the identical executable action across workspaces. Parses
/// the runtime exact-match context JSON, requires `raw_command_text`, and rebuilds
/// the canonical context payload with the location fields nulled.
fn runtime_tool_action_portable_match_context(ctx: Option<&str>) -> Option<String> {
    let ctx = ctx?;
    let payload: Value = serde_json::from_str(ctx).ok()?;
    let payload = payload.as_object()?;
    let raw_command_text = payload.get("raw_command_text")?.as_str()?;
    if raw_command_text.is_empty() {
        return None;
    }
    let wrapper_chain = payload
        .get("wrapper_chain")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .filter(|item| !item.is_empty())
                .map(|item| json!(item))
                .collect::<Vec<_>>()
        });
    let permission_mode = payload
        .get("permission_mode")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());
    let context = json!({
        "config_path": null,
        "source_scope": null,
        "raw_command_text": raw_command_text,
        "wrapper_chain": wrapper_chain.unwrap_or_default(),
        "permission_mode": permission_mode,
    });
    Some(canonical_json(&context))
}

/// `_global_runtime_scoped_exact_match_key`.
fn global_runtime_scoped_exact_match_key(
    artifact_id: Option<&str>,
    runtime_exact_match_context: Option<&str>,
) -> Option<String> {
    let id = artifact_id?;
    let family_key = artifact_family_key(Some(id))?;
    let family = family_key_value(&family_key);
    if !SCOPED_RUNTIME_EXACT_FAMILIES.contains(&family) {
        return None;
    }
    let canonical = format!("global:portable:{family}");
    runtime_scoped_exact_match_key(Some(&canonical), runtime_exact_match_context)
}

fn is_approval_context_token(value: &str) -> bool {
    value.starts_with("guard-approval-context:v1:")
}

/// `_is_approval_gate_one_shot_policy` — `approval-gate` + set `expires_at`.
fn is_approval_gate_one_shot_policy(row: &Value) -> bool {
    row_value(row, "source").as_str() == Some(APPROVAL_GATE_POLICY_SOURCE)
        && !row_value(row, "expires_at").is_null()
}

/// `_scoped_runtime_row_requires_exact_match` — a `harness`/`global` row whose
/// *stored* artifact carries a scoped family must be reached via an exact-match
/// key.
#[allow(clippy::too_many_arguments)]
fn scoped_runtime_row_requires_exact_match(
    scope: &str,
    stored_artifact_id: Option<&str>,
    stored_artifact_hash: Option<&str>,
    source: &str,
    requested_artifact_id: Option<&str>,
    requested_artifact_hash: Option<&str>,
    requested_runtime_exact_match_key: Option<&str>,
    requested_portable_exact_match_key: Option<&str>,
    requested_global_exact_match_key: Option<&str>,
) -> bool {
    if scope != "harness" && scope != "global" {
        return false;
    }
    if is_remote_policy_source(Some(source)) {
        return false;
    }
    let family_key = match stored_artifact_id.and_then(|id| artifact_family_key(Some(id))) {
        Some(f) => f,
        None => return false,
    };
    if !SCOPED_RUNTIME_EXACT_FAMILIES.contains(&family_key_value(&family_key)) {
        return false;
    }
    let mut expected: Vec<String> = Vec::new();
    if let Some(hash) = requested_artifact_hash {
        if is_approval_context_token(hash) {
            expected.push(hash.to_string());
        }
    }
    if let Some(k) = runtime_scoped_exact_match_key(requested_artifact_id, None) {
        expected.push(k);
    }
    for k in [
        requested_runtime_exact_match_key,
        requested_portable_exact_match_key,
        requested_global_exact_match_key,
    ]
    .into_iter()
    .flatten()
    {
        expected.push(k.to_string());
    }
    if expected.is_empty() {
        return true;
    }
    let stored = stored_artifact_hash.unwrap_or("");
    !expected.iter().any(|k| k == stored)
}

/// `_warn_only_policy_integrity_status`.
fn warn_only_policy_integrity_status(status: &str, state: &Value, source: &str) -> bool {
    if is_remote_policy_source(Some(source)) {
        return false;
    }
    if status == "valid" {
        return true;
    }
    let mode = state
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("degraded");
    matches!(mode, "degraded" | "warn" | "warn_only")
        && matches!(
            status,
            "unsigned" | "missing_integrity" | "unknown_key" | "untrusted_generation"
        )
}

/// `LOCAL_TRUST_DEGRADED_REASON_LABELS` — reason → user-safe label.
fn degraded_reason_label(reason: &str) -> &'static str {
    match reason {
        "system_keyring_unavailable" => "System credential store unavailable",
        "policy_integrity_key_unavailable" => "Local rule signing key unavailable",
        "policy_integrity_control_unavailable" => "Local rollback control unavailable",
        "guard_home_symlink" => "Guard home path is not trusted",
        "guard_db_symlink" => "Guard database path is not trusted",
        "guard_home_permissions" => "Guard home permissions are too broad",
        "guard_db_permissions" => "Guard database permissions are too broad",
        "guard_home_inaccessible" => "Guard home could not be inspected",
        "guard_db_inaccessible" => "Guard database could not be inspected",
        "trust_backend_timeout" => "Local trust backend timed out",
        "trust_backend_unavailable" => "Local trust backend unavailable",
        "trust_backend_permission_denied" => "Local trust backend permission denied",
        "trust_backend_corrupt" => "Local trust backend data could not be read",
        _ => "Guard trust check degraded",
    }
}

/// Whether a reason is a known `LOCAL_TRUST_DEGRADED_REASON_LABELS` key.
fn is_known_degraded_reason(reason: &str) -> bool {
    matches!(
        reason,
        "system_keyring_unavailable"
            | "policy_integrity_key_unavailable"
            | "policy_integrity_control_unavailable"
            | "guard_home_symlink"
            | "guard_db_symlink"
            | "guard_home_permissions"
            | "guard_db_permissions"
            | "guard_home_inaccessible"
            | "guard_db_inaccessible"
            | "trust_backend_timeout"
            | "trust_backend_unavailable"
            | "trust_backend_permission_denied"
            | "trust_backend_corrupt"
    )
}

/// `str(value or "unknown")` — Python truthiness + str() coercion for `backend`.
///
/// Python: `None`/empty/`0`/`False` all falsy → `"unknown"`; otherwise `str(v)`.
/// Numeric/array/object bodies use `Value::to_string()` (JSON repr), the closest
/// faithful rendering for a field that is a string in every real integrity-state.
fn py_str_or_unknown(value: Option<&Value>) -> Value {
    match value {
        None | Some(Value::Null) => json!("unknown"),
        Some(Value::String(s)) => {
            if s.is_empty() {
                json!("unknown")
            } else {
                json!(s)
            }
        }
        Some(Value::Bool(false)) => json!("unknown"),
        Some(Value::Bool(true)) => json!("True"),
        Some(v) => {
            if v.as_i64() == Some(0) || v.as_u64() == Some(0) || v.as_f64() == Some(0.0) {
                json!("unknown")
            } else {
                json!(v.to_string())
            }
        }
    }
}

/// `TrustStatus.from_policy_integrity_state(state).to_dict()` — exact port.
///
/// Output key order matches the Python `to_dict()` for parsed-equality parity:
/// `{runtime_protection, remembered_rules, cloud_policies, backend,
///   degraded_reasons, degraded_reason_labels, setup_available, last_proof}`.
fn trust_status_from_state(state: &Value) -> Value {
    let mode = state.get("mode").and_then(Value::as_str);
    let reasons: Vec<String> = state
        .get("degraded_reasons")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let mut runtime_protection = match mode {
        Some("protected") => "protected",
        Some("degraded") => "degraded",
        _ => "unknown",
    };
    let mut remembered_rules = match mode {
        Some("protected") => "enforced",
        Some("degraded") => "disabled_degraded",
        _ => "unknown",
    };
    let mut setup_available = state
        .get("setup_available")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !setup_available {
        setup_available = reasons.iter().any(|r| is_known_degraded_reason(r));
    }
    if let Some(o) = state.get("runtime_protection").and_then(Value::as_str) {
        if matches!(o, "protected" | "degraded" | "unknown") {
            runtime_protection = o;
        }
    }
    if let Some(o) = state.get("remembered_rules").and_then(Value::as_str) {
        if matches!(o, "enforced" | "disabled_degraded" | "unknown") {
            remembered_rules = o;
        }
    }
    let cloud_policies = match state.get("cloud_policies").and_then(Value::as_str) {
        Some(o) if matches!(o, "available" | "setup_unavailable" | "unknown") => o,
        _ if setup_available => "setup_unavailable",
        _ => "available",
    };
    let backend = py_str_or_unknown(state.get("backend"));
    let labels: serde_json::Map<String, Value> = reasons
        .iter()
        .map(|r| (r.clone(), json!(degraded_reason_label(r))))
        .collect();
    json!({
        "runtime_protection": runtime_protection,
        "remembered_rules": remembered_rules,
        "cloud_policies": cloud_policies,
        "backend": backend,
        "degraded_reasons": reasons,
        "degraded_reason_labels": labels,
        "setup_available": setup_available,
        "last_proof": Value::Null,
    })
}

/// `local_once_integrity_purpose`.
fn local_once_integrity_purpose(authority_kind: Option<&str>) -> String {
    match authority_kind {
        Some(kind) if !kind.is_empty() && kind != LOCAL_ONCE_LEGACY_AUTHORITY_KIND => {
            format!("{LOCAL_ONCE_INTEGRITY_PURPOSE}:{kind}")
        }
        _ => LOCAL_ONCE_INTEGRITY_PURPOSE.to_string(),
    }
}

fn value_or_null(cell: rusqlite::types::ValueRef<'_>) -> Value {
    use rusqlite::types::ValueRef;
    match cell {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => Value::from(i),
        ValueRef::Real(f) => Value::from(f),
        ValueRef::Text(t) => Value::from(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => Value::from(hex::encode(b)),
    }
}

/// Row → JSON for `POLICY_LOOKUP_COLUMNS` (19 cols).
fn policy_row_to_json(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    const COLS: [&str; 19] = [
        "decision_id",
        "harness",
        "scope",
        "artifact_id",
        "action",
        "artifact_hash",
        "workspace",
        "publisher",
        "source",
        "reason",
        "owner",
        "expires_at",
        "updated_at",
        "integrity_version",
        "integrity_generation",
        "payload_hash",
        "payload_mac",
        "integrity_key_id",
        "signed_at",
    ];
    let mut map = serde_json::Map::with_capacity(COLS.len());
    for (i, col) in COLS.iter().enumerate() {
        map.insert(col.to_string(), value_or_null(row.get_ref(i)?));
    }
    Ok(Value::Object(map))
}

/// Row → JSON for `LOCAL_ONCE_CLAIM_COLUMNS` (17 cols).
fn local_once_row_to_json(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    const COLS: [&str; 17] = [
        "approval_id",
        "request_id",
        "harness",
        "artifact_id",
        "artifact_hash",
        "workspace",
        "publisher",
        "action",
        "created_at",
        "expires_at",
        "claimed_at",
        "integrity_version",
        "payload_hash",
        "payload_mac",
        "integrity_key_id",
        "signed_at",
        "authority_kind",
    ];
    let mut map = serde_json::Map::with_capacity(COLS.len());
    for (i, col) in COLS.iter().enumerate() {
        map.insert(col.to_string(), value_or_null(row.get_ref(i)?));
    }
    Ok(Value::Object(map))
}

/// `_local_once_approval_signed_payload` — `authority_kind` appended when set.
fn local_once_signed_payload(row: &Value) -> Value {
    let mut payload = json!({
        "approval_id": row_value(row, "approval_id"),
        "request_id": row_value(row, "request_id"),
        "harness": row_value(row, "harness"),
        "artifact_id": row_value(row, "artifact_id"),
        "artifact_hash": row_value(row, "artifact_hash"),
        "workspace": row_value(row, "workspace"),
        "publisher": row_value(row, "publisher"),
        "action": row_value(row, "action"),
        "created_at": row_value(row, "created_at"),
        "expires_at": row_value(row, "expires_at"),
        "claimed_at": row_value(row, "claimed_at"),
    });
    if let (Value::Object(ref mut m), Value::String(ak)) =
        (&mut payload, row_value(row, "authority_kind"))
    {
        m.insert("authority_kind".into(), Value::from(ak.clone()));
    }
    payload
}

fn local_once_integrity(row: &Value) -> Value {
    json!({
        "integrity_version": row_value(row, "integrity_version"),
        "payload_hash": row_value(row, "payload_hash"),
        "payload_mac": row_value(row, "payload_mac"),
        "integrity_key_id": row_value(row, "integrity_key_id"),
        "signed_at": row_value(row, "signed_at"),
    })
}

/// `_local_once_approval_payload`.
fn local_once_approval_payload(row: &Value) -> Value {
    let mut payload = json!({
        "action": row_value(row, "action"),
        "approval_id": row_value(row, "approval_id"),
        "artifact_hash": row_value(row, "artifact_hash"),
        "artifact_id": row_value(row, "artifact_id"),
        "decision_id": Value::Null,
        "expires_at": row_value(row, "expires_at"),
        "harness": row_value(row, "harness"),
        "integrity_key_id": row_value(row, "integrity_key_id"),
        "integrity_status": "valid",
        "integrity_version": row_value(row, "integrity_version"),
        "owner": Value::Null,
        "publisher": row_value(row, "publisher"),
        "reason": "approved once in review",
        "request_id": row_value(row, "request_id"),
        "scope": "artifact",
        "source": "approval-gate-once",
        "fresh_local_approval": crate::approval_reuse::exact_artifact_approval_qualification(
            row, "approval-gate-once", true,
        ).0,
        "signed_at": row_value(row, "signed_at"),
        "updated_at": row_value(row, "created_at"),
        "workspace": row_value(row, "workspace"),
    });
    if let (Value::Object(ref mut m), Value::String(ak)) =
        (&mut payload, row_value(row, "authority_kind"))
    {
        m.insert("authority_kind".into(), Value::from(ak.clone()));
    }
    payload
}

/// `_local_once_approval_integrity_failure`.
fn local_once_integrity_failure(row: &Value, result: &LocalAuthorityVerification) -> Value {
    json!({
        "approval_id": row_value(row, "approval_id"),
        "decision_id": Value::Null,
        "harness": row_value(row, "harness"),
        "artifact_id": row_value(row, "artifact_id"),
        "scope": "artifact",
        "source": "approval-gate-once",
        "integrity_status": result.status,
        "integrity_message": result.message.map(Value::from).unwrap_or(Value::Null),
    })
}

/// `verify_local_once_approval` — purpose from `authority_kind`.
fn verify_local_once(
    row: &Value,
    key: Option<&[u8]>,
    key_id: Option<&str>,
) -> LocalAuthorityVerification {
    let authority_kind = row_value(row, "authority_kind");
    verify_local_authority_payload(
        &local_once_signed_payload(row),
        &local_once_integrity(row),
        key,
        key_id,
        &local_once_integrity_purpose(authority_kind.as_str()),
    )
}

/// `_peek_local_once_approval_lookup_locked` — single NULL-tolerant
/// exact-match query, `order by created_at desc limit 1`.
#[allow(clippy::too_many_arguments)]
fn peek_local_once_lookup(
    conn: &Connection,
    harness: &str,
    artifact_id: Option<&str>,
    artifact_hash: Option<&str>,
    workspace_key: Option<&str>,
    publisher: Option<&str>,
    now: &str,
    integrity_key: Option<&[u8]>,
    integrity_key_id: Option<&str>,
) -> rusqlite::Result<(Option<Value>, Option<Value>)> {
    if artifact_id.is_none() || artifact_hash.is_none() {
        return Ok((None, None));
    }
    let sql = format!(
        "select {LOCAL_ONCE_CLAIM_COLUMNS} from guard_local_once_approvals \
         where claimed_at is null and harness = ? and artifact_id = ? and artifact_hash = ? \
         and julianday(expires_at) > julianday(?) \
         and (workspace is null or workspace = ?) \
         and (publisher is null or publisher = ?) \
         and (authority_kind is null or authority_kind = ?) \
         order by created_at desc limit 1"
    );
    let row = conn
        .query_row(
            &sql,
            params![
                harness,
                artifact_id.unwrap_or(""),
                artifact_hash.unwrap_or(""),
                now,
                workspace_key,
                publisher,
                LOCAL_ONCE_LEGACY_AUTHORITY_KIND,
            ],
            local_once_row_to_json,
        )
        .optional()?;
    let row = match row {
        Some(r) => r,
        None => return Ok((None, None)),
    };
    let integrity_result = verify_local_once(&row, integrity_key, integrity_key_id);
    if integrity_result.status != "valid" {
        return Ok((
            None,
            Some(local_once_integrity_failure(&row, &integrity_result)),
        ));
    }
    if row_value(&row, "authority_kind").is_null() {
        let mut failure = local_once_integrity_failure(&row, &integrity_result);
        if let Value::Object(ref mut m) = failure {
            m.insert("integrity_status".into(), Value::from("ambiguous_legacy"));
            m.insert(
                "integrity_message".into(),
                Value::from("legacy_local_once_provenance_unknown"),
            );
        }
        return Ok((None, Some(failure)));
    }
    Ok((Some(local_once_approval_payload(&row)), None))
}

/// `_local_once_approval_is_reusable` — `":package-request:" in artifact_id`.
fn local_once_approval_is_reusable(artifact_id: &Value) -> bool {
    artifact_id
        .as_str()
        .map(|s| s.contains(":package-request:"))
        .unwrap_or(false)
}

/// `_claim_local_once_approval_lookup_locked` — peek then claim by id.
#[allow(clippy::too_many_arguments)]
fn claim_local_once_lookup(
    conn: &Connection,
    harness: &str,
    artifact_id: Option<&str>,
    artifact_hash: Option<&str>,
    workspace_key: Option<&str>,
    publisher: Option<&str>,
    now: &str,
    integrity_key: Option<&[u8]>,
    integrity_key_id: Option<&str>,
) -> rusqlite::Result<Option<Value>> {
    let (decision, _failure) = peek_local_once_lookup(
        conn,
        harness,
        artifact_id,
        artifact_hash,
        workspace_key,
        publisher,
        now,
        integrity_key,
        integrity_key_id,
    )?;
    match decision {
        None => Ok(None),
        Some(d) => {
            if local_once_approval_is_reusable(&row_value(&d, "artifact_id")) {
                Ok(Some(d))
            } else {
                match row_value(&d, "approval_id").as_str() {
                    Some(id) => claim_local_once_by_id(
                        conn,
                        id,
                        now,
                        integrity_key,
                        integrity_key_id,
                        true,
                        None,
                    ),
                    None => Ok(None),
                }
            }
        }
    }
}

/// `_claim_local_once_approval_by_id_locked` — re-select, verify, re-sign with
/// `claimed_at`, consume.
fn claim_local_once_by_id(
    conn: &Connection,
    approval_id: &str,
    now: &str,
    integrity_key: Option<&[u8]>,
    integrity_key_id: Option<&str>,
    consume: bool,
    expected: Option<&Value>,
) -> rusqlite::Result<Option<Value>> {
    let sql = format!(
        "select {LOCAL_ONCE_CLAIM_COLUMNS} from guard_local_once_approvals \
         where approval_id = ?1 and claimed_at is null \
         and julianday(expires_at) > julianday(?2)"
    );
    let row = conn
        .query_row(&sql, params![approval_id, now], local_once_row_to_json)
        .optional()?;
    let row = match row {
        Some(r) => r,
        None => return Ok(None),
    };
    if row_value(&row, "authority_kind").as_str() != Some(LOCAL_ONCE_LEGACY_AUTHORITY_KIND) {
        return Ok(None);
    }
    let integrity_result = verify_local_once(&row, integrity_key, integrity_key_id);
    if integrity_result.status != "valid" || integrity_key.is_none() || integrity_key_id.is_none() {
        return Ok(None);
    }
    let decision = local_once_approval_payload(&row);
    const IDENTITY_KEYS: [&str; 16] = [
        "action",
        "approval_id",
        "artifact_hash",
        "artifact_id",
        "expires_at",
        "harness",
        "integrity_key_id",
        "integrity_status",
        "integrity_version",
        "publisher",
        "request_id",
        "source",
        "signed_at",
        "updated_at",
        "workspace",
        "authority_kind",
    ];
    if expected.is_some_and(|expected| {
        IDENTITY_KEYS
            .iter()
            .any(|k| row_value(&decision, k) != row_value(expected, k))
    }) {
        return Ok(None);
    }
    if !consume {
        return Ok(Some(decision));
    }
    let mut claimed = local_once_signed_payload(&row);
    if let Value::Object(ref mut m) = claimed {
        m.insert("claimed_at".into(), Value::from(now));
    }
    let authority_kind = row_value(&row, "authority_kind");
    let purpose = local_once_integrity_purpose(authority_kind.as_str());
    let signed = match sign_local_authority_payload(
        &claimed,
        integrity_key.unwrap_or(&[]),
        integrity_key_id.unwrap_or(""),
        &purpose,
        now,
    ) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    let changed = conn.execute(
        "update guard_local_once_approvals set claimed_at = ?, integrity_version = ?, \
         payload_hash = ?, payload_mac = ?, integrity_key_id = ?, signed_at = ? \
         where approval_id = ? and claimed_at is null",
        params![
            now,
            signed.integrity_version,
            signed.payload_hash,
            signed.payload_mac,
            signed.integrity_key_id,
            signed.signed_at,
            approval_id,
        ],
    )?;
    if changed == 0 {
        return Ok(None);
    }
    Ok(Some(decision))
}

// ---------------------------------------------------------------------------
// Part 2 — eligibility, integrity, probe engine, selection, entry point.
// ---------------------------------------------------------------------------

/// `_materialized_policy_bundle_row_identity` — 11-tuple equality probe.
fn materialized_policy_bundle_row_identity(row: &Value) -> Value {
    json!([
        row_value(row, "harness"),
        row_value(row, "scope"),
        row_value(row, "artifact_id"),
        row_value(row, "artifact_hash"),
        row_value(row, "workspace"),
        row_value(row, "publisher"),
        row_value(row, "action"),
        row_value(row, "reason"),
        row_value(row, "owner"),
        row_value(row, "source"),
        row_value(row, "expires_at"),
    ])
}

/// `_runtime_policy_row_is_eligible`.
#[allow(clippy::too_many_arguments)]
fn runtime_policy_row_is_eligible(
    row: &Value,
    bundle_identities: &[Vec<Value>],
    requested_artifact_id: Option<&str>,
    requested_artifact_hash: Option<&str>,
    runtime_exact_match_key: Option<&str>,
    portable_runtime_exact_match_key: Option<&str>,
    global_runtime_exact_match_key: Option<&str>,
) -> bool {
    let source = row_value(row, "source").as_str().unwrap_or("").to_string();
    if source == "cloud-sync" || source == "team-policy" {
        return false;
    }
    if source == POLICY_BUNDLE_SOURCE {
        let identity = materialized_policy_bundle_row_identity(row);
        if !bundle_identities
            .iter()
            .any(|i| Value::from(i.clone()) == identity)
        {
            return false;
        }
    }
    !scoped_runtime_row_requires_exact_match(
        row_value(row, "scope").as_str().unwrap_or(""),
        row_value(row, "artifact_id").as_str(),
        row_value(row, "artifact_hash").as_str(),
        &source,
        requested_artifact_id,
        requested_artifact_hash,
        runtime_exact_match_key,
        portable_runtime_exact_match_key,
        global_runtime_exact_match_key,
    )
}

/// `_policy_integrity_result_for_row` — remote sources short-circuit valid.
fn policy_integrity_result_for_row(
    row: &Value,
    mode: &str,
    key: Option<&[u8]>,
    key_id: Option<&str>,
    trusted_generation: Option<i64>,
) -> PolicyIntegrityVerification {
    let source = row_value(row, "source").as_str().unwrap_or("").to_string();
    if is_remote_policy_source(Some(&source)) {
        return PolicyIntegrityVerification {
            status: "valid",
            payload_hash: None,
            key_id: None,
            message: None,
            generation: None,
        };
    }
    verify_local_policy_row(row, key, key_id, mode != "protected", trusted_generation)
}

/// `_policy_row_payload` — base columns plus integrity overlays.
fn policy_row_payload(
    row: &Value,
    integrity_result: Option<&PolicyIntegrityVerification>,
    state: Option<&Value>,
) -> Value {
    let source = row_value(row, "source").as_str().unwrap_or("").to_string();
    let mut map = serde_json::Map::new();
    let (fresh, durable) = crate::approval_reuse::exact_artifact_approval_qualification(
        row,
        &source,
        integrity_result.is_some_and(|result| result.status == "valid"),
    );
    map.insert("fresh_local_approval".into(), Value::Bool(fresh));
    map.insert("durable_exact_approval".into(), Value::Bool(durable));
    let keys = [
        "action",
        "artifact_hash",
        "artifact_id",
        "decision_id",
        "expires_at",
        "harness",
        "owner",
        "publisher",
        "reason",
        "scope",
        "source",
        "updated_at",
        "workspace",
    ];
    for k in keys {
        map.insert(k.to_string(), row_value(row, k));
    }
    if let Some(ir) = integrity_result {
        if !is_remote_policy_source(Some(&source)) {
            map.insert("integrity_status".into(), Value::from(ir.status));
            map.insert(
                "integrity_message".into(),
                ir.message.map(Value::from).unwrap_or(Value::Null),
            );
        }
    }
    if let Some(st) = state {
        if !is_remote_policy_source(Some(&source)) {
            map.insert(
                "integrity_mode".into(),
                st.get("mode").cloned().unwrap_or(Value::Null),
            );
            map.insert(
                "integrity_enforcement".into(),
                st.get("enforcement").cloned().unwrap_or(Value::Null),
            );
        }
    }
    if !row_value(row, "integrity_version").is_null() {
        map.insert(
            "integrity_version".into(),
            row_value(row, "integrity_version"),
        );
    }
    if !row_value(row, "integrity_generation").is_null() {
        map.insert(
            "integrity_generation".into(),
            row_value(row, "integrity_generation"),
        );
    }
    if !row_value(row, "integrity_key_id").is_null() {
        map.insert(
            "integrity_key_id".into(),
            row_value(row, "integrity_key_id"),
        );
    }
    if !row_value(row, "signed_at").is_null() {
        map.insert("signed_at".into(), row_value(row, "signed_at"));
    }
    Value::Object(map)
}

fn policy_row_specificity(row: &Value, harness: &str) -> (u8, u8, u8, u8, u8, u8) {
    let scope = match row_value(row, "scope").as_str().unwrap_or("") {
        "artifact" => 5,
        "workspace" => 4,
        "publisher" => 3,
        "harness" => 2,
        "global" => 1,
        _ => 0,
    };
    let exact_harness = u8::from(row_value(row, "harness").as_str() == Some(harness));
    let exact_hash = u8::from(!row_value(row, "artifact_hash").is_null());
    let exact_artifact = u8::from(!row_value(row, "artifact_id").is_null());
    let exact_workspace = u8::from(!row_value(row, "workspace").is_null());
    let exact_publisher = u8::from(!row_value(row, "publisher").is_null());
    (
        scope,
        exact_harness,
        exact_hash,
        exact_artifact,
        exact_workspace,
        exact_publisher,
    )
}

fn policy_row_outranks(candidate: &Value, selected: &Value, harness: &str) -> bool {
    let candidate_severity =
        guard_action_severity(&row_value(candidate, "action"), GuardAction::Block);
    let selected_severity =
        guard_action_severity(&row_value(selected, "action"), GuardAction::Block);
    candidate_severity > selected_severity
        || (candidate_severity == selected_severity
            && policy_row_specificity(candidate, harness)
                > policy_row_specificity(selected, harness))
}

/// `_distinct_non_null`.
fn distinct_non_null<'a>(values: &[Option<&'a str>]) -> Vec<&'a str> {
    let mut seen = Vec::new();
    for &s in values.iter().flatten() {
        if !seen.contains(&s) {
            seen.push(s);
        }
    }
    seen
}

struct SqlProbe {
    predicate: String,
    parameters: Vec<Value>,
    index_name: &'static str,
}

/// `_hash_partition_probes` — exact-hash probes then a legacy-hash probe.
fn hash_partition_probes(
    base_predicate: &str,
    base_parameters: Vec<Value>,
    exact_hashes: &[Option<&str>],
    exact_index: &'static str,
    legacy_index: Option<&'static str>,
    exact_first: bool,
) -> Vec<SqlProbe> {
    let mut probes = Vec::new();
    let distinct: Vec<&str> = distinct_non_null(exact_hashes);
    let emit_exact = |probes: &mut Vec<SqlProbe>| {
        for h in &distinct {
            let mut p = base_parameters.clone();
            p.push(Value::from(*h));
            probes.push(SqlProbe {
                predicate: format!("{base_predicate} and artifact_hash = ?"),
                parameters: p,
                index_name: exact_index,
            });
        }
    };
    let nullable_probe = |probes: &mut Vec<SqlProbe>| {
        probes.push(SqlProbe {
            predicate: format!("{base_predicate} and artifact_hash is null"),
            parameters: base_parameters.clone(),
            index_name: exact_index,
        });
    };
    // `_hash_partition_probes` ordering: exact_first ⇒ exact, nullable,
    // legacy; otherwise nullable, exact, legacy.
    if exact_first {
        emit_exact(&mut probes);
        nullable_probe(&mut probes);
    } else {
        nullable_probe(&mut probes);
        emit_exact(&mut probes);
    }
    if let Some(legacy_idx) = legacy_index {
        // `artifact_hash is not null` keeps the legacy probe disjoint from the
        // nullable probe (Python embeds the guard; the Rust port dropped it).
        // The legacy partial indexes carry `artifact_hash not like
        // 'guard-approval-context:v1:%'` in their WHERE clause. SQLite only
        // honors INDEXED BY on a partial index when the query WHERE implies
        // the index predicate textually — a bound parameter cannot be proven
        // equal, so the pattern must be embedded as a literal (it is a
        // compile-time constant, never interpolated data). Matches Python
        // `_hash_partition_probes` verbatim.
        let mut legacy_predicate = format!(
            "{base_predicate} and artifact_hash is not null and artifact_hash not like '{APPROVAL_CONTEXT_SQL_PATTERN}'"
        );
        let mut legacy_parameters = base_parameters.clone();
        for h in &distinct {
            legacy_predicate.push_str(" and artifact_hash <> ?");
            legacy_parameters.push(Value::from(*h));
        }
        probes.push(SqlProbe {
            predicate: legacy_predicate,
            parameters: legacy_parameters,
            index_name: legacy_idx,
        });
    }
    probes
}

fn value_to_bind(value: &Value) -> rusqlite::types::Value {
    use rusqlite::types::Value as V;
    match value {
        Value::Null => V::Null,
        Value::Bool(b) => V::Integer(i64::from(*b)),
        Value::Number(n) => n
            .as_i64()
            .map(V::Integer)
            .or_else(|| n.as_f64().map(V::Real))
            .unwrap_or(V::Null),
        Value::String(s) => V::Text(s.clone()),
        _ => V::Null,
    }
}

/// `_bounded_non_consuming_policy_rows` — disjoint exact probes, one-over-limit.
#[allow(clippy::too_many_arguments)]
fn bounded_non_consuming_policy_rows(
    conn: &Connection,
    harness: &str,
    artifact_id: Option<&str>,
    artifact_hash: Option<&str>,
    runtime_exact_match_key: Option<&str>,
    global_runtime_exact_match_key: Option<&str>,
    workspace_key: Option<&str>,
    workspace: Option<&str>,
    publisher: Option<&str>,
    action_family_key: Option<&str>,
    current_time: &str,
) -> rusqlite::Result<Vec<Value>> {
    let limit = NON_CONSUMING_POLICY_MATCH_LIMIT + 1;
    let harness_selectors = distinct_non_null(&[Some(harness), Some("*")]);
    let mut probes: Vec<SqlProbe> = Vec::new();

    // artifact scope
    if let Some(id) = artifact_id {
        for hs in &harness_selectors {
            probes.extend(hash_partition_probes(
                "scope = 'artifact' and artifact_id = ? and harness = ?",
                vec![Value::from(id), Value::from(*hs)],
                &[artifact_hash, runtime_exact_match_key],
                "idx_policy_decisions_lookup_artifact",
                None,
                false,
            ));
        }
    }

    // workspace scope
    let workspace_selectors = distinct_non_null(&[workspace_key, workspace]);
    for ws in &workspace_selectors {
        for hs in &harness_selectors {
            for artifact_sel in distinct_non_null(&[artifact_id, action_family_key]) {
                probes.extend(hash_partition_probes(
                    "scope = 'workspace' and workspace = ? and harness = ? and artifact_id = ?",
                    vec![
                        Value::from(*ws),
                        Value::from(*hs),
                        Value::from(artifact_sel),
                    ],
                    &[artifact_hash],
                    "idx_policy_decisions_lookup_workspace",
                    None,
                    true,
                ));
            }
            probes.push(SqlProbe {
                predicate:
                    "scope = 'workspace' and workspace = ? and harness = ? and artifact_id is null"
                        .to_string(),
                parameters: vec![Value::from(*ws), Value::from(*hs)],
                index_name: "idx_policy_decisions_lookup_workspace",
            });
        }
    }

    // publisher scope
    if let Some(p) = publisher {
        for hs in &harness_selectors {
            probes.extend(hash_partition_probes(
                "scope = 'publisher' and publisher = ? and harness = ?",
                vec![Value::from(p), Value::from(*hs)],
                &[artifact_hash],
                "idx_policy_decisions_lookup_publisher",
                Some("idx_policy_decisions_lookup_publisher_legacy"),
                false,
            ));
        }
    }

    // harness scope
    for hs in &harness_selectors {
        for artifact_sel in distinct_non_null(&[artifact_id, action_family_key]) {
            probes.extend(hash_partition_probes(
                "scope = 'harness' and harness = ? and artifact_id = ?",
                vec![Value::from(*hs), Value::from(artifact_sel)],
                &[artifact_hash],
                "idx_policy_decisions_lookup_harness",
                Some("idx_policy_decisions_lookup_harness_legacy"),
                true,
            ));
        }
        probes.push(SqlProbe {
            predicate: "scope = 'harness' and harness = ? and artifact_id is null".to_string(),
            parameters: vec![Value::from(*hs)],
            index_name: "idx_policy_decisions_lookup_harness",
        });
    }

    // global scope
    for hs in &harness_selectors {
        for artifact_sel in distinct_non_null(&[artifact_id, action_family_key]) {
            probes.extend(hash_partition_probes(
                "scope = 'global' and harness = ? and artifact_id = ?",
                vec![Value::from(*hs), Value::from(artifact_sel)],
                &[artifact_hash, global_runtime_exact_match_key],
                "idx_policy_decisions_lookup_global",
                Some("idx_policy_decisions_lookup_global_legacy"),
                true,
            ));
        }
        probes.push(SqlProbe {
            predicate: "scope = 'global' and harness = ? and artifact_id is null".to_string(),
            parameters: vec![Value::from(*hs)],
            index_name: "idx_policy_decisions_lookup_global",
        });
    }

    // Execute probes, bounded by remaining cap.
    let mut rows: Vec<Value> = Vec::new();
    for probe in &probes {
        let remaining = limit - rows.len() as i64;
        if remaining <= 0 {
            break;
        }
        let sql = format!(
            "select {POLICY_LOOKUP_COLUMNS} from policy_decisions indexed by {} \
             where {} and (expires_at is null or julianday(expires_at) > julianday(?)) limit ?",
            probe.index_name, probe.predicate
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut bind: Vec<rusqlite::types::Value> =
            probe.parameters.iter().map(value_to_bind).collect();
        bind.push(rusqlite::types::Value::Text(current_time.to_string()));
        bind.push(rusqlite::types::Value::Integer(remaining));
        let collected = stmt
            .query_map(params_from_iter(bind), policy_row_to_json)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.extend(collected);
        if rows.len() as i64 >= limit {
            break;
        }
    }
    Ok(rows)
}

/// `mapping_int` — integer extraction for `state["generation"]`.
fn mapping_int(value: &Value) -> Option<i64> {
    match value {
        Value::Number(n) => n.as_i64().filter(|_| !n.is_f64()),
        Value::Bool(b) => Some(i64::from(*b)),
        _ => None,
    }
}

/// `request_digest` — SHA-256 over the canonical request bytes.
fn request_digest(request: &PolicyDecisionLookupRequestV1) -> Result<String, String> {
    let material =
        serde_json::to_value(request).map_err(|_| "native_policy_decision_lookup_invalid")?;
    let mut bytes = Vec::new();
    write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| "native_policy_decision_lookup_invalid")?;
    Ok(format!("sha256:{}", digest_bytes(&bytes)))
}

pub(crate) fn evaluate_policy_decision_lookup_request(
    request: &PolicyDecisionLookupRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    let (status, code, payload) = match evaluate(request) {
        Ok(p) => ("ok".to_owned(), "ok".to_owned(), Some(p)),
        Err(c) => ("error".to_owned(), c, None),
    };
    crate::resident_protocol::encode_response(&PolicyDecisionLookupResultV1 {
        schema: POLICY_DECISION_LOOKUP_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

fn evaluate(request: &PolicyDecisionLookupRequestV1) -> Result<Value, String> {
    if request.schema != POLICY_DECISION_LOOKUP_REQUEST_SCHEMA {
        return Err("native_policy_decision_lookup_schema_mismatch".to_owned());
    }
    let current_time = canonical_utc_timestamp(&request.now)
        .ok_or_else(|| "native_policy_decision_lookup_invalid_now".to_owned())?;
    let mut conn = Connection::open(&request.store_path)
        .map_err(|_| "native_policy_decision_lookup_store_unavailable".to_owned())?;
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| "native_policy_decision_lookup_store_unavailable".to_owned())?;
    conn.execute("pragma foreign_keys = on", [])
        .map_err(|_| "native_policy_decision_lookup_store_unavailable".to_owned())?;
    if request.consume_one_shot {
        // Serialize selection with consumption. Rollback-on-drop also keeps a
        // one-shot usable when its required audit write or commit fails.
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "native_policy_decision_lookup_write_failed".to_owned())?;
        let payload = evaluate_in_connection(request, &transaction, &current_time)?;
        transaction
            .commit()
            .map_err(|_| "native_policy_decision_lookup_write_failed".to_owned())?;
        Ok(payload)
    } else {
        evaluate_in_connection(request, &conn, &current_time)
    }
}

fn evaluate_in_connection(
    request: &PolicyDecisionLookupRequestV1,
    conn: &Connection,
    current_time: &str,
) -> Result<Value, String> {
    let harness = request.harness.as_str();
    let artifact_id = request.artifact_id.as_deref();
    let artifact_hash = request.artifact_hash.as_deref();
    let workspace = request.workspace.as_deref();
    let publisher = request.publisher.as_deref();
    let consume_one_shot = request.consume_one_shot;
    let workspace_key = workspace_policy_key(workspace);
    let action_family_key = artifact_family_key(artifact_id);
    let runtime_exact_match_key = artifact_hash.and_then(|_| {
        runtime_scoped_exact_match_key(artifact_id, request.runtime_exact_match_context.as_deref())
    });
    let portable_runtime_exact_match_key = (artifact_hash.is_some()
        && request.runtime_exact_match_context.is_some())
    .then(|| {
        runtime_scoped_exact_match_key(
            artifact_id,
            runtime_tool_action_portable_match_context(
                request.runtime_exact_match_context.as_deref(),
            )
            .as_deref(),
        )
    })
    .flatten();
    let global_runtime_exact_match_key = (artifact_hash.is_some()
        && request.runtime_exact_match_context.is_some())
    .then(|| {
        global_runtime_scoped_exact_match_key(
            artifact_id,
            runtime_tool_action_portable_match_context(
                request.runtime_exact_match_context.as_deref(),
            )
            .as_deref(),
        )
    })
    .flatten();

    let integrity_state: Value = request.integrity_state.clone().unwrap_or_else(|| json!({}));
    let integrity_key = request.integrity_key_b64.as_deref().and_then(b64url_decode);
    let integrity_key_id = request.integrity_key_id.as_deref();
    let local_once_key = request
        .local_once_integrity_key_b64
        .as_deref()
        .and_then(b64url_decode);
    let local_once_key_id = request.local_once_integrity_key_id.as_deref();
    let bundle_identities: Vec<Vec<Value>> = request
        .policy_bundle_decision_identities
        .clone()
        .unwrap_or_default();

    let starting_revision = approval_authority_revision(conn).unwrap_or(-1);
    let mut events: Vec<(String, Value)> = Vec::new();
    let mut selected_payload: Option<Value> = None;
    let mut ignored_local_integrity: Option<Value> = None;

    // ---- local-once peek loop (non-consuming preview; claimed later) ----
    let mut local_once_decision: Option<Value> = None;
    let mut local_once_hash: Option<String> = None;
    let mut reported_local_once_failures: Vec<Value> = Vec::new();
    let local_once_hashes: Vec<String> = {
        let mut v = Vec::new();
        for h in [
            artifact_hash.map(str::to_string),
            runtime_exact_match_key.clone(),
        ]
        .into_iter()
        .flatten()
        {
            if !v.contains(&h) {
                v.push(h);
            }
        }
        v
    };
    for lo_hash in &local_once_hashes {
        let (decision, failure) = peek_local_once_lookup(
            conn,
            harness,
            artifact_id,
            Some(lo_hash.as_str()),
            workspace_key.as_deref(),
            publisher,
            current_time,
            None,
            None,
        )
        .map_err(|_| "native_policy_decision_lookup_query_failed".to_owned())?;
        let (decision, failure) = if decision.is_none()
            && failure
                .as_ref()
                .and_then(|f| f.get("integrity_status"))
                .and_then(Value::as_str)
                == Some("unknown_key")
        {
            peek_local_once_lookup(
                conn,
                harness,
                artifact_id,
                Some(lo_hash.as_str()),
                workspace_key.as_deref(),
                publisher,
                current_time,
                local_once_key.as_deref(),
                local_once_key_id,
            )
            .map_err(|_| "native_policy_decision_lookup_query_failed".to_owned())?
        } else {
            (decision, failure)
        };
        if let Some(f) = failure {
            if ignored_local_integrity.is_none() {
                ignored_local_integrity = Some(f.clone());
            }
            let fid = f.get("approval_id").cloned().unwrap_or(Value::Null);
            if !reported_local_once_failures.contains(&fid) {
                reported_local_once_failures.push(fid);
                // `**failure`, `message=` renames `integrity_message`.
                let mut payload = f.clone();
                if let Value::Object(ref mut m) = payload {
                    let msg = m.remove("integrity_message").unwrap_or(Value::Null);
                    m.insert("message".into(), msg);
                }
                events.push(("rule.ignored.local_integrity".to_owned(), payload));
            }
        }
        if let Some(d) = decision {
            local_once_decision = Some(d);
            local_once_hash = Some(lo_hash.clone());
            break;
        }
    }
    if local_once_decision.is_some() {
        selected_payload = local_once_decision.clone();
    }

    // ---- policy rows: non-consuming probes vs consuming multi-scope SQL ----
    let rows = if !consume_one_shot {
        bounded_non_consuming_policy_rows(
            conn,
            harness,
            artifact_id,
            artifact_hash,
            runtime_exact_match_key.as_deref(),
            global_runtime_exact_match_key.as_deref(),
            workspace_key.as_deref(),
            workspace,
            publisher,
            action_family_key.as_deref(),
            current_time,
        )
        .map_err(|_| "native_policy_decision_lookup_query_failed".to_owned())?
    } else {
        consuming_policy_rows(
            conn,
            harness,
            artifact_id,
            artifact_hash,
            runtime_exact_match_key.as_deref(),
            global_runtime_exact_match_key.as_deref(),
            workspace_key.as_deref(),
            workspace,
            publisher,
            action_family_key.as_deref(),
            current_time,
            -1,
        )
        .map_err(|_| "native_policy_decision_lookup_query_failed".to_owned())?
    };

    let mut rows = rows;
    let policy_match_overflow =
        !consume_one_shot && (rows.len() as i64) > NON_CONSUMING_POLICY_MATCH_LIMIT;
    if policy_match_overflow {
        rows.truncate(NON_CONSUMING_POLICY_MATCH_LIMIT as usize);
        selected_payload = Some(json!({
            "action": "block",
            "artifact_hash": artifact_hash,
            "artifact_id": artifact_id,
            "decision_id": Value::Null,
            "expires_at": Value::Null,
            "harness": harness,
            "owner": Value::Null,
            "publisher": publisher,
            "reason": "Guard policy match limit exceeded during approval reuse.",
            "scope": "global",
            "source": "guard-policy-match-cap",
            "updated_at": current_time,
            "workspace": workspace,
        }));
        events.push((
            "approval.policy_lookup_overflow".to_owned(),
            json!({
                "harness": harness,
                "artifact_id": artifact_id,
                "match_limit": NON_CONSUMING_POLICY_MATCH_LIMIT,
                "authoritative_action": "block",
            }),
        ));
    }

    let cached_state = integrity_state.clone();
    let cached_trust_status = trust_status_from_state(&cached_state);

    // No rows and no local-once selection → empty result.
    if rows.is_empty() && selected_payload.is_none() {
        flush_events(conn, &events, current_time)
            .map_err(|_| "native_policy_decision_lookup_write_failed".to_owned())?;
        if let Some(ref mut ili) = ignored_local_integrity {
            ili["trust_status"] = cached_trust_status.clone();
        }
        return Ok(lookup_result(
            conn,
            None,
            ignored_local_integrity,
            cached_trust_status,
            consume_one_shot,
            starting_revision,
        ));
    }

    let bundle_identities: Vec<Vec<Value>> = if rows
        .iter()
        .any(|c| row_value(c, "source").as_str() == Some(POLICY_BUNDLE_SOURCE))
    {
        bundle_identities
    } else {
        Vec::new()
    };
    let has_local_rows = rows
        .iter()
        .any(|c| !is_remote_policy_source(row_value(c, "source").as_str()));

    // claim_selected_local_once — consume the previewed one-shot winner.
    let claim_local_once = |selected: &Option<Value>,
                            local_once: &Option<Value>,
                            events: &mut Vec<(String, Value)>|
     -> rusqlite::Result<Option<Value>> {
        if !consume_one_shot || local_once.is_none() {
            return Ok(selected.clone());
        }
        if selected.as_ref() != local_once.as_ref() {
            return Ok(selected.clone());
        }
        let claimed = claim_local_once_lookup(
            conn,
            harness,
            artifact_id,
            local_once_hash.as_deref(),
            workspace_key.as_deref(),
            publisher,
            current_time,
            local_once_key.as_deref(),
            local_once_key_id,
        )?;
        match claimed {
            None => Ok(None),
            Some(c) => {
                events.push((
                    "approval.local_once_applied".to_owned(),
                    json!({
                        "approval_id": c.get("approval_id").cloned().unwrap_or(Value::Null),
                        "request_id": c.get("request_id").cloned().unwrap_or(Value::Null),
                        "harness": harness,
                        "artifact_id": artifact_id,
                    }),
                ));
                Ok(Some(c))
            }
        }
    };

    if !has_local_rows {
        // Remote-only branch — uses cached_state, no integrity material.
        for candidate in &rows {
            if !runtime_policy_row_is_eligible(
                candidate,
                &bundle_identities,
                artifact_id,
                artifact_hash,
                runtime_exact_match_key.as_deref(),
                portable_runtime_exact_match_key.as_deref(),
                global_runtime_exact_match_key.as_deref(),
            ) {
                continue;
            }
            let integrity_result = policy_integrity_result_for_row(
                candidate,
                cached_state
                    .get("mode")
                    .and_then(Value::as_str)
                    .unwrap_or("protected"),
                None,
                None,
                cached_state.get("generation").and_then(mapping_int),
            );
            if integrity_result.status != "valid" {
                events.push((
                    "policy_integrity_violation".to_owned(),
                    json!({
                        "decision_id": row_value(candidate, "decision_id"),
                        "harness": row_value(candidate, "harness"),
                        "artifact_id": row_value(candidate, "artifact_id"),
                        "integrity_status": integrity_result.status,
                        "message": integrity_result.message.map(Value::from).unwrap_or(Value::Null),
                    }),
                ));
                continue;
            }
            let candidate_payload =
                policy_row_payload(candidate, Some(&integrity_result), Some(&cached_state));
            let outranks = selected_payload
                .as_ref()
                .is_none_or(|sp| policy_row_outranks(candidate, sp, harness));
            if outranks {
                if consume_one_shot && is_approval_gate_one_shot_policy(candidate) {
                    let deleted = conn
                        .execute(
                            "delete from policy_decisions where decision_id = ?",
                            params![row_value(candidate, "decision_id").as_i64().unwrap_or(0)],
                        )
                        .map_err(|_| "native_policy_decision_lookup_write_failed".to_owned())?;
                    if deleted != 1 {
                        continue;
                    }
                }
                selected_payload = Some(candidate_payload);
                if consume_one_shot
                    && is_remote_policy_source(row_value(candidate, "source").as_str())
                {
                    events.push((
                        "policy.cloud.applied".to_owned(),
                        json!({
                            "decision_id": row_value(candidate, "decision_id"),
                            "harness": row_value(candidate, "harness"),
                            "artifact_id": row_value(candidate, "artifact_id"),
                            "scope": row_value(candidate, "scope"),
                            "source": row_value(candidate, "source"),
                            "action": row_value(candidate, "action"),
                        }),
                    ));
                }
            }
            if consume_one_shot {
                break;
            }
        }
        selected_payload = claim_local_once(&selected_payload, &local_once_decision, &mut events)
            .map_err(|_| "native_policy_decision_lookup_write_failed".to_owned())?;
        flush_events(conn, &events, current_time)
            .map_err(|_| "native_policy_decision_lookup_write_failed".to_owned())?;
        if let Some(ref mut ili) = ignored_local_integrity {
            ili["trust_status"] = cached_trust_status.clone();
        }
        return Ok(lookup_result(
            conn,
            selected_payload,
            ignored_local_integrity,
            cached_trust_status,
            consume_one_shot,
            starting_revision,
        ));
    }

    // Local-rows branch — caller ships post-refresh `integrity_state` + key.
    let trust_status = trust_status_from_state(&integrity_state);
    let mode = integrity_state
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("degraded");
    let trusted_generation = integrity_state.get("generation").and_then(mapping_int);
    for candidate in &rows {
        if !runtime_policy_row_is_eligible(
            candidate,
            &bundle_identities,
            artifact_id,
            artifact_hash,
            runtime_exact_match_key.as_deref(),
            portable_runtime_exact_match_key.as_deref(),
            global_runtime_exact_match_key.as_deref(),
        ) {
            continue;
        }
        let integrity_result = policy_integrity_result_for_row(
            candidate,
            mode,
            integrity_key.as_deref(),
            integrity_key_id,
            trusted_generation,
        );
        let source = row_value(candidate, "source")
            .as_str()
            .unwrap_or("")
            .to_string();
        if integrity_result.status == "valid"
            || warn_only_policy_integrity_status(integrity_result.status, &integrity_state, &source)
        {
            let candidate_payload =
                policy_row_payload(candidate, Some(&integrity_result), Some(&integrity_state));
            let outranks = selected_payload
                .as_ref()
                .is_none_or(|sp| policy_row_outranks(candidate, sp, harness));
            if outranks {
                if consume_one_shot && is_approval_gate_one_shot_policy(candidate) {
                    let deleted = conn
                        .execute(
                            "delete from policy_decisions where decision_id = ?",
                            params![row_value(candidate, "decision_id").as_i64().unwrap_or(0)],
                        )
                        .map_err(|_| "native_policy_decision_lookup_write_failed".to_owned())?;
                    if deleted != 1 {
                        continue;
                    }
                }
                selected_payload = Some(candidate_payload);
            }
            if outranks && consume_one_shot && is_remote_policy_source(Some(&source)) {
                events.push((
                    "policy.cloud.applied".to_owned(),
                    json!({
                        "decision_id": row_value(candidate, "decision_id"),
                        "harness": row_value(candidate, "harness"),
                        "artifact_id": row_value(candidate, "artifact_id"),
                        "scope": row_value(candidate, "scope"),
                        "source": row_value(candidate, "source"),
                        "action": row_value(candidate, "action"),
                    }),
                ));
            }
            if consume_one_shot {
                break;
            }
            continue;
        }
        events.push((
            "policy_integrity_violation".to_owned(),
            json!({
                "decision_id": row_value(candidate, "decision_id"),
                "harness": row_value(candidate, "harness"),
                "artifact_id": row_value(candidate, "artifact_id"),
                "integrity_status": integrity_result.status,
                "message": integrity_result.message.map(Value::from).unwrap_or(Value::Null),
            }),
        ));
        if ignored_local_integrity.is_none() && !is_remote_policy_source(Some(&source)) {
            ignored_local_integrity = Some(json!({
                "decision_id": row_value(candidate, "decision_id"),
                "harness": row_value(candidate, "harness"),
                "artifact_id": row_value(candidate, "artifact_id"),
                "scope": row_value(candidate, "scope"),
                "source": row_value(candidate, "source"),
                "integrity_status": integrity_result.status,
                "integrity_message": integrity_result.message.map(Value::from).unwrap_or(Value::Null),
                "trust_status": trust_status,
            }));
        }
        if !is_remote_policy_source(Some(&source)) {
            events.push((
                "rule.ignored.local_integrity".to_owned(),
                json!({
                    "decision_id": row_value(candidate, "decision_id"),
                    "harness": row_value(candidate, "harness"),
                    "artifact_id": row_value(candidate, "artifact_id"),
                    "scope": row_value(candidate, "scope"),
                    "source": row_value(candidate, "source"),
                    "integrity_status": integrity_result.status,
                    "message": integrity_result.message.map(Value::from).unwrap_or(Value::Null),
                }),
            ));
        }
    }
    selected_payload = claim_local_once(&selected_payload, &local_once_decision, &mut events)
        .map_err(|_| "native_policy_decision_lookup_write_failed".to_owned())?;
    flush_events(conn, &events, current_time)
        .map_err(|_| "native_policy_decision_lookup_write_failed".to_owned())?;
    if let Some(ref mut ili) = ignored_local_integrity {
        ili["trust_status"] = trust_status.clone();
    }
    Ok(lookup_result(
        conn,
        selected_payload,
        ignored_local_integrity,
        trust_status,
        consume_one_shot,
        starting_revision,
    ))
}

/// `lookup_result` — `{decision, ignored_local_integrity, trust_status, authority_revision}`.
fn lookup_result(
    conn: &Connection,
    decision: Option<Value>,
    ignored_integrity: Option<Value>,
    trust_status: Value,
    consume_one_shot: bool,
    starting_revision: i64,
) -> Value {
    let stable_revision = match approval_authority_revision(conn) {
        Ok(revision) if revision == starting_revision => starting_revision,
        _ => -1,
    };
    let mut decision = decision;
    if let (Some(Value::Object(ref mut m)), false) = (&mut decision, consume_one_shot) {
        m.insert(
            "_approval_authority_revision".into(),
            Value::from(stable_revision),
        );
    }
    json!({
        "decision": decision.unwrap_or(Value::Null),
        "ignored_local_integrity": ignored_integrity.unwrap_or(Value::Null),
        "trust_status": trust_status,
        "authority_revision": stable_revision,
    })
}

/// `_flush_events` — append each audit event row; a failed insert propagates
/// and aborts the lookup rather than silently dropping the event.
fn flush_events(
    conn: &Connection,
    events: &[(String, Value)],
    current_time: &str,
) -> rusqlite::Result<()> {
    for (name, payload) in events {
        conn.execute(
            "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, ?)",
            params![name, canonical_json(payload), current_time],
        )?;
    }
    Ok(())
}

/// Consuming multi-scope `policy_decisions` select — preserves scope
/// precedence ordering for one-shot (`consume_one_shot`) lookups.
#[allow(clippy::too_many_arguments)]
fn consuming_policy_rows(
    conn: &Connection,
    harness: &str,
    artifact_id: Option<&str>,
    artifact_hash: Option<&str>,
    runtime_exact_match_key: Option<&str>,
    global_runtime_exact_match_key: Option<&str>,
    workspace_key: Option<&str>,
    workspace: Option<&str>,
    publisher: Option<&str>,
    action_family_key: Option<&str>,
    current_time: &str,
    limit: i64,
) -> rusqlite::Result<Vec<Value>> {
    let sql = format!(
        "select {POLICY_LOOKUP_COLUMNS} from policy_decisions \
         where (harness = ? or harness = '*') and ( \
           (scope = 'artifact' and artifact_id = ? and ( \
             artifact_hash is null or (? is not null and artifact_hash = ?) \
             or (? is not null and artifact_hash = ?))) \
           or (scope = 'workspace' and (workspace = ? or workspace = ?) and ( \
             artifact_id is null or ((artifact_id = ? or artifact_id = ?) and ( \
               artifact_hash is null or (? is not null and artifact_hash = ?))))) \
           or (scope = 'publisher' and publisher = ? and ( \
             artifact_hash is null or artifact_hash = ? \
             or artifact_hash not like 'guard-approval-context:v1:%')) \
           or (scope = 'harness' and (artifact_id is null or artifact_id = ? or artifact_id = ?) and ( \
             artifact_hash is null or artifact_hash = ? \
             or (? is not null and artifact_hash = ?) \
             or artifact_hash not like 'guard-approval-context:v1:%')) \
           or (scope = 'global' and (artifact_id is null or artifact_id = ? or artifact_id = ?) and ( \
             artifact_hash is null or artifact_hash = ? \
             or (? is not null and artifact_hash = ?) \
             or artifact_hash not like 'guard-approval-context:v1:%'))) \
         and (expires_at is null or julianday(expires_at) > julianday(?)) \
         order by case scope when 'artifact' then 0 when 'workspace' then 1 \
                  when 'publisher' then 2 when 'harness' then 3 else 4 end, \
                  case when scope in ('workspace','harness','global') and artifact_id is not null \
                       then 0 else 1 end, updated_at desc limit ?"
    );
    let binds = [
        harness,
        artifact_id.unwrap_or(""),
        artifact_hash.unwrap_or(""),
        artifact_hash.unwrap_or(""),
        runtime_exact_match_key.unwrap_or(""),
        runtime_exact_match_key.unwrap_or(""),
        workspace_key.unwrap_or(""),
        workspace.unwrap_or(""),
        artifact_id.unwrap_or(""),
        action_family_key.unwrap_or(""),
        artifact_hash.unwrap_or(""),
        artifact_hash.unwrap_or(""),
        publisher.unwrap_or(""),
        artifact_hash.unwrap_or(""),
        artifact_id.unwrap_or(""),
        action_family_key.unwrap_or(""),
        artifact_hash.unwrap_or(""),
        runtime_exact_match_key.unwrap_or(""),
        runtime_exact_match_key.unwrap_or(""),
        artifact_id.unwrap_or(""),
        action_family_key.unwrap_or(""),
        artifact_hash.unwrap_or(""),
        global_runtime_exact_match_key.unwrap_or(""),
        global_runtime_exact_match_key.unwrap_or(""),
        current_time,
    ];
    let mut stmt = conn.prepare(&sql)?;
    // Bind the 25 positional params individually to preserve order; the limit
    // is appended as the 26th parameter via params_from_iter.
    let mut bind: Vec<rusqlite::types::Value> = binds
        .iter()
        .map(|s| {
            if s.is_empty() {
                rusqlite::types::Value::Null
            } else {
                rusqlite::types::Value::Text(s.to_string())
            }
        })
        .collect();
    bind.push(rusqlite::types::Value::Integer(limit));
    let rows = stmt
        .query_map(params_from_iter(bind), policy_row_to_json)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

#[cfg(test)]
#[path = "policy_decision_lookup_tests.rs"]
mod tests;

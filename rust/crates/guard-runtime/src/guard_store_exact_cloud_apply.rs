//! `StoreExactCloudReviewMixin.resolve_one_request_with_signed_remote_exact_result`:
//! a signed Cloud Review verdict applied to the local approval queue.
//!
//! Every mutable input the cloud signed over - the OAuth binding, the consent
//! capability, the revocation marker, the queued request itself - is reread
//! inside the write transaction and compared with what the caller verified.
//! The receipt row claims the verdict exactly once, so a redelivered receipt
//! cannot resolve a second request, and the local-once authority is signed in
//! the same transaction that resolved the request.
//!
//! The caller keeps the OAuth credential lock and the secret material: it
//! supplies the verified DPoP thumbprint and the local integrity key. Both are
//! facts about key material rather than verdicts; every allow and refusal here
//! is computed from the rows this transaction reads.

use base64ct::{Base64UrlUnpadded, Encoding};
use rusqlite::Connection;
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

use guard_contracts::utc_timestamp_micros;

use crate::guard_store_approval_queue_result::{block_reason, request};
use crate::guard_store_approval_resolve::set_resolution;
use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_one, value_error, StoreError, StoreResult};
use crate::guard_store_json::dumps_sorted;
use crate::guard_store_local_once_mint::{mint_local_once_approval, LocalOnceMint};
use crate::local_once_store::EXACT_CLOUD_AUTHORITY_KIND;
use crate::policy_bundle_time::micros_to_utc_isoformat;
use crate::policy_store::PolicySnapshotStore;

const CAPABILITY_KEY: &str = "guard_exact_cloud_review_capability";
const OAUTH_KEY: &str = "oauth_local_credentials";
const REVOCATION_KEY: &str = "guard_exact_cloud_review_revocation";

/// The local integrity key is the policy integrity secret; keep the bound the
/// policy upsert puts on it.
const MAX_KEY_BYTES: usize = 1024;

/// `_exact_error`: a refusal the caller reads, not a failed call. Python
/// returned these from inside its transaction, so a diagnostic written just
/// before the refusal - the stale-request event - is committed with it.
fn exact_error(code: &str, now: &str) -> StoreResult<Value> {
    Ok(json!({
        "checked_at": now,
        "error": code,
        "replayed": false,
        "resolved": false,
    }))
}

/// `_exact_transaction_now`: `datetime.now(timezone.utc).isoformat()`, taken
/// inside the write transaction so every expiry is judged against the instant
/// the row lock was actually held.
fn transaction_now() -> StoreResult<String> {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_micros()).ok())
        .ok_or(StoreError::Invalid("native_exact_cloud_clock_invalid"))?;
    micros_to_utc_isoformat(micros, "+00:00")
        .ok_or(StoreError::Invalid("native_exact_cloud_clock_invalid"))
}

/// `_load_exact_state`: the parsed `sync_state` payload, or null when the row
/// is missing or its text is not JSON.
fn exact_state(connection: &Connection, state_key: &str) -> StoreResult<Value> {
    let Some(row) = query_one(
        connection,
        "select payload_json from sync_state where state_key = ?",
        &[Value::from(state_key)],
    )?
    else {
        return Ok(Value::Null);
    };
    Ok(row
        .get("payload_json")
        .and_then(Value::as_str)
        .and_then(|text| serde_json::from_str(text).ok())
        .unwrap_or(Value::Null))
}

/// `_record_exact_event`.
fn record_event(
    connection: &Connection,
    event_name: &str,
    payload: &Value,
    now: &str,
) -> StoreResult<()> {
    let encoded =
        dumps_sorted(payload).ok_or(StoreError::Invalid("native_exact_cloud_event_invalid"))?;
    exec(
        connection,
        "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, ?)",
        &[
            Value::from(event_name),
            Value::from(encoded),
            Value::from(now),
        ],
    )?;
    Ok(())
}

/// `str(value)` for the stored cells this path stringifies.
fn py_str(value: &Value) -> String {
    match value {
        Value::Null => "None".to_owned(),
        Value::Bool(flag) => (if *flag { "True" } else { "False" }).to_owned(),
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// `_optional_text`: a non-empty string, or null.
fn optional_text(row: &Map<String, Value>, name: &str) -> Value {
    match row.get(name).and_then(Value::as_str) {
        Some(text) if !text.is_empty() => Value::from(text),
        _ => Value::Null,
    }
}

/// `_oauth_binding_from_state`: the local delivery target the signed
/// capability must still name. `dpop_thumbprint` is the caller's verified
/// thumbprint; it is null when the stored secret has no usable key material or
/// disagrees with its own recorded thumbprint, and a null thumbprint has no
/// binding.
fn oauth_binding(
    connection: &Connection,
    oauth_state: &Value,
    dpop_thumbprint: Option<&str>,
) -> StoreResult<Value> {
    let (Some(state), Some(thumbprint)) = (oauth_state.as_object(), dpop_thumbprint) else {
        return Ok(Value::Null);
    };
    let device_id = state.get("device_id").and_then(Value::as_str);
    if !device_id.is_some_and(|id| !id.trim().is_empty() && id == thumbprint) {
        return Ok(Value::Null);
    }
    let device = query_one(
        connection,
        "select installation_id from guard_devices where device_key = ?",
        &[Value::from("local-device")],
    )?;
    let installation_id = match device {
        None => Value::Null,
        Some(row) => Value::from(py_str(row.get("installation_id").unwrap_or(&Value::Null))),
    };
    let field = |name: &str| state.get(name).cloned().unwrap_or(Value::Null);
    Ok(json!({
        "deviceId": field("device_id"),
        "dpopThumbprint": thumbprint,
        "grantId": field("grant_id"),
        "installationId": installation_id,
        "machineId": field("machine_id"),
        "runtimeId": field("runtime_id"),
        "workspaceId": field("workspace_id"),
    }))
}

/// `_capability_matches_oauth_binding`: every binding field the capability
/// carries must still name this install.
fn capability_matches_binding(capability: &Value, binding: &Value) -> bool {
    let (Some(capability), Some(binding)) = (capability.as_object(), binding.as_object()) else {
        return false;
    };
    binding
        .iter()
        .all(|(key, value)| capability.get(key).unwrap_or(&Value::Null) == value)
}

/// `_changed_request_fields`: the field names whose stored value no longer
/// matches what the cloud signed over. Names only, so the stale-request
/// diagnostic cannot carry the values themselves.
fn changed_request_fields(
    current: &Map<String, Value>,
    expected: &Map<String, Value>,
) -> Vec<Value> {
    let mut names: Vec<&String> = current.keys().chain(expected.keys()).collect();
    names.sort_unstable();
    names.dedup();
    names
        .into_iter()
        .filter(|name| {
            current.get(*name).unwrap_or(&Value::Null)
                != expected.get(*name).unwrap_or(&Value::Null)
        })
        .map(|name| Value::from(name.as_str()))
        .collect()
}

/// `persist_local_once_approval` for the exact-cloud authority kind, inside
/// the caller's transaction. Returns false where Python returned `None`: the
/// request names no exact artifact to bind the authority to.
fn persist_local_once_approval(
    connection: &Connection,
    request_id: &str,
    row: &Map<String, Value>,
    created_at: &str,
    expires_at: &str,
    key: &[u8],
    key_id: &str,
) -> StoreResult<bool> {
    let artifact_id = optional_text(row, "artifact_id");
    let artifact_hash = optional_text(row, "artifact_hash");
    let workspace = optional_text(row, "workspace");
    let mint = LocalOnceMint {
        request_id,
        harness: Value::from(py_str(row.get("harness").unwrap_or(&Value::Null))),
        artifact_id: artifact_id.as_str(),
        artifact_hash: artifact_hash.as_str(),
        workspace: workspace.as_str(),
        publisher: optional_text(row, "publisher"),
        action: Value::from("allow"),
        created_at,
        expires_at,
        authority_kind: EXACT_CLOUD_AUTHORITY_KIND,
    };
    Ok(mint_local_once_approval(
        connection,
        &mint,
        key,
        key_id,
        "native_exact_cloud_timestamp_invalid",
        "native_exact_cloud_random_failed",
    )?
    .is_some())
}

/// A local-once signing key and the id it is stored under.
pub(crate) type IntegrityMaterial<'a> = (Zeroizing<Vec<u8>>, &'a str);

/// The local-once signing key, when the caller shipped both halves of usable
/// key material. An allow without it is refused before the transaction writes.
pub(crate) fn integrity_material<'a>(
    args: &Args<'a>,
) -> StoreResult<Option<IntegrityMaterial<'a>>> {
    let (Some(encoded), Some(key_id)) = (
        args.opt_str("integrity_key_b64")?,
        args.opt_str("integrity_key_id")?,
    ) else {
        return Ok(None);
    };
    let Ok(decoded) = Base64UrlUnpadded::decode_vec(encoded) else {
        return Ok(None);
    };
    if decoded.is_empty() || decoded.len() > MAX_KEY_BYTES || key_id.is_empty() {
        return Ok(None);
    }
    Ok(Some((Zeroizing::new(decoded), key_id)))
}

/// `resolve_one_request_with_signed_remote_exact_result`.
pub(crate) fn apply_signed_remote_exact_result(
    connection: &Connection,
    guard_home: &str,
    args: &Args<'_>,
    owner: Option<&PolicySnapshotStore>,
) -> StoreResult<Value> {
    let request_id = args.str("request_id")?;
    let receipt_id = args.str("receipt_id")?;
    let resolution_action = args.str("resolution_action")?;
    let resolution_scope = args.str("resolution_scope")?;
    let reason = args.str("reason")?;
    let receipt_expires_at = args.str("receipt_expires_at")?;
    let skip_exact_capability = args.flag("skip_exact_capability")?;
    let expected_capability = args.raw("expected_capability").unwrap_or(&Value::Null);
    let expected_oauth_binding = args.raw("expected_oauth_binding").unwrap_or(&Value::Null);
    let expected_request = args.object("expected_request")?;
    let expected_raw_request = args.object("expected_raw_request")?;
    let dpop_thumbprint = args.opt_str("dpop_thumbprint")?;
    // The caller derived `expected_request` from a queue read made in its own
    // directory. Both rereads below resolve the request's scope from the same
    // place, so a relative `config_path` with no stored workspace does not read
    // as a changed request.
    let cwd = args.opt_str("cwd")?;

    let allowing = resolution_action == "allow";
    let material = integrity_material(args)?;
    if allowing && material.is_none() {
        return exact_error(
            "remote_exact_local_authority_unavailable",
            &transaction_now()?,
        );
    }

    let resolved_at = transaction_now()?;
    let now_micros = utc_timestamp_micros(&resolved_at)
        .ok_or(StoreError::Invalid("native_exact_cloud_clock_invalid"))?;

    let oauth_state = exact_state(connection, OAUTH_KEY)?;
    let binding = oauth_binding(connection, &oauth_state, dpop_thumbprint)?;
    if &binding != expected_oauth_binding {
        return exact_error("remote_exact_oauth_changed", &resolved_at);
    }

    let revoked = !exact_state(connection, REVOCATION_KEY)?.is_null();
    let mut capability_expires_micros = None;
    if skip_exact_capability {
        if revoked {
            return exact_error("cloud_review_capability_revoked", &resolved_at);
        }
    } else {
        let capability = exact_state(connection, CAPABILITY_KEY)?;
        if &capability != expected_capability {
            return exact_error("remote_exact_capability_changed", &resolved_at);
        }
        if revoked {
            return exact_error("cloud_review_capability_revoked", &resolved_at);
        }
        if !capability_matches_binding(&capability, &binding) {
            return exact_error("cloud_review_capability_binding_mismatch", &resolved_at);
        }
        capability_expires_micros = capability
            .get("expiresAt")
            .and_then(Value::as_str)
            .and_then(utc_timestamp_micros);
        if capability_expires_micros.is_none_or(|expires| expires <= now_micros) {
            return exact_error("cloud_review_capability_expired", &resolved_at);
        }
    }

    let Some(receipt_expires_micros) =
        utc_timestamp_micros(receipt_expires_at).filter(|expires| *expires > now_micros)
    else {
        return exact_error("remote_approval_expired", &resolved_at);
    };

    let current = request(connection, guard_home, request_id, cwd, owner)?;
    let Some(current_fields) = current.as_object() else {
        return exact_error("remote_exact_request_not_pending", &resolved_at);
    };
    if current_fields.get("status").and_then(Value::as_str) != Some("pending") {
        return exact_error("remote_exact_request_not_pending", &resolved_at);
    }
    let changed = changed_request_fields(current_fields, expected_request);
    if !changed.is_empty() {
        record_event(
            connection,
            "cloud_review.exact_request_stale",
            &json!({"changed_fields": changed, "request_id": request_id}),
            &resolved_at,
        )?;
        return exact_error("remote_exact_request_stale", &resolved_at);
    }
    let Some(raw) = query_one(
        connection,
        "select * from approval_requests where request_id = ?",
        &[Value::from(request_id)],
    )?
    else {
        return exact_error("remote_exact_request_not_pending", &resolved_at);
    };
    let changed_raw = changed_request_fields(&raw, expected_raw_request);
    if !changed_raw.is_empty() {
        record_event(
            connection,
            "cloud_review.exact_request_stale",
            &json!({"changed_fields": changed_raw, "request_id": request_id}),
            &resolved_at,
        )?;
        return exact_error("remote_exact_request_stale", &resolved_at);
    }

    // The receipt row is the replay guard: its primary key claims this cloud
    // verdict once, before anything else is written.
    let claimed = exec(
        connection,
        "insert or ignore into guard_exact_cloud_review_receipts (receipt_id, request_id, claimed_at)
         values (?, ?, ?)",
        &[
            Value::from(receipt_id),
            Value::from(request_id),
            Value::from(resolved_at.as_str()),
        ],
    )?;
    if claimed != 1 {
        return Ok(json!({"checked_at": resolved_at, "replayed": true, "resolved": false}));
    }

    // `require_resolvable_approval_request`: a terminal or contract-invalid
    // row is a caller contract error, so the whole transaction - the receipt
    // claim included - is discarded rather than answered.
    if let Some(reason) = block_reason(&current) {
        return value_error(reason);
    }

    let resolved = set_resolution(
        connection,
        request_id,
        [
            Value::from(resolution_action),
            Value::from(resolution_scope),
            Value::from(reason),
            Value::from(resolved_at.as_str()),
        ],
        true,
    )?;
    if resolved != 1 {
        exec(
            connection,
            "delete from guard_exact_cloud_review_receipts where receipt_id = ?",
            &[Value::from(receipt_id)],
        )?;
        return exact_error("remote_exact_apply_failed", &resolved_at);
    }

    if allowing {
        let Some((key, key_id)) = material.as_ref() else {
            return Err(StoreError::Invalid("native_exact_cloud_key_missing"));
        };
        let expires_micros = match capability_expires_micros {
            Some(capability) => capability.min(receipt_expires_micros),
            None => receipt_expires_micros,
        };
        let expires_at = micros_to_utc_isoformat(expires_micros, "+00:00")
            .ok_or(StoreError::Invalid("native_exact_cloud_timestamp_invalid"))?;
        if !persist_local_once_approval(
            connection,
            request_id,
            current_fields,
            &resolved_at,
            &expires_at,
            key,
            key_id,
        )? {
            return Err(StoreError::Runtime(
                "exact Cloud Review request has no exact local authority target".to_owned(),
            ));
        }
    }

    let resolved_request = request(connection, guard_home, request_id, cwd, owner)?;
    record_event(
        connection,
        "cloud_review.exact_applied",
        &json!({
            "receipt_id": receipt_id,
            "request_id": request_id,
            "resolution_action": resolution_action,
            "resolution_scope": resolution_scope,
        }),
        &resolved_at,
    )?;
    Ok(json!({
        "replayed": false,
        "resolved": true,
        "resolved_at": resolved_at,
        "resolved_request": resolved_request,
        "resolved_duplicate_ids": [],
    }))
}

#[cfg(test)]
#[path = "guard_store_exact_cloud_apply_tests.rs"]
mod tests;

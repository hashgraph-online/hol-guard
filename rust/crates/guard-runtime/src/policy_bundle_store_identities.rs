//! The decision identities a cached signed policy bundle authorizes, derived
//! in the resident (`_cached_policy_bundle_decision_identities`,
//! `store_policy.py`).
//!
//! A saved `policy-bundle` row counts only while the bundle Guard Cloud signed
//! still yields it. The lookup keeps such a row when its identity is one of
//! these; a lane that could not derive them used to hand the call back to the
//! Python store. Every step asks the same policy-bundle authority the Python
//! store asked: validation under the stored and machine-managed keyrings, the
//! rollout and downgrade checks, and decision materialization for this device.
//! A bundle that fails any of them authorizes nothing, so its rows are dropped.

use std::collections::HashSet;

use guard_contracts::{
    canonical_utc_timestamp, utc_timestamp_micros, PolicyBundleAuthorityRequestV1,
    POLICY_BUNDLE_AUTHORITY_REQUEST_SCHEMA,
};
use guard_policy_bundle::keys::{keys_to_value, load_keys};
use guard_policy_bundle::python::py_strip;
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::claim_reuse_binding::{cloud_workspace_id, local_device, sync_state_payload};
use crate::managed_policy_load::{
    load_managed_policy, ManagedPolicySource, ManagedPolicyStatus, REGISTRY_UNREADABLE,
};
use crate::policy_decision_lookup_op::{artifact_family_key, workspace_policy_key};

#[cfg(test)]
#[path = "policy_bundle_store_identities_tests.rs"]
mod tests;

/// `CHUNK_CHARS` (`native_policy_bundle.py`).
const CHUNK_CHARS: usize = 100_000;
/// `MAX_DOCUMENT_BYTES` (`native_policy_bundle.py`), counted in characters as
/// `len(text)` counts them.
const MAX_DOCUMENT_CHARS: usize = 3 * 1024 * 1024;
/// `_ORDERING_KEYS` (`policy_bundle_parser.py`).
const ORDERING_KEYS: [&str; 5] = [
    "bundleVersion",
    "bundleHash",
    "payloadHash",
    "issuedAt",
    "workspaceId",
];
/// `GENERIC_DEVICE_LABELS` (`store_inventory.py`).
const GENERIC_DEVICE_LABELS: [&str; 5] = [
    "",
    "local machine",
    "local-device",
    "this machine",
    "localhost",
];
const DEVICE_LABEL_CHOICE_KEY: &str = "device_label_choice";
const DEVICE_NAME_CHARS: usize = 120;

/// One decision identity: harness, scope, artifact id, artifact hash,
/// workspace, publisher, action, reason, owner, source and expiry.
pub(crate) type Identity = Vec<Value>;

/// The identities the cached bundle authorizes at `now`, or `None` when the
/// resident cannot derive them the way the Python store would and the caller
/// must defer. A missing, rejected, inactive or downgraded bundle authorizes
/// nothing (`Some` of an empty list).
pub(crate) fn cached_bundle_identities(
    connection: &Connection,
    now: &str,
) -> Option<Vec<Identity>> {
    let bundle = match sync_payload(connection, "policy_bundle")? {
        Some(Value::Object(bundle)) if !bundle.is_empty() => bundle,
        _ => return Some(Vec::new()),
    };
    let now_epoch = utc_timestamp_micros(now)? as f64 / 1_000_000.0;
    let Some(validated) = validated(connection, &bundle, now_epoch)? else {
        return Some(Vec::new());
    };
    let (device_id, device_label) = local_device(connection).ok()??;
    let device_name = device_display_name(connection, &device_label)?;
    let mut seen = HashSet::new();
    let mut identities = Vec::new();
    for decision in decisions(&validated, &device_id, &device_name)? {
        let identity = identity(decision.as_object()?)?;
        if seen.insert(serde_json::to_string(&identity).ok()?) {
            identities.push(identity);
        }
    }
    Some(identities)
}

/// `cached_policy_bundle_validation`: the payload rules are read from, or
/// `Some(None)` when the bundle is not live authority.
fn validated(
    connection: &Connection,
    bundle: &Map<String, Value>,
    now: f64,
) -> Option<Option<Map<String, Value>>> {
    let (managed_configured, managed_keys) = managed_keys()?;
    let provenance = sync_payload(connection, "managed_policy_bundle_keyring_provenance")?;
    // The store drops every row of a bundle it cannot encode for validation,
    // such as one past the document limit.
    let Some(bundle_chunks) = chunks(&Value::Object(bundle.clone())) else {
        return Some(None);
    };
    let input = json!({
        "stored_keyring": sync_payload(connection, "policy_bundle_keyring")?,
        "sync_keys_raw": null,
        "managed_configured": managed_configured,
        "managed_keys": managed_keys,
        "provenance_present": provenance.is_some(),
        "expected_workspace_id": cloud_workspace_id(connection).ok()?,
        "now": now,
        "key_now": epoch_now()?.as_secs_f64(),
        "now_micros": i64::try_from(epoch_now()?.as_micros()).ok()?,
        "daemon_version": crate::PACKAGE_VERSION,
        "bundle_chunks": bundle_chunks,
    });
    let Ok(result) = authority("validate_synced", input)? else {
        return Some(None);
    };
    if result.get("ok") != Some(&Value::Bool(true)) {
        return Some(None);
    }
    let payload = match result.get("contract").and_then(Value::as_str) {
        Some("v2") => bundle.clone(),
        _ => {
            let (Some(Value::Array(keys)), Some(Value::String(hash))) =
                (result.get("payload_keys"), result.get("payload_hash"))
            else {
                return Some(None);
            };
            let mut payload = Map::new();
            for key in keys.iter().filter_map(Value::as_str) {
                if key != "payloadHash" {
                    payload.insert(key.to_owned(), bundle.get(key)?.clone());
                }
            }
            payload.insert("payloadHash".to_owned(), Value::String(hash.clone()));
            payload
        }
    };
    let slim: Map<String, Value> = ["contractVersion", "rolloutState"]
        .into_iter()
        .filter_map(|key| Some((key.to_owned(), payload.get(key)?.clone())))
        .collect();
    let enforceable = authority("is_enforceable", json!({ "bundle": slim }))?
        .is_ok_and(|result| result.get("value") == Some(&Value::Bool(true)));
    if !enforceable {
        return Some(None);
    }
    if let Some(checkpoint @ Value::Object(_)) =
        sync_payload(connection, "policy_bundle_acceptance_checkpoint")?
    {
        let input = json!({
            "accepted_chunks": chunks(&ordering_view(&checkpoint))?,
            "bundle_chunks": chunks(&ordering_view(&Value::Object(payload.clone())))?,
        });
        let ordered = authority("is_downgrade", input)?
            .is_ok_and(|result| result.get("value") == Some(&Value::Bool(false)));
        if !ordered {
            return Some(None);
        }
    }
    Some(Some(payload))
}

/// `managed_policy_bundle_verification_keys`: whether machine authority owns
/// the keyring, and the keys it anchors. `None` where this build cannot read
/// the authority the Python store would have read.
fn managed_keys() -> Option<(bool, Value)> {
    let state = load_managed_policy(&ManagedPolicySource::native());
    if state.reason_code == Some(REGISTRY_UNREADABLE) {
        return None;
    }
    match state.status {
        ManagedPolicyStatus::Absent => return Some((false, json!([]))),
        ManagedPolicyStatus::Active => {}
        _ => return Some((true, json!([]))),
    }
    let Some(keyring) = state.policy.and_then(|policy| policy.policy_bundle_keyring) else {
        return Some((true, json!([])));
    };
    match load_keys(&keyring, true) {
        Ok(keys) => Some((true, keys_to_value(&keys))),
        Err(_) => Some((true, json!([]))),
    }
}

/// `build_policy_bundle_decisions`, every page of it. A malformed or
/// inconsistent answer authorizes nothing.
fn decisions(
    payload: &Map<String, Value>,
    device_id: &str,
    device_name: &str,
) -> Option<Vec<Value>> {
    let Some(bundle_chunks) = chunks(&Value::Object(payload.clone())) else {
        return Some(Vec::new());
    };
    let mut rows = Vec::new();
    let mut offset: Option<u64> = None;
    let mut total: Option<Value> = None;
    loop {
        let input = json!({
            "bundle_chunks": bundle_chunks,
            "device_id": device_id,
            "device_name": device_name,
            "offset": offset,
        });
        let Ok(page) = authority("build_decisions", input)? else {
            return Some(Vec::new());
        };
        let Some(Value::Array(items)) = page.get("decisions") else {
            return Some(Vec::new());
        };
        if !items.iter().all(Value::is_object)
            || total
                .as_ref()
                .is_some_and(|total| page.get("total") != Some(total))
        {
            return Some(Vec::new());
        }
        total = page.get("total").cloned();
        rows.extend(items.iter().cloned());
        match page.get("next") {
            Some(Value::Number(next)) if next.as_u64() > offset => offset = next.as_u64(),
            Some(Value::Null) => break,
            _ => return Some(Vec::new()),
        }
    }
    if total.and_then(|total| total.as_u64()) != Some(rows.len() as u64) {
        return Some(Vec::new());
    }
    Some(rows)
}

/// The 11-field identity of one materialized decision, keyed the way
/// `_normalized_policy_keys` stores it. Bundle decisions carry no artifact
/// hash or publisher, so both stay unset.
fn identity(decision: &Map<String, Value>) -> Option<Identity> {
    let text = |name: &str| decision.get(name).and_then(Value::as_str);
    let scope = text("scope")?;
    let artifact_id = match scope {
        "harness" | "global" => artifact_family_key(text("artifact_id")),
        "artifact" | "workspace" => text("artifact_id").map(str::to_owned),
        _ => None,
    };
    let workspace = if scope == "workspace" {
        workspace_policy_key(text("workspace"))
    } else {
        None
    };
    let expires_at = match decision.get("expires_at") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(canonical_utc_timestamp(value)?),
        Some(_) => return None,
    };
    let field = |name: &str| decision.get(name).cloned().unwrap_or(Value::Null);
    Some(vec![
        Value::String(text("harness")?.to_owned()),
        Value::String(scope.to_owned()),
        json!(artifact_id),
        Value::Null,
        json!(workspace),
        Value::Null,
        field("action"),
        field("reason"),
        field("owner"),
        Value::String(text("source")?.to_owned()),
        json!(expires_at),
    ])
}

/// `device_display_name`: the stored label, unless it is still a generic one
/// nobody chose, which yields to the host name.
fn device_display_name(connection: &Connection, label: &str) -> Option<String> {
    let chosen = matches!(
        sync_payload(connection, DEVICE_LABEL_CHOICE_KEY),
        Some(Some(Value::Object(choice))) if choice.get("label").and_then(Value::as_str) == Some(label)
    );
    if chosen || !generic_label(label) {
        return Some(label.to_owned());
    }
    Some(machine_display_name(&host_name()?).unwrap_or_else(|| label.to_owned()))
}

/// `machine_display_name`: the host name without its domain, unless generic.
fn machine_display_name(host: &str) -> Option<String> {
    let name = py_strip(host).split('.').next().unwrap_or_default();
    let name = py_strip(name);
    if generic_label(name) {
        return None;
    }
    Some(name.chars().take(DEVICE_NAME_CHARS).collect())
}

fn generic_label(label: &str) -> bool {
    GENERIC_DEVICE_LABELS.contains(&py_strip(label).to_lowercase().as_str())
}

/// `platform.node()`: the node name the device name is derived from.
#[cfg(unix)]
fn host_name() -> Option<String> {
    nix::unistd::gethostname().ok()?.into_string().ok()
}

/// Off Unix, `platform.node()` is the DNS host name, which `COMPUTERNAME`
/// (the upper-cased, 15-character NetBIOS name) does not match. The resident
/// cannot read it yet, so the device name is unknown and the bundle's
/// identities are left to the store.
#[cfg(not(unix))]
fn host_name() -> Option<String> {
    None
}

/// One `sync_state` payload as `get_sync_payload` reads it: `Some(None)` when
/// missing or not a JSON object or list, `None` when it cannot be read.
fn sync_payload(connection: &Connection, key: &str) -> Option<Option<Value>> {
    let Some(text) = sync_state_payload(connection, key).ok()? else {
        return Some(None);
    };
    let value: Value = serde_json::from_str(&text).ok()?;
    Some(matches!(value, Value::Object(_) | Value::Array(_)).then_some(value))
}

/// `_ordering_view` (`policy_bundle_parser.py`).
fn ordering_view(bundle: &Value) -> Value {
    let Value::Object(bundle) = bundle else {
        return bundle.clone();
    };
    let view: Map<String, Value> = ORDERING_KEYS
        .into_iter()
        .filter_map(|key| Some((key.to_owned(), bundle.get(key)?.clone())))
        .collect();
    Value::Object(view)
}

/// `policy_bundle_chunks`: compact JSON text in bounded chunks, or `None`
/// for a document past the limit, which `policy_bundle_chunks` refuses.
fn chunks(document: &Value) -> Option<Vec<String>> {
    let text = serde_json::to_string(document).ok()?;
    let chars: Vec<char> = text.chars().collect();
    if chars.len() > MAX_DOCUMENT_CHARS {
        return None;
    }
    let chunks: Vec<String> = chars
        .chunks(CHUNK_CHARS)
        .map(|chunk| chunk.iter().collect())
        .collect();
    Some(if chunks.is_empty() {
        vec![String::new()]
    } else {
        chunks
    })
}

/// One policy-bundle authority verdict: `Err` with the rejection document
/// when the authority refuses the input, and `None` when the request itself
/// fails, which no store reading can explain.
fn authority(kind: &str, input: Value) -> Option<Result<Map<String, Value>, Map<String, Value>>> {
    let request = PolicyBundleAuthorityRequestV1 {
        schema: POLICY_BUNDLE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        request_id: "resident-bundle-identities".to_owned(),
        kind: kind.to_owned(),
        input,
    };
    let result = guard_policy_bundle::evaluate_with_payload_hasher(
        &request,
        crate::policy_bundle_payload_hash::payload_hash,
    );
    if result.status != "ok" || result.code != "ok" {
        return None;
    }
    match result.result {
        Value::Object(result) if result.contains_key("error") => Some(Err(result)),
        Value::Object(result) => Some(Ok(result)),
        _ => None,
    }
}

fn epoch_now() -> Option<std::time::Duration> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
}

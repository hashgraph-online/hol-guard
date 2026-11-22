//! The remembered allow of an inline-approved relayed forward.
//!
//! When the client's inline prompt approves a relayed call, the relay forwards
//! it and marks its record `remember`. The proxy's `_allow_and_forward` saves
//! the artifact allow (`allow_tool_call(remember=True,
//! emit_runtime_evidence=False)`) before its receipt, and the retired Python
//! drain did the same for a relayed record. The resident does it here: the
//! approval gate is checked again, and the allow is signed with the
//! policy-integrity key under the generation lock, as `upsert_policy` signs
//! it. The call already went out, so a save that fails -- a gate closed since,
//! a key or control state that is unavailable, a store that refused the row --
//! costs the memory, never the receipt.

use std::fs::File;
use std::path::Path;
use std::time::Duration;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::{json, Map, Value};

use crate::encrypted_secret_store::EncryptedFileSecretStore;
use crate::local_mcp_grant_identity::composio_requires_action_review;
use crate::policy_integrity_generation::lock as policy_generation_lock;
use crate::policy_integrity_resolver::{
    build_scoped_secret_ref, finalization_state, load_policy_integrity_control_state,
    policy_integrity_secret_material, POLICY_INTEGRITY_CONTROL_REF,
};

pub(super) const KEY: &str = "remember";
const SOURCE: &str = "inline-approved";
const LOCK_WAIT: Duration = Duration::from_secs(2);
pub(super) const METHOD: &str = "upsert_policy";

/// The record without its `remember` flag, when the flag is the one an
/// inline-approved forward carries; `None` for a malformed flag or one on any
/// other record, which is then not plain.
pub(super) fn stripped(record: &Value) -> Option<Value> {
    let fields = record.as_object()?;
    let text = |key: &str| fields.get(key).and_then(Value::as_str);
    if fields.get(KEY) != Some(&Value::Bool(true))
        || text("kind") != Some("mcp_tool_call")
        || text("decision_source") != Some(SOURCE)
        || text("outcome") != Some("forward")
    {
        return None;
    }
    let mut plain = fields.clone();
    plain.remove(KEY);
    Some(Value::Object(plain))
}

/// The record with its `remember` flag again, for a record handed back before
/// its allow was saved.
pub(super) fn restored(mut record: Value) -> Value {
    if let Some(fields) = record.as_object_mut() {
        fields.insert(KEY.to_owned(), Value::Bool(true));
    }
    record
}

/// The form in which the writer handed a queued record back, when it did: as
/// queued, or without its `remember` flag once its allow was saved, so the
/// retry writes only the receipt and never saves the allow twice.
pub(crate) fn handed_back(queued: &Value, unwritten: &[Value]) -> Option<Value> {
    if unwritten.contains(queued) {
        return Some(queued.clone());
    }
    let forward = stripped(queued)?;
    unwritten.contains(&forward).then_some(forward)
}

/// The policy-generation lock, taken before the storage gate as the daemon's
/// policy writer takes it, so the two writers never wait on each other.
pub(super) fn lock(guard_home: &str) -> Option<File> {
    let home = Path::new(guard_home).canonicalize().ok()?;
    policy_generation_lock::acquire(&home, LOCK_WAIT)
}

/// Save the artifact allow of a composed remembered record while `_held`
/// holds the generation lock (`lock`); `store` runs one store operation and
/// returns its reply. Every failure is swallowed.
pub(super) fn save(
    guard_home: &str,
    record: &Value,
    now: &str,
    _held: &File,
    store: impl FnOnce(Map<String, Value>) -> (Option<Value>, bool),
) {
    let identity = &record["identity"];
    let artifact = &identity["artifact"];
    let (Some(harness), Some(artifact_id), Some(artifact_hash)) = (
        artifact["harness"].as_str(),
        artifact["artifact_id"].as_str(),
        identity["artifact_hash"].as_str(),
    ) else {
        return;
    };
    if composio_requires_action_review(artifact["command"].as_str().unwrap_or("")) {
        return;
    }
    let Ok(home) = Path::new(guard_home).canonicalize() else {
        return;
    };
    if crate::approval_gate_consumers::require_policy_write(
        &home,
        crate::approval_gate_op::grants(),
        "allow",
        "artifact",
        None,
        None,
    )
    .is_err()
    {
        return;
    }
    let mut args = Map::new();
    for (key, value) in [
        ("harness", json!(harness)),
        ("scope", json!("artifact")),
        ("artifact_id", json!(artifact_id)),
        ("artifact_hash", json!(artifact_hash)),
        ("workspace", Value::Null),
        ("publisher", Value::Null),
        ("action", json!("allow")),
        (
            "reason",
            json!(format!("Approved via Guard runtime ({SOURCE})")),
        ),
        ("owner", Value::Null),
        ("source", json!("runtime-inline")),
        ("expires_at", Value::Null),
        ("now", json!(now)),
    ] {
        args.insert(key.to_owned(), value);
    }
    signed(&home, args, store);
}

/// `upsert_policy` under a protected integrity state, with the generation
/// lock held by the caller: the pending generation
/// lands before the row is signed and is finalized from the reply. The prior
/// control state is put back only when the write did not commit. Without key material the allow is not
/// saved, since an unsigned local row is ignored under either state.
fn signed(
    home: &Path,
    mut args: Map<String, Value>,
    store: impl FnOnce(Map<String, Value>) -> (Option<Value>, bool),
) {
    let mut secrets = EncryptedFileSecretStore::new(home);
    let Some(material) = policy_integrity_secret_material(&mut secrets, home) else {
        return;
    };
    let control_ref = build_scoped_secret_ref(POLICY_INTEGRITY_CONTROL_REF, home);
    let Some(current) = control_state(&mut secrets, home, &control_ref) else {
        return;
    };
    let Some(generation) = current
        .get("generation")
        .and_then(Value::as_i64)
        .filter(|generation| *generation >= 0)
    else {
        return;
    };
    if !current.get("pending_generation").is_none_or(Value::is_null) {
        return;
    }
    let Some(next) = generation.checked_add(1) else {
        return;
    };
    let pending = json!({
        "cutover_complete": current["cutover_complete"].as_bool().unwrap_or(true),
        "generation": generation,
        "pending_generation": next,
        "version": 1,
    });
    if !put(&mut secrets, &control_ref, &pending) {
        return;
    }
    args.insert(
        "integrity_key_b64".to_owned(),
        json!(Base64UrlUnpadded::encode_string(&material.raw_key)),
    );
    args.insert("integrity_key_id".to_owned(), json!(material.key_id));
    args.insert("current_generation".to_owned(), json!(generation));
    let (reply, committed) = store(args);
    let finalized = reply
        .and_then(|reply| reply.get("next_control_state").cloned())
        .and_then(|proposed| finalization_state(Some(&pending), &proposed));
    if finalized.is_some_and(|finalized| put(&mut secrets, &control_ref, &finalized)) {
        return;
    }
    if !committed {
        put(&mut secrets, &control_ref, &current);
    }
    // A committed write re-signed every local row at the next generation, so
    // the earlier state would reject them all as a rollback. The pending
    // state stays for the integrity reconcile, which decides the generation.
}

/// The trusted control state, written at generation 0 when the home has
/// none. A control state that exists but does not load is never replaced: it
/// may hold a generation above 0, and resetting it would make every row
/// signed above 0 read as a rollback.
fn control_state(
    secrets: &mut EncryptedFileSecretStore,
    home: &Path,
    control_ref: &str,
) -> Option<Value> {
    if let Some(current) = load_policy_integrity_control_state(secrets, home) {
        return Some(current);
    }
    if secrets.get_secret(control_ref).is_some() {
        return None;
    }
    let initial = json!({
        "cutover_complete": true,
        "generation": 0,
        "pending_generation": null,
        "version": 1,
    });
    put(secrets, control_ref, &initial).then_some(initial)
}

fn put(secrets: &mut EncryptedFileSecretStore, control_ref: &str, state: &Value) -> bool {
    serde_json::to_string(state)
        .ok()
        .is_some_and(|serialized| secrets.set_secret(control_ref, &serialized).is_ok())
}

#[cfg(test)]
#[path = "mcp_relay_receipt_remember_tests.rs"]
mod tests;

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
use std::sync::PoisonError;
use std::time::Duration;

use base64ct::{Base64UrlUnpadded, Encoding};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::encrypted_secret_store::EncryptedFileSecretStore;
use crate::guard_store_op::MAX_BUSY_TIMEOUT_MS;
use crate::hook_direct::saved_decision::consume::repair_store_permissions;
use crate::hook_evidence_store_gate::hold_storage_gate;
use crate::hook_evidence_store_timeout::sqlite_timeout_ms;
use crate::local_mcp_grant_identity::composio_requires_action_review;
use crate::local_store_read::STORE_FILE_NAME;
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
/// other record, which is then not plain. A package call's forward remembers
/// the package request's allow, as `_record_package_forward` saves it.
pub(super) fn stripped(record: &Value) -> Option<Value> {
    let fields = record.as_object()?;
    let text = |key: &str| fields.get(key).and_then(Value::as_str);
    if fields.get(KEY) != Some(&Value::Bool(true))
        || !matches!(text("kind"), Some("mcp_tool_call" | super::package::KIND))
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
/// Match a failed writer result to the acknowledged queue entry by sequence,
/// so equal JSON records cannot make the drain retry the wrong item.
pub(crate) fn handed_back_with_sequence(
    sequence: u64,
    unwritten: &[(u64, Value)],
) -> Option<Value> {
    unwritten
        .iter()
        .find_map(|(candidate_sequence, candidate)| {
            (*candidate_sequence == sequence).then(|| candidate.clone())
        })
}

/// The artifact-scoped allow one remembered approval saves.
pub(crate) struct Allow<'a> {
    pub(crate) harness: &'a str,
    pub(crate) artifact_id: &'a str,
    pub(crate) artifact_hash: &'a str,
    /// The server command `allow_tool_call` reads for a provider action.
    pub(crate) command: Option<&'a str>,
    /// The workspace a package request's allow is bound to.
    pub(crate) workspace: Option<&'a str>,
}

/// The policy-generation lock, taken before the storage gate as the daemon's
/// policy writer takes it, so the two writers never wait on each other.
pub(super) fn lock(guard_home: &str) -> Option<File> {
    let home = Path::new(guard_home).canonicalize().ok()?;
    policy_generation_lock::acquire(&home, LOCK_WAIT)
}

/// Save the allow of a composed remembered record while `_held`
/// holds the generation lock (`lock`); `store` runs one store operation and
/// returns its reply. Every failure is swallowed.
pub(super) fn save(
    guard_home: &str,
    record: &Value,
    now: &str,
    held: &File,
    store: impl FnOnce(Map<String, Value>) -> (Option<Value>, bool),
) {
    let allow = if record["kind"] == super::package::KIND {
        let package = &record["package"];
        let (Some(harness), Some(artifact_id), Some(artifact_hash)) = (
            record["harness"].as_str(),
            package["artifact_id"].as_str(),
            package["artifact_hash"].as_str(),
        ) else {
            return;
        };
        Allow {
            harness,
            artifact_id,
            artifact_hash,
            command: None,
            workspace: package["policy_workspace"].as_str(),
        }
    } else {
        let identity = &record["identity"];
        let artifact = &identity["artifact"];
        let (Some(harness), Some(artifact_id), Some(artifact_hash)) = (
            artifact["harness"].as_str(),
            artifact["artifact_id"].as_str(),
            identity["artifact_hash"].as_str(),
        ) else {
            return;
        };
        Allow {
            harness,
            artifact_id,
            artifact_hash,
            command: artifact["command"].as_str(),
            workspace: None,
        }
    };
    save_allow(guard_home, &allow, now, held, store);
}

/// Save one remembered allow now, as the package lane does before it decides
/// the call again (`allow_tool_call(remember=True)` ahead of
/// `_handle_package_request`). The writer lock, the generation lock and the
/// storage gate are taken in the drain's order. The generation the signed
/// allow was finalized at, or `None` when it was not saved.
pub(crate) fn save_now(guard_home: &str, allow: &Allow<'_>) -> Option<u64> {
    let home = Path::new(guard_home);
    if !home.join(STORE_FILE_NAME).is_file() {
        return None;
    }
    let stamp = super::Stamp::fresh()?;
    let timeout_ms = sqlite_timeout_ms();
    let _writer = super::WRITER.lock().unwrap_or_else(PoisonError::into_inner);
    let held = lock(guard_home)?;
    let _gate = hold_storage_gate(home, Duration::from_millis(timeout_ms.into())).ok()?;
    let busy_timeout_ms = u64::from(timeout_ms).clamp(1, MAX_BUSY_TIMEOUT_MS);
    let saved = save_allow(guard_home, allow, &stamp.store_now, &held, |args| {
        super::evaluate(guard_home, busy_timeout_ms, METHOD, args)
    });
    repair_store_permissions(home);
    saved
}

/// The approval gate and the provider-action check `allow_tool_call` and
/// `upsert_policy` apply, then the signed write while `_held` holds the
/// generation lock. The generation it was finalized at.
fn save_allow(
    guard_home: &str,
    allow: &Allow<'_>,
    now: &str,
    _held: &File,
    store: impl FnOnce(Map<String, Value>) -> (Option<Value>, bool),
) -> Option<u64> {
    if composio_requires_action_review(allow.command.unwrap_or("")) {
        return None;
    }
    let home = Path::new(guard_home).canonicalize().ok()?;
    if saved_block_exists(&home, allow, now)? {
        return None;
    }
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
        return None;
    }
    let mut args = Map::new();
    for (key, value) in [
        ("harness", json!(allow.harness)),
        ("scope", json!("artifact")),
        ("artifact_id", json!(allow.artifact_id)),
        ("artifact_hash", json!(allow.artifact_hash)),
        ("workspace", json!(allow.workspace)),
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
    signed(&home, args, store)
}

/// A block committed after the inline approval wins over the remembered allow.
/// The receipt still records because this check only skips the policy write.
/// A live saved block only: an expired one no longer applies to the lookup.
fn saved_block_exists(home: &Path, allow: &Allow<'_>, now: &str) -> Option<bool> {
    let connection = Connection::open(home.join(STORE_FILE_NAME)).ok()?;
    connection
        .query_row(
            "select exists(
                select 1 from policy_decisions
                where harness = ?1 and scope = 'artifact'
                  and coalesce(artifact_id, '') = coalesce(?2, '')
                  and coalesce(artifact_hash, '') = coalesce(?3, '')
                  and coalesce(workspace, '') = coalesce(?4, '')
                  and coalesce(publisher, '') = ''
                  and action = 'block'
                  and (expires_at is null or julianday(expires_at) > julianday(?5))
            )",
            rusqlite::params![
                allow.harness,
                allow.artifact_id,
                allow.artifact_hash,
                allow.workspace,
                now,
            ],
            |row| row.get(0),
        )
        .ok()
}

/// `upsert_policy` under a protected integrity state, with the generation
/// lock held by the caller: the pending generation
/// lands before the row is signed and is finalized from the reply. The prior
/// control state is put back only when the write did not commit. Without key material the allow is not
/// saved, since an unsigned local row is ignored under either state. The
/// generation the write was finalized at.
fn signed(
    home: &Path,
    mut args: Map<String, Value>,
    store: impl FnOnce(Map<String, Value>) -> (Option<Value>, bool),
) -> Option<u64> {
    let mut secrets = EncryptedFileSecretStore::new(home);
    let material = policy_integrity_secret_material(&mut secrets, home)?;
    let control_ref = build_scoped_secret_ref(POLICY_INTEGRITY_CONTROL_REF, home);
    let current = control_state(&mut secrets, home, &control_ref)?;
    let generation = current
        .get("generation")
        .and_then(Value::as_i64)
        .filter(|generation| *generation >= 0)?;
    if !current.get("pending_generation").is_none_or(Value::is_null) {
        return None;
    }
    let next = generation.checked_add(1)?;
    let pending = json!({
        "cutover_complete": current["cutover_complete"].as_bool().unwrap_or(true),
        "generation": generation,
        "pending_generation": next,
        "version": 1,
    });
    if !put(home, &mut secrets, &control_ref, &pending) {
        // The vault may hold the pending state while the keyring copy was not
        // brought in step. Put the vault back, or every later save would find
        // a pending generation and refuse.
        restore_vault(&mut secrets, &control_ref, &current);
        return None;
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
    if let Some(finalized) =
        finalized.filter(|finalized| put(home, &mut secrets, &control_ref, finalized))
    {
        return finalized.get("generation").and_then(Value::as_u64);
    }
    if !committed {
        put(home, &mut secrets, &control_ref, &current);
    }
    // A committed write re-signed every local row at the next generation, so
    // the earlier state would reject them all as a rollback. The pending
    // state stays for the integrity reconcile, which decides the generation.
    None
}

/// The trusted control state, written at generation 0 when the home has
/// none. A control state that exists but does not load or decrypt is never
/// replaced: it may hold a generation above 0, and resetting it would make
/// every row signed above 0 read as a rollback.
fn control_state(
    secrets: &mut EncryptedFileSecretStore,
    home: &Path,
    control_ref: &str,
) -> Option<Value> {
    if let Some(current) = load_policy_integrity_control_state(secrets, home) {
        return Some(current);
    }
    // `get_secret` answers `None` for a file it cannot read or decrypt as
    // well as for a missing one, so only a missing file is absent.
    match std::fs::symlink_metadata(secrets.path_for(control_ref)) {
        Ok(_) => return None,
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return None,
        Err(_) => {}
    }
    let initial = json!({
        "cutover_complete": true,
        "generation": 0,
        "pending_generation": null,
        "version": 1,
    });
    put(home, secrets, control_ref, &initial).then_some(initial)
}

fn restore_vault(secrets: &mut EncryptedFileSecretStore, control_ref: &str, state: &Value) {
    if let Ok(serialized) = serde_json::to_string(state) {
        let _ = secrets.set_secret(control_ref, &serialized);
    }
}

fn put(
    home: &Path,
    secrets: &mut EncryptedFileSecretStore,
    control_ref: &str,
    state: &Value,
) -> bool {
    let Some(serialized) = serde_json::to_string(state).ok() else {
        return false;
    };
    if secrets.set_secret(control_ref, &serialized).is_err() {
        return false;
    }
    crate::policy_integrity_resolver::key_mint::mirror_existing_control_state(
        home,
        secrets,
        control_ref,
        &serialized,
    )
}

#[cfg(test)]
#[path = "mcp_relay_receipt_remember_tests.rs"]
mod tests;

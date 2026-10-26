//! Re-verification, under the claim's write lock, of the evidence a caller
//! gathered before dispatch.
//!
//! A saved allow is single-use authority. The integrity state, key and
//! policy-bundle identities that decide a claim are procured by the caller
//! outside the store's write lock, so a bundle, keyring, workspace or state
//! change could land between gathering and claiming. Before any member is
//! claimed the resident therefore re-reads the same store-resident sources
//! inside the `BEGIN IMMEDIATE` transaction and refuses the whole batch on any
//! difference. Evidence it cannot bind is never trusted: a missing binding, a
//! missing source or a key that does not match its identity all fail closed.

use guard_contracts::ClaimEvidenceBindingV1;
use guard_policy_snapshot::digest_bytes;
use guard_policy_snapshot::policy_integrity::is_remote_policy_source;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;

use crate::claim_reuse::ClaimEvidence;

/// `sync_state` rows the integrity state is persisted in.
const POLICY_INTEGRITY_STATE_KEY: &str = "policy_integrity";
/// `sync_state` rows a signed policy bundle's validity depends on. All of them
/// must be bound whenever a bundle-derived member is claimed.
pub const BUNDLE_STATE_KEYS: [&str; 5] = [
    "policy_bundle",
    "policy_bundle_keyring",
    "supply_chain_bundle_keyring",
    "managed_policy_bundle_keyring_provenance",
    "policy_bundle_acceptance_checkpoint",
];
/// Where the cloud workspace id the bundle is validated against lives.
const OAUTH_STATE_KEY: &str = "oauth_local_credentials";
const LOCAL_DEVICE_KEY: &str = "local-device";
/// Length of the key digest embedded in a policy-integrity key id.
const KEY_ID_DIGEST_CHARS: usize = 16;

/// Which evidence the selected members actually consult.
#[derive(Default)]
struct Needs {
    policy_state: bool,
    bundle: bool,
}

fn needs(members: &[(&Value, &'static str)]) -> Needs {
    let mut needs = Needs::default();
    for (decision, _) in members {
        if decision
            .get("approval_id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty())
        {
            continue;
        }
        let source = decision.get("source").and_then(Value::as_str);
        needs.policy_state |= source.is_some() && !is_remote_policy_source(source);
        needs.bundle |= source == Some("policy-bundle");
    }
    needs
}

fn sync_state_payload(connection: &Connection, key: &str) -> rusqlite::Result<Option<String>> {
    Ok(connection
        .query_row(
            "select payload_json from sync_state where state_key = ?1",
            params![key],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten())
}

/// The integrity state shipped with the claim must still be the persisted one,
/// and the shipped key must be the key that state names.
fn policy_state_is_bound(
    connection: &Connection,
    evidence: &ClaimEvidence<'_>,
) -> rusqlite::Result<bool> {
    let Some(shipped) = evidence.integrity_state else {
        return Ok(false);
    };
    let Some(stored) = sync_state_payload(connection, POLICY_INTEGRITY_STATE_KEY)? else {
        return Ok(false);
    };
    match serde_json::from_str::<Value>(&stored) {
        Ok(stored) if &stored == shipped => {}
        _ => return Ok(false),
    }
    let Some(key) = evidence.integrity_key else {
        return Ok(true);
    };
    let Some(key_id) = evidence.integrity_key_id else {
        return Ok(false);
    };
    let digest = digest_bytes(key);
    let named_digest = key_id.rsplit(':').next().unwrap_or("");
    if named_digest.len() != KEY_ID_DIGEST_CHARS || !digest.starts_with(named_digest) {
        return Ok(false);
    }
    Ok(shipped
        .get("key_id")
        .and_then(Value::as_str)
        .is_none_or(|state_key_id| state_key_id == key_id))
}

fn cloud_workspace_id(connection: &Connection) -> rusqlite::Result<Option<String>> {
    let Some(stored) = sync_state_payload(connection, OAUTH_STATE_KEY)? else {
        return Ok(None);
    };
    Ok(serde_json::from_str::<Value>(&stored)
        .ok()
        .and_then(|payload| {
            payload
                .get("workspace_id")
                .and_then(Value::as_str)
                .filter(|id| !id.trim().is_empty())
                .map(str::to_owned)
        }))
}

fn local_device(connection: &Connection) -> rusqlite::Result<Option<(String, String)>> {
    connection
        .query_row(
            "select installation_id, device_label from guard_devices where device_key = ?1",
            params![LOCAL_DEVICE_KEY],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
}

/// The bundle, its keyrings, its acceptance checkpoint, the workspace it is
/// validated for and the device its rows are materialized for must all be the
/// ones the shipped identities were derived from.
fn bundle_is_bound(
    connection: &Connection,
    binding: &ClaimEvidenceBindingV1,
) -> rusqlite::Result<bool> {
    for key in BUNDLE_STATE_KEYS {
        let Some(bound) = binding.sync_state_sha256.get(key) else {
            return Ok(false);
        };
        let current =
            sync_state_payload(connection, key)?.map(|text| digest_bytes(text.as_bytes()));
        if current != *bound {
            return Ok(false);
        }
    }
    if cloud_workspace_id(connection)? != binding.cloud_workspace_id {
        return Ok(false);
    }
    let device = local_device(connection)?;
    let bound_device = binding
        .device
        .as_ref()
        .map(|device| (device.installation_id.clone(), device.device_label.clone()));
    Ok(device == bound_device)
}

/// `Ok(true)` only when every source the selected members' evidence was derived
/// from is unchanged. Must run inside the claim's write transaction.
pub fn evidence_is_bound(
    connection: &Connection,
    members: &[(&Value, &'static str)],
    evidence: &ClaimEvidence<'_>,
    binding: Option<&ClaimEvidenceBindingV1>,
) -> rusqlite::Result<bool> {
    let needs = needs(members);
    if !needs.policy_state && !needs.bundle {
        return Ok(true);
    }
    let Some(binding) = binding else {
        return Ok(false);
    };
    if needs.policy_state && !policy_state_is_bound(connection, evidence)? {
        return Ok(false);
    }
    if needs.bundle && !bundle_is_bound(connection, binding)? {
        return Ok(false);
    }
    Ok(true)
}

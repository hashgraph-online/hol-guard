#![forbid(unsafe_code)]

//! Native resident policy-snapshot state.
//!
//! The store is intentionally owned by the resident process. Hook requests
//! can only compare their envelope to this already-installed snapshot; they
//! cannot install or mutate policy while a decision is in flight.

use guard_policy_snapshot::{
    snapshot_bytes, validate_v3, PolicySnapshotAckV1, PolicySnapshotPushV1, PolicySnapshotV3,
    POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION, POLICY_SNAPSHOT_MAX_BYTES,
    POLICY_SNAPSHOT_PUSH_SCHEMA,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[path = "policy_store_authority.rs"]
mod policy_store_authority;
#[path = "policy_store_migration.rs"]
mod policy_store_migration;
#[path = "policy_store_persistence.rs"]
mod policy_store_persistence;

use policy_store_authority::*;
use policy_store_persistence::*;

#[cfg(test)]
#[path = "policy_store_tests.rs"]
mod tests;
const SNAPSHOT_FILE_NAME: &str = "policy-snapshot-v3.json";
const GENERATION_FLOOR_FILE_NAME: &str = "policy-snapshot-generation-floor.json";
const VERIFIER_KEY_FILE_NAME: &str = "policy-verifier.key";
const VERIFIER_KEY_BYTES: usize = 32;
const MAX_KEY_FILE_BYTES: u64 = VERIFIER_KEY_BYTES as u64;
const MAX_FLOOR_BYTES: u64 = 8 * 1024;
const GENERATION_FLOOR_SCHEMA: &str = "guard-policy-snapshot-generation-floor.v1";
const AUTHORITY_RECORD_SCHEMA: &str = "guard-policy-snapshot-authority.v3";
const AUTHORITY_RECORD_MAX_BYTES: u64 = POLICY_SNAPSHOT_MAX_BYTES as u64 + 16 * 1024;

#[derive(Clone, Copy)]
#[repr(u8)]
enum PersistBoundary {
    TemporaryCreate = 1,
    Write = 2,
    FileSync = 3,
    Rename = 4,
    DirectorySync = 5,
}

#[cfg(test)]
thread_local! {
    static PERSIST_FAILPOINT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

fn persistence_fault(boundary: PersistBoundary) -> Result<(), String> {
    #[cfg(test)]
    if PERSIST_FAILPOINT.with(|failpoint| {
        if failpoint.get() == boundary as u8 {
            failpoint.set(0);
            true
        } else {
            false
        }
    }) {
        return Err("native_policy_snapshot_authority_persistence_failed".to_owned());
    }
    #[cfg(not(test))]
    let _ = boundary;
    Ok(())
}

/// One atomically replaced record is the durable source of truth for both the
/// accepted generation floor and the corresponding snapshot.  The old floor
/// and snapshot files are read only during migration; no push writes either
/// file independently.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyAuthorityRecordV3 {
    pub(super) schema: String,
    pub(super) generation_floor: u64,
    pub(super) policy_digest: String,
    pub(super) snapshot: Option<PolicySnapshotV3>,
    pub(super) floor_mac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationFloorV1 {
    pub(super) schema: String,
    pub(super) generation: u64,
    pub(super) policy_digest: String,
    pub(super) mac: String,
}

struct PolicyState {
    pub(super) snapshot: Option<PolicySnapshotV3>,
    pub(super) canonical_bytes: Vec<u8>,
    pub(super) generation_floor: u64,
    /// Digest authenticated together with `generation_floor`.  It remains
    /// available when a restart recovered only the monotonic floor, so a
    /// retry can receive a typed, bounded recovery ACK without trusting the
    /// incoming snapshot as authority.
    pub(super) policy_digest: Option<String>,
    pub(super) invalid_on_startup: bool,
}

struct LoadedAuthority {
    pub(super) snapshot: Option<PolicySnapshotV3>,
    pub(super) canonical_bytes: Vec<u8>,
    pub(super) generation_floor: u64,
    pub(super) policy_digest: Option<String>,
    pub(super) invalid_on_startup: bool,
    pub(super) migrate: bool,
}

pub(crate) struct PolicySnapshotStore {
    /// The authority record lives at the historical snapshot path so older
    /// launchers still recognize that native policy state exists.
    authority_path: PathBuf,
    expected_runtime_identity: String,
    expected_rule_digest: String,
    expected_guard_home: String,
    expected_scope_digest: String,
    verifier_key: [u8; VERIFIER_KEY_BYTES],
    state: Mutex<PolicyState>,
}

impl PolicySnapshotStore {
    pub(crate) fn new(state_base: &Path, runtime_identity: &str) -> Result<Self, String> {
        validate_private_directory(state_base)?;
        let verifier_key = read_verifier_key(state_base)?;
        let authority_path = state_base.join(SNAPSHOT_FILE_NAME);
        recover_authority_replacement(&authority_path)?;
        let (expected_guard_home, expected_scope_digest) = scope_binding_for_state_base(state_base);
        let expected_rule_digest = guard_rule_contract::rule_digest();
        let loaded = load_current_authority(
            &authority_path,
            runtime_identity,
            &expected_rule_digest,
            &expected_scope_digest,
            &verifier_key,
        )?;
        Ok(Self {
            authority_path,
            expected_runtime_identity: runtime_identity.to_owned(),
            expected_rule_digest,
            expected_guard_home,
            expected_scope_digest,
            verifier_key,
            state: Mutex::new(PolicyState {
                snapshot: loaded.snapshot,
                canonical_bytes: loaded.canonical_bytes,
                generation_floor: loaded.generation_floor,
                policy_digest: loaded.policy_digest,
                invalid_on_startup: loaded.invalid_on_startup,
            }),
        })
    }

    /// Migrate pre-transactional policy files only when an explicit upgrade
    /// command requests it. Resident startup never reads the legacy files.
    pub(crate) fn migrate_legacy_state(
        state_base: &Path,
        runtime_identity: &str,
    ) -> Result<(), String> {
        validate_private_directory(state_base)?;
        let verifier_key = read_verifier_key(state_base)?;
        let authority_path = state_base.join(SNAPSHOT_FILE_NAME);
        let legacy_floor_path = state_base.join(GENERATION_FLOOR_FILE_NAME);
        recover_authority_replacement(&authority_path)?;
        let (_, expected_scope_digest) = scope_binding_for_state_base(state_base);
        let expected_rule_digest = guard_rule_contract::rule_digest();
        let loaded = load_authority(
            &authority_path,
            &legacy_floor_path,
            runtime_identity,
            &expected_rule_digest,
            &expected_scope_digest,
            &verifier_key,
        )?;
        if loaded.migrate {
            if let Some(digest) = loaded.policy_digest.as_deref() {
                persist_authority(
                    &authority_path,
                    loaded.generation_floor,
                    digest,
                    loaded.snapshot.as_ref(),
                    &verifier_key,
                )?;
            }
        }
        Ok(())
    }

    pub(crate) fn push(&self, value: &Value) -> Result<Vec<u8>, String> {
        let request: PolicySnapshotPushV1 = serde_json::from_value(value.clone())
            .map_err(|_| "native_policy_snapshot_push_invalid".to_owned())?;
        if request.schema != POLICY_SNAPSHOT_PUSH_SCHEMA {
            return Err("native_policy_snapshot_push_schema_mismatch".to_owned());
        }
        let snapshot_bytes = snapshot_bytes(&request.snapshot).map_err(snapshot_error)?;
        let now = now_ms()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "native_policy_snapshot_state_unavailable".to_owned())?;
        if state.invalid_on_startup && state.generation_floor == 0 {
            return Err("native_policy_snapshot_invalid".to_owned());
        }
        // Validate the candidate's own signature and all identity/expiry
        // bindings before considering floor recovery.  A malformed or
        // unauthenticated request can never elicit the recovery status.
        let minimum_generation = if state.snapshot.is_none()
            && state.policy_digest.is_some()
            && request.snapshot.generation <= state.generation_floor
        {
            1
        } else {
            state.generation_floor.max(1)
        };
        validate_v3(
            &request.snapshot,
            minimum_generation,
            &self.expected_runtime_identity,
            &self.expected_rule_digest,
            &self.verifier_key,
            now,
        )
        .map_err(snapshot_error)?;
        if let Some(current) = state.snapshot.as_ref() {
            if request.snapshot.generation < current.generation {
                return Err("native_policy_snapshot_generation_downgrade".to_owned());
            }
            if request.snapshot.generation == current.generation {
                if snapshot_bytes != state.canonical_bytes {
                    return Err("native_policy_snapshot_generation_reused".to_owned());
                }
                return encode_ack(current, true);
            }
        } else if request.snapshot.generation <= state.generation_floor {
            // There is no current snapshot to compare for normal idempotent
            // retry.  The authenticated floor is still authoritative, so
            // equal/older input must force the publisher to allocate a new
            // generation rather than silently reusing the floor.
            return encode_requires_new_generation(&state);
        }
        persist_authority(
            &self.authority_path,
            request.snapshot.generation,
            &request.snapshot.policy_digest,
            Some(&request.snapshot),
            &self.verifier_key,
        )?;
        state.generation_floor = request.snapshot.generation;
        state.policy_digest = Some(request.snapshot.policy_digest.clone());
        state.snapshot = Some(request.snapshot.clone());
        state.canonical_bytes = snapshot_bytes;
        state.invalid_on_startup = false;
        encode_ack(&request.snapshot, false)
    }

    pub(crate) fn validate_request_snapshot(
        &self,
        value: &Value,
        guard_home: &str,
        generation: u64,
    ) -> Result<PolicySnapshotV3, String> {
        let incoming: PolicySnapshotV3 = serde_json::from_value(value.clone())
            .map_err(|_| "native_policy_snapshot_invalid".to_owned())?;
        let incoming_bytes = snapshot_bytes(&incoming).map_err(snapshot_error)?;
        let now = now_ms()?;
        let state = self
            .state
            .lock()
            .map_err(|_| "native_policy_snapshot_state_unavailable".to_owned())?;
        if state.invalid_on_startup {
            return Err("native_policy_snapshot_invalid".to_owned());
        }
        let Some(current) = state.snapshot.as_ref() else {
            return Err("native_policy_snapshot_missing".to_owned());
        };
        validate_v3(
            current,
            state.generation_floor.max(1),
            &self.expected_runtime_identity,
            &self.expected_rule_digest,
            &self.verifier_key,
            now,
        )
        .map_err(snapshot_error)?;
        if generation != current.generation || incoming.generation != current.generation {
            return Err("native_policy_snapshot_not_current".to_owned());
        }
        if incoming_bytes != state.canonical_bytes {
            return Err("native_policy_snapshot_request_mismatch".to_owned());
        }
        if normalize_scope_text(guard_home) != self.expected_guard_home
            || current.scope_contract.scope_digest != self.expected_scope_digest
        {
            return Err("native_policy_snapshot_scope_mismatch".to_owned());
        }
        Ok(current.clone())
    }

    #[cfg(test)]
    pub(crate) fn current_generation(&self) -> Option<u64> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.snapshot.as_ref().map(|snapshot| snapshot.generation))
    }
}

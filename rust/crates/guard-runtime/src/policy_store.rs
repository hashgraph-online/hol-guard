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
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

#[path = "approval_authority.rs"]
pub(crate) mod approval_authority;
#[path = "approval_enrollment.rs"]
pub(crate) mod approval_enrollment;
#[path = "approval_v4_assertion_state.rs"]
pub(crate) mod approval_v4_assertion_state;
#[path = "approval_v4_authority.rs"]
pub(crate) mod approval_v4_authority;
#[path = "approval_v4_enrollment.rs"]
pub(crate) mod approval_v4_enrollment;
#[path = "approval_v4_secure_state.rs"]
pub(crate) mod approval_v4_secure_state;
#[path = "policy_store_approval.rs"]
mod policy_store_approval;
#[path = "policy_store_authority.rs"]
mod policy_store_authority;
#[path = "policy_store_migration.rs"]
mod policy_store_migration;
#[path = "policy_store_persistence.rs"]
mod policy_store_persistence;

use approval_authority::ApprovalAuthority;
use approval_v4_authority::ApprovalV4Authority;
pub(crate) use policy_store_approval::ApprovalPolicyFence;
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

#[cfg(test)]
pub(crate) fn scope_digest_for_test(state_base: &Path) -> String {
    scope_binding_for_state_base(state_base).1
}

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
    pub(super) snapshot: Option<Arc<PolicySnapshotV3>>,
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
    // Managed resident startup generation; zero for direct store tests.
    resident_generation: u64,
    verifier_key: [u8; VERIFIER_KEY_BYTES],
    approval_authority: Option<ApprovalAuthority>,
    approval_authority_observed: Arc<Mutex<Option<String>>>,
    approval_v4_authority: Option<ApprovalV4Authority>,
    approval_v4_authority_observed: Arc<Mutex<Option<String>>>,
    approval_replay_memory: crate::approval::ApprovalReplayMemory,
    authority_observed: Arc<Mutex<Option<String>>>,
    authority_changed: Arc<AtomicBool>,
    state: Mutex<PolicyState>,
}

impl PolicySnapshotStore {
    #[cfg(test)]
    pub(crate) fn new(state_base: &Path, runtime_identity: &str) -> Result<Self, String> {
        Self::new_with_resident_generation(state_base, runtime_identity, 0)
    }
    pub(crate) fn new_with_resident_generation(
        state_base: &Path,
        runtime_identity: &str,
        resident_generation: u64,
    ) -> Result<Self, String> {
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
        let approval_authority = approval_authority::load(state_base)?;
        let approval_v4_authority = approval_v4_authority::load(state_base)?;
        let approval_authority_observed = Arc::new(Mutex::new(
            approval_authority
                .as_ref()
                .map(|authority| authority.fingerprint.clone())
                .or_else(|| {
                    authority_fingerprint(
                        &state_base.join(approval_authority::APPROVAL_AUTHORITY_FILE_NAME),
                    )
                }),
        ));
        let approval_v4_authority_observed = Arc::new(Mutex::new(
            approval_v4_authority
                .as_ref()
                .map(|authority| authority.fingerprint.clone())
                .or_else(|| {
                    authority_fingerprint(
                        &state_base.join(approval_v4_authority::AUTHORITY_FILE_NAME),
                    )
                }),
        ));
        let approval_replay_memory = crate::approval::ApprovalReplayMemory::new()?;
        let authority_observed = Arc::new(Mutex::new(authority_fingerprint(&authority_path)));
        let authority_changed = Arc::new(AtomicBool::new(false));
        start_authority_watcher(
            authority_path.clone(),
            Arc::clone(&authority_observed),
            Arc::downgrade(&authority_changed),
        );
        start_authority_watcher(
            state_base.join(approval_authority::APPROVAL_AUTHORITY_FILE_NAME),
            Arc::clone(&approval_authority_observed),
            Arc::downgrade(&authority_changed),
        );
        start_authority_watcher(
            state_base.join(approval_v4_authority::AUTHORITY_FILE_NAME),
            Arc::clone(&approval_v4_authority_observed),
            Arc::downgrade(&authority_changed),
        );
        Ok(Self {
            authority_path,
            expected_runtime_identity: runtime_identity.to_owned(),
            expected_rule_digest,
            expected_guard_home,
            expected_scope_digest,
            resident_generation,
            verifier_key,
            approval_authority,
            approval_authority_observed,
            approval_v4_authority,
            approval_v4_authority_observed,
            approval_replay_memory,
            authority_observed,
            authority_changed,
            state: Mutex::new(PolicyState {
                snapshot: loaded.snapshot.map(Arc::new),
                canonical_bytes: loaded.canonical_bytes,
                generation_floor: loaded.generation_floor,
                policy_digest: loaded.policy_digest,
                invalid_on_startup: loaded.invalid_on_startup,
            }),
        })
    }

    /// Migrate legacy policy files only on an explicit upgrade command.
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
        // Validate the candidate before considering authenticated floor recovery.
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
                return encode_ack(current.as_ref(), true, self.resident_generation);
            }
        } else if request.snapshot.generation <= state.generation_floor {
            // There is no current snapshot to compare for normal idempotent
            // retry.  The authenticated floor is still authoritative, so
            // equal/older input must force the publisher to allocate a new
            // generation rather than silently reusing the floor.
            return encode_requires_new_generation(&state, self.resident_generation);
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
        state.snapshot = Some(Arc::new(request.snapshot.clone()));
        state.canonical_bytes = snapshot_bytes;
        state.invalid_on_startup = false;
        if let Ok(mut observed) = self.authority_observed.lock() {
            *observed = authority_fingerprint(&self.authority_path);
        } else {
            self.authority_changed.store(true, Ordering::SeqCst);
        }
        self.authority_changed.store(
            !policy_store_authority::authorities_unchanged(self),
            Ordering::SeqCst,
        );
        encode_ack(&request.snapshot, false, self.resident_generation)
    }

    pub(crate) fn validate_request_snapshot(
        &self,
        value: &Value,
        guard_home: &str,
        generation: u64,
    ) -> Result<Arc<PolicySnapshotV3>, String> {
        let now = now_ms()?;
        let state = self
            .state
            .lock()
            .map_err(|_| "native_policy_snapshot_state_unavailable".to_owned())?;
        self.validate_request_snapshot_locked(&state, value, guard_home, generation, now)
    }

    fn validate_request_snapshot_locked(
        &self,
        state: &PolicyState,
        value: &Value,
        guard_home: &str,
        generation: u64,
        now: u64,
    ) -> Result<Arc<PolicySnapshotV3>, String> {
        if self.authority_changed.load(Ordering::SeqCst)
            || !policy_store_authority::authority_unchanged_fenced(self)
        {
            return Err("native_policy_snapshot_context_mismatch".to_owned());
        }
        if state.invalid_on_startup {
            return Err("native_policy_snapshot_invalid".to_owned());
        }
        let Some(current) = state.snapshot.as_ref() else {
            return Err("native_policy_snapshot_missing".to_owned());
        };
        if current.expires_at_ms <= now {
            return Err("snapshot_expired".to_owned());
        }
        if generation != current.generation {
            return Err("native_policy_snapshot_not_current".to_owned());
        }
        let Some(reference) = value.as_object() else {
            return Err("native_policy_snapshot_invalid".to_owned());
        };
        let compact_keys = ["generation", "policy_digest", "runtime_identity"];
        let is_compact_reference = reference.len() == compact_keys.len()
            && compact_keys.iter().all(|key| reference.contains_key(*key));
        if is_compact_reference {
            let reference_generation = reference
                .get("generation")
                .and_then(Value::as_u64)
                .ok_or_else(|| "native_policy_snapshot_invalid".to_owned())?;
            let policy_digest = reference
                .get("policy_digest")
                .and_then(Value::as_str)
                .ok_or_else(|| "native_policy_snapshot_invalid".to_owned())?;
            let runtime_identity = reference
                .get("runtime_identity")
                .and_then(Value::as_str)
                .ok_or_else(|| "native_policy_snapshot_invalid".to_owned())?;
            if reference_generation != current.generation
                || policy_digest != current.policy_digest
                || runtime_identity != self.expected_runtime_identity
            {
                return Err("native_policy_snapshot_request_mismatch".to_owned());
            }
        } else {
            let incoming: PolicySnapshotV3 = serde_json::from_value(value.clone())
                .map_err(|_| "native_policy_snapshot_invalid".to_owned())?;
            let incoming_bytes = snapshot_bytes(&incoming).map_err(snapshot_error)?;
            if incoming.generation != current.generation || incoming_bytes != state.canonical_bytes
            {
                return Err("native_policy_snapshot_request_mismatch".to_owned());
            }
        }
        if canonical_scope_text(guard_home) != self.expected_guard_home
            || current.scope_contract.scope_digest != self.expected_scope_digest
        {
            return Err("native_policy_snapshot_scope_mismatch".to_owned());
        }
        Ok(Arc::clone(current))
    }

    /// Fence an approval challenge to the resident's current authenticated
    /// snapshot. The callback runs while the state mutex is held, so action
    /// reconstruction and binding derivation cannot observe a policy push in
    /// between. The callback must not call APIs that reacquire `state`.
    pub(crate) fn with_approval_fence<F, T>(
        &self,
        envelope: &guard_contracts::GuardHookEnvelopeV2,
        callback: F,
    ) -> Result<T, String>
    where
        F: FnOnce(&PolicySnapshotV3) -> Result<T, String>,
    {
        let now = now_ms()?;
        let state = self
            .state
            .lock()
            .map_err(|_| "native_policy_snapshot_state_unavailable".to_owned())?;
        let snapshot = self.validate_request_snapshot_locked(
            &state,
            &envelope.policy_snapshot,
            &envelope.source.guard_home,
            envelope.policy_generation,
            now,
        )?;
        callback(snapshot.as_ref())
    }

    pub(crate) fn current_snapshot(&self) -> Result<PolicySnapshotV3, String> {
        let now = now_ms()?;
        if self.authority_changed.load(Ordering::SeqCst)
            || !policy_store_authority::authority_unchanged_fenced(self)
        {
            return Err("native_policy_snapshot_context_mismatch".to_owned());
        }
        let state = self
            .state
            .lock()
            .map_err(|_| "native_policy_snapshot_state_unavailable".to_owned())?;
        if state.invalid_on_startup {
            return Err("native_policy_snapshot_invalid".to_owned());
        }
        let snapshot = state
            .snapshot
            .as_ref()
            .ok_or_else(|| "native_policy_snapshot_missing".to_owned())?;
        validate_v3(
            snapshot,
            state.generation_floor.max(1),
            &self.expected_runtime_identity,
            &self.expected_rule_digest,
            &self.verifier_key,
            now,
        )
        .map_err(snapshot_error)?;
        Ok(snapshot.as_ref().clone())
    }

    #[cfg(test)]
    pub(crate) fn current_generation(&self) -> Option<u64> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.snapshot.as_ref().map(|snapshot| snapshot.generation))
    }
}

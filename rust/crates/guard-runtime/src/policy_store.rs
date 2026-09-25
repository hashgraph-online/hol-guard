#![forbid(unsafe_code)]

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
#[path = "policy_store_command_authority.rs"]
mod policy_store_command_authority;
#[path = "policy_store_command_floor.rs"]
mod policy_store_command_floor;
#[path = "policy_store_migration.rs"]
mod policy_store_migration;
#[path = "policy_store_persistence.rs"]
mod policy_store_persistence;
#[path = "policy_store_request.rs"]
mod policy_store_request;
#[path = "policy_store_validation.rs"]
mod policy_store_validation;

use crate::policy_enforcement::AdmittedPolicySnapshot;
use approval_authority::ApprovalAuthority;
use approval_v4_authority::ApprovalV4Authority;
pub(crate) use policy_store_approval::ApprovalPolicyFence;
use policy_store_authority::*;
use policy_store_persistence::*;
use policy_store_validation::{read_verifier_key, validate_private_directory};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyAuthorityRecordV3 {
    pub(super) schema: String,
    pub(super) generation_floor: u64,
    pub(super) policy_digest: String,
    pub(super) snapshot: Option<PolicySnapshotV3>,
    pub(super) floor_mac: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) command_control_floor: Option<policy_store_command_floor::CommandControlFloor>,
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
    pub(super) snapshot: Option<Arc<AdmittedPolicySnapshot>>,
    pub(super) canonical_bytes: Vec<u8>,
    pub(super) generation_floor: u64,
    pub(super) policy_digest: Option<String>,
    pub(super) invalid_on_startup: bool,
    pub(super) command_control_floor: Option<policy_store_command_floor::CommandControlFloor>,
}

struct LoadedAuthority {
    pub(super) snapshot: Option<PolicySnapshotV3>,
    pub(super) canonical_bytes: Vec<u8>,
    pub(super) generation_floor: u64,
    pub(super) policy_digest: Option<String>,
    pub(super) invalid_on_startup: bool,
    pub(super) migrate: bool,
    pub(super) command_control_floor: Option<policy_store_command_floor::CommandControlFloor>,
}

pub(crate) struct PolicySnapshotStore {
    authority_path: PathBuf,
    expected_runtime_identity: String,
    expected_rule_digest: String,
    expected_guard_home: String,
    expected_scope_digest: String,
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
        let (admitted_snapshot, admission_failed) = match loaded.snapshot.as_ref() {
            Some(snapshot) => match AdmittedPolicySnapshot::new(snapshot.clone()) {
                Ok(snapshot) => (Some(Arc::new(snapshot)), false),
                Err(_) => (None, true),
            },
            None => (None, false),
        };
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
                snapshot: admitted_snapshot,
                canonical_bytes: loaded.canonical_bytes,
                generation_floor: loaded.generation_floor,
                policy_digest: loaded.policy_digest,
                invalid_on_startup: loaded.invalid_on_startup || admission_failed,
                command_control_floor: loaded.command_control_floor,
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
        let _command_lease = self.command_authority_lease(&request.snapshot)?;
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
        let control_floor = policy_store_command_floor::next_floor(
            state.command_control_floor.as_ref(),
            &request.snapshot,
        )?;
        let admitted = Arc::new(AdmittedPolicySnapshot::new(request.snapshot)?);
        let mut observed = match self.authority_observed.lock() {
            Ok(observed) => observed,
            Err(_) => {
                self.authority_changed.store(true, Ordering::SeqCst);
                return Err("native_policy_snapshot_context_mismatch".to_owned());
            }
        };
        // The watcher samples the authority while holding this same lock. Keep
        // it across the atomic replacement and expected-fingerprint publication
        // so a legitimate push never presents a new file with an old expected
        // identity to the watcher.
        persist_authority_with_control_floor(
            &self.authority_path,
            admitted.generation,
            &admitted.policy_digest,
            Some(admitted.snapshot()),
            &self.verifier_key,
            control_floor.as_ref(),
        )?;
        state.generation_floor = admitted.generation;
        state.policy_digest = Some(admitted.policy_digest.clone());
        state.snapshot = Some(Arc::clone(&admitted));
        state.canonical_bytes = snapshot_bytes;
        state.invalid_on_startup = false;
        state.command_control_floor = control_floor;
        *observed = authority_fingerprint(&self.authority_path);
        drop(observed);
        self.authority_changed.store(
            !policy_store_authority::authorities_unchanged(self),
            Ordering::SeqCst,
        );
        encode_ack(admitted.snapshot(), false, self.resident_generation)
    }

    #[cfg(test)]
    pub(crate) fn current_generation(&self) -> Option<u64> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.snapshot.as_ref().map(|snapshot| snapshot.generation))
    }
}

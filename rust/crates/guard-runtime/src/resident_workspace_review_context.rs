#![forbid(unsafe_code)]

//! Native workspace-review context for Cloud Review upload.
//!
//! This operation exposes only public authority metadata and digests derived
//! from the resident-owned request snapshot. It never verifies or consumes a
//! decision envelope, and it never changes the resident replay set.
//! Authority loading can persist a verified enrollment transition and clock.

use guard_contracts::{WorkspaceReviewAuthorityV1, NATIVE_WORKSPACE_REVIEW_MAX_AUTHORITY_BYTES};
use guard_policy_snapshot::{canonical_json_bytes, digest_bytes};
use serde_json::{json, Value};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use super::PolicySnapshotStore;

pub(crate) const CONTEXT_SCHEMA: &str = "guard-native-workspace-review-context.v1";
pub(crate) const CONTEXT_VERSION: u16 = 1;

fn now_ms() -> Result<u64, String> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "native_resident_clock_invalid".to_owned())?
        .as_millis();
    u64::try_from(value).map_err(|_| "native_resident_clock_invalid".to_owned())
}

fn installed_authority_record(
    state_base: &Path,
) -> Result<(WorkspaceReviewAuthorityV1, Vec<u8>), String> {
    let private_root = crate::resident_state::private_root_for_state_base(state_base)?;
    let path = state_base.join(super::workspace_review_authority::AUTHORITY_FILE_NAME);
    let Some((value, bytes)) = super::policy_store_persistence::read_private_json(
        &path,
        NATIVE_WORKSPACE_REVIEW_MAX_AUTHORITY_BYTES as u64,
        "workspace_review_authority",
        &private_root,
    )
    .map_err(|_| "native_workspace_review_authority_invalid".to_owned())?
    else {
        return Err("native_workspace_review_authority_missing".to_owned());
    };
    let canonical = canonical_json_bytes(&value)
        .map_err(|_| "native_workspace_review_authority_invalid".to_owned())?;
    if canonical != bytes {
        return Err("native_workspace_review_authority_noncanonical".to_owned());
    }
    let record = serde_json::from_value(value)
        .map_err(|_| "native_workspace_review_authority_invalid".to_owned())?;
    Ok((record, bytes))
}

pub(crate) fn build_context(
    policy_store: &PolicySnapshotStore,
    request_id: &str,
) -> Result<Value, String> {
    super::approval_enrollment::with_transition_lock(policy_store.state_base(), || {
        build_context_under_lock(policy_store, request_id)
    })
}

fn build_context_under_lock(
    policy_store: &PolicySnapshotStore,
    request_id: &str,
) -> Result<Value, String> {
    let state_base = policy_store.state_base();
    let snapshot = policy_store.current_snapshot()?;
    let (workspace_binding, scope_binding) =
        super::workspace_review_decision::current_native_workspace_review_bindings(
            state_base,
            &snapshot.scope_contract.scope_digest,
        )?;
    let authority =
        super::workspace_review_authority::read_installed_record(state_base, now_ms()?)?
            .ok_or_else(|| "native_workspace_review_authority_missing".to_owned())?;
    super::workspace_review_decision::ensure_current_native_workspace_review_provenance(
        &authority,
        &workspace_binding,
        &scope_binding,
    )?;
    let request = super::workspace_review_request::load(policy_store, request_id)?;
    let (record, record_bytes) = installed_authority_record(state_base)?;
    if digest_bytes(&record_bytes) != authority.record_digest {
        return Err("native_workspace_review_authority_invalid".to_owned());
    }
    if record.status != "active"
        || record.enrollment_generation != authority.enrollment_generation
        || record.key_id != authority.key_id
        || record.workspace_binding != authority.workspace_binding
        || record.device_binding != authority.device_binding
        || record.installation_binding != authority.installation_binding
        || record.scope_binding != authority.scope_binding
    {
        return Err("native_workspace_review_authority_provenance_mismatch".to_owned());
    }
    let authority_record = serde_json::to_value(record)
        .map_err(|_| "native_workspace_review_context_invalid".to_owned())?;
    Ok(json!({
        "schema": CONTEXT_SCHEMA,
        "version": CONTEXT_VERSION,
        "request_id": request.request_id,
        "authority_record": authority_record,
        "authority_record_digest": authority.record_digest,
        "authority_generation": authority.enrollment_generation,
        "authority_key_id": authority.key_id,
        "workspace_binding": authority.workspace_binding,
        "device_binding": authority.device_binding,
        "installation_binding": authority.installation_binding,
        "scope_binding": authority.scope_binding,
        "request_snapshot_digest": request.request_snapshot_digest,
        "request_binding": request.request_binding,
        "action_binding": request.action_binding,
        "intent_binding": request.intent_binding,
        "revision_binding": request.revision_binding,
        "policy_binding": request.policy_binding,
        "retry_scope_binding": request.retry_scope_binding,
    }))
}

#[cfg(test)]
#[path = "resident_workspace_review_context_tests.rs"]
mod tests;

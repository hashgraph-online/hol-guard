#![forbid(unsafe_code)]

//! Local metadata from frozen authenticated input, never an execution grant.
//! This is separate from the strict Cloud-upload context and exports no raw
//! content, recipient/domain values, account identifiers, or resource details.

use super::PolicySnapshotStore;
use serde_json::{json, Value};

pub(crate) fn build(store: &PolicySnapshotStore, request_id: &str) -> Result<Value, String> {
    build_with_recheck(store, request_id, || {})
}

fn build_with_recheck(
    store: &PolicySnapshotStore,
    request_id: &str,
    before_recheck: impl FnOnce(),
) -> Result<Value, String> {
    // This reader neither enrolls authority nor consumes a decision. Do not
    // occupy the exclusive transition lock used by those mutations. Reject a
    // policy change across loading instead of labeling a stale snapshot current.
    let before = store.current_snapshot()?;
    let request = super::workspace_review_request::load(store, request_id)?;
    let input = request
        .business_input
        .as_ref()
        .ok_or_else(|| "native_local_business_summary_unavailable".to_owned())?;
    let facts = input.facts();
    let summary = json!({
        "schema": "guard-native-local-business-review-summary.v1",
        "version": 1,
        "request_id": request.request_id,
        "request_snapshot_digest": request.request_snapshot_digest,
        "prepared_input_binding": input.binding(),
        "service": facts.provider.service,
        "operation": facts.operation,
        "audience_kind": facts.audience.kind,
        "audience_expansion_state": facts.audience.expansion_state,
        "recipient_count": facts.volume.recipient_count,
        "record_count": facts.volume.record_count,
        "byte_count": facts.volume.byte_count,
        "attachment_count": input.attachments().len(),
        "inspection_state": facts.content.inspection_state,
        "sensitivity_labels": facts.content.sensitivity_labels,
        "snapshot_fact_completeness": facts.completeness,
        // Integrity of this snapshot does not establish current provider
        // identity, account lease validity, custody, or any provider effect.
        "account_currentness": "not_asserted",
        "execution_state": "not_checked"
    });
    before_recheck();
    let after = store.current_snapshot()?;
    if before.generation != after.generation
        || before.policy_digest != after.policy_digest
        || before.rule_digest != after.rule_digest
        || before.runtime_identity != after.runtime_identity
        || before.scope_contract.scope_digest != after.scope_contract.scope_digest
    {
        return Err("native_local_business_summary_unavailable".into());
    }
    Ok(summary)
}

#[cfg(test)]
pub(crate) fn build_with_policy_change_test_hook(
    store: &PolicySnapshotStore,
    request_id: &str,
    change: impl FnOnce(),
) -> Result<Value, String> {
    build_with_recheck(store, request_id, change)
}

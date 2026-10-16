#![forbid(unsafe_code)]

//! Local metadata from frozen authenticated input, never an execution grant.
//! This is separate from the strict Cloud-upload context and exports no raw
//! content, recipient/domain values, account identifiers, or resource details.

use super::PolicySnapshotStore;
use guard_policy_snapshot::PolicySnapshotV3;
use serde_json::{json, Value};

const MAX_QUEUE_ITEMS: usize = 128;

fn same_policy(before: &PolicySnapshotV3, after: &PolicySnapshotV3) -> bool {
    before.generation == after.generation
        && before.policy_digest == after.policy_digest
        && before.rule_digest == after.rule_digest
        && before.runtime_identity == after.runtime_identity
        && before.scope_contract.scope_digest == after.scope_contract.scope_digest
}

/// Local presentation of saved pending snapshots; not a decision or a statement
/// that a snapshot remains dispatchable. No private request material leaves Rust.
pub(crate) fn queue(store: &PolicySnapshotStore) -> Result<Value, String> {
    let before = store.current_snapshot()?;
    let selectors = super::workspace_review_business_queue::selectors(store)?;
    let claims_before = if selectors.is_empty() {
        None
    } else {
        super::workspace_review_secure_state::load(store.state_base())?
    };
    let mut items = Vec::new();
    for selector in &selectors {
        let request = super::workspace_review_business_queue::load(store, selector)?;
        if super::workspace_review_business_queue::consumed_with_state(
            store,
            &request,
            claims_before.as_ref(),
        )? {
            continue;
        }
        if items.len() >= MAX_QUEUE_ITEMS {
            return Err("native_local_business_queue_unavailable".into());
        }
        items.push(render(&request)?);
    }
    let after = store.current_snapshot()?;
    if !same_policy(&before, &after)
        || selectors != super::workspace_review_business_queue::selectors(store)?
        || (!selectors.is_empty()
            && claims_before != super::workspace_review_secure_state::load(store.state_base())?)
    {
        return Err("native_local_business_queue_unavailable".into());
    }
    Ok(
        json!({"schema":"guard-native-local-business-review-queue.v1", "version":1,
        "items":items}),
    )
}

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
    if super::workspace_review_business_queue::consumed(store, &request)? {
        return Err("native_local_business_summary_unavailable".into());
    }
    let summary = render(&request)?;
    before_recheck();
    let after = store.current_snapshot()?;
    if !same_policy(&before, &after)
        || super::workspace_review_business_queue::consumed(store, &request)?
    {
        return Err("native_local_business_summary_unavailable".into());
    }
    Ok(summary)
}

fn render(
    request: &super::workspace_review_request::TrustedWorkspaceReviewRequest,
) -> Result<Value, String> {
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

//! Integrity-bound, non-consuming policy lookups shared by saved decisions.

use super::{portable, Context, HookDirectDefer, StoreShape};
use crate::local_store_read::STORE_FILE_NAME;
use base64ct::{Base64UrlUnpadded, Encoding};
use guard_contracts::{PolicyDecisionLookupRequestV1, POLICY_DECISION_LOOKUP_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::path::Path;
use zeroize::Zeroizing;

/// Read the effective policy decision for one artifact without consuming a
/// one-shot approval. The caller supplies the exact-action hash when it has
/// one, or `None` for a command identity lookup.
pub(super) fn policy_lookup(
    context: &Context<'_>,
    connection: &Connection,
    artifact_id: &str,
    artifact_hash: Option<&str>,
) -> Result<Value, HookDirectDefer> {
    let binding = context.binding;
    let (Some(integrity), Some(key)) = (
        binding.policy_integrity_state.as_ref(),
        binding.integrity_key.as_ref(),
    ) else {
        return Err(HookDirectDefer::SavedDecision);
    };
    if integrity.enforcement != "enforce"
        || integrity.mode != "protected"
        || !integrity.cutover_complete
        || !integrity.degraded_reasons.is_empty()
        || integrity.generation.is_none()
        || integrity.key_id.as_deref() != Some(key.key_id.as_str())
    {
        return Err(HookDirectDefer::SavedDecision);
    }
    let integrity_state =
        serde_json::to_value(integrity).map_err(|_| HookDirectDefer::SavedDecision)?;
    let store = StoreShape {
        connection,
        harness: context.harness,
        artifact_id,
    };
    let Some(has_local_policy) = store.readable(&integrity_state)? else {
        return Err(HookDirectDefer::SavedDecision);
    };
    let now =
        crate::hook_direct::lifecycle::utc_now_isoformat().ok_or(HookDirectDefer::SavedDecision)?;
    let (bundle_identities, _) = store.bundle_authority(&now)?;
    let composition = portable::composition(context.workspace)?;
    let key_b64 = Zeroizing::new(Base64UrlUnpadded::encode_string(&key.key));
    let request = PolicyDecisionLookupRequestV1 {
        schema: POLICY_DECISION_LOOKUP_REQUEST_SCHEMA.to_owned(),
        request_id: String::new(),
        store_path: Path::new(context.guard_home)
            .join(STORE_FILE_NAME)
            .to_string_lossy()
            .into_owned(),
        guard_home: context.guard_home.to_owned(),
        harness: context.harness.to_owned(),
        artifact_id: Some(artifact_id.to_owned()),
        artifact_hash: artifact_hash.map(str::to_owned),
        workspace: Some(context.workspace.to_owned()),
        publisher: None,
        now,
        runtime_exact_match_context: None,
        consume_one_shot: false,
        local_once_only: false,
        integrity_state: Some(if has_local_policy {
            integrity_state
        } else {
            json!({})
        }),
        integrity_key_b64: has_local_policy.then(|| key_b64.to_string()),
        integrity_key_id: has_local_policy.then(|| key.key_id.clone()),
        local_once_integrity_key_b64: Some(key_b64.to_string()),
        local_once_integrity_key_id: Some(key.key_id.clone()),
        policy_bundle_decision_identities: (!bundle_identities.is_empty())
            .then_some(bundle_identities),
        // The lookup lifts Cloud-excepted bundle rules itself. The local and
        // portable probes both match exceptions on the checkout path.
        exception_workspace: Some(context.workspace.to_owned()),
        cloud_exception_bundle: Default::default(),
        probe_groups: None,
        portable_workspace: None,
        evidence_binding: None,
    };
    let lookup = |workspace: &str| {
        let request = PolicyDecisionLookupRequestV1 {
            workspace: Some(workspace.to_owned()),
            ..request.clone()
        };
        crate::policy_decision_lookup_op::evaluate_non_consuming(&request, connection)
            .map_err(|_| HookDirectDefer::SavedDecision)
    };
    // A workspace that already names its identity reads that lookup alone, so
    // the local lookup is never run for it. A row matched with invalid
    // integrity then defers over the audit write the read-only connection
    // cannot take.
    match composition {
        portable::Composition::Local => lookup(context.workspace),
        portable::Composition::Named(identity) => {
            Ok(portable::restrictive_only(lookup(&identity)?))
        }
        portable::Composition::Both(identity) => {
            let local = lookup(context.workspace)?;
            portable::compose(local, lookup(&identity)?)
        }
    }
}

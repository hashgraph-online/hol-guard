#![forbid(unsafe_code)]

//! Trusted local request material for native workspace-review decisions.
//!
//! The request snapshot is materialized from the local approval store before a
//! Cloud decision is handed to the resident. The resident accepts only the
//! request id as a selector and derives every signed binding from this private,
//! canonical snapshot.

use guard_contracts::{
    NATIVE_WORKSPACE_REVIEW_ACTION_BINDING_DOMAIN, NATIVE_WORKSPACE_REVIEW_INTENT_BINDING_DOMAIN,
    NATIVE_WORKSPACE_REVIEW_MAX_DECISION_BYTES, NATIVE_WORKSPACE_REVIEW_POLICY_BINDING_DOMAIN,
    NATIVE_WORKSPACE_REVIEW_REQUEST_BINDING_DOMAIN,
    NATIVE_WORKSPACE_REVIEW_REVISION_BINDING_DOMAIN,
};
use guard_policy_snapshot::{canonical_json_bytes, digest_bytes};
use serde::Deserialize;
use serde_json::Value;
use std::path::{Path, PathBuf};

const REQUEST_STATE_SCHEMA: &str = "guard-native-workspace-review-request.v1";
const REQUEST_STATE_VERSION: u16 = 1;
const REQUEST_STATE_DIRECTORY: &str = "workspace-review-requests";
const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_REQUEST_STATE_BYTES: u64 = 4 * NATIVE_WORKSPACE_REVIEW_MAX_DECISION_BYTES as u64;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceReviewRequestStateV1 {
    schema: String,
    version: u16,
    request_id: String,
    status: String,
    action: Value,
    intent: Value,
    revision: Value,
    policy: Value,
}

pub(crate) struct TrustedWorkspaceReviewRequest {
    pub(crate) request_id: String,
    pub(crate) request_snapshot_digest: String,
    pub(crate) request_binding: String,
    pub(crate) action_binding: String,
    pub(crate) intent_binding: String,
    pub(crate) revision_binding: String,
    pub(crate) policy_binding: String,
    pub(crate) retry_scope_binding: String,
    pub(crate) business_input: Option<guard_command::business_input::PreparedBusinessInputV1>,
}

impl std::fmt::Debug for TrustedWorkspaceReviewRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedWorkspaceReviewRequest")
            .field("request_id", &self.request_id)
            .field("request_snapshot_digest", &self.request_snapshot_digest)
            .field("has_business_input", &self.business_input.is_some())
            .finish_non_exhaustive()
    }
}

pub(super) fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REQUEST_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn binding(domain: &[u8], value: &Value) -> Result<String, String> {
    let canonical = canonical_json_bytes(value)
        .map_err(|_| "native_workspace_review_request_invalid".to_owned())?;
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&canonical);
    Ok(digest_bytes(&preimage))
}

fn request_binding(request_id: &str) -> Result<String, String> {
    binding(
        NATIVE_WORKSPACE_REVIEW_REQUEST_BINDING_DOMAIN,
        &Value::String(request_id.to_owned()),
    )
}

fn request_path(state_base: &Path, request_id: &str) -> Result<PathBuf, String> {
    if !valid_request_id(request_id) {
        return Err("native_workspace_review_request_invalid".to_owned());
    }
    Ok(state_base
        .join(REQUEST_STATE_DIRECTORY)
        .join(format!("{request_id}.json")))
}

pub(crate) fn load(
    policy_store: &super::PolicySnapshotStore,
    request_id: &str,
) -> Result<TrustedWorkspaceReviewRequest, String> {
    let state_base = policy_store.state_base();
    let path = request_path(state_base, request_id)?;
    let request_directory = path
        .parent()
        .ok_or_else(|| "native_workspace_review_request_unavailable".to_owned())?;
    super::validate_private_directory(request_directory)?;
    let private_root = crate::resident_state::private_root_for_state_base(state_base)?;
    let Some((value, bytes)) = super::policy_store_persistence::read_private_json(
        &path,
        MAX_REQUEST_STATE_BYTES,
        "workspace_review_request",
        &private_root,
    )
    .map_err(|_| "native_workspace_review_request_unavailable".to_owned())?
    else {
        return Err("native_workspace_review_request_missing".to_owned());
    };
    let canonical = canonical_json_bytes(&value)
        .map_err(|_| "native_workspace_review_request_invalid".to_owned())?;
    if canonical != bytes {
        return Err("native_workspace_review_request_noncanonical".to_owned());
    }
    let state: WorkspaceReviewRequestStateV1 = serde_json::from_value(value)
        .map_err(|_| "native_workspace_review_request_invalid".to_owned())?;
    if state.schema != REQUEST_STATE_SCHEMA
        || state.version != REQUEST_STATE_VERSION
        || state.request_id != request_id
        || state.status != "pending"
    {
        return Err("native_workspace_review_request_invalid".to_owned());
    }
    let envelope = state.action.get("action_envelope");
    let receipt = envelope
        .and_then(|envelope| envelope.get("native_origin_receipt"))
        .map(|origin| {
            serde_json::from_value::<guard_contracts::NativeHookDecisionReceiptV1>(origin.clone())
        })
        .transpose()
        .map_err(|_| "native_workspace_review_origin_invalid".to_owned())?;
    if let Some(receipt) = &receipt {
        super::native_review_origin::verify(policy_store, receipt)?;
    }
    // An admitted business policy requires authenticated native provenance for
    // every request, including generic ones. Removing the entire envelope must
    // not erase the distinction and reopen the legacy retry path.
    // Historical generic requests may be read before any policy is installed.
    // Claiming still requires a current snapshot in verify_and_claim_request.
    // Expiry, authentication and all other policy failures remain errors.
    let snapshot = match policy_store.current_snapshot() {
        Ok(snapshot) => Some(snapshot),
        Err(error) if error == "native_policy_snapshot_missing" => None,
        Err(error) => return Err(error),
    };
    if let Some(snapshot) = snapshot.filter(|s| s.business_policy.is_some()) {
        let origin = receipt
            .as_ref()
            .ok_or_else(|| "native_workspace_review_business_invalid".to_owned())?;
        if origin.request_id != request_id
            || origin.policy_generation != snapshot.generation
            || origin.policy_digest.as_deref() != Some(snapshot.policy_digest.as_str())
            || origin.rule_digest.as_deref() != Some(snapshot.rule_digest.as_str())
            || origin.runtime_identity.as_deref() != Some(snapshot.runtime_identity.as_str())
        {
            return Err("native_workspace_review_business_invalid".to_owned());
        }
    }
    let business_input = super::workspace_review_business::load(
        policy_store,
        request_id,
        envelope,
        receipt.as_ref(),
    )?;
    let action_binding = binding(NATIVE_WORKSPACE_REVIEW_ACTION_BINDING_DOMAIN, &state.action)?;
    let intent_binding = binding(NATIVE_WORKSPACE_REVIEW_INTENT_BINDING_DOMAIN, &state.intent)?;
    let revision_binding = binding(
        NATIVE_WORKSPACE_REVIEW_REVISION_BINDING_DOMAIN,
        &state.revision,
    )?;
    let policy_binding = binding(NATIVE_WORKSPACE_REVIEW_POLICY_BINDING_DOMAIN, &state.policy)?;
    let retry_scope_binding = super::workspace_review_decision::retry_scope_binding(
        &action_binding,
        &intent_binding,
        &revision_binding,
        &policy_binding,
    )?;
    Ok(TrustedWorkspaceReviewRequest {
        request_id: state.request_id,
        request_snapshot_digest: digest_bytes(&bytes),
        request_binding: request_binding(request_id)?,
        action_binding,
        intent_binding,
        revision_binding,
        policy_binding,
        retry_scope_binding,
        business_input,
    })
}

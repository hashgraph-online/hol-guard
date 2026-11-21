//! `ExtensionControl` prepared-candidate queries — what the daemon binds around
//! an Extension control commit that was prepared in advance.
//!
//! Pure: every query is answered from the request alone.
//!
//! - `request_digest`: the digest that identifies one apply request. The preview
//!   that issued a proof remembers it, and the apply must repeat exactly that
//!   request. It is the SHA-256 of the canonical JSON (sorted keys, ASCII
//!   escapes) of the six fields that make two requests the same request, taken
//!   as the caller sent them: a field that is missing is `null`, and the request
//!   is not yet known to be well formed.
//! - `candidate_nonce`: the nonce a prepared candidate's mutation is proven
//!   under. The caller's nonce is bound to the identities of the activation
//!   records staged for the candidate, so an approval cannot commit other
//!   records than the ones it was shown.
//! - `preview_event_targets`: the audit projection of a semantic preview. Each
//!   changed target is named by a digest of its kind and id, never by the id, so
//!   the event records what changed and which rules it touches without
//!   disclosing the target.

use guard_contracts::{
    ExtensionControlEventTargetV1, ExtensionControlPayloadV1, ExtensionControlPreviewRegistryV1,
    NativeExtensionControlLayerV1, EXTENSION_CONTROL_MAX_EVENT_RULE_IDS,
    EXTENSION_CONTROL_MAX_EVENT_TARGETS,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::extension_control_preview_op::semantic_preview;
use crate::extension_control_proof::UNENCODABLE;
use crate::guard_store_json::dumps_sorted;

/// Separates the parts a target reference hashes, so no two targets share one.
const TARGET_REF_DOMAIN: &str = "extension-control-target-ref";

/// The answer to `request_digest`.
pub(crate) fn request_digest(
    fields: [(&str, &Value); 6],
) -> Result<ExtensionControlPayloadV1, String> {
    let request: Map<String, Value> = fields
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.clone()))
        .collect();
    Ok(ExtensionControlPayloadV1::RequestDigest {
        digest: canonical_digest(&Value::Object(request))?,
    })
}

/// The answer to `candidate_nonce`.
pub(crate) fn candidate_nonce(
    nonce: &str,
    activation_digest: &str,
    lifecycle_before: &str,
    lifecycle_after: &str,
    security_digest: Option<&str>,
) -> Result<ExtensionControlPayloadV1, String> {
    let bound = json!([
        nonce,
        activation_digest,
        lifecycle_before,
        lifecycle_after,
        security_digest,
    ]);
    Ok(ExtensionControlPayloadV1::CandidateNonce {
        nonce: canonical_digest(&bound)?,
    })
}

/// The answer to `preview_event_targets`: the semantic preview of replacing
/// `current_layers` with `proposed_layers`, one entry per changed target.
pub(crate) fn event_targets(
    registry: &ExtensionControlPreviewRegistryV1,
    current_layers: &[NativeExtensionControlLayerV1],
    proposed_layers: &[NativeExtensionControlLayerV1],
) -> Result<ExtensionControlPayloadV1, String> {
    let preview = semantic_preview(registry, current_layers, proposed_layers)?;
    let targets = preview
        .changed_targets
        .into_iter()
        .take(EXTENSION_CONTROL_MAX_EVENT_TARGETS)
        .map(|target| ExtensionControlEventTargetV1 {
            target_ref: target_ref(&target.target.kind, &target.target.target_id),
            kind: target.target.kind,
            before_explicit: target.before_explicit,
            after_explicit: target.after_explicit,
            before_effective: target.before_effective,
            after_effective: target.after_effective,
            affected_rule_ids: target
                .affected_rule_ids
                .into_iter()
                .take(EXTENSION_CONTROL_MAX_EVENT_RULE_IDS)
                .collect(),
        })
        .collect();
    Ok(ExtensionControlPayloadV1::PreviewEventTargets { targets })
}

/// Lowercase hex SHA-256 of the value's canonical JSON.
fn canonical_digest(value: &Value) -> Result<String, String> {
    let canonical = dumps_sorted(value).ok_or_else(|| UNENCODABLE.to_owned())?;
    Ok(hex::encode(Sha256::digest(canonical.as_bytes())))
}

/// Names a target without disclosing its id.
fn target_ref(kind: &str, target_id: &str) -> String {
    hex::encode(Sha256::digest(
        format!("{TARGET_REF_DOMAIN}\0{kind}\0{target_id}").as_bytes(),
    ))
}

#[cfg(test)]
#[path = "extension_control_prepared_op_tests.rs"]
mod tests;

//! The managed-controls records a policy writer seals: the publication epoch
//! and the activation of a verified policy on the local authority.
//!
//! Both ops are pure. They answer with the state the caller stores under the
//! exclusive authority lease, or a `tampered` fault naming the refusal.

use guard_contracts::{ExtensionControlAuthorityRequestV1, ExtensionControlManagedActivationV1};
use serde_json::{json, Map, Value};

use super::layers::{layers_from_values, layers_to_json};
use super::managed::{
    projection_digest, require_key, ACTIVATION_PURPOSE, ACTIVATION_SCHEMA, REVISION_PURPOSE,
};
use super::records::{authenticated_record, field, tampered, Res};

/// The longest control-set id or name an activation keeps.
const MAX_CONTROL_SET_CHARS: usize = 160;
/// The longest bundle timestamp an activation keeps.
const MAX_TIMESTAMP_CHARS: usize = 80;

fn authentication(payload: Map<String, Value>, key: &[u8], purpose: &str) -> Res<Value> {
    let (record, digest, mac) = authenticated_record(&payload, key, purpose)?;
    Ok(json!({ "record": record, "digest": digest, "mac": mac }))
}

/// `build_managed_controls_revision_state`.
pub(super) fn seal_revision_op(
    request: &ExtensionControlAuthorityRequestV1,
    key: Option<&[u8]>,
) -> Res<Value> {
    let key = require_key(key)?;
    let revision = request
        .revision
        .filter(|revision| *revision >= 1)
        .ok_or_else(|| tampered("managed controls revision must be positive"))?;
    let payload = Map::from_iter([("revision".to_owned(), json!(revision))]);
    Ok(json!({
        "state": {
            "revision": revision,
            "authentication": authentication(payload, key, REVISION_PURPOSE)?,
        }
    }))
}

/// Python's `str.isspace`: Unicode `White_Space` plus the information
/// separators U+001C..U+001F.
fn py_space(character: char) -> bool {
    character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
}

/// `value.strip()[:limit]` for a string that is not blank once stripped.
fn stripped(value: &Value, limit: usize) -> Option<String> {
    let text = value.as_str()?.trim_matches(py_space);
    (!text.is_empty()).then(|| text.chars().take(limit).collect())
}

/// `isinstance(value, int)` on decoded JSON, which never yields a bool here.
fn is_int(value: &Value) -> bool {
    matches!(value, Value::Number(number) if !number.is_f64())
}

/// `_activation_metadata`: the policy revision, control-set id and name.
fn activation_metadata(
    payload: &Map<String, Value>,
    bundle_version: &Value,
) -> (Value, Option<String>, Option<String>) {
    let Value::Object(metadata) = field(payload, "metadata") else {
        return (bundle_version.clone(), None, None);
    };
    let candidate = field(metadata, "revision");
    let revision = if candidate.is_string() || is_int(candidate) {
        candidate.clone()
    } else {
        bundle_version.clone()
    };
    (
        revision,
        stripped(field(metadata, "id"), MAX_CONTROL_SET_CHARS),
        stripped(field(metadata, "name"), MAX_CONTROL_SET_CHARS),
    )
}

fn non_empty_string(value: &Value) -> bool {
    matches!(value, Value::String(text) if !text.is_empty())
}

/// The unsigned, acknowledged activation of `input` on the authority
/// committed under `catalog_digest`.
fn activation(
    input: &ExtensionControlManagedActivationV1,
    catalog_digest: &str,
) -> Res<Map<String, Value>> {
    if input.managed_revision < 1 {
        return Err(tampered("managed_revision must be positive"));
    }
    let Value::Object(bundle) = &input.bundle else {
        return Err(tampered("managed policy payload is required"));
    };
    let (bundle_hash, bundle_version, workspace_id) = (
        field(bundle, "bundleHash"),
        field(bundle, "bundleVersion"),
        field(bundle, "workspaceId"),
    );
    if !non_empty_string(bundle_hash) {
        return Err(tampered("managed bundle hash is required"));
    }
    if !is_int(bundle_version) {
        return Err(tampered("managed bundle version is required"));
    }
    if !non_empty_string(workspace_id) {
        return Err(tampered("managed workspace binding is required"));
    }
    let Value::Object(payload) = field(bundle, "payload") else {
        return Err(tampered("managed policy payload is required"));
    };
    if !input.rule_targets.is_array() || !input.delegated_targets.is_array() {
        return Err(tampered("invalid managed controls activation targets"));
    }
    let (policy_revision, control_set_id, control_set_name) =
        activation_metadata(payload, bundle_version);
    let mut capabilities = input.negotiated_capabilities.clone();
    capabilities.sort();
    capabilities.dedup();
    let signed_layers = layers_from_values(&input.signed_cloud_layers)?;
    let Value::Object(mut activation) = json!({
        "schemaVersion": ACTIVATION_SCHEMA,
        "complete": true,
        "bundleHash": bundle_hash,
        "bundleVersion": bundle_version,
        "workspaceId": workspace_id,
        "catalogDigest": catalog_digest,
        "baseAuthorityRevision": input.base_revision,
        "baseAuthoritySnapshotDigest": input.base_snapshot_digest,
        "extensionAuthorityRevision": input.managed_revision,
        "signedCloudLayersJson": layers_to_json(&signed_layers)?,
        "ruleTargets": input.rule_targets,
        "delegatedTargets": input.delegated_targets,
        "provenance": {
            "bundleHash": bundle_hash,
            "bundleVersion": bundle_version,
            "payloadHash": field(bundle, "payloadHash"),
            "policyRevision": policy_revision,
            "workspaceId": workspace_id,
        },
        "negotiatedCapabilities": capabilities,
    }) else {
        unreachable!("an object literal is an object");
    };
    if let Some(mode) = &input.authority_mode {
        activation.insert("authorityMode".to_owned(), json!(mode));
    }
    for (name, value) in [
        ("controlSetId", control_set_id),
        ("controlSetName", control_set_name),
        (
            "issuedAt",
            stripped(field(bundle, "issuedAt"), MAX_TIMESTAMP_CHARS),
        ),
        (
            "expiresAt",
            stripped(field(bundle, "expiresAt"), MAX_TIMESTAMP_CHARS),
        ),
    ] {
        if let Some(value) = value {
            activation.insert(name.to_owned(), json!(value));
        }
    }
    let acknowledgement = json!({
        "bundleHash": bundle_hash,
        "bundleVersion": bundle_version,
        "policyRevision": policy_revision,
        "extensionAuthorityRevision": input.managed_revision,
        "catalogDigest": catalog_digest,
        "effectiveProjectionDigest": projection_digest(&activation)?,
        "status": "applied",
    });
    activation.insert("acknowledgement".to_owned(), acknowledgement);
    Ok(activation)
}

/// `build_managed_controls_activation_state`: the complete activation the
/// caller persists atomically with its publication epoch.
pub(super) fn seal_activation_op(
    request: &ExtensionControlAuthorityRequestV1,
    key: Option<&[u8]>,
) -> Res<Value> {
    let key = require_key(key)?;
    let (Some(input), Some(catalog_digest)) = (
        request.managed_activation.as_ref(),
        request.catalog_digest.as_deref(),
    ) else {
        return Err(tampered("invalid managed controls activation request"));
    };
    let mut activation = activation(input, catalog_digest)?;
    let payload = Map::from_iter([("activation".to_owned(), Value::Object(activation.clone()))]);
    let authentication = authentication(payload, key, ACTIVATION_PURPOSE)?;
    activation.insert("authentication".to_owned(), authentication);
    Ok(json!({ "activation": activation }))
}

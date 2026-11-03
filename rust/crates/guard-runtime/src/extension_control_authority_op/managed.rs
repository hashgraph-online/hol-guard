//! The authenticated managed-controls activation and publication epoch, and
//! their composition onto the local authority view.

use guard_command::extension_control::{
    ControlLayerKind, ControlState, ExtensionControl, ExtensionControlLayer,
};
use guard_contracts::ExtensionControlAuthorityRequestV1;
use rusqlite::params;
use serde_json::{json, Map, Value};

use super::layers::{
    layers_from_json, layers_to_values, manifest_sha256, preserve_managed, Manifest,
};
use super::records::{
    canonical, exact_int, field, py_eq, query_rows, row_text, sha256_hex, tampered, verify_record,
    Res,
};
use super::{Ctx, View, PROTECTED};

const ACTIVE_STATE_KEY: &str = "managed_controls_active";
const REVISION_STATE_KEY: &str = "managed_controls_revision";
pub(super) const ACTIVATION_SCHEMA: &str = "guard.managed-controls-activation.v1";
pub(super) const ACTIVATION_PURPOSE: &str = "managed-controls.activation";
pub(super) const REVISION_PURPOSE: &str = "managed-controls.revision";

pub(super) fn require_key(key: Option<&[u8]>) -> Res<&[u8]> {
    key.ok_or_else(|| tampered("extension control authentication key missing"))
}

/// The `record`, `digest` and `mac` strings of an `authentication` mapping.
fn authentication_parts<'a>(
    authentication: &'a Map<String, Value>,
    invalid: &str,
) -> Res<(&'a str, &'a str, &'a str)> {
    match (
        field(authentication, "record").as_str(),
        field(authentication, "digest").as_str(),
        field(authentication, "mac").as_str(),
    ) {
        (Some(record), Some(digest), Some(mac)) => Ok((record, digest, mac)),
        _ => Err(tampered(invalid)),
    }
}

/// `managed_controls_revision_from_state`.
pub(super) fn revision_from_state(value: &Value, key: &[u8]) -> Res<i64> {
    let invalid = || tampered("invalid managed controls revision state");
    let Value::Object(state) = value else {
        return Err(invalid());
    };
    let revision = exact_int(field(state, "revision"))
        .filter(|revision| *revision >= 1)
        .ok_or_else(invalid)?;
    let Value::Object(authentication) = field(state, "authentication") else {
        return Err(invalid());
    };
    let (record, digest, mac) = authentication_parts(
        authentication,
        "invalid managed controls revision authentication",
    )?;
    let authenticated = verify_record(record, digest, mac, key, REVISION_PURPOSE)?;
    if !py_eq(field(&authenticated, "revision"), &json!(revision)) {
        return Err(tampered("managed controls revision payload mismatch"));
    }
    Ok(revision)
}

/// `_projection_digest`.
pub(super) fn projection_digest(unsigned: &Map<String, Value>) -> Res<String> {
    let projection: Map<String, Value> = unsigned
        .iter()
        .filter(|(name, _)| {
            !matches!(
                name.as_str(),
                "acknowledgement" | "authentication" | "complete"
            )
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    Ok(sha256_hex(&canonical(&Value::Object(projection))?))
}

/// `managed_controls_layers_from_activation_state`.
pub(super) fn activation_layers(
    value: &Value,
    catalog_digest: &Value,
    key: &[u8],
) -> Res<(Vec<ExtensionControlLayer>, i64)> {
    let invalid_state = || tampered("invalid managed controls activation state");
    let Value::Object(state) = value else {
        return Err(invalid_state());
    };
    if !py_eq(field(state, "schemaVersion"), &json!(ACTIVATION_SCHEMA)) {
        return Err(invalid_state());
    }
    if field(state, "complete") != &Value::Bool(true)
        || !py_eq(field(state, "catalogDigest"), catalog_digest)
    {
        return Err(tampered("incomplete managed controls activation state"));
    }
    let Value::Object(authentication) = field(state, "authentication") else {
        return Err(tampered(
            "missing managed controls activation authentication",
        ));
    };
    let (record, digest, mac) = authentication_parts(
        authentication,
        "invalid managed controls activation authentication",
    )?;
    let authenticated = verify_record(record, digest, mac, key, ACTIVATION_PURPOSE)?;
    let mut unsigned = state.clone();
    unsigned.remove("authentication");
    if !py_eq(
        field(&authenticated, "activation"),
        &Value::Object(unsigned.clone()),
    ) {
        return Err(tampered("managed controls activation payload mismatch"));
    }
    let revision = exact_int(field(state, "extensionAuthorityRevision"))
        .filter(|revision| *revision >= 1)
        .ok_or_else(|| tampered("invalid managed controls activation revision"))?;
    let (Value::String(encoded_layers), Value::Object(acknowledgement)) = (
        field(state, "signedCloudLayersJson"),
        field(state, "acknowledgement"),
    ) else {
        return Err(tampered("invalid managed controls activation projection"));
    };
    if !py_eq(
        field(acknowledgement, "bundleHash"),
        field(state, "bundleHash"),
    ) || !py_eq(
        field(acknowledgement, "bundleVersion"),
        field(state, "bundleVersion"),
    ) || !py_eq(
        field(acknowledgement, "extensionAuthorityRevision"),
        &json!(revision),
    ) || !py_eq(field(acknowledgement, "catalogDigest"), catalog_digest)
        || !py_eq(
            field(acknowledgement, "effectiveProjectionDigest"),
            &json!(projection_digest(&unsigned)?),
        )
    {
        return Err(tampered("managed controls acknowledgement mismatch"));
    }
    let layers = layers_from_json(encoded_layers)?;
    if layers.len() > 1
        || layers
            .iter()
            .any(|layer| layer.kind != ControlLayerKind::SignedCloud)
    {
        return Err(tampered("invalid managed signed Cloud layer"));
    }
    Ok((layers, revision))
}

/// `managed_activation`: verify `state` against `catalog_digest`, or against
/// the catalog the state names when the request leaves it out.
pub(super) fn activation_op(
    request: &ExtensionControlAuthorityRequestV1,
    key: Option<&[u8]>,
) -> Res<Value> {
    let state = request.state.as_ref().unwrap_or(&Value::Null);
    let catalog_digest = match request.catalog_digest.as_deref() {
        Some(digest) => json!(digest),
        None => state.get("catalogDigest").cloned().unwrap_or(Value::Null),
    };
    let (layers, revision) = activation_layers(state, &catalog_digest, require_key(key)?)?;
    Ok(json!({ "layers": layers_to_values(&layers), "revision": revision }))
}

/// `managed_revision`.
pub(super) fn revision_op(
    request: &ExtensionControlAuthorityRequestV1,
    key: Option<&[u8]>,
) -> Res<Value> {
    let state = request.state.as_ref().unwrap_or(&Value::Null);
    Ok(json!({ "revision": revision_from_state(state, require_key(key)?)? }))
}

/// `None`, JSON `null` and `{}` all read as no state.
fn absent(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::Object(map)) => map.is_empty(),
        Some(_) => false,
    }
}

impl Ctx<'_> {
    /// `_with_managed_controls_activation`.
    pub(super) fn compose_managed(&self, view: View, previous: Option<&Manifest>) -> Res<Value> {
        let rows = query_rows(
            self.connection,
            "select state_key, payload_json from sync_state where state_key in (?, ?)",
            params![ACTIVE_STATE_KEY, REVISION_STATE_KEY],
        )?;
        let (mut active, mut revision_state) = (None, None);
        for row in rows {
            let decoded = serde_json::from_str::<Value>(&row_text(&row, "payload_json")?)
                .map_err(|_| tampered("invalid managed controls state"))?;
            match row_text(&row, "state_key")?.as_str() {
                ACTIVE_STATE_KEY => active = Some(decoded),
                _ => revision_state = Some(decoded),
            }
        }
        let local_layers: Vec<ExtensionControlLayer> = view
            .layers
            .iter()
            .filter(|layer| layer.kind == ControlLayerKind::LocalAdmin)
            .cloned()
            .collect();
        if absent(active.as_ref()) {
            let Some(revision_state) = revision_state.filter(|state| !absent(Some(state))) else {
                return Ok(json!({ "view": view.to_value() }));
            };
            let managed_revision = revision_from_state(&revision_state, self.require_key()?)?;
            let view = View {
                layers: local_layers,
                managed_revision,
                ..view
            };
            return Ok(json!({ "view": view.to_value() }));
        }
        if view.health != PROTECTED {
            return Err(tampered(
                "managed controls require protected local authority",
            ));
        }
        let Some(revision_state) = revision_state.filter(|state| !absent(Some(state))) else {
            return Err(tampered("managed controls revision state is missing"));
        };
        let key = self.require_key()?;
        let Some(Value::Object(active)) = active else {
            return Err(tampered("invalid managed controls activation state"));
        };
        let active_catalog_digest = match field(&active, "catalogDigest") {
            Value::String(digest) if !digest.is_empty() => digest.clone(),
            _ => return Err(tampered("invalid managed controls activation catalog")),
        };
        let (mut managed_layers, managed_revision) =
            activation_layers(&Value::Object(active), &json!(active_catalog_digest), key)?;
        let current = self.current_manifest();
        let current_sha256 = self.request.current_manifest_sha256.as_deref();
        let current_known = current.is_some() || current_sha256.is_some();
        let fingerprint_refresh = match (previous, current_known) {
            (Some(previous), true) if active_catalog_digest == view.catalog_digest => match current
            {
                Some(current) => previous != current,
                None => Some(manifest_sha256(previous)?.as_str()) != current_sha256,
            },
            _ => false,
        };
        if active_catalog_digest != view.catalog_digest || fingerprint_refresh {
            if managed_layers
                .iter()
                .any(|layer| layer.catalog_digest != active_catalog_digest)
            {
                return Err(tampered(
                    "managed controls activation layer catalog mismatch",
                ));
            }
            if !current_known {
                return Err(tampered(
                    "managed controls current catalog manifest is missing",
                ));
            }
            let Some(current) = current else {
                return Ok(json!({ "need": "current_manifest" }));
            };
            // A missing prior manifest must not act as an implicit fingerprint
            // match: stale managed allows stay disabled until Cloud refreshes.
            let prior: Manifest = match (fingerprint_refresh, previous) {
                (true, Some(previous)) => previous.clone(),
                _ => self
                    .load_manifest(&active_catalog_digest)?
                    .unwrap_or_default(),
            };
            managed_layers = managed_layers
                .into_iter()
                .map(|layer| ExtensionControlLayer {
                    catalog_digest: view.catalog_digest.clone(),
                    controls: layer
                        .controls
                        .iter()
                        .map(|control| {
                            if preserve_managed(control, &prior, current) {
                                control.clone()
                            } else {
                                ExtensionControl {
                                    state: ControlState::Disabled,
                                    ..control.clone()
                                }
                            }
                        })
                        .collect(),
                    ..layer
                })
                .collect();
        }
        if managed_revision != revision_from_state(&revision_state, key)? {
            return Err(tampered("managed controls activation revision mismatch"));
        }
        let mut layers = local_layers;
        layers.extend(managed_layers);
        let view = View {
            layers,
            managed_revision,
            ..view
        };
        Ok(json!({ "view": view.to_value() }))
    }
}

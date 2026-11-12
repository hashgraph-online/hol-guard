//! Control layers and catalog manifests of the extension-control authority,
//! in the value shapes the Python store serialized them in.

use std::collections::BTreeMap;

use guard_command::extension_control::{
    compose_control_layers, ControlLayerKind, ControlState, ControlTarget, ControlTargetKind,
    ExtensionControl, ExtensionControlLayer, MAX_CONTROL_LAYERS,
};
use serde_json::{json, Value};

use super::records::{canonical, field, sha256_hex, tampered, Res};

const MAX_CONTROLS_PER_LAYER: usize = 512;
const MAX_SERIALIZED_LAYERS_BYTES: usize = 256 * 1024;

fn layer_kind(value: &Value) -> Option<ControlLayerKind> {
    match value.as_str()? {
        "local-admin" => Some(ControlLayerKind::LocalAdmin),
        "signed-cloud" => Some(ControlLayerKind::SignedCloud),
        _ => None,
    }
}

fn target_kind(value: &Value) -> Option<ControlTargetKind> {
    match value.as_str()? {
        "extension" => Some(ControlTargetKind::Extension),
        "permission" => Some(ControlTargetKind::Permission),
        _ => None,
    }
}

fn control_state(value: &Value) -> Option<ControlState> {
    match value.as_str()? {
        "enabled" => Some(ControlState::Enabled),
        "disabled" => Some(ControlState::Disabled),
        _ => None,
    }
}

/// `_layer_from_value`.
pub(super) fn layer_from_value(raw: &Value) -> Res<ExtensionControlLayer> {
    let invalid_layer = || tampered("invalid extension control layer");
    let Value::Object(value) = raw else {
        return Err(invalid_layer());
    };
    let Value::Array(items) = field(value, "controls") else {
        return Err(tampered("invalid extension controls"));
    };
    let mut controls = Vec::with_capacity(items.len());
    for item in items {
        let Value::Object(item) = item else {
            return Err(tampered("invalid extension control"));
        };
        let kind = target_kind(field(item, "target_kind")).ok_or_else(invalid_layer)?;
        let Value::String(target_id) = field(item, "target_id") else {
            return Err(tampered("invalid extension control target"));
        };
        let target = ControlTarget::new(kind, target_id.clone()).map_err(|_| invalid_layer())?;
        let state = control_state(field(item, "state")).ok_or_else(invalid_layer)?;
        controls.push(ExtensionControl { target, state });
    }
    let (Value::String(schema_version), Value::String(catalog_digest)) = (
        field(value, "schema_version"),
        field(value, "catalog_digest"),
    ) else {
        return Err(tampered("invalid extension control layer metadata"));
    };
    let Value::Bool(global_lockdown) = field(value, "global_lockdown") else {
        return Err(tampered("invalid extension control lockdown"));
    };
    let kind = layer_kind(field(value, "kind")).ok_or_else(invalid_layer)?;
    let layer = ExtensionControlLayer {
        schema_version: schema_version.clone(),
        kind,
        catalog_digest: catalog_digest.clone(),
        global_lockdown: *global_lockdown,
        controls,
    };
    layer.validate().map_err(|_| invalid_layer())?;
    Ok(layer)
}

/// `layers_from_json`.
pub(super) fn layers_from_json(text: &str) -> Res<Vec<ExtensionControlLayer>> {
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(text) else {
        return Err(tampered("invalid extension control layers"));
    };
    items.iter().map(layer_from_value).collect()
}

/// `layers_from_json` over values the caller already decoded.
pub(super) fn layers_from_values(value: &Value) -> Res<Vec<ExtensionControlLayer>> {
    let Value::Array(items) = value else {
        return Err(tampered("invalid extension control layers"));
    };
    items.iter().map(layer_from_value).collect()
}

/// `_layer_to_value`.
pub(super) fn layer_to_value(layer: &ExtensionControlLayer) -> Value {
    json!({
        "schema_version": layer.schema_version,
        "kind": layer.kind.as_str(),
        "catalog_digest": layer.catalog_digest,
        "global_lockdown": layer.global_lockdown,
        "controls": layer.controls.iter().map(|control| json!({
            "target_kind": control.target.kind.as_str(),
            "target_id": control.target.target_id,
            "state": control.state.as_str(),
        })).collect::<Vec<_>>(),
    })
}

pub(super) fn layers_to_values(layers: &[ExtensionControlLayer]) -> Value {
    Value::Array(layers.iter().map(layer_to_value).collect())
}

/// `layers_to_json`.
pub(super) fn layers_to_json(layers: &[ExtensionControlLayer]) -> Res<String> {
    canonical(&layers_to_values(layers))
}

/// Layer tuples compare equal exactly when their canonical values do.
pub(super) fn same_layers(left: &[ExtensionControlLayer], right: &[ExtensionControlLayer]) -> bool {
    layers_to_values(left) == layers_to_values(right)
}

/// `_validate_layers`.
pub(super) fn validate_layers(layers: &[ExtensionControlLayer], catalog_digest: &str) -> Res<()> {
    if layers.len() > MAX_CONTROL_LAYERS {
        return Err(tampered("too many extension control layers"));
    }
    if layers
        .iter()
        .any(|layer| layer.controls.len() > MAX_CONTROLS_PER_LAYER)
    {
        return Err(tampered("too many extension controls in layer"));
    }
    if layers
        .iter()
        .any(|layer| layer.catalog_digest != catalog_digest)
    {
        return Err(tampered("extension control catalog digest mismatch"));
    }
    if !compose_control_layers(layers).failures.is_empty() {
        return Err(tampered("invalid extension control layers"));
    }
    let mut kinds: Vec<ControlLayerKind> = layers.iter().map(|layer| layer.kind).collect();
    kinds.sort();
    kinds.dedup();
    if kinds.len() != layers.len() {
        return Err(tampered("duplicate extension control layer"));
    }
    Ok(())
}

/// `_validate_serialized_layers`.
pub(super) fn validate_serialized_layers(layers_json: &str) -> Res<()> {
    if layers_json.len() > MAX_SERIALIZED_LAYERS_BYTES {
        return Err(tampered("extension control layers exceed storage limit"));
    }
    Ok(())
}

/// The `kind:target_id` key a catalog manifest fingerprints a control under.
pub(super) fn manifest_key(control: &ExtensionControl) -> String {
    format!(
        "{}:{}",
        control.target.kind.as_str(),
        control.target.target_id
    )
}

pub(super) type Manifest = BTreeMap<String, String>;

/// `preserve_migrated_extension_control`.
pub(super) fn preserve_migrated(
    control: &ExtensionControl,
    previous: &Manifest,
    current: &Manifest,
) -> bool {
    let key = manifest_key(control);
    let Some(fingerprint) = current.get(&key) else {
        return false;
    };
    control.state == ControlState::Disabled
        || previous.get(&key).is_none_or(|prior| prior == fingerprint)
}

/// `preserve_managed_extension_control`.
pub(super) fn preserve_managed(
    control: &ExtensionControl,
    previous: &Manifest,
    current: &Manifest,
) -> bool {
    let key = manifest_key(control);
    let Some(fingerprint) = current.get(&key) else {
        return true;
    };
    control.state == ControlState::Disabled || previous.get(&key) == Some(fingerprint)
}

/// SHA-256 of a manifest's canonical JSON, the identity the transport sends
/// in place of a large manifest.
pub(super) fn manifest_sha256(manifest: &Manifest) -> Res<String> {
    let value = Value::Object(
        manifest
            .iter()
            .map(|(k, v)| (k.clone(), json!(v)))
            .collect(),
    );
    Ok(sha256_hex(&canonical(&value)?))
}

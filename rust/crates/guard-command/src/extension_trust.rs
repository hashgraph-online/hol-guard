//! Rust port of `runtime/extension_trust.py`.
//!
//! `evaluate_command` consumes only `filter_inert_external_observations`
//! (command_evaluation.py:201) — which reduces to `extension_is_active` +
//! `trust_class_for`. The catalog-UI helpers (`catalog_trust_fields`,
//! `publisher_for`, `activation_for`, `catalog_enabled`) are not on the
//! command-evaluation path and are not ported.
//!
//! `trust_class_for` reads `CatalogExtension.trust_class` — verified
//! identical to `_trust_map()[id]` for all 81 packaged catalog extensions
//! (`trust-class-map.v1.json` is the map's packaging source); unmapped ids
//! fall back to `"first-party"` exactly as Python does (extension_trust.py:102-105).
use crate::command_evaluation::NativeCommandExtensionObservation;
use crate::extension_control::{
    compose_control_layers, ControlLayerKind, ControlState, ControlTargetKind,
    ExtensionControlLayer,
};
use crate::native_command_catalog::CommandCatalog;

/// `trust_class_for` (extension_trust.py:94).
pub fn trust_class_for<'a>(catalog: &'a CommandCatalog, extension_id: &str) -> &'a str {
    catalog
        .get(extension_id)
        .map(|ext| ext.trust_class.as_str())
        .unwrap_or("first-party")
}

/// `extension_is_active` (extension_trust.py:158).
///
/// `required` mirrors `item.extension.required`. On the native path the
/// observation's extension identity is registry-validated upstream, so
/// `catalog.get` resolves; the `unwrap_or(false)` arm is unreachable in
/// production and matches Python only in the never-hit "extension absent"
/// case (Python would `KeyError` earlier during identity resolution).
pub fn extension_is_active(
    catalog: &CommandCatalog,
    extension_id: &str,
    required: bool,
    layers: &[ExtensionControlLayer],
) -> bool {
    if required || trust_class_for(catalog, extension_id) != "external" {
        return true;
    }
    let composed = compose_control_layers(layers);
    if composed.state_for(ControlTargetKind::Extension, extension_id) == ControlState::Disabled {
        return false;
    }
    layers.iter().any(|layer| {
        layer.kind == ControlLayerKind::LocalAdmin
            && layer.controls.iter().any(|control| {
                control.target.kind == ControlTargetKind::Extension
                    && control.target.target_id == extension_id
                    && control.state == ControlState::Enabled
            })
    })
}

/// `filter_inert_external_observations` (extension_trust.py:184).
///
/// Drops external-class observations unless a local-admin ENABLE layer is
/// present. `required` is resolved from the catalog (Python reads
/// `item.extension.required` — the registry object built from this same
/// catalog).
pub fn filter_inert_external_observations(
    catalog: &CommandCatalog,
    observations: &[NativeCommandExtensionObservation],
    layers: &[ExtensionControlLayer],
) -> Vec<NativeCommandExtensionObservation> {
    observations
        .iter()
        .filter(|obs| {
            let required = catalog
                .get(&obs.extension_id)
                .map(|ext| ext.required)
                .unwrap_or(false);
            extension_is_active(catalog, &obs.extension_id, required, layers)
        })
        .cloned()
        .collect()
}

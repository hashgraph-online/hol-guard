//! The Extension Control Center's effective-state projection. Ported from
//! `daemon/extension_control_projection.py`.
//!
//! Every extension and permission resolves for command evaluation against the
//! same layers, through the resolver the command path uses, and each also
//! reports what the local and the managed layer set on it. The reason codes
//! are the resolver's factor and failure codes only, never private decision
//! evidence.

use std::collections::BTreeSet;

use guard_command::extension_control::{
    ControlLayerKind, ControlTargetKind, ExtensionControlLayer,
};
use guard_contracts::{
    ExtensionControlItemResultV1, ExtensionControlItemV1, ExtensionControlPayloadV1,
    ExtensionControlPermissionFactsV1, ExtensionControlProjectedExtensionV1,
    ExtensionControlProjectedPermissionV1, ExtensionControlRegistryV1, ExtensionControlScenarioV1,
    NativeExtensionControlLayerV1,
};

use crate::extension_control_op::{resolve_scenario, typed_layers, RequestRegistry};

/// The most extensions and permissions one projection lists; the rest of a
/// larger registry is left out, in registry order.
const MAX_EXTENSIONS: usize = 512;
const MAX_PERMISSIONS: usize = 4_096;
const SURFACE: &str = "command-evaluation";

pub(crate) fn project(
    registry: &ExtensionControlRegistryV1,
    permission_facts: &[ExtensionControlPermissionFactsV1],
    layers: &[NativeExtensionControlLayerV1],
    authority_failure: Option<&str>,
) -> Result<ExtensionControlPayloadV1, String> {
    if permission_facts.len() != registry.permissions.len() {
        return Err("native_extension_control_registry_invalid".to_owned());
    }
    let index = RequestRegistry::new(registry)?;
    let extensions = &registry.extensions[..registry.extensions.len().min(MAX_EXTENSIONS)];
    let permissions = &registry.permissions[..registry.permissions.len().min(MAX_PERMISSIONS)];
    // Each item also asks whether its extension (for a permission, its owner)
    // is active; an owner the registry does not know never is.
    let items = extensions
        .iter()
        .map(|extension| ExtensionControlItemV1 {
            extension_ids: vec![extension.extension_id.clone()],
            permission_ids: Vec::new(),
            active_extension_id: Some(extension.extension_id.clone()),
        })
        .chain(permissions.iter().map(|permission| ExtensionControlItemV1 {
            extension_ids: Vec::new(),
            permission_ids: vec![permission.permission_id.clone()],
            active_extension_id: Some(permission.extension_id.clone()),
        }))
        .collect();
    let scenario = ExtensionControlScenarioV1 {
        layers: layers.to_vec(),
        surface: SURFACE.to_owned(),
        authority_failure: authority_failure.map(str::to_owned),
        items,
    };
    let resolved = resolve_scenario(&index, &scenario)?;
    let typed = typed_layers(layers)?;
    let (extension_results, permission_results) = resolved.results.split_at(extensions.len());
    let extensions = extensions
        .iter()
        .zip(extension_results)
        .map(|(extension, result)| {
            let (local_state, managed_state) = explicit_states(
                &typed,
                ControlTargetKind::Extension,
                &extension.extension_id,
            );
            ExtensionControlProjectedExtensionV1 {
                extension_id: extension.extension_id.clone(),
                effective_state: effective_state(result).to_owned(),
                local_state,
                managed_state,
                required: extension.required,
                reason_codes: reason_codes(result),
            }
        })
        .collect();
    let permissions = permissions
        .iter()
        .zip(permission_facts)
        .zip(permission_results)
        .map(|((permission, facts), result)| {
            let (local_state, managed_state) = explicit_states(
                &typed,
                ControlTargetKind::Permission,
                &permission.permission_id,
            );
            ExtensionControlProjectedPermissionV1 {
                permission_id: permission.permission_id.clone(),
                extension_id: permission.extension_id.clone(),
                effective_state: effective_state(result).to_owned(),
                local_state,
                managed_state,
                configurable: facts.configurable,
                fixed_reason: facts.fixed_reason.clone(),
                reason_codes: reason_codes(result),
            }
        })
        .collect();
    Ok(ExtensionControlPayloadV1::Project {
        extensions,
        permissions,
    })
}

fn effective_state(result: &ExtensionControlItemResultV1) -> &'static str {
    if result.blocked || result.active != Some(true) {
        "blocked"
    } else {
        "allowed"
    }
}

/// What the local and the managed layer set on one target, from the first
/// control of that kind of layer naming it, or `inherited`.
fn explicit_states(
    layers: &[ExtensionControlLayer],
    target_kind: ControlTargetKind,
    target_id: &str,
) -> (String, String) {
    let state = |layer_kind: ControlLayerKind| {
        layers
            .iter()
            .filter(|layer| layer.kind == layer_kind)
            .flat_map(|layer| &layer.controls)
            .find(|control| {
                control.target.kind == target_kind && control.target.target_id == target_id
            })
            .map_or("inherited", |control| control.state.as_str())
            .to_owned()
    };
    (
        state(ControlLayerKind::LocalAdmin),
        state(ControlLayerKind::SignedCloud),
    )
}

fn reason_codes(result: &ExtensionControlItemResultV1) -> Vec<String> {
    result
        .factor_reason_codes
        .iter()
        .cloned()
        .chain(
            result
                .failures
                .iter()
                .map(|failure| format!("resolver.{}", failure.code)),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
#[path = "extension_control_projection_op_tests.rs"]
mod tests;

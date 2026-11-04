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
    expand_legacy_dns_layers, ControlLayerKind, ControlTargetKind, ExtensionControlLayer,
};
use guard_contracts::{
    ExtensionControlItemResultV1, ExtensionControlItemV1, ExtensionControlPayloadV1,
    ExtensionControlProjectedRowV1, ExtensionControlRegistryV1, ExtensionControlScenarioV1,
    NativeExtensionControlLayerV1,
};

use crate::extension_control_op::{resolve_scenario, typed_layers, RequestRegistry};

/// The most extensions and permissions the projection lists; the rest of a
/// larger registry is left out, in registry order.
const MAX_EXTENSIONS: usize = 512;
const MAX_PERMISSIONS: usize = 4_096;
/// The most rows one answer holds, so a page stays within the resolve
/// query's per-request work and the transport's reply cap.
const PAGE_ROWS: usize = 2_048;
const SURFACE: &str = "command-evaluation";

/// The rows from `start` on, at most `PAGE_ROWS`: the registry's leading
/// extensions, then its leading permissions. Every row resolves against the
/// same layers; a page past the last row is refused.
pub(crate) fn project(
    registry: &ExtensionControlRegistryV1,
    layers: &[NativeExtensionControlLayerV1],
    authority_failure: Option<&str>,
    start: u32,
) -> Result<ExtensionControlPayloadV1, String> {
    let index = RequestRegistry::new(registry)?;
    let extensions = &registry.extensions[..registry.extensions.len().min(MAX_EXTENSIONS)];
    let permissions = &registry.permissions[..registry.permissions.len().min(MAX_PERMISSIONS)];
    let total = extensions.len() + permissions.len();
    let start = usize::try_from(start).unwrap_or(usize::MAX);
    if start > total || (start == total && total != 0) {
        return Err("native_extension_control_registry_invalid".to_owned());
    }
    // Each row names its target and asks whether its extension (for a
    // permission, its owner) is active; an owner the registry does not know
    // never is.
    let targets: Vec<(ControlTargetKind, &str, &str)> = extensions
        .iter()
        .map(|extension| {
            let id = extension.extension_id.as_str();
            (ControlTargetKind::Extension, id, id)
        })
        .chain(permissions.iter().map(|permission| {
            (
                ControlTargetKind::Permission,
                permission.permission_id.as_str(),
                permission.extension_id.as_str(),
            )
        }))
        .skip(start)
        .take(PAGE_ROWS)
        .collect();
    let items = targets
        .iter()
        .map(|(kind, id, owner)| {
            let ids = vec![(*id).to_owned()];
            let (extension_ids, permission_ids) = match kind {
                ControlTargetKind::Extension => (ids, Vec::new()),
                ControlTargetKind::Permission => (Vec::new(), ids),
            };
            ExtensionControlItemV1 {
                extension_ids,
                permission_ids,
                active_extension_id: Some((*owner).to_owned()),
            }
        })
        .collect();
    let scenario = ExtensionControlScenarioV1 {
        layers: layers.to_vec(),
        surface: SURFACE.to_owned(),
        authority_failure: authority_failure.map(str::to_owned),
        items,
    };
    let resolved = resolve_scenario(&index, &scenario)?;
    // The resolver reads a retired aggregate DNS control as one on each
    // provider; the shown layer states read it the same way.
    let typed = expand_legacy_dns_layers(&typed_layers(layers)?);
    let rows = targets
        .iter()
        .zip(&resolved.results)
        .map(|((kind, id, _), result)| {
            let (local_state, managed_state) = explicit_states(&typed, *kind, id);
            ExtensionControlProjectedRowV1 {
                effective_state: effective_state(result).to_owned(),
                local_state,
                managed_state,
                reason_codes: reason_codes(result),
            }
        })
        .collect();
    Ok(ExtensionControlPayloadV1::Project { rows })
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

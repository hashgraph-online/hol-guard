//! Control-snapshot projection for command evaluation: binding-derived layers,
//! authority failure, the catalog-backed [`ControlRegistry`], and the wire
//! form of the composite evaluation.

use guard_contracts::NativeCommandControlBindingV1;
use serde_json::{json, Value};

use crate::command_evaluation::CompositeCommandEvaluation;
use crate::command_native_factors::AuthorityEvidence;
use crate::extension_control::{
    ControlLayerKind, ControlRegistry, ControlState, ControlTarget, ControlTargetKind,
    ExtensionControl, ExtensionControlLayer, RegistryExtension, RegistryPermission,
    ResolverFailureCode,
};
use crate::native_command_catalog::CommandCatalog;

const ERR_BINDING: &str = "native_command_control_binding_invalid";
const ERR_LAYER: &str = "native_command_control_layer_invalid";
const ERR_TARGET: &str = "native_command_control_target_invalid";

/// `ExtensionControlRuntimeSnapshot.authority_failure`.
pub fn authority_failure_for_health(
    health: &str,
) -> Result<Option<ResolverFailureCode>, &'static str> {
    match health {
        "protected" => Ok(None),
        "tampered" | "recovery-required" => Ok(Some(ResolverFailureCode::AuthorityTampered)),
        "unenrolled" | "degraded-unacknowledged" | "degraded-acknowledged" => {
            Ok(Some(ResolverFailureCode::AuthorityUnavailable))
        }
        _ => Err(ERR_BINDING),
    }
}

/// `ExtensionControlRuntimeSnapshot.private_evidence`. The binding digest is
/// bound upstream (receipt binding); it is not recomputed here.
pub fn authority_evidence(binding: &NativeCommandControlBindingV1) -> AuthorityEvidence {
    AuthorityEvidence {
        revision: binding.revision,
        effective_digest: binding.effective_digest.clone(),
    }
}

/// Wire layers -> typed layers with structural validation only.
pub fn control_layers_from_binding(
    binding: &NativeCommandControlBindingV1,
) -> Result<Vec<ExtensionControlLayer>, &'static str> {
    if binding.layers.len() > 2 {
        return Err(ERR_BINDING);
    }
    let mut layers = Vec::with_capacity(binding.layers.len());
    for wire in &binding.layers {
        let kind = match wire.kind.as_str() {
            "local-admin" => ControlLayerKind::LocalAdmin,
            "signed-cloud" => ControlLayerKind::SignedCloud,
            _ => return Err(ERR_LAYER),
        };
        if wire.controls.len() > 512 {
            return Err(ERR_LAYER);
        }
        let mut controls = Vec::with_capacity(wire.controls.len());
        for control in &wire.controls {
            let target_kind = match control.target_kind.as_str() {
                "extension" => ControlTargetKind::Extension,
                "permission" => ControlTargetKind::Permission,
                _ => return Err(ERR_TARGET),
            };
            let state = match control.state.as_str() {
                "enabled" => ControlState::Enabled,
                "disabled" => ControlState::Disabled,
                _ => return Err(ERR_TARGET),
            };
            let target = ControlTarget::new(target_kind, control.target_id.clone())
                .map_err(|_| ERR_TARGET)?;
            controls.push(ExtensionControl { target, state });
        }
        let layer = ExtensionControlLayer {
            schema_version: wire.schema_version.clone(),
            kind,
            catalog_digest: wire.catalog_digest.clone(),
            global_lockdown: wire.global_lockdown,
            controls,
        };
        layer.validate().map_err(|_| ERR_LAYER)?;
        layers.push(layer);
    }
    Ok(layers)
}

/// Wire form: `CompositeCommandEvaluation.to_dict()` plus the control
/// resolution fields host callers read.
pub fn to_wire_payload(evaluation: &CompositeCommandEvaluation) -> Value {
    let mut payload = evaluation.to_payload();
    let resolution = &evaluation.control_resolution;
    payload["control_resolution"] = json!({
        "blocked": resolution.blocked,
        "failures": resolution
            .failures
            .iter()
            .map(|failure| json!({
                "code": failure.code.as_str(),
                "layer_kind": failure.layer_kind.map(ControlLayerKind::as_str),
            }))
            .collect::<Vec<_>>(),
        "explicitly_enabled_permission_ids": resolution.explicitly_enabled_permission_ids,
        "factors": resolution.factors,
        "composed": {
            "global_lockdown": resolution.composed.global_lockdown,
            "failures": resolution
                .composed
                .failures
                .iter()
                .map(|failure| json!({
                    "code": failure.code.as_str(),
                    "layer_kind": failure.layer_kind.map(ControlLayerKind::as_str),
                }))
                .collect::<Vec<_>>(),
            "controls": resolution
                .composed
                .controls
                .iter()
                .map(|control| json!({
                    "target_kind": control.target.kind.as_str(),
                    "target_id": control.target.target_id,
                    "state": control.state.as_str(),
                }))
                .collect::<Vec<_>>(),
        },
    });
    payload
}

impl ControlRegistry for CommandCatalog {
    fn catalog_digest(&self) -> &str {
        self.catalog_digest.as_str()
    }

    fn extension(&self, extension_id: &str) -> Option<RegistryExtension> {
        CommandCatalog::get(self, extension_id).map(|extension| RegistryExtension {
            extension_id: extension.extension_id.clone(),
            dependencies: extension.dependencies.clone(),
        })
    }

    fn permission(&self, permission_id: &str) -> Option<RegistryPermission> {
        CommandCatalog::permission(self, permission_id).map(|permission| RegistryPermission {
            permission_id: permission.permission_id.clone(),
            extension_id: permission.extension_id.clone(),
            dependencies: permission.dependencies.clone(),
            implied_permissions: permission.implied_permissions.clone(),
        })
    }

    fn permission_for_rule_id(&self, rule_id: &str) -> Option<String> {
        CommandCatalog::permission_for_rule_id(self, rule_id)
            .map(|permission| permission.permission_id.clone())
    }
}

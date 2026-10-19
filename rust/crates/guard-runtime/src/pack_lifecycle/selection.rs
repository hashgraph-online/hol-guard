use super::*;
use guard_command::extension_control::{
    compose_control_layers, ControlLayerKind, ControlState, ControlTarget, ControlTargetKind,
    ExtensionControl, ExtensionControlLayer,
};

pub(super) fn select(input: &Value) -> Result<Value, String> {
    let raw = input["layers"]
        .as_array()
        .ok_or("pack_lifecycle_layers_invalid")?;
    if raw.len() > 2 {
        return Err("pack_lifecycle_layers_invalid".into());
    }
    let mut layers = Vec::new();
    let mut local = BTreeSet::new();
    let mut retained = BTreeSet::new();
    for layer in raw {
        let kind: ControlLayerKind = parse(&layer["kind"])?;
        let controls = layer["controls"]
            .as_array()
            .ok_or("pack_lifecycle_controls_invalid")?;
        if controls.len() > 512 {
            return Err("pack_lifecycle_controls_invalid".into());
        }
        let mut values = Vec::new();
        for control in controls {
            let target_kind: ControlTargetKind = parse(&control["target_kind"])?;
            let id = control["target_id"]
                .as_str()
                .ok_or("pack_lifecycle_target_invalid")?;
            let state: ControlState = parse(&control["state"])?;
            let target = ControlTarget::new(target_kind, id.into()).map_err(str::to_owned)?;
            let owner = if target_kind == ControlTargetKind::Extension {
                id
            } else {
                input["owners"][id]
                    .as_str()
                    .ok_or("pack_lifecycle_permission_unknown")?
            };
            retained.insert(owner.to_owned());
            if kind == ControlLayerKind::LocalAdmin
                && target_kind == ControlTargetKind::Extension
                && state == ControlState::Enabled
            {
                local.insert(id.to_owned());
            }
            values.push(ExtensionControl { target, state });
        }
        let layer = ExtensionControlLayer {
            schema_version: layer["schema_version"]
                .as_str()
                .ok_or("pack_lifecycle_schema_invalid")?
                .into(),
            catalog_digest: layer["catalog_digest"]
                .as_str()
                .ok_or("pack_lifecycle_digest_invalid")?
                .into(),
            kind,
            global_lockdown: layer["global_lockdown"]
                .as_bool()
                .ok_or("pack_lifecycle_lockdown_invalid")?,
            controls: values,
        };
        layer.validate().map_err(str::to_owned)?;
        layers.push(layer);
    }
    let composed = compose_control_layers(&layers);
    if !composed.failures.is_empty() {
        return Err("pack_lifecycle_composition_failed".into());
    }
    let selected: BTreeSet<_> = local
        .into_iter()
        .filter(|id| composed.state_for(ControlTargetKind::Extension, id) == ControlState::Enabled)
        .collect();
    Ok(json!({"selected":selected,"retained":retained}))
}

//! Derive compiler targets after validating the unchanged raw binding.

use std::collections::BTreeMap;

use guard_contracts::NativeExtensionControlLayerV1;

const DNS_EXTENSION_TARGETS: [&str; 3] =
    ["command.dns.aws", "command.dns.gcp", "command.dns.azure"];
const DNS_PERMISSION_TARGETS: [&str; 3] = [
    "command.dns.aws.permission.zone-deletion",
    "command.dns.gcp.permission.zone-deletion",
    "command.dns.azure.permission.public-zone-deletion",
];

/// Caller must first validate the original complete binding and exact program.
/// `true` denotes disabled. The source layer/binding is never modified.
pub(crate) fn project_validated_layer(
    layer: &NativeExtensionControlLayerV1,
) -> Result<BTreeMap<(&str, &str), bool>, &'static str> {
    let mut projected = BTreeMap::<(&str, &str), bool>::new();
    for control in &layer.controls {
        let original = [control.target_id.as_str()];
        let replacements: &[&str] = match (control.target_kind.as_str(), control.target_id.as_str())
        {
            ("extension", "command.dns") => &DNS_EXTENSION_TARGETS,
            ("permission", "command.dns.permission.delete") => &DNS_PERMISSION_TARGETS,
            _ => &original,
        };
        for target in replacements {
            let disabled = control.state == "disabled";
            projected
                .entry((control.target_kind.as_str(), *target))
                .and_modify(|previous| *previous |= disabled)
                .or_insert(disabled);
        }
    }
    if projected.len() > 512 {
        return Err("native_command_control_layer_invalid");
    }
    Ok(projected)
}

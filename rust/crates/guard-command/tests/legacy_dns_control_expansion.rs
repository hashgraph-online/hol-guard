//! Retired aggregate `command.dns` controls expand onto the provider-specific
//! DNS extensions. A collision between the aggregate and a provider target
//! merges with disable dominance in either order, and a duplicated original
//! target stays duplicated so composition still fails closed.

use guard_command::extension_control::{
    expand_legacy_dns_layers, ControlLayerKind, ControlState, ControlTarget, ControlTargetKind,
    ExtensionControl, ExtensionControlLayer, CONTROL_SCHEMA_VERSION,
};

fn layer(controls: Vec<ExtensionControl>) -> ExtensionControlLayer {
    ExtensionControlLayer {
        schema_version: CONTROL_SCHEMA_VERSION.to_owned(),
        kind: ControlLayerKind::LocalAdmin,
        catalog_digest: "a".repeat(64),
        global_lockdown: false,
        controls,
    }
}

fn control(target_id: &str, state: ControlState) -> ExtensionControl {
    ExtensionControl {
        target: ControlTarget::new(ControlTargetKind::Extension, target_id.to_owned()).unwrap(),
        state,
    }
}

fn states(layer: &ExtensionControlLayer) -> Vec<(&str, ControlState)> {
    layer
        .controls
        .iter()
        .map(|c| (c.target.target_id.as_str(), c.state))
        .collect()
}

#[test]
fn a_provider_collision_merges_with_disable_dominance_in_either_order() {
    let orders = [
        vec![
            control("command.dns", ControlState::Enabled),
            control("command.dns.aws", ControlState::Disabled),
        ],
        vec![
            control("command.dns.aws", ControlState::Disabled),
            control("command.dns", ControlState::Enabled),
        ],
    ];
    for controls in orders {
        let merged = expand_legacy_dns_layers(&[layer(controls)]);
        let mut got = states(&merged[0]);
        got.sort();
        assert_eq!(
            got,
            vec![
                ("command.dns.aws", ControlState::Disabled),
                ("command.dns.azure", ControlState::Enabled),
                ("command.dns.gcp", ControlState::Enabled),
            ]
        );
    }
}

#[test]
fn a_duplicated_original_target_stays_duplicated() {
    let duplicated = expand_legacy_dns_layers(&[layer(vec![
        control("command.dns.aws", ControlState::Disabled),
        control("command.dns.aws", ControlState::Disabled),
    ])]);
    assert_eq!(
        states(&duplicated[0]),
        vec![
            ("command.dns.aws", ControlState::Disabled),
            ("command.dns.aws", ControlState::Disabled),
        ]
    );
}

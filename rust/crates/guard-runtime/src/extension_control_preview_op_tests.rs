use super::layers::layers_with_target_reverted;
use super::*;
use crate::extension_control_op::evaluate_extension_control_request;
use guard_contracts::{
    ExtensionControlPayloadV1, ExtensionControlQueryV1, ExtensionControlRequestV1,
    ExtensionControlResultV1, NativeExtensionControlV1, EXTENSION_CONTROL_REQUEST_SCHEMA,
};

const ALPHA: &str = "command.alpha";
const BETA: &str = "command.beta";
const GAMMA: &str = "command.gamma";
const ALPHA_READ: &str = "command.alpha.permission.read";
const ALPHA_WRITE: &str = "command.alpha.permission.write";
const BETA_RUN: &str = "command.beta.permission.run";
const GAMMA_DEPLOY: &str = "command.gamma.permission.deploy";
const UNKNOWN: &str = "command.unknown.permission.read";

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn digest() -> String {
    "a".repeat(64)
}

fn control(kind: &str, target_id: &str, state: &str) -> NativeExtensionControlV1 {
    NativeExtensionControlV1 {
        target_kind: kind.to_owned(),
        target_id: target_id.to_owned(),
        state: state.to_owned(),
    }
}

fn permission_control(target_id: &str, state: &str) -> NativeExtensionControlV1 {
    control("permission", target_id, state)
}

fn layer(
    kind: &str,
    lockdown: bool,
    controls: Vec<NativeExtensionControlV1>,
) -> NativeExtensionControlLayerV1 {
    NativeExtensionControlLayerV1 {
        schema_version: "1.0.0".to_owned(),
        kind: kind.to_owned(),
        catalog_digest: digest(),
        global_lockdown: lockdown,
        controls,
    }
}

fn local(controls: Vec<NativeExtensionControlV1>) -> NativeExtensionControlLayerV1 {
    layer("local-admin", false, controls)
}

fn cloud(controls: Vec<NativeExtensionControlV1>) -> NativeExtensionControlLayerV1 {
    layer("signed-cloud", false, controls)
}

fn extension(id: &str, name: &str, dependencies: &[&str]) -> ExtensionControlPreviewExtensionV1 {
    ExtensionControlPreviewExtensionV1 {
        extension_id: id.to_owned(),
        name: name.to_owned(),
        aliases: Vec::new(),
        dependencies: strings(dependencies),
        rule_ids: vec![format!("{id}.rule.base")],
    }
}

fn permission(
    id: &str,
    owner: &str,
    label: &str,
    dependencies: &[&str],
    conflicts: &[&str],
) -> ExtensionControlPreviewPermissionV1 {
    ExtensionControlPreviewPermissionV1 {
        permission_id: id.to_owned(),
        extension_id: owner.to_owned(),
        label: label.to_owned(),
        risk_tier: "high".to_owned(),
        baseline_floor: "review".to_owned(),
        rule_ids: vec![format!("{id}.rule")],
        dependencies: strings(dependencies),
        conflicts: strings(conflicts),
        implied_permissions: Vec::new(),
    }
}

/// gamma depends on alpha; gamma's deploy permission depends on alpha's write
/// permission, and alpha's write permission conflicts with its read one.
fn registry() -> ExtensionControlPreviewRegistryV1 {
    ExtensionControlPreviewRegistryV1 {
        catalog_digest: digest(),
        extensions: vec![
            extension(ALPHA, "Alpha", &[]),
            extension(BETA, "Beta", &[]),
            extension(GAMMA, "Gamma", &[ALPHA]),
        ],
        permissions: vec![
            permission(ALPHA_READ, ALPHA, "Alpha read", &[], &[]),
            permission(ALPHA_WRITE, ALPHA, "Alpha write", &[], &[ALPHA_READ]),
            permission(BETA_RUN, BETA, "Beta run", &[], &[]),
            permission(GAMMA_DEPLOY, GAMMA, "Gamma deploy", &[ALPHA_WRITE], &[]),
        ],
    }
}

fn run(
    registry: ExtensionControlPreviewRegistryV1,
    current_layers: Vec<NativeExtensionControlLayerV1>,
    proposed_layers: Vec<NativeExtensionControlLayerV1>,
) -> ExtensionControlResultV1 {
    let request = ExtensionControlRequestV1 {
        schema: EXTENSION_CONTROL_REQUEST_SCHEMA.to_owned(),
        request_id: "extension-control-preview-1".to_owned(),
        query: ExtensionControlQueryV1::Preview {
            registry,
            current_layers,
            proposed_layers,
        },
    };
    let bytes = evaluate_extension_control_request(&request).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn preview(
    current_layers: Vec<NativeExtensionControlLayerV1>,
    proposed_layers: Vec<NativeExtensionControlLayerV1>,
) -> ExtensionControlSemanticPreviewV1 {
    let result = run(registry(), current_layers, proposed_layers);
    assert_eq!(result.status, "ok", "{}", result.code);
    match result.payload {
        Some(ExtensionControlPayloadV1::Preview { preview }) => preview,
        other => panic!("expected preview payload, got {other:?}"),
    }
}

#[test]
fn disabling_a_permission_reports_its_marginal_blast_radius() {
    let preview = preview(
        Vec::new(),
        vec![local(vec![permission_control(ALPHA_WRITE, "disabled")])],
    );

    assert_eq!(
        preview.schema_version,
        "guard.daemon.extension-control-semantic-preview.v1"
    );
    assert!(preview.approval_required);
    assert_eq!(preview.changed_target_count, 1);
    let target = &preview.changed_targets[0];
    assert_eq!(target.target.kind, "permission");
    assert_eq!(target.target.target_id, ALPHA_WRITE);
    assert_eq!(target.extension_id, ALPHA);
    assert_eq!(target.label, "Alpha write");
    assert_eq!(target.extension_name.as_deref(), Some("Alpha"));
    assert_eq!(
        (
            target.before_explicit.as_str(),
            target.after_explicit.as_str()
        ),
        ("inherited", "disabled")
    );
    assert_eq!(
        (
            target.before_effective.as_str(),
            target.after_effective.as_str()
        ),
        ("allowed", "blocked")
    );
    assert_eq!(target.baseline_risk.as_deref(), Some("high"));
    assert_eq!(target.baseline_floor.as_deref(), Some("review"));
    // deploy depends on write, so disabling write blocks it too.
    assert_eq!(
        target.affected_permission_ids,
        strings(&[ALPHA_WRITE, GAMMA_DEPLOY])
    );
    assert_eq!(
        target.affected_rule_ids,
        vec![
            format!("{ALPHA_WRITE}.rule"),
            format!("{GAMMA_DEPLOY}.rule")
        ]
    );
    assert_eq!(target.affected_extension_ids, strings(&[ALPHA, GAMMA]));
    assert_eq!(target.conflict_permission_ids, strings(&[ALPHA_READ]));
    assert_eq!(target.provenance, strings(&["local-admin"]));
    let codes: Vec<&str> = target.warnings.iter().map(|w| w.code.as_str()).collect();
    assert_eq!(
        codes,
        [
            "conflicting-permission-effective",
            "dependent-permissions-affected"
        ]
    );
    assert_eq!(target.warnings[0].target_id.as_deref(), Some(ALPHA_READ));
    assert_eq!(
        target.warnings[0].message,
        "Conflicting permission Alpha read remains effective."
    );
    assert_eq!(target.warnings[1].count, Some(1));
    assert_eq!(preview.affected_permission_count, 2);
    assert_eq!(preview.affected_rule_count, 2);
    assert_eq!(preview.summary.newly_blocked_permissions, 2);
    assert_eq!(preview.summary.newly_allowed_permissions, 0);
    assert_eq!(preview.summary.effective_change_count, 2);
}

#[test]
fn a_managed_disable_dominating_a_local_allow_is_explained() {
    let managed = cloud(vec![permission_control(BETA_RUN, "disabled")]);
    let preview = preview(
        vec![managed.clone()],
        vec![
            local(vec![permission_control(BETA_RUN, "enabled")]),
            managed,
        ],
    );

    let target = &preview.changed_targets[0];
    assert_eq!(target.after_explicit, "enabled");
    assert_eq!(target.after_effective, "blocked");
    assert_eq!(target.provenance, strings(&["local-admin", "signed-cloud"]));
    assert_eq!(target.warnings[0].code, "requested-allow-not-effective");
    assert_eq!(
        target.warnings[0].message,
        "A stronger parent, dependency, lockdown, or managed control still blocks this permission."
    );
    assert_eq!(preview.summary.effective_change_count, 0);
}

#[test]
fn disabling_an_extension_reports_its_rules_and_dependencies() {
    let preview = preview(
        Vec::new(),
        vec![local(vec![control("extension", GAMMA, "disabled")])],
    );

    let target = &preview.changed_targets[0];
    assert_eq!(target.target.kind, "extension");
    assert_eq!(target.label, "Gamma");
    assert_eq!(target.before_effective, "allowed");
    assert_eq!(target.after_effective, "blocked");
    assert_eq!(target.affected_permission_ids, strings(&[GAMMA_DEPLOY]));
    assert_eq!(
        target.affected_rule_ids,
        vec![format!("{GAMMA_DEPLOY}.rule"), format!("{GAMMA}.rule.base")]
    );
    assert_eq!(target.affected_extension_ids, strings(&[ALPHA, GAMMA]));
    assert!(target.baseline_risk.is_none() && target.extension_name.is_none());
    assert!(target.dependency_permission_ids.is_empty());
    assert!(target.warnings.is_empty());
}

#[test]
fn unchanged_and_unknown_targets_yield_no_entries() {
    let same = vec![local(vec![permission_control(ALPHA_READ, "disabled")])];
    let unchanged = preview(same.clone(), same);
    assert_eq!(unchanged.changed_target_count, 0);
    assert!(!unchanged.approval_required);

    let unknown = preview(
        Vec::new(),
        vec![local(vec![permission_control(UNKNOWN, "disabled")])],
    );
    assert_eq!(unknown.changed_target_count, 0);
    assert!(unknown.changed_targets.is_empty());
}

#[test]
fn an_unknown_target_that_changes_what_is_blocked_still_needs_approval() {
    // A layer holding a target the catalog does not know blocks every
    // permission while it is present, with no changed target to show for it.
    let added = preview(
        Vec::new(),
        vec![local(vec![permission_control(UNKNOWN, "disabled")])],
    );
    assert!(added.changed_targets.is_empty());
    assert_eq!(added.summary.newly_blocked_permissions, 4);
    assert!(added.approval_required);

    let dropped = preview(
        vec![local(vec![permission_control(UNKNOWN, "disabled")])],
        Vec::new(),
    );
    assert!(dropped.changed_targets.is_empty());
    assert_eq!(dropped.summary.newly_allowed_permissions, 4);
    assert!(dropped.approval_required);
}

#[test]
fn a_lockdown_change_needs_approval_and_leads_provenance() {
    let preview = preview(
        Vec::new(),
        vec![layer(
            "local-admin",
            true,
            vec![permission_control(ALPHA_READ, "disabled")],
        )],
    );

    assert!(preview.global_lockdown.after && preview.global_lockdown.changed);
    assert!(!preview.global_lockdown.before);
    assert!(preview.approval_required);
    assert_eq!(
        preview.changed_targets[0].provenance,
        strings(&["global-lockdown", "local-admin"])
    );
}

#[test]
fn reverting_a_target_restores_the_current_control_in_sorted_order() {
    let current = vec![local(vec![permission_control(BETA_RUN, "enabled")])];
    let proposed = vec![local(vec![
        permission_control(GAMMA_DEPLOY, "disabled"),
        permission_control(BETA_RUN, "disabled"),
        control("extension", ALPHA, "disabled"),
    ])];

    let restored = layers_with_target_reverted(&current, &proposed, ("permission", BETA_RUN));
    let ids: Vec<(&str, &str, &str)> = restored[0]
        .controls
        .iter()
        .map(|c| {
            (
                c.target_kind.as_str(),
                c.target_id.as_str(),
                c.state.as_str(),
            )
        })
        .collect();
    assert_eq!(
        ids,
        [
            ("extension", ALPHA, "disabled"),
            ("permission", BETA_RUN, "enabled"),
            ("permission", GAMMA_DEPLOY, "disabled"),
        ]
    );

    let removed = layers_with_target_reverted(&current, &proposed, ("permission", GAMMA_DEPLOY));
    assert_eq!(removed[0].controls.len(), 2);
    // A target the current local layer holds no control for has nothing to put back.
    assert!(layers_with_target_reverted(&current, &[], ("permission", ALPHA_READ)).is_empty());
}

#[test]
fn reverting_against_a_proposal_without_a_local_layer_restores_only_that_control() {
    let current = vec![layer(
        "local-admin",
        true,
        vec![
            permission_control(BETA_RUN, "disabled"),
            permission_control(ALPHA_READ, "disabled"),
        ],
    )];
    let managed = cloud(Vec::new());
    let proposed = vec![managed.clone()];

    let restored = layers_with_target_reverted(&current, &proposed, ("permission", BETA_RUN));
    assert_eq!(restored.len(), 2);
    assert_eq!(restored[0].kind, "local-admin");
    assert_eq!(restored[0].catalog_digest, digest());
    // The lockdown belongs to the layer the proposal dropped.
    assert!(!restored[0].global_lockdown);
    assert_eq!(
        restored[0].controls,
        vec![permission_control(BETA_RUN, "disabled")]
    );
    assert_eq!(restored[1], managed);
    assert_eq!(
        layers_with_target_reverted(&current, &proposed, ("permission", ALPHA_WRITE)),
        proposed
    );
}

#[test]
fn a_proposal_that_clears_the_local_layer_reports_each_target_its_marginal_effect() {
    let preview = preview(
        vec![local(vec![permission_control(ALPHA_WRITE, "disabled")])],
        Vec::new(),
    );

    assert_eq!(preview.changed_target_count, 1);
    let target = &preview.changed_targets[0];
    assert_eq!(
        (
            target.before_explicit.as_str(),
            target.after_explicit.as_str()
        ),
        ("disabled", "inherited")
    );
    assert_eq!(
        (
            target.before_effective.as_str(),
            target.after_effective.as_str()
        ),
        ("blocked", "allowed")
    );
    assert_eq!(
        target.affected_permission_ids,
        strings(&[ALPHA_WRITE, GAMMA_DEPLOY])
    );
    assert_eq!(preview.summary.newly_allowed_permissions, 2);
}

#[test]
fn the_wire_keeps_the_dashboard_field_order_and_omits_absent_fields() {
    let preview = preview(
        Vec::new(),
        vec![local(vec![
            permission_control(ALPHA_WRITE, "disabled"),
            control("extension", BETA, "disabled"),
        ])],
    );
    let extension = serde_json::to_string(&preview.changed_targets[0]).unwrap();
    assert!(extension.starts_with(r#"{"target":{"kind":"extension""#));
    assert!(!extension.contains("baseline_risk") && !extension.contains("extension_name"));

    let permission = serde_json::to_string(&preview.changed_targets[1]).unwrap();
    let order = [
        "\"target\"",
        "\"extension_id\"",
        "\"label\"",
        "\"after_effective\"",
        "\"baseline_risk\"",
        "\"baseline_floor\"",
        "\"affected_permission_ids\"",
        "\"provenance\"",
        "\"warnings\"",
        "\"extension_name\"",
    ];
    let positions: Vec<usize> = order
        .iter()
        .map(|key| permission.find(key).unwrap())
        .collect();
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "{permission}"
    );
    assert!(permission.contains(r#"{"code":"conflicting-permission-effective","target_id":"#));
}

#[test]
fn a_broken_catalog_or_layer_is_refused() {
    let mut duplicate = registry();
    duplicate.permissions.push(duplicate.permissions[0].clone());
    assert_eq!(
        run(duplicate, Vec::new(), Vec::new()).code,
        "native_extension_control_registry_invalid"
    );

    let mut broken = local(Vec::new());
    broken.kind = "local".to_owned();
    let result = run(registry(), Vec::new(), vec![broken]);
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_extension_control_layer_invalid");
    assert!(result.payload.is_none());
}

#[path = "extension_control_preview_op_limits_tests.rs"]
mod limits;

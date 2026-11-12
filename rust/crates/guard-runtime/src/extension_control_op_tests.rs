use super::*;
use guard_contracts::NativeExtensionControlV1;

const DIGEST_CHARS: &str = "a";
const ALPHA: &str = "command.alpha";
const BETA: &str = "command.beta";
const BETA_ALIAS: &str = "command.beta-legacy";
const GAMMA: &str = "command.gamma";
const ALPHA_READ: &str = "command.alpha.permission.read";
const ALPHA_WRITE: &str = "command.alpha.permission.write";
const BETA_RUN: &str = "command.beta.permission.run";
const GAMMA_DEPLOY: &str = "command.gamma.permission.deploy";

fn digest() -> String {
    DIGEST_CHARS.repeat(64)
}

fn control(kind: &str, target_id: &str, state: &str) -> NativeExtensionControlV1 {
    NativeExtensionControlV1 {
        target_kind: kind.to_owned(),
        target_id: target_id.to_owned(),
        state: state.to_owned(),
    }
}

fn disabled_extension(target_id: &str) -> NativeExtensionControlV1 {
    control("extension", target_id, "disabled")
}

fn enabled_extension(target_id: &str) -> NativeExtensionControlV1 {
    control("extension", target_id, "enabled")
}

fn disabled_permission(target_id: &str) -> NativeExtensionControlV1 {
    control("permission", target_id, "disabled")
}

fn enabled_permission(target_id: &str) -> NativeExtensionControlV1 {
    control("permission", target_id, "enabled")
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

fn extension(
    id: &str,
    aliases: &[&str],
    dependencies: &[&str],
    required: bool,
    trust_class: &str,
) -> ExtensionControlRegistryExtensionV1 {
    ExtensionControlRegistryExtensionV1 {
        extension_id: id.to_owned(),
        aliases: aliases.iter().map(|value| (*value).to_owned()).collect(),
        dependencies: dependencies
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        required,
        trust_class: Some(trust_class.to_owned()),
    }
}

fn permission(
    id: &str,
    owner: &str,
    dependencies: &[&str],
    implied: &[&str],
) -> ExtensionControlRegistryPermissionV1 {
    ExtensionControlRegistryPermissionV1 {
        permission_id: id.to_owned(),
        extension_id: owner.to_owned(),
        dependencies: dependencies
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        implied_permissions: implied.iter().map(|value| (*value).to_owned()).collect(),
    }
}

/// alpha (first-party), beta (external, aliased), gamma (required, depends on
/// alpha). gamma's deploy permission depends on alpha's write permission and
/// implies beta's run permission.
fn registry() -> ExtensionControlRegistryV1 {
    ExtensionControlRegistryV1 {
        catalog_digest: digest(),
        extensions: vec![
            extension(ALPHA, &[], &[], false, "first-party"),
            extension(BETA, &[BETA_ALIAS], &[], false, "external"),
            extension(GAMMA, &[], &[ALPHA], true, "trusted-library"),
        ],
        permissions: vec![
            permission(ALPHA_READ, ALPHA, &[], &[]),
            permission(ALPHA_WRITE, ALPHA, &[], &[]),
            permission(BETA_RUN, BETA, &[], &[]),
            permission(GAMMA_DEPLOY, GAMMA, &[ALPHA_WRITE], &[BETA_RUN]),
        ],
    }
}

fn item(extensions: &[&str], permissions: &[&str]) -> ExtensionControlItemV1 {
    ExtensionControlItemV1 {
        extension_ids: extensions.iter().map(|value| (*value).to_owned()).collect(),
        permission_ids: permissions
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        active_extension_id: None,
    }
}

fn active_item(extension_id: &str) -> ExtensionControlItemV1 {
    ExtensionControlItemV1 {
        extension_ids: Vec::new(),
        permission_ids: Vec::new(),
        active_extension_id: Some(extension_id.to_owned()),
    }
}

fn scenario(
    layers: Vec<NativeExtensionControlLayerV1>,
    items: Vec<ExtensionControlItemV1>,
) -> ExtensionControlScenarioV1 {
    ExtensionControlScenarioV1 {
        layers,
        surface: "command-evaluation".to_owned(),
        authority_failure: None,
        items,
    }
}

fn request(query: ExtensionControlQueryV1) -> ExtensionControlRequestV1 {
    ExtensionControlRequestV1 {
        schema: EXTENSION_CONTROL_REQUEST_SCHEMA.to_owned(),
        request_id: "extension-control-1".to_owned(),
        query,
    }
}

fn resolve_request(scenarios: Vec<ExtensionControlScenarioV1>) -> ExtensionControlRequestV1 {
    request(ExtensionControlQueryV1::Resolve {
        registry: registry(),
        scenarios,
    })
}

fn run(request: &ExtensionControlRequestV1) -> ExtensionControlResultV1 {
    let bytes = evaluate_extension_control_request(request).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn resolved(scenarios: Vec<ExtensionControlScenarioV1>) -> Vec<ExtensionControlScenarioResultV1> {
    let result = run(&resolve_request(scenarios));
    assert_eq!(result.status, "ok", "{}", result.code);
    match result.payload {
        Some(ExtensionControlPayloadV1::Resolve { scenarios }) => scenarios,
        other => panic!("expected resolve payload, got {other:?}"),
    }
}

fn resolve_one(
    layers: Vec<NativeExtensionControlLayerV1>,
    item: ExtensionControlItemV1,
) -> ExtensionControlItemResultV1 {
    resolved(vec![scenario(layers, vec![item])])
        .remove(0)
        .results
        .remove(0)
}

fn composed(layers: Vec<NativeExtensionControlLayerV1>) -> ExtensionControlComposedV1 {
    let result = run(&request(ExtensionControlQueryV1::Compose { layers }));
    assert_eq!(result.status, "ok", "{}", result.code);
    match result.payload {
        Some(ExtensionControlPayloadV1::Compose { composed }) => composed,
        other => panic!("expected compose payload, got {other:?}"),
    }
}

fn error_code(request: &ExtensionControlRequestV1) -> String {
    let result = run(request);
    assert_eq!(result.status, "error");
    assert!(result.payload.is_none());
    result.code
}

fn failure_pairs(failures: &[ExtensionControlFailureV1]) -> Vec<(String, Option<String>)> {
    failures
        .iter()
        .map(|failure| (failure.code.clone(), failure.layer_kind.clone()))
        .collect()
}

fn failure_codes(failures: &[ExtensionControlFailureV1]) -> Vec<&str> {
    failures
        .iter()
        .map(|failure| failure.code.as_str())
        .collect()
}

#[test]
fn composition_is_permutation_independent_and_disable_dominates_enable() {
    let local_layer = local(vec![
        enabled_extension(ALPHA),
        disabled_permission(ALPHA_READ),
    ]);
    let cloud_layer = cloud(vec![
        disabled_extension(ALPHA),
        enabled_permission(ALPHA_READ),
    ]);
    let forward = composed(vec![local_layer.clone(), cloud_layer.clone()]);
    let reverse = composed(vec![cloud_layer, local_layer]);

    assert_eq!(forward, reverse);
    assert!(!forward.global_lockdown);
    assert!(forward.failures.is_empty());
    let states: Vec<(&str, &str, &str)> = forward
        .controls
        .iter()
        .map(|control| {
            (
                control.target_kind.as_str(),
                control.target_id.as_str(),
                control.state.as_str(),
            )
        })
        .collect();
    assert_eq!(
        states,
        vec![
            ("extension", ALPHA, "disabled"),
            ("permission", ALPHA_READ, "disabled"),
        ]
    );
}

#[test]
fn composition_reports_duplicates_sorted_by_string_value() {
    let duplicated = composed(vec![
        local(vec![disabled_extension(ALPHA), disabled_extension(ALPHA)]),
        local(Vec::new()),
    ]);

    assert_eq!(
        failure_pairs(&duplicated.failures),
        vec![
            (
                "duplicate-layer-kind".to_owned(),
                Some("local-admin".to_owned())
            ),
            (
                "duplicate-target-in-layer".to_owned(),
                Some("local-admin".to_owned())
            ),
        ]
    );
}

#[test]
fn composition_takes_more_layers_than_the_resolver_admits_and_reports_them() {
    let three = composed(vec![
        local(Vec::new()),
        cloud(Vec::new()),
        local(Vec::new()),
    ]);

    assert_eq!(failure_codes(&three.failures), vec!["duplicate-layer-kind"]);
}

#[test]
fn composition_of_nothing_is_empty_and_unlocked() {
    let nothing = composed(Vec::new());

    assert!(!nothing.global_lockdown);
    assert!(nothing.controls.is_empty());
    assert!(nothing.failures.is_empty());
}

#[test]
fn lockdown_in_any_layer_locks_the_composition() {
    let locked = composed(vec![
        local(Vec::new()),
        layer("signed-cloud", true, Vec::new()),
    ]);

    assert!(locked.global_lockdown);
}

#[test]
fn an_unreadable_layer_is_a_bound_error_naming_the_layer() {
    for broken in [
        layer("unknown-kind", false, Vec::new()),
        NativeExtensionControlLayerV1 {
            schema_version: "2.0.0".to_owned(),
            ..local(Vec::new())
        },
        NativeExtensionControlLayerV1 {
            catalog_digest: "A".repeat(64),
            ..local(Vec::new())
        },
        local(vec![control("extension", ALPHA, "inherited")]),
        local(vec![control("extension", "not-a-catalog-id", "disabled")]),
        local(vec![control("permission", ALPHA, "disabled")]),
        local(vec![control("extension", ALPHA_READ, "disabled")]),
    ] {
        assert_eq!(
            error_code(&request(ExtensionControlQueryV1::Compose {
                layers: vec![broken.clone()]
            })),
            "native_extension_control_layer_invalid",
            "{broken:?}"
        );
        assert_eq!(
            error_code(&resolve_request(vec![scenario(
                vec![broken],
                vec![item(&[ALPHA], &[])]
            )])),
            "native_extension_control_layer_invalid"
        );
    }
}

#[path = "extension_control_op_boundary_tests.rs"]
mod boundary;
#[path = "extension_control_op_resolve_tests.rs"]
mod resolve;
#[path = "extension_control_op_snapshot_tests.rs"]
mod snapshot;

use super::*;
use crate::extension_control_op::evaluate_extension_control_request;
use guard_contracts::{
    ExtensionControlMutationPermissionV1, ExtensionControlQueryV1, ExtensionControlRequestV1,
    ExtensionControlResultV1, EXTENSION_CONTROL_REQUEST_SCHEMA,
};
use serde_json::{json, Value};

const ALPHA: &str = "command.alpha";
const BETA: &str = "command.beta";
const BETA_ALIAS: &str = "command.beta-legacy";
const GAMMA: &str = "command.gamma";
const DELTA: &str = "command.delta";
const DELTA_REQUIRED: &str = "command.delta-required";
const UNKNOWN: &str = "command.unknown";
const ALPHA_READ: &str = "command.alpha.permission.read";
const GAMMA_FIXED: &str = "command.gamma.permission.fixed";
const DELTA_READ: &str = "command.delta.permission.read";
const DELTA_FIXED: &str = "command.delta.permission.fixed";
const UNKNOWN_PERMISSION: &str = "command.alpha.permission.unknown";

fn digest() -> String {
    "a".repeat(64)
}

fn other_digest() -> String {
    "b".repeat(64)
}

fn control(kind: &str, target_id: &str, state: &str) -> NativeExtensionControlV1 {
    NativeExtensionControlV1 {
        target_kind: kind.to_owned(),
        target_id: target_id.to_owned(),
        state: state.to_owned(),
    }
}

fn extension_control(target_id: &str, state: &str) -> NativeExtensionControlV1 {
    control("extension", target_id, state)
}

fn permission_control(target_id: &str, state: &str) -> NativeExtensionControlV1 {
    control("permission", target_id, state)
}

fn layer(kind: &str, controls: Vec<NativeExtensionControlV1>) -> NativeExtensionControlLayerV1 {
    NativeExtensionControlLayerV1 {
        schema_version: "1.0.0".to_owned(),
        kind: kind.to_owned(),
        catalog_digest: digest(),
        global_lockdown: false,
        controls,
    }
}

fn local(controls: Vec<NativeExtensionControlV1>) -> NativeExtensionControlLayerV1 {
    layer("local-admin", controls)
}

fn cloud(controls: Vec<NativeExtensionControlV1>) -> NativeExtensionControlLayerV1 {
    layer("signed-cloud", controls)
}

fn catalog_extension(
    id: &str,
    aliases: &[&str],
    required: bool,
) -> ExtensionControlMutationExtensionV1 {
    ExtensionControlMutationExtensionV1 {
        extension_id: id.to_owned(),
        aliases: aliases.iter().map(|alias| (*alias).to_owned()).collect(),
        required,
    }
}

fn catalog_permission(id: &str, configurable: bool) -> ExtensionControlMutationPermissionV1 {
    ExtensionControlMutationPermissionV1 {
        permission_id: id.to_owned(),
        configurable,
    }
}

fn overlay(
    id: &str,
    required: bool,
    permissions: Vec<ExtensionControlMutationPermissionV1>,
) -> ExtensionControlMutationOverlayV1 {
    ExtensionControlMutationOverlayV1 {
        extension_id: id.to_owned(),
        required,
        permissions,
    }
}

/// alpha, beta (aliased) and gamma (required); gamma's fixed permission is not
/// configurable. The overlay knows delta and a required delta-required, each
/// with a fixed permission where it matters.
fn registry() -> ExtensionControlMutationRegistryV1 {
    ExtensionControlMutationRegistryV1 {
        extensions: vec![
            catalog_extension(ALPHA, &[], false),
            catalog_extension(BETA, &[BETA_ALIAS], false),
            catalog_extension(GAMMA, &[], true),
        ],
        permissions: vec![
            catalog_permission(ALPHA_READ, true),
            catalog_permission(GAMMA_FIXED, false),
        ],
        overlay: vec![
            overlay(
                DELTA,
                false,
                vec![
                    catalog_permission(DELTA_READ, true),
                    catalog_permission(DELTA_FIXED, false),
                ],
            ),
            overlay(DELTA_REQUIRED, true, Vec::new()),
        ],
    }
}

fn request(query: ExtensionControlQueryV1) -> ExtensionControlRequestV1 {
    ExtensionControlRequestV1 {
        schema: EXTENSION_CONTROL_REQUEST_SCHEMA.to_owned(),
        request_id: "extension-control-1".to_owned(),
        query,
    }
}

fn run(query: ExtensionControlQueryV1) -> ExtensionControlResultV1 {
    let bytes = evaluate_extension_control_request(&request(query)).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// A verdict's refusal and layers; the reply itself must be `ok`.
fn verdict(query: ExtensionControlQueryV1) -> (Option<String>, Vec<NativeExtensionControlLayerV1>) {
    let result = run(query);
    assert_eq!(result.status, "ok", "{}", result.code);
    match result.payload {
        Some(ExtensionControlPayloadV1::MutationValidate { refusal, layers }) => (refusal, layers),
        Some(
            ExtensionControlPayloadV1::MutationBounds { refusal }
            | ExtensionControlPayloadV1::MutabilityValidate { refusal },
        ) => (refusal, Vec::new()),
        other => panic!("expected a mutation verdict, got {other:?}"),
    }
}

fn error_code(query: ExtensionControlQueryV1) -> String {
    let result = run(query);
    assert_eq!(result.status, "error");
    assert!(result.payload.is_none());
    result.code
}

fn bounds_query(layers: Vec<NativeExtensionControlLayerV1>) -> ExtensionControlQueryV1 {
    ExtensionControlQueryV1::MutationBounds { layers }
}

fn validate_query(
    registry: ExtensionControlMutationRegistryV1,
    requested_catalog_digest: String,
    current_layers: Vec<NativeExtensionControlLayerV1>,
    layers: Vec<NativeExtensionControlLayerV1>,
) -> ExtensionControlQueryV1 {
    ExtensionControlQueryV1::MutationValidate {
        registry,
        catalog_digest: digest(),
        requested_catalog_digest,
        current_layers,
        layers,
    }
}

/// The refusal a draft meets against the served catalog.
fn refusal(
    current_layers: Vec<NativeExtensionControlLayerV1>,
    layers: Vec<NativeExtensionControlLayerV1>,
) -> Option<String> {
    verdict(validate_query(registry(), digest(), current_layers, layers)).0
}

fn mutability_refusal(
    registry: ExtensionControlMutationRegistryV1,
    current_layers: Vec<NativeExtensionControlLayerV1>,
    layers: Vec<NativeExtensionControlLayerV1>,
) -> Option<String> {
    let (refusal, canonical) = verdict(ExtensionControlQueryV1::MutabilityValidate {
        registry,
        current_layers,
        layers,
    });
    assert!(canonical.is_empty());
    refusal
}

fn controls(count: usize) -> Vec<NativeExtensionControlV1> {
    (0..count)
        .map(|_| extension_control(ALPHA, "disabled"))
        .collect()
}

fn some(reason: &str) -> Option<String> {
    Some(reason.to_owned())
}

#[test]
fn bounds_accept_the_largest_mutation() {
    let (refusal, layers) = verdict(bounds_query(vec![
        local(controls(512)),
        cloud(controls(512)),
    ]));
    assert_eq!(refusal, None);
    assert!(layers.is_empty());
    assert_eq!(verdict(bounds_query(Vec::new())).0, None);
}

#[test]
fn bounds_refuse_a_third_layer() {
    let layers = vec![local(Vec::new()), cloud(Vec::new()), local(Vec::new())];
    assert_eq!(
        verdict(bounds_query(layers)).0,
        some("layer_limit_exceeded")
    );
}

#[test]
fn bounds_refuse_a_layer_over_its_control_limit() {
    let layers = vec![local(controls(513))];
    assert_eq!(
        verdict(bounds_query(layers)).0,
        some("layer_control_limit_exceeded")
    );
}

#[test]
fn bounds_report_the_layer_count_before_the_control_count() {
    let layers = vec![
        local(controls(513)),
        cloud(controls(513)),
        local(controls(513)),
    ];
    assert_eq!(
        verdict(bounds_query(layers)).0,
        some("layer_limit_exceeded")
    );
}

#[test]
fn an_accepted_mutation_returns_its_layers_unchanged() {
    let layers = vec![local(vec![
        extension_control(ALPHA, "disabled"),
        permission_control(ALPHA_READ, "enabled"),
    ])];
    let (refusal, canonical) = verdict(validate_query(
        registry(),
        digest(),
        Vec::new(),
        layers.clone(),
    ));
    assert_eq!(refusal, None);
    assert_eq!(canonical, layers);
}

#[test]
fn an_empty_mutation_is_accepted() {
    let (refusal, canonical) =
        verdict(validate_query(registry(), digest(), Vec::new(), Vec::new()));
    assert_eq!(refusal, None);
    assert!(canonical.is_empty());
}

#[test]
fn an_alias_resolves_to_its_canonical_extension() {
    let layers = vec![
        local(vec![
            extension_control(BETA_ALIAS, "disabled"),
            permission_control(ALPHA_READ, "disabled"),
        ]),
        cloud(Vec::new()),
    ];
    // The managed layer a draft names must be the one the runtime holds.
    let current = vec![cloud(Vec::new())];
    let (refused, canonical) = verdict(validate_query(registry(), digest(), current, layers));
    assert_eq!(refused, None);
    assert_eq!(
        canonical,
        vec![
            local(vec![
                extension_control(BETA, "disabled"),
                permission_control(ALPHA_READ, "disabled"),
            ]),
            cloud(Vec::new()),
        ]
    );
}

#[test]
fn canonical_layers_keep_their_other_fields() {
    let mut draft = local(vec![extension_control(BETA_ALIAS, "enabled")]);
    draft.global_lockdown = true;
    let (refusal, canonical) = verdict(validate_query(
        registry(),
        digest(),
        Vec::new(),
        vec![draft.clone()],
    ));
    assert_eq!(refusal, None);
    assert_eq!(canonical.len(), 1);
    assert_eq!(canonical[0].kind, draft.kind);
    assert_eq!(canonical[0].schema_version, draft.schema_version);
    assert_eq!(canonical[0].catalog_digest, draft.catalog_digest);
    assert!(canonical[0].global_lockdown);
    assert_eq!(
        canonical[0].controls,
        vec![extension_control(BETA, "enabled")]
    );
}

#[test]
fn an_unknown_extension_is_refused() {
    assert_eq!(
        refusal(
            Vec::new(),
            vec![local(vec![extension_control(UNKNOWN, "disabled")])]
        ),
        some("unknown_extension")
    );
}

#[test]
fn an_unknown_permission_is_refused() {
    assert_eq!(
        refusal(
            Vec::new(),
            vec![local(vec![permission_control(
                UNKNOWN_PERMISSION,
                "disabled"
            )])]
        ),
        some("unknown_permission")
    );
}

#[test]
fn an_alias_beside_its_extension_is_a_duplicate_target() {
    let layers = vec![local(vec![
        extension_control(BETA, "disabled"),
        extension_control(BETA_ALIAS, "enabled"),
    ])];
    assert_eq!(
        refusal(Vec::new(), layers),
        some("duplicate_control_target")
    );
}

#[test]
fn the_same_target_twice_is_a_duplicate_target() {
    let layers = vec![local(vec![
        permission_control(ALPHA_READ, "disabled"),
        permission_control(ALPHA_READ, "enabled"),
    ])];
    assert_eq!(
        refusal(Vec::new(), layers),
        some("duplicate_control_target")
    );
}

#[test]
fn one_target_in_two_layers_is_not_a_duplicate() {
    let current = vec![cloud(vec![extension_control(ALPHA, "disabled")])];
    let layers = vec![
        local(vec![extension_control(ALPHA, "disabled")]),
        cloud(vec![extension_control(ALPHA, "disabled")]),
    ];
    assert_eq!(refusal(current, layers), None);
}

#[test]
fn a_mutation_for_another_catalog_is_a_conflict() {
    let layers = vec![local(vec![extension_control(ALPHA, "disabled")])];
    let (refused, canonical) = verdict(validate_query(
        registry(),
        other_digest(),
        Vec::new(),
        layers,
    ));
    assert_eq!(refused, some("catalog_conflict"));
    assert!(canonical.is_empty());
}

#[test]
fn a_layer_for_another_catalog_is_a_conflict() {
    let mut stale = local(vec![extension_control(ALPHA, "disabled")]);
    stale.catalog_digest = other_digest();
    assert_eq!(refusal(Vec::new(), vec![stale]), some("catalog_conflict"));
}

#[test]
fn a_catalog_conflict_is_reported_before_an_unknown_permission() {
    let layers = vec![local(vec![permission_control(
        UNKNOWN_PERMISSION,
        "disabled",
    )])];
    let (refused, _) = verdict(validate_query(
        registry(),
        other_digest(),
        Vec::new(),
        layers,
    ));
    assert_eq!(refused, some("catalog_conflict"));
}

#[test]
fn an_unknown_extension_is_reported_before_a_catalog_conflict() {
    let layers = vec![local(vec![extension_control(UNKNOWN, "disabled")])];
    let (refused, _) = verdict(validate_query(
        registry(),
        other_digest(),
        Vec::new(),
        layers,
    ));
    assert_eq!(refused, some("unknown_extension"));
}

#[test]
fn the_bounds_are_checked_before_any_target() {
    let layers = vec![
        local(vec![extension_control(UNKNOWN, "disabled")]),
        cloud(Vec::new()),
        local(Vec::new()),
    ];
    assert_eq!(refusal(Vec::new(), layers), some("layer_limit_exceeded"));
    let wide = vec![local(
        (0..513)
            .map(|_| extension_control(UNKNOWN, "disabled"))
            .collect(),
    )];
    assert_eq!(
        refusal(Vec::new(), wide),
        some("layer_control_limit_exceeded")
    );
}

#[test]
fn a_draft_that_is_not_a_layer_is_an_invalid_mutation() {
    let mut stale = local(vec![extension_control(ALPHA, "disabled")]);
    stale.schema_version = "0.0.1".to_owned();
    assert_eq!(refusal(Vec::new(), vec![stale]), some("invalid_mutation"));
    let unknown_kind = layer("operator", vec![extension_control(ALPHA, "disabled")]);
    assert_eq!(
        refusal(Vec::new(), vec![unknown_kind]),
        some("invalid_mutation")
    );
    let bad_state = local(vec![extension_control(ALPHA, "paused")]);
    assert_eq!(
        refusal(Vec::new(), vec![bad_state]),
        some("invalid_mutation")
    );
}

#[test]
fn current_layers_the_resident_cannot_read_are_a_broken_request() {
    let mut stale = local(Vec::new());
    stale.schema_version = "0.0.1".to_owned();
    assert_eq!(
        error_code(validate_query(
            registry(),
            digest(),
            vec![stale.clone()],
            Vec::new()
        )),
        "native_extension_control_layer_invalid"
    );
    assert_eq!(
        error_code(ExtensionControlQueryV1::MutabilityValidate {
            registry: registry(),
            current_layers: vec![stale],
            layers: Vec::new(),
        }),
        "native_extension_control_layer_invalid"
    );
}

#[path = "extension_control_mutation_op_immutable_tests.rs"]
mod immutable;
#[path = "extension_control_mutation_op_overlay_tests.rs"]
mod overlay_targets;
#[path = "extension_control_mutation_op_wire_tests.rs"]
mod wire;

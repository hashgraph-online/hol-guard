//! What one preview may cost: it answers exactly as the resolver does, and a
//! preview too costly to work out or to send is refused with a stable code.

use super::super::budget::MAX_PREVIEW_REPLY_BYTES;
use super::super::catalog::resolver_projection;
use super::*;
use crate::extension_control_op::{encode_outcome, typed_layers, REPLY_TOO_LARGE};
use guard_command::extension_control::{resolve_extension_controls, ControlSurface};
use guard_contracts::EXTENSION_CONTROL_RESULT_SCHEMA;

const CHAIN: &str = "command.chain";
const SOLO: &str = "command.solo";
const HUB: &str = "command.hub";

fn chain_permission(index: usize) -> String {
    format!("{CHAIN}.permission.c{index}")
}

fn solo_permission(index: usize) -> String {
    format!("{SOLO}.permission.s{index}")
}

fn hub_permission(index: usize) -> String {
    format!("{HUB}.permission.h{index}")
}

fn dependent_permission(index: usize) -> String {
    format!("{HUB}.permission.d{index}")
}

/// `chain` permissions each depending on the one before it, so the last one's
/// closure holds them all, and `solo` permissions depending on nothing.
fn work_registry(chain: usize, solo: usize) -> ExtensionControlPreviewRegistryV1 {
    let mut permissions = Vec::new();
    for index in 0..chain {
        let previous: Vec<String> = index
            .checked_sub(1)
            .map(chain_permission)
            .into_iter()
            .collect();
        let previous: Vec<&str> = previous.iter().map(String::as_str).collect();
        let id = chain_permission(index);
        permissions.push(permission(&id, CHAIN, "Chained", &previous, &[]));
    }
    for index in 0..solo {
        let id = solo_permission(index);
        permissions.push(permission(&id, SOLO, "Solo", &[], &[]));
    }
    ExtensionControlPreviewRegistryV1 {
        catalog_digest: digest(),
        extensions: vec![extension(CHAIN, "Chain", &[]), extension(SOLO, "Solo", &[])],
        permissions,
    }
}

/// `hubs` permissions depending on nothing and `dependents` permissions each
/// depending on every hub, so reverting any one hub's control alone changes
/// every dependent.
fn hub_registry(hubs: usize, dependents: usize) -> ExtensionControlPreviewRegistryV1 {
    let hub_ids: Vec<String> = (0..hubs).map(hub_permission).collect();
    let hub_refs: Vec<&str> = hub_ids.iter().map(String::as_str).collect();
    let mut permissions: Vec<ExtensionControlPreviewPermissionV1> = hub_ids
        .iter()
        .map(|id| permission(id, HUB, "Hub", &[], &[]))
        .collect();
    for index in 0..dependents {
        let id = dependent_permission(index);
        permissions.push(permission(&id, HUB, "Dependent", &hub_refs, &[]));
    }
    ExtensionControlPreviewRegistryV1 {
        catalog_digest: digest(),
        extensions: vec![extension(HUB, "Hub", &[])],
        permissions,
    }
}

fn disabled(ids: impl Iterator<Item = String>) -> NativeExtensionControlLayerV1 {
    local(ids.map(|id| permission_control(&id, "disabled")).collect())
}

fn layer_sets() -> Vec<Vec<NativeExtensionControlLayerV1>> {
    let mut stale = local(vec![permission_control(ALPHA_READ, "disabled")]);
    stale.catalog_digest = "b".repeat(64);
    vec![
        Vec::new(),
        vec![local(Vec::new())],
        vec![local(vec![permission_control(ALPHA_READ, "disabled")])],
        vec![local(vec![permission_control(ALPHA_WRITE, "disabled")])],
        vec![local(vec![permission_control(GAMMA_DEPLOY, "enabled")])],
        vec![local(vec![control("extension", ALPHA, "disabled")])],
        vec![local(vec![control("extension", BETA, "disabled")])],
        vec![layer("local-admin", true, Vec::new())],
        vec![
            cloud(vec![permission_control(BETA_RUN, "disabled")]),
            local(vec![permission_control(BETA_RUN, "enabled")]),
        ],
        vec![local(vec![permission_control(UNKNOWN, "disabled")])],
        vec![stale],
        vec![local(vec![
            permission_control(ALPHA_READ, "enabled"),
            permission_control(ALPHA_READ, "disabled"),
        ])],
    ]
}

fn blocked_by_the_resolver(
    catalog: &PreviewCatalog<'_>,
    layers: &[NativeExtensionControlLayerV1],
    extension_ids: &[String],
    permission_ids: &[String],
) -> bool {
    let typed = typed_layers(layers).unwrap();
    resolve_extension_controls(
        &typed,
        Some(catalog.resolver()),
        extension_ids,
        permission_ids,
        ControlSurface::CommandEvaluation,
        &[],
        None,
    )
    .blocked
}

#[test]
fn the_prepared_resolution_answers_as_the_resolver_does() {
    let catalog_registry = registry();
    let projection = resolver_projection(&catalog_registry);
    let resolver = RequestRegistry::new(&projection).unwrap();
    let catalog = PreviewCatalog::new(&catalog_registry, &resolver);
    let extension_ids = strings(&[ALPHA, BETA, GAMMA]);
    let closures = catalog.closures(&extension_ids, usize::MAX).unwrap();

    let (mut saw_blocked, mut saw_allowed) = (false, false);
    for layers in layer_sets() {
        let effective = resolve_effective(
            &catalog,
            &layers,
            &closures.permissions,
            &closures.extensions,
        )
        .unwrap();
        for permission in &catalog_registry.permissions {
            let ids = [permission.permission_id.clone()];
            let expected = !blocked_by_the_resolver(&catalog, &layers, &[], &ids);
            assert_eq!(
                effective.allowed(&permission.permission_id),
                expected,
                "{} under {layers:?}",
                permission.permission_id
            );
            saw_allowed |= expected;
            saw_blocked |= !expected;
        }
        for id in &extension_ids {
            let expected =
                blocked_by_the_resolver(&catalog, &layers, std::slice::from_ref(id), &[]);
            assert_eq!(
                effective.blocked_extension(id),
                expected,
                "{id} under {layers:?}"
            );
        }
    }
    assert!(saw_blocked && saw_allowed);
}

#[test]
fn a_large_catalog_and_many_changed_targets_are_resolved() {
    let solo = 200;
    let result = run(
        work_registry(200, solo),
        Vec::new(),
        vec![disabled((0..solo).map(solo_permission))],
    );

    assert_eq!(result.status, "ok", "{}", result.code);
    let Some(ExtensionControlPayloadV1::Preview { preview }) = result.payload else {
        panic!("expected preview payload");
    };
    assert_eq!(preview.changed_target_count, solo as u64);
    assert_eq!(preview.summary.newly_blocked_permissions, solo as u64);
}

#[test]
fn a_preview_whose_resolution_costs_too_much_is_refused() {
    let solo = 200;
    let result = run(
        work_registry(300, solo),
        Vec::new(),
        vec![disabled((0..solo).map(solo_permission))],
    );

    assert_eq!(result.status, "error");
    assert_eq!(result.code, TOO_MANY_ITEMS);
    assert!(result.payload.is_none());
}

#[test]
fn a_large_reply_that_fits_is_sent_whole() {
    let result = run(
        hub_registry(2, 3_500),
        vec![disabled((0..2).map(hub_permission))],
        vec![local(Vec::new())],
    );

    assert_eq!(result.status, "ok", "{}", result.code);
    let Some(ExtensionControlPayloadV1::Preview { preview }) = result.payload else {
        panic!("expected preview payload");
    };
    assert_eq!(preview.changed_target_count, 2);
    assert!(preview
        .changed_targets
        .iter()
        .all(|target| target.affected_permission_ids.len() == 3_501));
}

#[test]
fn a_reply_over_the_transport_cap_is_refused_not_cut() {
    let result = run(
        hub_registry(12, 3_500),
        vec![disabled((0..12).map(hub_permission))],
        vec![local(Vec::new())],
    );

    assert_eq!(result.status, "error");
    assert_eq!(result.code, REPLY_TOO_LARGE);
    assert!(result.payload.is_none());
}

fn sized_target(ids: usize) -> ExtensionControlPreviewChangedTargetV1 {
    ExtensionControlPreviewChangedTargetV1 {
        target: ExtensionControlPreviewTargetRefV1 {
            kind: "permission".to_owned(),
            target_id: ALPHA_READ.to_owned(),
        },
        extension_id: ALPHA.to_owned(),
        label: "Alpha read".to_owned(),
        before_explicit: "inherited".to_owned(),
        after_explicit: "disabled".to_owned(),
        before_effective: "allowed".to_owned(),
        after_effective: "blocked".to_owned(),
        baseline_risk: None,
        baseline_floor: None,
        affected_permission_ids: vec!["p".repeat(1_000); ids],
        affected_rule_ids: Vec::new(),
        affected_extension_ids: Vec::new(),
        dependency_permission_ids: Vec::new(),
        implied_permission_ids: Vec::new(),
        conflict_permission_ids: Vec::new(),
        provenance: Vec::new(),
        warnings: Vec::new(),
        extension_name: None,
    }
}

#[test]
fn the_reply_budget_admits_targets_up_to_its_cap_and_then_refuses() {
    let target = sized_target(100);
    let encoded = serde_json::to_vec(&target).unwrap().len() + 1;
    let fits = MAX_PREVIEW_REPLY_BYTES / encoded;
    assert!(fits > 1);

    let mut budget = ReplyBudget::default();
    for _ in 0..fits {
        budget.admit(&target).unwrap();
    }
    assert_eq!(budget.admit(&target), Err(REPLY_TOO_LARGE.to_owned()));
}

#[test]
fn an_answer_over_the_transport_cap_is_encoded_as_the_refusal() {
    let request = ExtensionControlRequestV1 {
        schema: EXTENSION_CONTROL_REQUEST_SCHEMA.to_owned(),
        request_id: "extension-control-preview-oversized".to_owned(),
        query: ExtensionControlQueryV1::Preview {
            registry: registry(),
            current_layers: Vec::new(),
            proposed_layers: Vec::new(),
        },
    };
    let oversized = ExtensionControlPayloadV1::Preview {
        preview: ExtensionControlSemanticPreviewV1 {
            schema_version: EXTENSION_CONTROL_SEMANTIC_PREVIEW_SCHEMA.to_owned(),
            global_lockdown: ExtensionControlPreviewLockdownV1 {
                before: false,
                after: false,
                changed: false,
            },
            changed_target_count: 1,
            affected_permission_count: 0,
            affected_rule_count: 0,
            changed_targets: vec![sized_target(2_200)],
            approval_required: true,
            summary: ExtensionControlPreviewSummaryV1 {
                newly_blocked_permissions: 0,
                newly_allowed_permissions: 0,
                effective_change_count: 0,
            },
        },
    };

    let bytes = encode_outcome(&request, "sha256:test", Ok(oversized)).unwrap();

    assert!(bytes.len() < crate::MAX_NATIVE_RESPONSE_BYTES);
    let result: ExtensionControlResultV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result.schema, EXTENSION_CONTROL_RESULT_SCHEMA);
    assert_eq!(result.request_id, request.request_id);
    assert_eq!(result.request_sha256, "sha256:test");
    assert_eq!(
        (result.status.as_str(), result.code.as_str()),
        ("error", REPLY_TOO_LARGE)
    );
    assert!(result.payload.is_none());
}

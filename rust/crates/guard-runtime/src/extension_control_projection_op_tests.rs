use guard_contracts::{
    ExtensionControlQueryV1, ExtensionControlRegistryExtensionV1,
    ExtensionControlRegistryPermissionV1, ExtensionControlRequestV1, ExtensionControlResultV1,
    NativeExtensionControlV1, EXTENSION_CONTROL_REQUEST_SCHEMA,
};
use serde_json::{json, Value};

use super::*;

const ALPHA: &str = "command.alpha";
const BETA: &str = "command.beta";
const GAMMA: &str = "command.gamma";
const ALPHA_READ: &str = "command.alpha.permission.read";
const BETA_RUN: &str = "command.beta.permission.run";

fn digest() -> String {
    "a".repeat(64)
}

fn extension(id: &str, required: bool, trust_class: &str) -> ExtensionControlRegistryExtensionV1 {
    ExtensionControlRegistryExtensionV1 {
        extension_id: id.to_owned(),
        aliases: Vec::new(),
        dependencies: Vec::new(),
        required,
        trust_class: Some(trust_class.to_owned()),
    }
}

fn permission(id: &str, owner: &str) -> ExtensionControlRegistryPermissionV1 {
    ExtensionControlRegistryPermissionV1 {
        permission_id: id.to_owned(),
        extension_id: owner.to_owned(),
        dependencies: Vec::new(),
        implied_permissions: Vec::new(),
    }
}

/// alpha (first-party), beta (external, so inert until enabled) and gamma
/// (required); a permission each for alpha and beta.
fn registry() -> ExtensionControlRegistryV1 {
    ExtensionControlRegistryV1 {
        catalog_digest: digest(),
        extensions: vec![
            extension(ALPHA, false, "first-party"),
            extension(BETA, false, "external"),
            extension(GAMMA, true, "trusted-library"),
        ],
        permissions: vec![permission(ALPHA_READ, ALPHA), permission(BETA_RUN, BETA)],
    }
}

fn control(kind: &str, target_id: &str, state: &str) -> NativeExtensionControlV1 {
    NativeExtensionControlV1 {
        target_kind: kind.to_owned(),
        target_id: target_id.to_owned(),
        state: state.to_owned(),
    }
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

fn rows(
    registry: &ExtensionControlRegistryV1,
    layers: &[NativeExtensionControlLayerV1],
    failure: Option<&str>,
    start: u32,
) -> Vec<Value> {
    let payload = project(registry, layers, failure, start).expect("projection");
    let ExtensionControlPayloadV1::Project { rows } = payload else {
        panic!("unexpected payload");
    };
    rows.iter()
        .map(|row| serde_json::to_value(row).expect("row"))
        .collect()
}

fn projected(layers: &[NativeExtensionControlLayerV1], failure: Option<&str>) -> Vec<Value> {
    rows(&registry(), layers, failure, 0)
}

fn row(effective: &str, local: &str, managed: &str, codes: &[&str]) -> Value {
    json!({
        "effective_state": effective,
        "local_state": local,
        "managed_state": managed,
        "reason_codes": codes,
    })
}

#[test]
fn every_extension_then_every_permission_is_a_row_in_registry_order() {
    let inherited = |effective: &str| row(effective, "inherited", "inherited", &[]);
    assert_eq!(
        projected(&[], None),
        vec![
            inherited("allowed"),
            // An external extension is inert until it is enabled.
            inherited("blocked"),
            inherited("allowed"),
            inherited("allowed"),
            inherited("blocked"),
        ]
    );
}

#[test]
fn local_and_managed_controls_are_shown_beside_the_effective_state() {
    let layers = [
        layer(
            "local-admin",
            false,
            vec![
                control("permission", ALPHA_READ, "enabled"),
                control("extension", BETA, "enabled"),
            ],
        ),
        layer(
            "signed-cloud",
            false,
            vec![control("permission", ALPHA_READ, "disabled")],
        ),
    ];
    let answer = projected(&layers, None);
    assert_eq!(
        answer[3],
        row(
            "blocked",
            "enabled",
            "disabled",
            &["control.disabled-permission"]
        )
    );
    // Enabling the external extension locally makes it and its permission active.
    assert_eq!(answer[1]["local_state"], "enabled");
    assert_eq!(answer[1]["effective_state"], "allowed");
    assert_eq!(answer[4]["effective_state"], "allowed");
    // A control on an extension says nothing about its permissions' own state.
    assert_eq!(answer[4]["local_state"], "inherited");
}

#[test]
fn a_retired_dns_control_is_shown_on_each_provider() {
    let providers = ["command.dns.aws", "command.dns.gcp", "command.dns.azure"];
    let registry = ExtensionControlRegistryV1 {
        catalog_digest: digest(),
        extensions: providers
            .iter()
            .map(|id| extension(id, false, "first-party"))
            .collect(),
        permissions: Vec::new(),
    };
    let layers = [layer(
        "local-admin",
        false,
        vec![control("extension", "command.dns", "disabled")],
    )];
    for answer in rows(&registry, &layers, None, 0) {
        assert_eq!(answer["effective_state"], "blocked", "{answer}");
        assert_eq!(answer["local_state"], "disabled", "{answer}");
        assert_eq!(answer["managed_state"], "inherited", "{answer}");
    }
}

#[test]
fn an_unreadable_authority_or_a_lockdown_blocks_everything() {
    let unavailable = projected(&[], Some("authority-unavailable"));
    let lockdown = projected(&[layer("local-admin", true, Vec::new())], None);
    for (answer, reason) in [
        (&unavailable, "resolver.authority-unavailable"),
        (&lockdown, "control.global-lockdown"),
    ] {
        for item in answer {
            assert_eq!(item["effective_state"], "blocked", "{item}");
            let codes = item["reason_codes"].as_array().expect("codes");
            assert!(codes.contains(&json!(reason)), "{item}");
            let mut sorted = codes.clone();
            sorted.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
            sorted.dedup();
            assert_eq!(&sorted, codes);
        }
    }
}

#[test]
fn an_unknown_failure_or_a_page_past_the_last_row_is_refused() {
    assert_eq!(
        project(&registry(), &[], Some("not-a-failure"), 0),
        Err("native_extension_control_authority_failure_invalid".to_owned())
    );
    for start in [5, 6, u32::MAX] {
        assert_eq!(
            project(&registry(), &[], None, start),
            Err("native_extension_control_registry_invalid".to_owned()),
            "{start}"
        );
    }
    let empty = ExtensionControlRegistryV1 {
        catalog_digest: digest(),
        extensions: Vec::new(),
        permissions: Vec::new(),
    };
    assert!(rows(&empty, &[], None, 0).is_empty());
}

#[test]
fn a_large_registry_is_cut_to_the_listed_bound_and_answered_in_pages() {
    let mut registry = registry();
    registry.extensions = (0..MAX_EXTENSIONS + 3)
        .map(|index| extension(&format!("command.ext{index}"), false, "first-party"))
        .collect();
    // The last listed extension owns every permission, and the first one
    // past the bound owns none that is listed.
    let owner = format!("command.ext{}", MAX_EXTENSIONS - 1);
    registry.permissions = (0..2_000)
        .map(|index| permission(&format!("{owner}.permission.p{index}"), &owner))
        .collect();
    let first = rows(&registry, &[], None, 0);
    let second = rows(&registry, &[], None, PAGE_ROWS as u32);
    assert_eq!(first.len(), PAGE_ROWS);
    assert_eq!(second.len(), MAX_EXTENSIONS + 2_000 - PAGE_ROWS);
    assert!(first
        .iter()
        .chain(&second)
        .all(|answer| answer["effective_state"] == "allowed"));
    assert_eq!(
        project(&registry, &[], None, (MAX_EXTENSIONS + 2_000) as u32),
        Err("native_extension_control_registry_invalid".to_owned())
    );
}

#[test]
fn the_op_answers_a_project_query() {
    let request = ExtensionControlRequestV1 {
        schema: EXTENSION_CONTROL_REQUEST_SCHEMA.to_owned(),
        request_id: "projection-test".to_owned(),
        query: ExtensionControlQueryV1::Project {
            registry: registry(),
            layers: Vec::new(),
            authority_failure: None,
            start: 1,
        },
    };
    let wire = serde_json::to_value(&request).expect("wire");
    assert_eq!(wire["query"]["kind"], "project");
    assert_eq!(wire["query"]["start"], 1);
    let bytes =
        crate::extension_control_op::evaluate_extension_control_request(&request).expect("answer");
    let result: ExtensionControlResultV1 = serde_json::from_slice(&bytes).expect("result");
    assert_eq!(result.status, "ok", "{}", result.code);
    assert_eq!(
        serde_json::to_value(result.payload).expect("payload"),
        json!({"kind": "project", "rows": projected(&[], None)[1..].to_vec()})
    );
}

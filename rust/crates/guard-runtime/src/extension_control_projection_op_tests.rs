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

fn facts() -> Vec<ExtensionControlPermissionFactsV1> {
    vec![
        ExtensionControlPermissionFactsV1 {
            configurable: true,
            fixed_reason: None,
        },
        ExtensionControlPermissionFactsV1 {
            configurable: false,
            fixed_reason: Some("Always reviewed.".to_owned()),
        },
    ]
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

fn projected(layers: &[NativeExtensionControlLayerV1], failure: Option<&str>) -> Value {
    let payload = project(&registry(), &facts(), layers, failure).expect("projection");
    serde_json::to_value(payload).expect("wire")
}

#[test]
fn every_item_is_listed_in_registry_order_with_its_own_facts() {
    let answer = projected(&[], None);
    assert_eq!(
        answer,
        json!({
            "kind": "project",
            "extensions": [
                {
                    "extension_id": ALPHA, "effective_state": "allowed",
                    "local_state": "inherited", "managed_state": "inherited",
                    "required": false, "reason_codes": [],
                },
                // An external extension is inert until it is enabled.
                {
                    "extension_id": BETA, "effective_state": "blocked",
                    "local_state": "inherited", "managed_state": "inherited",
                    "required": false, "reason_codes": [],
                },
                {
                    "extension_id": GAMMA, "effective_state": "allowed",
                    "local_state": "inherited", "managed_state": "inherited",
                    "required": true, "reason_codes": [],
                },
            ],
            "permissions": [
                {
                    "permission_id": ALPHA_READ, "extension_id": ALPHA,
                    "effective_state": "allowed", "local_state": "inherited",
                    "managed_state": "inherited", "configurable": true,
                    "fixed_reason": null, "reason_codes": [],
                },
                {
                    "permission_id": BETA_RUN, "extension_id": BETA,
                    "effective_state": "blocked", "local_state": "inherited",
                    "managed_state": "inherited", "configurable": false,
                    "fixed_reason": "Always reviewed.", "reason_codes": [],
                },
            ],
        })
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
    let read = &answer["permissions"][0];
    assert_eq!(read["local_state"], "enabled");
    assert_eq!(read["managed_state"], "disabled");
    assert_eq!(read["effective_state"], "blocked");
    assert_eq!(read["reason_codes"], json!(["control.disabled-permission"]));
    // Enabling the external extension locally makes it and its permission active.
    assert_eq!(answer["extensions"][1]["local_state"], "enabled");
    assert_eq!(answer["extensions"][1]["effective_state"], "allowed");
    assert_eq!(answer["permissions"][1]["effective_state"], "allowed");
    // A control on an extension says nothing about its permissions' own state.
    assert_eq!(answer["permissions"][1]["local_state"], "inherited");
}

#[test]
fn an_unreadable_authority_or_a_lockdown_blocks_everything() {
    let unavailable = projected(&[], Some("authority-unavailable"));
    let lockdown = projected(&[layer("local-admin", true, Vec::new())], None);
    for (answer, reason) in [
        (&unavailable, "resolver.authority-unavailable"),
        (&lockdown, "control.global-lockdown"),
    ] {
        let items = answer["extensions"]
            .as_array()
            .into_iter()
            .chain(answer["permissions"].as_array())
            .flatten();
        for item in items {
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
fn facts_that_do_not_match_the_permissions_are_refused() {
    let short = &facts()[..1];
    assert_eq!(
        project(&registry(), short, &[], None),
        Err("native_extension_control_registry_invalid".to_owned())
    );
    assert_eq!(
        project(&registry(), &facts(), &[], Some("not-a-failure")),
        Err("native_extension_control_authority_failure_invalid".to_owned())
    );
}

#[test]
fn a_large_registry_is_cut_to_the_listed_bound() {
    let mut registry = registry();
    registry.extensions = (0..MAX_EXTENSIONS + 3)
        .map(|index| extension(&format!("command.ext{index}"), false, "first-party"))
        .collect();
    registry.permissions.clear();
    let payload = project(&registry, &[], &[], None).expect("projection");
    let ExtensionControlPayloadV1::Project {
        extensions,
        permissions,
    } = payload
    else {
        panic!("unexpected payload");
    };
    assert_eq!(extensions.len(), MAX_EXTENSIONS);
    assert_eq!(extensions[0].extension_id, "command.ext0");
    assert!(permissions.is_empty());
}

#[test]
fn the_op_answers_a_project_query() {
    let request = ExtensionControlRequestV1 {
        schema: EXTENSION_CONTROL_REQUEST_SCHEMA.to_owned(),
        request_id: "projection-test".to_owned(),
        query: ExtensionControlQueryV1::Project {
            registry: registry(),
            permission_facts: facts(),
            layers: Vec::new(),
            authority_failure: None,
        },
    };
    let wire = serde_json::to_value(&request).expect("wire");
    assert_eq!(wire["query"]["kind"], "project");
    let bytes =
        crate::extension_control_op::evaluate_extension_control_request(&request).expect("answer");
    let result: ExtensionControlResultV1 = serde_json::from_slice(&bytes).expect("result");
    assert_eq!(result.status, "ok", "{}", result.code);
    assert_eq!(
        serde_json::to_value(result.payload).expect("payload"),
        projected(&[], None)
    );
}

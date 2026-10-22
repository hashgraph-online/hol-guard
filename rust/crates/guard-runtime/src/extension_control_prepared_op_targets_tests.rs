use super::*;
use guard_contracts::{
    ExtensionControlPreviewExtensionV1, ExtensionControlPreviewPermissionV1,
    NativeExtensionControlV1,
};

const ALPHA: &str = "command.alpha";
const GAMMA: &str = "command.gamma";
const ALPHA_READ: &str = "command.alpha.permission.read";
const ALPHA_WRITE: &str = "command.alpha.permission.write";
const GAMMA_DEPLOY: &str = "command.gamma.permission.deploy";
const UNKNOWN: &str = "command.unknown.permission.read";

/// `sha256("extension-control-target-ref\0permission\0command.alpha.permission.write")`
/// and `...\0extension\0command.gamma`, computed by the retired Python projection.
const ALPHA_WRITE_REF: &str = "94b4fc50fdd8fba999b932882e2495b7bcf75005c072195fc888b2f61a6e3848";
const GAMMA_REF: &str = "320cb2c79172232ae769d42439f9bb2efda5054f52fcc7ed9b4ee5d53149df34";

fn control(kind: &str, target_id: &str, state: &str) -> NativeExtensionControlV1 {
    NativeExtensionControlV1 {
        target_kind: kind.to_owned(),
        target_id: target_id.to_owned(),
        state: state.to_owned(),
    }
}

fn local(controls: Vec<NativeExtensionControlV1>) -> NativeExtensionControlLayerV1 {
    NativeExtensionControlLayerV1 {
        schema_version: "1.0.0".to_owned(),
        kind: "local-admin".to_owned(),
        catalog_digest: digest(),
        global_lockdown: false,
        controls,
    }
}

fn extension(id: &str, dependencies: &[&str], rule: &str) -> ExtensionControlPreviewExtensionV1 {
    ExtensionControlPreviewExtensionV1 {
        extension_id: id.to_owned(),
        name: id.to_owned(),
        aliases: Vec::new(),
        dependencies: dependencies.iter().map(|id| (*id).to_owned()).collect(),
        rule_ids: vec![rule.to_owned()],
    }
}

fn permission(
    id: &str,
    owner: &str,
    dependencies: &[&str],
    rule: &str,
) -> ExtensionControlPreviewPermissionV1 {
    ExtensionControlPreviewPermissionV1 {
        permission_id: id.to_owned(),
        extension_id: owner.to_owned(),
        label: id.to_owned(),
        risk_tier: "high".to_owned(),
        baseline_floor: "review".to_owned(),
        rule_ids: vec![rule.to_owned()],
        dependencies: dependencies.iter().map(|id| (*id).to_owned()).collect(),
        conflicts: Vec::new(),
        implied_permissions: Vec::new(),
    }
}

/// gamma depends on alpha and its deploy permission on alpha's write one. The
/// rule ids do not contain the target ids, so a leaked id is not mistaken for a
/// rule.
fn registry() -> ExtensionControlPreviewRegistryV1 {
    ExtensionControlPreviewRegistryV1 {
        catalog_digest: digest(),
        extensions: vec![
            extension(ALPHA, &[], "rule.alpha"),
            extension(GAMMA, &[ALPHA], "rule.gamma"),
        ],
        permissions: vec![
            permission(ALPHA_READ, ALPHA, &[], "rule.read"),
            permission(ALPHA_WRITE, ALPHA, &[], "rule.write"),
            permission(GAMMA_DEPLOY, GAMMA, &[ALPHA_WRITE], "rule.deploy"),
        ],
    }
}

fn targets_reply(
    registry: ExtensionControlPreviewRegistryV1,
    proposed_layers: Vec<NativeExtensionControlLayerV1>,
) -> ExtensionControlResultV1 {
    reply(&ExtensionControlRequestV1 {
        schema: EXTENSION_CONTROL_REQUEST_SCHEMA.to_owned(),
        request_id: "extension-control-prepared-3".to_owned(),
        query: ExtensionControlQueryV1::PreviewEventTargets {
            registry,
            current_layers: Vec::new(),
            proposed_layers,
        },
    })
}

fn targets(
    registry: ExtensionControlPreviewRegistryV1,
    proposed_layers: Vec<NativeExtensionControlLayerV1>,
) -> Vec<ExtensionControlEventTargetV1> {
    let result = targets_reply(registry, proposed_layers);
    assert_eq!(result.status, "ok", "{}", result.code);
    match result.payload {
        Some(ExtensionControlPayloadV1::PreviewEventTargets { targets }) => targets,
        other => panic!("expected preview_event_targets payload, got {other:?}"),
    }
}

#[test]
fn a_changed_permission_is_named_by_its_reference_and_the_rules_it_touches() {
    let targets = targets(
        registry(),
        vec![local(vec![control("permission", ALPHA_WRITE, "disabled")])],
    );

    assert_eq!(
        targets,
        vec![ExtensionControlEventTargetV1 {
            kind: "permission".to_owned(),
            target_ref: ALPHA_WRITE_REF.to_owned(),
            before_explicit: "inherited".to_owned(),
            after_explicit: "disabled".to_owned(),
            before_effective: "allowed".to_owned(),
            after_effective: "blocked".to_owned(),
            // deploy depends on write, so disabling write touches its rule too.
            affected_rule_ids: vec!["rule.deploy".to_owned(), "rule.write".to_owned()],
        }]
    );
    let encoded = serde_json::to_string(&targets).unwrap();
    assert!(!encoded.contains(ALPHA_WRITE) && !encoded.contains("target_id"));
}

#[test]
fn a_changed_extension_is_named_by_its_reference_and_carries_its_rules() {
    let targets = targets(
        registry(),
        vec![local(vec![control("extension", GAMMA, "disabled")])],
    );

    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].kind, "extension");
    assert_eq!(targets[0].target_ref, GAMMA_REF);
    assert_eq!(
        (
            targets[0].before_effective.as_str(),
            targets[0].after_effective.as_str()
        ),
        ("allowed", "blocked")
    );
    assert_eq!(
        targets[0].affected_rule_ids,
        vec!["rule.deploy".to_owned(), "rule.gamma".to_owned()]
    );
    assert!(!serde_json::to_string(&targets).unwrap().contains(GAMMA));
}

#[test]
fn targets_that_are_unchanged_or_unknown_to_the_catalog_are_not_named() {
    let unknown = targets(
        registry(),
        vec![local(vec![control("permission", UNKNOWN, "disabled")])],
    );
    assert!(unknown.is_empty());
    assert!(targets(registry(), vec![local(Vec::new())]).is_empty());
}

#[test]
fn an_event_names_the_targets_in_preview_order_and_no_more_than_the_cap() {
    let count = EXTENSION_CONTROL_MAX_EVENT_TARGETS + 88;
    let ids: Vec<String> = (0..count)
        .map(|index| format!("command.solo.permission.s{index:04}"))
        .collect();
    let wide = ExtensionControlPreviewRegistryV1 {
        catalog_digest: digest(),
        extensions: vec![extension("command.solo", &[], "rule.solo")],
        permissions: ids
            .iter()
            .map(|id| permission(id, "command.solo", &[], "rule.solo"))
            .collect(),
    };
    let layers = vec![local(
        ids.iter()
            .map(|id| control("permission", id, "disabled"))
            .collect(),
    )];

    let full = semantic_preview(&wide, &[], &layers).unwrap();
    assert_eq!(full.changed_targets.len(), count);
    let named = targets(wide, layers);

    assert_eq!(named.len(), EXTENSION_CONTROL_MAX_EVENT_TARGETS);
    for (event, changed) in named.iter().zip(&full.changed_targets) {
        assert_eq!(
            event.target_ref,
            target_ref(&changed.target.kind, &changed.target.target_id)
        );
    }
}

#[test]
fn an_event_names_no_more_rules_per_target_than_the_cap() {
    let dependents = EXTENSION_CONTROL_MAX_EVENT_RULE_IDS + 76;
    let hub = "command.hub.permission.h0".to_owned();
    let mut crowded = ExtensionControlPreviewRegistryV1 {
        catalog_digest: digest(),
        extensions: vec![extension("command.hub", &[], "rule.hub")],
        permissions: vec![permission(&hub, "command.hub", &[], "rule.hub")],
    };
    for index in 0..dependents {
        crowded.permissions.push(permission(
            &format!("command.hub.permission.d{index:04}"),
            "command.hub",
            &[hub.as_str()],
            &format!("rule.dependent.{index:04}"),
        ));
    }
    let layers = vec![local(vec![control("permission", &hub, "disabled")])];

    let full = semantic_preview(&crowded, &[], &layers).unwrap();
    let all_rules = &full.changed_targets[0].affected_rule_ids;
    assert!(all_rules.len() > EXTENSION_CONTROL_MAX_EVENT_RULE_IDS);
    let named = targets(crowded, layers);

    assert_eq!(named.len(), 1);
    assert_eq!(
        named[0].affected_rule_ids,
        all_rules[..EXTENSION_CONTROL_MAX_EVENT_RULE_IDS].to_vec()
    );
}

#[test]
fn a_broken_catalog_or_layer_is_a_refusal_not_an_empty_event() {
    let mut duplicate = registry();
    duplicate.permissions.push(duplicate.permissions[0].clone());
    let result = targets_reply(duplicate, Vec::new());
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_extension_control_registry_invalid");
    assert!(result.payload.is_none());

    let mut broken = local(Vec::new());
    broken.kind = "local".to_owned();
    let result = targets_reply(registry(), vec![broken]);
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_extension_control_layer_invalid");
    assert!(result.payload.is_none());
}

fn payload_keys(reply: &Value) -> Vec<&str> {
    let mut keys: Vec<&str> = reply["payload"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

#[test]
fn each_reply_carries_its_query_kind_and_exactly_its_declared_fields() {
    let six = r#""previous_revision":1,"catalog_digest":null,"layers":[],"actor_id":"a","idempotency_key":"k","nonce":"n""#;
    let digest_reply = reply(&wire_request(&format!(
        r#"{{"kind":"request_digest",{six}}}"#
    )));
    let digest_reply: Value = serde_json::to_value(digest_reply).unwrap();
    assert_eq!(digest_reply["payload"]["kind"], "request_digest");
    assert_eq!(payload_keys(&digest_reply), vec!["digest", "kind"]);

    let nonce_reply = reply(&wire_request(&format!(
        r#"{{"kind":"candidate_nonce","nonce":"n","activation_digest":"{0}","lifecycle_before":"{0}","lifecycle_after":"{0}","security_digest":null}}"#,
        digest()
    )));
    let nonce_reply: Value = serde_json::to_value(nonce_reply).unwrap();
    assert_eq!(nonce_reply["payload"]["kind"], "candidate_nonce");
    assert_eq!(payload_keys(&nonce_reply), vec!["kind", "nonce"]);

    let named = targets_reply(
        registry(),
        vec![local(vec![control("permission", ALPHA_READ, "disabled")])],
    );
    let named: Value = serde_json::to_value(named).unwrap();
    assert_eq!(named["payload"]["kind"], "preview_event_targets");
    assert_eq!(payload_keys(&named), vec!["kind", "targets"]);
    let mut fields: Vec<&str> = named["payload"]["targets"][0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        [
            "affected_rule_ids",
            "after_effective",
            "after_explicit",
            "before_effective",
            "before_explicit",
            "kind",
            "target_ref",
        ]
    );
}

#[test]
fn the_wire_names_of_the_three_queries_are_stable_and_closed() {
    let sample_layer = json!({
        "schema_version": "1.0.0",
        "kind": "local-admin",
        "catalog_digest": digest(),
        "global_lockdown": false,
        "controls": [],
    });
    let sample_registry = json!({
        "catalog_digest": digest(),
        "extensions": [{
            "extension_id": ALPHA,
            "name": "Alpha",
            "aliases": [],
            "dependencies": [],
            "rule_ids": [],
        }],
        "permissions": [],
    });
    for query in [
        json!({
            "kind": "request_digest",
            "previous_revision": 1,
            "catalog_digest": digest(),
            "layers": [sample_layer],
            "actor_id": "actor",
            "idempotency_key": "key",
            "nonce": "n",
        }),
        json!({
            "kind": "candidate_nonce",
            "nonce": "n",
            "activation_digest": digest(),
            "lifecycle_before": digest(),
            "lifecycle_after": digest(),
            "security_digest": digest(),
        }),
        json!({
            "kind": "preview_event_targets",
            "registry": sample_registry,
            "current_layers": [sample_layer],
            "proposed_layers": [sample_layer],
        }),
    ] {
        let wire = json!({
            "schema": EXTENSION_CONTROL_REQUEST_SCHEMA,
            "request_id": "extension-control-1",
            "query": query,
        });
        let parsed: ExtensionControlRequestV1 = serde_json::from_value(wire.clone()).unwrap();
        let result = reply(&parsed);
        assert_eq!(result.status, "ok", "{}", result.code);

        // The request digest hashes exactly six fields: a seventh, such as an
        // approval or session field, is not a field of the query at all.
        let mut unlisted = wire;
        unlisted["query"]["unlisted"] = json!(true);
        assert!(serde_json::from_value::<ExtensionControlRequestV1>(unlisted).is_err());
    }
}

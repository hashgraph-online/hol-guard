use super::*;

#[test]
fn each_reply_carries_its_query_kind_and_exactly_its_declared_fields() {
    let layers = vec![local(vec![extension_control(ALPHA, "disabled")])];
    let accepted = evaluate_extension_control_request(&request(validate_query(
        registry(),
        digest(),
        Vec::new(),
        layers.clone(),
    )))
    .unwrap();
    let accepted: Value = serde_json::from_slice(&accepted).unwrap();
    assert_eq!(accepted["payload"]["kind"], "mutation_validate");
    assert_eq!(payload_keys(&accepted), vec!["kind", "layers", "refusal"]);
    assert_eq!(accepted["payload"]["refusal"], Value::Null);

    let refused = evaluate_extension_control_request(&request(validate_query(
        registry(),
        other_digest(),
        Vec::new(),
        layers.clone(),
    )))
    .unwrap();
    let refused: Value = serde_json::from_slice(&refused).unwrap();
    assert_eq!(refused["status"], "ok");
    assert_eq!(refused["code"], "ok");
    assert_eq!(refused["payload"]["kind"], "mutation_validate");
    assert_eq!(refused["payload"]["refusal"], "catalog_conflict");
    assert_eq!(refused["payload"]["layers"], json!([]));

    let bounds = evaluate_extension_control_request(&request(bounds_query(vec![
        local(Vec::new()),
        cloud(Vec::new()),
        local(Vec::new()),
    ])))
    .unwrap();
    let bounds: Value = serde_json::from_slice(&bounds).unwrap();
    assert_eq!(bounds["status"], "ok");
    assert_eq!(bounds["payload"]["kind"], "mutation_bounds");
    assert_eq!(payload_keys(&bounds), vec!["kind", "refusal"]);
    assert_eq!(bounds["payload"]["refusal"], "layer_limit_exceeded");

    let mutability =
        evaluate_extension_control_request(&request(ExtensionControlQueryV1::MutabilityValidate {
            registry: registry(),
            current_layers: Vec::new(),
            layers,
        }))
        .unwrap();
    let mutability: Value = serde_json::from_slice(&mutability).unwrap();
    assert_eq!(mutability["payload"]["kind"], "mutability_validate");
    assert_eq!(payload_keys(&mutability), vec!["kind", "refusal"]);
    assert_eq!(mutability["payload"]["refusal"], Value::Null);
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
fn the_wire_names_of_the_three_queries_are_stable() {
    let sample_layer = json!({
        "schema_version": "1.0.0",
        "kind": "local-admin",
        "catalog_digest": digest(),
        "global_lockdown": false,
        "controls": [],
    });
    let sample_registry = json!({
        "extensions": [{"extension_id": ALPHA, "aliases": [], "required": false}],
        "permissions": [{"permission_id": ALPHA_READ, "configurable": true}],
        "overlay": [{
            "extension_id": DELTA,
            "required": false,
            "permissions": [{"permission_id": DELTA_READ, "configurable": true}],
        }],
    });
    for query in [
        json!({"kind": "mutation_bounds", "layers": [sample_layer]}),
        json!({
            "kind": "mutation_validate",
            "registry": sample_registry,
            "catalog_digest": digest(),
            "requested_catalog_digest": digest(),
            "current_layers": [sample_layer],
            "layers": [sample_layer],
        }),
        json!({
            "kind": "mutability_validate",
            "registry": sample_registry,
            "current_layers": [sample_layer],
            "layers": [sample_layer],
        }),
    ] {
        let wire = json!({
            "schema": EXTENSION_CONTROL_REQUEST_SCHEMA,
            "request_id": "extension-control-1",
            "query": query,
        });
        let parsed: ExtensionControlRequestV1 = serde_json::from_value(wire.clone()).unwrap();
        let result = run(parsed.query);
        assert_eq!(result.status, "ok", "{}", result.code);

        let mut unlisted = wire;
        unlisted["query"]["layers"][0]["unlisted"] = json!(true);
        assert!(serde_json::from_value::<ExtensionControlRequestV1>(unlisted).is_err());
    }
}

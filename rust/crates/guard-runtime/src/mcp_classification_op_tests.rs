//! Static-evidence description: the reviewed mapping, what schema field names
//! add to it, and the bounds that keep an unreadable declaration honest.

use super::{classify, evaluate, schema_fields};
use guard_contracts::{McpClassificationItemV1, McpClassificationRequestV1};
use serde_json::{json, Value};

fn item(name: &str, schema: Value) -> McpClassificationItemV1 {
    McpClassificationItemV1 {
        name: name.to_owned(),
        schema: Some(schema),
        provider: None,
        annotations: None,
        full_schema: true,
    }
}

fn texts(value: &Value, key: &str) -> Vec<String> {
    value[key]
        .as_array()
        .expect("list")
        .iter()
        .map(|entry| entry.as_str().expect("text").to_owned())
        .collect()
}

#[test]
fn an_uninspected_tool_resolves_to_nothing_and_says_so() {
    let classification = classify(&item("safe_read_only", json!({"type": "object"})));
    assert_eq!(classification["effect"], "unknown");
    assert_eq!(classification["data"], "unknown");
    assert_eq!(classification["destination"], "unknown");
    assert_eq!(classification["confidence"], "limited");
    assert_eq!(classification["advisory_only"], true);
    assert_eq!(
        classification["schema_version"],
        "guard.mcp-classification.v1"
    );
    assert!(texts(&classification, "warnings").contains(&"effect-unresolved".to_owned()));
}

#[test]
fn declared_field_names_raise_the_description_without_reading_values() {
    let classification = classify(&item(
        "send",
        json!({"properties": {
            "Body": {"type": "string"},
            "webhook_url": {"type": "string", "default": "https://example.test/hook"},
            "api_key": {"type": "string"},
            "command": {"type": "string"},
        }}),
    ));
    assert_eq!(classification["effect"], "execute");
    assert_eq!(classification["data"], "credentials-possible");
    assert_eq!(classification["destination"], "caller-selected");
    let evidence = texts(&classification, "evidence");
    assert!(evidence.contains(&"schema:content-fields".to_owned()));
    assert!(evidence.contains(&"schema:credential-fields".to_owned()));
    assert!(evidence.contains(&"schema:destination-fields".to_owned()));
    assert!(evidence.contains(&"schema:execution-fields".to_owned()));
    let warnings = texts(&classification, "warnings");
    assert!(warnings.contains(&"external-transfer-possible".to_owned()));
    assert!(warnings.contains(&"arbitrary-execution-possible".to_owned()));
    assert!(!warnings.contains(&"effect-unresolved".to_owned()));
}

#[test]
fn a_reviewed_provider_action_keeps_its_mapping_and_nothing_near_it_does() {
    let schema = json!({"properties": {"query": {"type": "string"}}});
    let mut reviewed = item("SLACK_SEARCH_MESSAGES", schema.clone());
    reviewed.provider = Some("composio".to_owned());
    let classification = classify(&reviewed);
    assert_eq!(classification["effect"], "read");
    assert_eq!(classification["data"], "private-content");
    assert_eq!(classification["destination"], "slack");
    assert_eq!(classification["reversibility"], "not-applicable");
    assert_eq!(classification["confidence"], "reviewed-mapping");
    assert!(texts(&classification, "evidence").contains(&"reviewed-provider-mapping:v1".to_owned()));

    let mut lookalike = reviewed.clone();
    lookalike.name = "SLACK_SEARCH_MESSAGES_EVIL".to_owned();
    assert_eq!(classify(&lookalike)["effect"], "unknown");

    let mut unclaimed_provider = reviewed.clone();
    unclaimed_provider.provider = None;
    assert_eq!(classify(&unclaimed_provider)["effect"], "unknown");

    let mut partial = reviewed;
    partial.full_schema = false;
    let classification = classify(&partial);
    assert_eq!(classification["confidence"], "limited");
    assert!(texts(&classification, "warnings").contains(&"schema-incomplete".to_owned()));
}

#[test]
fn provider_claims_are_recorded_as_claims_and_never_as_findings() {
    let mut benign = item(
        "run",
        json!({"properties": {"command": {"type": "string"}}}),
    );
    benign.annotations = Some(json!({"readOnlyHint": true}));
    let classification = classify(&benign);
    assert_eq!(classification["effect"], "execute");
    let warnings = texts(&classification, "warnings");
    assert!(
        texts(&classification, "evidence").contains(&"provider-annotations:unverified".to_owned())
    );
    assert!(warnings.contains(&"annotation-conflicts-with-evidence".to_owned()));

    let mut destructive = item("wipe", json!({"type": "object"}));
    destructive.annotations = Some(json!({"destructiveHint": true}));
    let classification = classify(&destructive);
    // A claim cannot resolve the effect either way.
    assert_eq!(classification["effect"], "unknown");
    assert!(texts(&classification, "warnings").contains(&"provider-claims-destructive".to_owned()));

    let mut not_a_claim = item("run", json!({"type": "object"}));
    not_a_claim.annotations = Some(json!({"readOnlyHint": "yes"}));
    assert!(!texts(&classify(&not_a_claim), "evidence")
        .contains(&"provider-annotations:unverified".to_owned()));
}

#[test]
fn a_fold_equivalent_field_name_is_still_the_field_it_spells() {
    let classification = classify(&item(
        "store",
        json!({"properties": {"SECRET": {"type": "string"}}}),
    ));
    assert_eq!(classification["data"], "credentials-possible");
}

#[test]
fn nested_declarations_are_read_through_their_keywords() {
    let (fields, complete) = schema_fields(Some(&json!({
        "allOf": [{"properties": {"token": {"type": "string"}}}],
        "$defs": {"inner": {"properties": {"body": {"type": "string"}}}},
        "items": {"properties": {"url": {"type": "string"}}},
    })));
    assert!(complete);
    assert_eq!(
        fields.into_iter().collect::<Vec<_>>(),
        vec!["body".to_owned(), "token".to_owned(), "url".to_owned()]
    );
}

#[test]
fn an_unreadable_declaration_is_reported_incomplete_rather_than_resolved() {
    assert_eq!(schema_fields(None), (Default::default(), false));
    assert_eq!(
        schema_fields(Some(&json!([{"properties": {"token": {}}}]))),
        (Default::default(), false)
    );
    // A reference would have to be resolved, and remote fetching is out of scope.
    let (_, complete) = schema_fields(Some(&json!({"$ref": "#/$defs/other"})));
    assert!(!complete);
    // Too wide, too deep and too many nodes each stop the walk.
    let wide: Value = json!({"properties": Value::Object(
        (0..300).map(|index| (format!("field{index}"), json!({"type": "string"}))).collect()
    )});
    assert!(!schema_fields(Some(&wide)).1);
    let mut deep = json!({"type": "string"});
    for _ in 0..20 {
        deep = json!({"items": deep});
    }
    assert!(!schema_fields(Some(&deep)).1);
}

#[test]
fn a_batch_answers_in_request_order_and_refuses_an_oversized_one() {
    let request = McpClassificationRequestV1 {
        schema: guard_contracts::MCP_CLASSIFICATION_REQUEST_SCHEMA.to_owned(),
        request_id: "mcp-classification-test".to_owned(),
        items: vec![
            item("first", json!({"properties": {"command": {}}})),
            item("second", json!({"type": "object"})),
        ],
    };
    let payload = evaluate(&request).expect("classified");
    let classifications = payload["classifications"].as_array().expect("list");
    assert_eq!(classifications.len(), 2);
    assert_eq!(classifications[0]["effect"], "execute");
    assert_eq!(classifications[1]["effect"], "unknown");

    let mut oversized = request;
    oversized.items = (0..guard_contracts::MCP_CLASSIFICATION_MAX_ITEMS + 1)
        .map(|_| item("tool", json!({"type": "object"})))
        .collect();
    assert_eq!(
        evaluate(&oversized).unwrap_err(),
        "native_mcp_classification_too_large"
    );
}

#[test]
fn a_request_naming_another_contract_is_refused() {
    const {
        assert!(
            guard_contracts::MCP_CLASSIFICATION_MAX_BYTES
                < guard_contracts::MAX_NATIVE_REQUEST_BYTES
        )
    };
    let request = McpClassificationRequestV1 {
        schema: "guard-mcp-classification-request.v2".to_owned(),
        request_id: "mcp-classification-test".to_owned(),
        items: vec![item("first", json!({"type": "object"}))],
    };
    assert_eq!(
        evaluate(&request).unwrap_err(),
        "native_mcp_classification_schema_unsupported"
    );
}

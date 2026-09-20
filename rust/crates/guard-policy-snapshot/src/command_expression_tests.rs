use super::{NativeCommandExpression, NormalizedCommand};
use serde_json::{json, Value};

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../../spec/guard-policy/v1alpha1/native-command-expression-vectors.json"
    ))
    .expect("shared vectors must remain valid JSON")
}

fn expression() -> Value {
    json!({
        "combinator": "all",
        "conditions": [{
            "field": "command",
            "operator": "exact",
            "value": "printf value",
            "caseSensitive": true
        }]
    })
}

fn parse(value: Value) -> Result<NativeCommandExpression, serde_json::Error> {
    serde_json::from_value(value)
}

#[test]
fn shared_normalization_vectors_preserve_python_whitespace_and_scalar_limits() {
    let vectors = vectors();
    let cases = vectors["normalization"].as_array().unwrap();
    assert_eq!(cases.len(), 11);
    for case in cases {
        let actual = NormalizedCommand::new(case["input"].as_str().unwrap());
        if let Some(error) = case["error"].as_str() {
            assert_eq!(actual.unwrap_err().to_string(), error, "{}", case["id"]);
        } else {
            assert_eq!(
                actual.unwrap().as_str(),
                case["output"].as_str().unwrap(),
                "{}",
                case["id"]
            );
        }
    }
}

#[test]
fn every_shared_literal_and_boolean_vector_matches_the_python_result() {
    let vectors = vectors();
    let cases = vectors["evaluations"].as_array().unwrap();
    assert_eq!(cases.len(), 18);
    for case in cases {
        let parsed = parse(case["expression"].clone()).unwrap();
        assert_eq!(
            serde_json::to_value(&parsed).unwrap(),
            case["expression"],
            "{}",
            case["id"]
        );
        let command = NormalizedCommand::new(case["command"].as_str().unwrap()).unwrap();
        assert_eq!(
            parsed.matches(&command),
            case["matches"].as_bool().unwrap(),
            "{}",
            case["id"]
        );
    }
}

#[test]
fn every_shared_unsupported_clause_refuses_the_complete_expression() {
    let vectors = vectors();
    let cases = vectors["unsupported"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    for case in cases {
        assert_eq!(
            parse(case["expression"].clone()).unwrap_err().to_string(),
            case["error"].as_str().unwrap(),
            "{}",
            case["id"]
        );
    }
}

#[test]
fn unsupported_later_clause_is_not_hidden_by_any_short_circuit() {
    let mut value = expression();
    value["combinator"] = json!("any");
    let mut unsupported = value["conditions"][0].clone();
    unsupported["operator"] = json!("regex");
    value["conditions"]
        .as_array_mut()
        .unwrap()
        .push(unsupported);
    assert!(parse(value).is_err());
}

#[test]
fn unknown_fields_at_both_levels_and_unknown_field_kind_refuse() {
    let mut top = expression();
    top["not"] = json!(true);
    assert!(parse(top).is_err());
    let mut clause = expression();
    clause["conditions"][0]["extra"] = json!(true);
    assert!(parse(clause).is_err());
    let mut field = expression();
    field["conditions"][0]["field"] = json!("path");
    assert!(parse(field).is_err());
}

#[test]
fn case_sensitive_must_be_explicitly_true() {
    for invalid in [json!(false), json!(1), Value::Null, json!("true")] {
        let mut value = expression();
        value["conditions"][0]["caseSensitive"] = invalid;
        assert!(parse(value).is_err());
    }
    let mut missing = expression();
    missing["conditions"][0]
        .as_object_mut()
        .unwrap()
        .remove("caseSensitive");
    assert!(parse(missing).is_err());
}

#[test]
fn empty_and_oversized_condition_sets_refuse_before_matching() {
    for count in [0, 65] {
        let mut value = expression();
        value["conditions"] = Value::Array(vec![value["conditions"][0].clone(); count]);
        assert!(parse(value).is_err());
    }
}

#[test]
fn pattern_limit_counts_scalars_and_refuses_noncanonical_or_empty_values() {
    let mut valid = expression();
    valid["conditions"][0]["value"] = json!("🦊".repeat(512));
    assert!(parse(valid).is_ok());
    for invalid in [
        "🦊".repeat(513),
        String::new(),
        " \t".to_owned(),
        "two\twords".to_owned(),
    ] {
        let mut value = expression();
        value["conditions"][0]["value"] = json!(invalid);
        assert!(parse(value).is_err());
    }
}

#[test]
fn malformed_combination_and_non_string_values_refuse() {
    for invalid in [json!("none"), Value::Null, json!(true)] {
        let mut value = expression();
        value["combinator"] = invalid;
        assert!(parse(value).is_err());
    }
    let mut value = expression();
    value["conditions"][0]["value"] = json!(3);
    assert!(parse(value).is_err());
}

#[test]
fn surrogate_json_cannot_create_native_authority() {
    let raw = r#"{"combinator":"all","conditions":[{"field":"command","operator":"exact","value":"\ud800","caseSensitive":true}]}"#;
    assert!(serde_json::from_str::<NativeCommandExpression>(raw).is_err());
}

#[test]
fn information_separators_are_whitespace_but_zero_width_and_bom_are_not() {
    assert_eq!(
        NormalizedCommand::new("\u{1c}one\u{1f}two")
            .unwrap()
            .as_str(),
        "one two"
    );
    assert_eq!(
        NormalizedCommand::new("one\u{200b}two").unwrap().as_str(),
        "one\u{200b}two"
    );
    assert_eq!(
        NormalizedCommand::new("\u{feff}one").unwrap().as_str(),
        "\u{feff}one"
    );
}

#[test]
fn unsupported_operator_diagnostic_is_bounded_and_does_not_echo_input() {
    for operator in ["regex", "glob", "EXACT", "PRIVATE_CANARY@example.test"] {
        let mut value = expression();
        value["conditions"][0]["operator"] = json!(operator);
        assert_eq!(
            parse(value).unwrap_err().to_string(),
            "native_command_operator_unsupported"
        );
    }
}

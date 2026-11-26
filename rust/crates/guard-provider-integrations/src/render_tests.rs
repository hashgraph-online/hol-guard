use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::*;

fn facts() -> BTreeMap<String, Value> {
    BTreeMap::from([
        ("url".to_owned(), json!("https://shop.example.test/basket")),
        ("origin".to_owned(), json!("https://shop.example.test")),
        ("formFields".to_owned(), json!(["email", "card-number"])),
        ("pageText".to_owned(), json!("never declared")),
        ("score".to_owned(), json!(3)),
    ])
}

#[test]
fn body_holds_declared_fields_in_declared_order_and_nothing_else() {
    let body = render_body(&[("target", "url"), ("site", "origin")], &facts()).unwrap();
    assert_eq!(
        body,
        r#"{"target":"https://shop.example.test/basket","site":"https://shop.example.test"}"#
    );
    assert!(!body.contains("never declared"));
    let parsed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed.as_object().unwrap().len(), 2);
}

#[test]
fn array_facts_render_as_string_arrays() {
    let body = render_body(&[("fields", "formFields")], &facts()).unwrap();
    assert_eq!(body, r#"{"fields":["email","card-number"]}"#);
    assert_eq!(render_body(&[], &facts()).unwrap(), "{}");
}

#[test]
fn a_missing_or_unshareable_fact_refuses_the_whole_body() {
    assert_eq!(
        render_body(&[("target", "url"), ("who", "account")], &facts()),
        Err(RenderError::FactMissing("who".to_owned()))
    );
    assert_eq!(
        render_body(&[("n", "score")], &facts()),
        Err(RenderError::FactInvalid("n".to_owned()))
    );
    let mut long = facts();
    long.insert("url".to_owned(), json!("a".repeat(MAX_FACT_BYTES + 1)));
    assert_eq!(
        render_body(&[("target", "url")], &long).unwrap_err().code(),
        "provider_body_fact_invalid"
    );
    long.insert("url".to_owned(), json!(["a", 1]));
    assert!(render_body(&[("target", "url")], &long).is_err());
}

#[test]
fn duplicate_or_too_many_fields_are_refused() {
    assert_eq!(
        render_body(&[("target", "url"), ("target", "origin")], &facts()),
        Err(RenderError::DuplicateField("target".to_owned()))
    );
    let names: Vec<String> = (0..=MAX_BODY_FIELDS).map(|n| format!("f{n}")).collect();
    let fields: Vec<(&str, &str)> = names.iter().map(|name| (name.as_str(), "url")).collect();
    assert_eq!(
        render_body(&fields, &facts()),
        Err(RenderError::FieldsInvalid)
    );
    assert_eq!(
        render_body(&[("", "url")], &facts()),
        Err(RenderError::FieldsInvalid)
    );
}

#[test]
fn field_names_are_json_escaped() {
    let body = render_body(&[("a\"b", "origin")], &facts()).unwrap();
    let parsed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["a\"b"], "https://shop.example.test");
}

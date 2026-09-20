//! Commitments let the Python producer compare every consumed field without data dumps.

use super::policy_vector_fixtures::digest;
use super::{policy_vector_generic, policy_vector_mixed, policy_vector_ordinary};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

fn commitment(fixture: Value, fields: &[&str], count: usize) -> Value {
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), count);
    let names: BTreeSet<&str> = cases
        .iter()
        .map(|case| case["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), count);
    let projected: Vec<Value> = cases
        .iter()
        .map(|case| {
            Value::Object(
                fields
                    .iter()
                    .map(|field| {
                        let value = case.get(*field).expect("required vector field");
                        ((*field).to_owned(), value.clone())
                    })
                    .collect::<Map<String, Value>>(),
            )
        })
        .collect();
    json!({"count": count, "fields": fields, "sha256": digest(&json!(projected))})
}

#[test]
fn source_defined_policy_vectors_match_declared_case_sets() {
    let ordinary = commitment(
        policy_vector_ordinary::vectors(),
        &[
            "name",
            "harness",
            "source",
            "payload",
            "artifactId",
            "mode",
            "effectivePolicy",
            "expected",
        ],
        133,
    );
    let mixed = commitment(
        policy_vector_mixed::vectors(),
        &[
            "name",
            "harness",
            "source",
            "payload",
            "artifactId",
            "mode",
            "localEffectivePolicy",
            "managedConfiguration",
            "expected",
        ],
        188,
    );
    let generic = commitment(
        policy_vector_generic::vectors(),
        &[
            "name",
            "harness",
            "mode",
            "payload",
            "artifactId",
            "localEffectivePolicy",
            "managedConfiguration",
            "expected",
        ],
        260,
    );
    println!(
        "POLICY_VECTOR_COMMITMENT={}",
        json!({
            "schema": "native-policy-vector-commitments.v1",
            "ordinary": ordinary, "mixed": mixed, "generic": generic,
        })
    );
}

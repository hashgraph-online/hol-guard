//! Cases from `tests/test_guard_workflow_benchmark_contracts.py` at b4efd817.

use gauntlet_contracts::{load_record, schema_kinds, RecordError};
use serde_json::{json, Value};

fn authorization() -> Value {
    json!({
        "schema_version": "1.0",
        "actor": "user",
        "tenant": "fixture",
        "accounts": ["account"],
        "resources": ["resource"],
        "data_projection": ["name"],
        "destinations": ["private"],
        "allowed_operations": ["read", "create-draft"],
        "terminal_effects": ["draft"],
        "write_budget": 2,
        "approval_policy": "draft-only",
        "policy_version": "v1"
    })
}

#[test]
fn all_pinned_schemas_compile_and_authorization_round_trips() {
    assert_eq!(schema_kinds().count(), 22);
    let original = authorization();
    let record = load_record("authorization", original.to_string().as_bytes()).unwrap();
    assert_eq!(record.value(), &original);
    assert_eq!(
        record.canonical_bytes(),
        gauntlet_contracts::canonicalize(original.to_string().as_bytes()).unwrap()
    );
}

#[test]
fn python_strict_integer_and_unknown_field_behavior() {
    let mut invalid = authorization();
    for value in [json!(true), json!(2.0), json!("2")] {
        invalid["write_budget"] = value;
        assert!(matches!(
            load_record("authorization", invalid.to_string().as_bytes()),
            Err(RecordError::InvalidRecord)
        ));
    }
    invalid = authorization();
    invalid["unexpected"] = json!("candidate.module");
    assert!(matches!(
        load_record("authorization", invalid.to_string().as_bytes()),
        Err(RecordError::InvalidRecord)
    ));
    invalid = authorization();
    invalid.as_object_mut().unwrap().remove("tenant");
    assert!(matches!(
        load_record("authorization", invalid.to_string().as_bytes()),
        Err(RecordError::InvalidRecord)
    ));
    assert!(matches!(
        load_record("module:execute", b"{}"),
        Err(RecordError::UnknownKind)
    ));
}

#[test]
fn data_boundary_precedes_schema_validation() {
    assert!(matches!(
        load_record("authorization", br#"{"actor":"a","actor":"b"}"#),
        Err(RecordError::Json(_))
    ));
    assert!(matches!(
        load_record("authorization", br#"{"write_budget":NaN}"#),
        Err(RecordError::Json(_))
    ));
}

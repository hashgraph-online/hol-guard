use super::evaluate;
use guard_contracts::{
    ReviewedInvocationBindingsRequestV1, ReviewedInvocationV1, ReviewedOperationV1,
    REVIEWED_INVOCATION_BINDINGS_REQUEST_SCHEMA,
};
use serde_json::Value;

fn operation(operation_id: &str, path: &[&str], flags: &[&str]) -> ReviewedOperationV1 {
    ReviewedOperationV1 {
        operation_id: operation_id.to_owned(),
        path: path.iter().map(|token| (*token).to_owned()).collect(),
        flags: flags.iter().map(|token| (*token).to_owned()).collect(),
        options_with_values: Vec::new(),
    }
}

fn row(operation_id: &str, argv: &[&str]) -> ReviewedInvocationV1 {
    ReviewedInvocationV1 {
        operation_id: operation_id.to_owned(),
        argv: argv.iter().map(|token| (*token).to_owned()).collect(),
    }
}

fn request(
    operations: Vec<ReviewedOperationV1>,
    rows: Vec<ReviewedInvocationV1>,
) -> ReviewedInvocationBindingsRequestV1 {
    ReviewedInvocationBindingsRequestV1 {
        schema: REVIEWED_INVOCATION_BINDINGS_REQUEST_SCHEMA.to_owned(),
        request_id: "reviewed-invocation-bindings-test".to_owned(),
        executable: "git".to_owned(),
        operations,
        rows,
        blocked_operation_ids: Vec::new(),
    }
}

#[test]
fn an_extension_whose_vectors_all_bind_carries_no_refusal() {
    let answer = evaluate(&request(
        vec![operation("status", &["status"], &["--short"])],
        vec![row("status", &["status", "--short"])],
    ))
    .expect("validated");
    assert_eq!(answer["refused"], Value::Null);
}

#[test]
fn the_first_row_the_grammar_refuses_names_its_own_position() {
    let answer = evaluate(&request(
        vec![operation("status", &["status"], &["--short"])],
        vec![
            row("status", &["status", "--short"]),
            row("status", &["status", "--porcelain"]),
        ],
    ))
    .expect("validated");
    assert_eq!(answer["refused"]["index"], 1);
    assert_eq!(answer["refused"]["code"], "safe_variant_option");
}

#[test]
fn a_vector_a_blocked_operation_also_matches_is_refused() {
    let mut value = request(
        vec![
            operation("push", &["push"], &["--force"]),
            operation("push-force", &["push"], &["--force"]),
        ],
        vec![row("push", &["push", "--force"])],
    );
    value.blocked_operation_ids = vec!["push-force".to_owned()];
    let answer = evaluate(&value).expect("validated");
    assert_eq!(answer["refused"]["code"], "safe_variant_conflict");
}

#[test]
fn a_row_naming_an_operation_the_discovery_lacks_is_an_error() {
    assert_eq!(
        evaluate(&request(
            vec![operation("status", &["status"], &[])],
            vec![row("unknown", &["status"])],
        ))
        .expect_err("unknown operation"),
        "native_reviewed_invocation_operation_unknown"
    );
}

#[test]
fn a_request_built_against_another_contract_is_refused() {
    let mut other = request(
        vec![operation("status", &["status"], &[])],
        vec![row("status", &["status"])],
    );
    other.schema = "guard-reviewed-invocation-bindings-request.v2".to_owned();
    assert_eq!(
        evaluate(&other).expect_err("schema"),
        "native_reviewed_invocation_schema_mismatch"
    );
}

#[test]
fn more_rows_than_one_extension_may_bind_are_refused() {
    let rows = vec![
        row("status", &["status"]);
        guard_contracts::REVIEWED_INVOCATION_BINDINGS_MAX_ROWS + 1
    ];
    assert_eq!(
        evaluate(&request(vec![operation("status", &["status"], &[])], rows)).expect_err("limit"),
        "native_reviewed_invocation_too_large"
    );
}

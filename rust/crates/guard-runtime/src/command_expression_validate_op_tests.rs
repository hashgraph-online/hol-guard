use super::evaluate;
use guard_contracts::{
    CommandConditionV1, CommandExpressionV1, CommandExpressionValidationRequestV1,
    COMMAND_EXPRESSION_VALIDATION_REQUEST_SCHEMA,
};
use serde_json::Value;

fn expression(operator: &str, value: &str) -> CommandExpressionV1 {
    CommandExpressionV1 {
        combinator: "all".to_owned(),
        conditions: vec![CommandConditionV1 {
            operator: operator.to_owned(),
            value: value.to_owned(),
            case_sensitive: false,
        }],
    }
}

fn request(expressions: Vec<CommandExpressionV1>) -> CommandExpressionValidationRequestV1 {
    CommandExpressionValidationRequestV1 {
        schema: COMMAND_EXPRESSION_VALIDATION_REQUEST_SCHEMA.to_owned(),
        request_id: "command-expression-validation-test".to_owned(),
        expressions,
    }
}

#[test]
fn a_document_whose_patterns_all_compile_carries_no_invalid_expression() {
    let answer = evaluate(&request(vec![
        expression("glob", "git *"),
        expression("exact", "git push"),
    ]))
    .expect("validated");
    assert_eq!(answer["invalid"], Value::Null);
}

#[test]
fn the_first_pattern_the_dialect_refuses_names_its_own_row() {
    let answer = evaluate(&request(vec![
        expression("glob", "git *"),
        expression("regex", "git ("),
        expression("glob", "rm -[rf"),
    ]))
    .expect("validated");
    assert_eq!(answer["invalid"]["index"], 1);
    assert_eq!(answer["invalid"]["code"], "invalid_command_regex");
}

#[test]
fn a_request_built_against_another_contract_is_refused() {
    let mut other = request(vec![expression("exact", "git push")]);
    other.schema = "guard-command-expression-validation-request.v2".to_owned();
    assert_eq!(
        evaluate(&other).expect_err("schema"),
        "native_command_expression_validation_schema_mismatch"
    );
}

#[test]
fn more_expressions_than_one_document_may_decide_are_refused() {
    let expressions = vec![
        expression("exact", "git push");
        guard_contracts::COMMAND_EXPRESSION_VALIDATION_MAX_EXPRESSIONS + 1
    ];
    assert_eq!(
        evaluate(&request(expressions)).expect_err("limit"),
        "native_command_expression_validation_too_large"
    );
}

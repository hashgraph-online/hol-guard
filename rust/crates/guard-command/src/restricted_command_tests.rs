use super::*;

#[test]
fn original_bounded_argv_outcomes_are_portable() {
    let recorded: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/restricted_pytest_parity.json"
    ))
    .unwrap();
    for case in recorded["cases"].as_array().unwrap() {
        if case["operation"] == "normalized_command" {
            assert_eq!(evaluate_normalized(&case["input"]), case["expected"]);
        }
    }
}

#[test]
fn error_details_are_bounded_without_changing_the_reason() {
    let result = error_reply(RestrictedPytestError::new(
        "pytest_restricted_invalid_command",
        "x".repeat(100_000),
    ));
    assert_eq!(result["reason_code"], "pytest_restricted_invalid_command");
    assert!(result["message"].as_str().unwrap().len() < 4096);
}

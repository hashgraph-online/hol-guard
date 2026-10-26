use super::*;

fn operation(
    operation_id: &str,
    path: &[&str],
    flags: &[&str],
    options: &[&str],
) -> ReviewedOperation {
    ReviewedOperation {
        operation_id: operation_id.to_owned(),
        path: path.iter().map(|token| (*token).to_owned()).collect(),
        flags: flags.iter().map(|token| (*token).to_owned()).collect(),
        options_with_values: options.iter().map(|token| (*token).to_owned()).collect(),
    }
}

fn row(operation_id: &str, argv: &[&str]) -> ReviewedInvocation {
    ReviewedInvocation {
        operation_id: operation_id.to_owned(),
        argv: argv.iter().map(|token| (*token).to_owned()).collect(),
    }
}

fn validate(
    operations: &[ReviewedOperation],
    rows: &[ReviewedInvocation],
    blocked: &[&str],
) -> Result<Option<ReviewedBindingRefusal>, &'static str> {
    let blocked_ids = blocked.iter().map(|id| (*id).to_owned()).collect();
    validate_reviewed_invocations("git", operations, rows, &blocked_ids, None)
}

#[test]
fn a_vector_the_claiming_operation_owns_is_accepted() {
    let operations = [operation("status", &["status"], &["--short"], &[])];
    let rows = [row("status", &["status", "--short"])];
    assert_eq!(validate(&operations, &rows, &[]), Ok(None));
}

#[test]
fn nothing_to_review_asks_the_grammar_nothing() {
    assert_eq!(validate(&[], &[], &[]), Ok(None));
}

#[test]
fn an_option_the_discovery_never_reported_is_refused() {
    let operations = [operation("status", &["status"], &["--short"], &[])];
    let rows = [row("status", &["status", "--porcelain"])];
    assert_eq!(
        validate(&operations, &rows, &[]),
        Ok(Some(ReviewedBindingRefusal {
            index: 0,
            code: SAFE_VARIANT_OPTION
        }))
    );
}

#[test]
fn a_value_taking_option_without_its_value_is_refused() {
    let operations = [operation("log", &["log"], &[], &["--format"])];
    let rows = [row("log", &["log", "--format"])];
    assert_eq!(
        validate(&operations, &rows, &[]),
        Ok(Some(ReviewedBindingRefusal {
            index: 0,
            code: SAFE_VARIANT_OPTION
        }))
    );
}

#[test]
fn a_value_taking_option_carrying_its_value_is_accepted() {
    let operations = [operation("log", &["log"], &[], &["--format"])];
    let rows = [
        row("log", &["log", "--format", "oneline"]),
        row("log", &["log", "--format=oneline"]),
    ];
    assert_eq!(validate(&operations, &rows, &[]), Ok(None));
}

#[test]
fn a_root_operation_owns_no_operands() {
    let operations = [operation("git", &[], &["--version"], &[])];
    let rows = [row("git", &["status"])];
    assert_eq!(
        validate(&operations, &rows, &[]),
        Ok(Some(ReviewedBindingRefusal {
            index: 0,
            code: SAFE_VARIANT_SCOPE
        }))
    );
}

#[test]
fn a_longer_path_takes_the_vector_from_the_operation_that_claimed_it() {
    let operations = [
        operation("remote", &["remote"], &[], &[]),
        operation("remote-add", &["remote", "add"], &[], &[]),
    ];
    let rows = [row("remote", &["remote", "add"])];
    assert_eq!(
        validate(&operations, &rows, &[]),
        Ok(Some(ReviewedBindingRefusal {
            index: 0,
            code: SAFE_VARIANT_SCOPE
        }))
    );
}

#[test]
fn the_longest_matching_path_keeps_its_own_vector() {
    let operations = [
        operation("remote", &["remote"], &[], &[]),
        operation("remote-add", &["remote", "add"], &[], &[]),
    ];
    let rows = [row("remote-add", &["remote", "add"])];
    assert_eq!(validate(&operations, &rows, &[]), Ok(None));
}

#[test]
fn a_vector_a_blocked_operation_also_matches_is_refused() {
    let operations = [
        operation("push", &["push"], &["--force"], &[]),
        operation("push-force", &["push"], &["--force"], &[]),
    ];
    let rows = [row("push", &["push", "--force"])];
    assert_eq!(
        validate(&operations, &rows, &["push-force"]),
        Ok(Some(ReviewedBindingRefusal {
            index: 0,
            code: SAFE_VARIANT_CONFLICT
        }))
    );
}

#[test]
fn the_index_names_the_row_the_grammar_refused() {
    let operations = [operation("status", &["status"], &["--short"], &[])];
    let rows = [
        row("status", &["status", "--short"]),
        row("status", &["status", "--porcelain"]),
    ];
    assert_eq!(
        validate(&operations, &rows, &[]),
        Ok(Some(ReviewedBindingRefusal {
            index: 1,
            code: SAFE_VARIANT_OPTION
        }))
    );
}

#[test]
fn a_row_naming_an_operation_the_discovery_lacks_is_a_failure() {
    let operations = [operation("status", &["status"], &[], &[])];
    let rows = [row("unknown", &["status"])];
    assert_eq!(
        validate(&operations, &rows, &[]),
        Err("native_reviewed_invocation_operation_unknown")
    );
}

#[test]
fn an_executable_the_discovery_never_named_is_a_failure() {
    let operations = [operation("status", &["status"], &[], &[])];
    let rows = [row("status", &["status"])];
    let blocked = BTreeSet::new();
    assert_eq!(
        validate_reviewed_invocations("  ", &operations, &rows, &blocked, None),
        Err("native_reviewed_invocation_executable_empty")
    );
}

#[test]
fn a_discovery_that_names_its_command_in_mixed_case_still_binds() {
    let operations = [operation("remote-add", &["Remote", "Add"], &["-F"], &[])];
    let rows = [row("remote-add", &["Remote", "Add", "-F"])];
    let blocked_ids = BTreeSet::new();
    assert_eq!(
        validate_reviewed_invocations("MyTool", &operations, &rows, &blocked_ids, None),
        Ok(None)
    );
}

#[test]
fn a_vector_that_differs_only_in_case_from_the_discovery_binds() {
    let operations = [operation("remote-add", &["Remote", "Add"], &["-F"], &[])];
    let rows = [row("remote-add", &["remote", "add", "-f"])];
    let blocked_ids = BTreeSet::new();
    assert_eq!(
        validate_reviewed_invocations("MyTool", &operations, &rows, &blocked_ids, None),
        Ok(None)
    );
}

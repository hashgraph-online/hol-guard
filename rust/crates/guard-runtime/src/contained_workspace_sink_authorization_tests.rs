use super::*;

#[test]
fn authorization_failure_explains_that_nothing_ran_outside_the_sandbox() {
    let failure = Failure::unauthorized();
    assert_eq!(failure.reason, "contained_run_authorization_failed");
    assert!(failure.message.contains("no unapproved command ran outside the sandbox"));
}

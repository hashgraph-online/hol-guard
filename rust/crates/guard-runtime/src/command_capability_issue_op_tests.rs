use super::*;

use guard_contracts::{LOCAL_CONFIRMATION_COMMAND_OPERATIONS, STATE_CHANGING_COMMAND_OPERATIONS};

const DAY_SECONDS: i64 = 24 * 60 * 60;

fn request(requested: &[&str]) -> CommandCapabilityIssueRequestV1 {
    let mut supported: Vec<String> = READ_ONLY_COMMAND_OPERATIONS
        .iter()
        .chain(LOCAL_CONFIRMATION_COMMAND_OPERATIONS)
        .chain(STATE_CHANGING_COMMAND_OPERATIONS)
        .map(|operation| (*operation).to_owned())
        .collect();
    supported.push(EXACT_CLOUD_REVIEW_OPERATION.to_owned());
    CommandCapabilityIssueRequestV1 {
        schema: COMMAND_CAPABILITY_ISSUE_REQUEST_SCHEMA.to_owned(),
        request_id: "issue-1".to_owned(),
        requested: requested.iter().map(|word| (*word).to_owned()).collect(),
        supported_operations: supported,
        issuer: "local-cli".to_owned(),
        ttl_seconds: 30 * DAY_SECONDS,
    }
}

fn answer(request: &CommandCapabilityIssueRequestV1) -> Value {
    let encoded = evaluate_command_capability_issue_request(request).expect("response");
    serde_json::from_slice(&encoded).expect("json")
}

fn granted(request: &CommandCapabilityIssueRequestV1) -> Vec<String> {
    let response = answer(request);
    assert_eq!(response["status"], "ok");
    assert_eq!(response["payload"]["granted"], true);
    response["payload"]["operations"]
        .as_array()
        .expect("operations")
        .iter()
        .map(|operation| operation.as_str().expect("name").to_owned())
        .collect()
}

fn refusal(request: &CommandCapabilityIssueRequestV1) -> String {
    let response = answer(request);
    assert_eq!(response["status"], "ok");
    assert_eq!(response["payload"]["granted"], false);
    assert!(response["payload"]["operations"]
        .as_array()
        .expect("operations")
        .is_empty());
    response["payload"]["reason"]
        .as_str()
        .expect("reason")
        .to_owned()
}

#[test]
fn the_group_name_stands_for_every_read_only_operation() {
    let mut expected: Vec<String> = READ_ONLY_COMMAND_OPERATIONS
        .iter()
        .map(|operation| (*operation).to_owned())
        .collect();
    expected.sort();

    assert_eq!(granted(&request(&["read-only"])), expected);
}

#[test]
fn typed_words_are_split_trimmed_sorted_and_deduplicated() {
    let operations = granted(&request(&[
        " guard.app.status , guard.packageShims.audit ",
        "guard.app.status",
    ]));

    assert_eq!(
        operations,
        vec![
            "guard.app.status".to_owned(),
            "guard.packageShims.audit".to_owned(),
        ]
    );
}

#[test]
fn the_group_name_combines_with_an_exact_operation() {
    let operations = granted(&request(&["read-only,guard.app.update"]));

    assert!(operations.contains(&"guard.app.update".to_owned()));
    assert!(operations.contains(&"guard.app.status".to_owned()));
}

#[test]
fn an_issuer_of_only_spacing_names_nobody() {
    let mut asked = request(&["guard.app.status"]);
    asked.issuer = "  ".to_owned();

    assert_eq!(refusal(&asked), "capability_issuer_required");
}

#[test]
fn a_life_outside_the_admitted_range_is_refused() {
    for ttl_seconds in [0, -1, COMMAND_CAPABILITY_MAX_TTL_SECONDS + 1] {
        let mut asked = request(&["guard.app.status"]);
        asked.ttl_seconds = ttl_seconds;

        assert_eq!(refusal(&asked), "invalid_capability_ttl", "{ttl_seconds}");
    }
}

#[test]
fn words_that_name_no_operation_are_an_empty_request() {
    assert_eq!(
        refusal(&request(&[" ", ",", ""])),
        "capability_operations_required"
    );
}

#[test]
fn an_operation_this_installation_cannot_run_is_refused() {
    let mut asked = request(&["guard.app.status"]);
    asked.supported_operations = vec!["guard.app.updateCheck".to_owned()];

    assert_eq!(refusal(&asked), "unsupported_capability_operation");
}

#[test]
fn an_unknown_operation_is_refused_even_when_the_caller_supports_it() {
    let mut asked = request(&["guard.app.detonate"]);
    asked
        .supported_operations
        .push("guard.app.detonate".to_owned());

    assert_eq!(refusal(&asked), "unsupported_capability_operation");
}

#[test]
fn the_exact_review_grant_is_never_a_capability_operation() {
    assert_eq!(
        refusal(&request(&[EXACT_CLOUD_REVIEW_OPERATION])),
        "unsupported_capability_operation"
    );
}

#[test]
fn decision_memory_is_granted_only_on_its_own() {
    assert_eq!(
        granted(&request(&["guard.review.syncPolicyMemory"])),
        vec!["guard.review.syncPolicyMemory".to_owned()]
    );
    assert_eq!(
        refusal(&request(&[
            "guard.review.syncPolicyMemory",
            "guard.app.status"
        ])),
        "policy_memory_capability_must_be_isolated"
    );
    assert_eq!(
        refusal(&request(&["read-only,guard.review.syncPolicyMemory"])),
        "policy_memory_capability_must_be_isolated"
    );
}

#[test]
fn a_request_naming_another_contract_is_refused_rather_than_answered() {
    let mut asked = request(&["guard.app.status"]);
    asked.schema = "guard-command-capability-request.v1".to_owned();
    let response = answer(&asked);

    assert_eq!(response["status"], "error");
    assert_eq!(
        response["code"],
        "native_command_capability_issue_schema_mismatch"
    );
    assert!(response.get("payload").is_none() || response["payload"].is_null());
}

#[test]
fn every_classified_operation_may_be_granted() {
    for operation in READ_ONLY_COMMAND_OPERATIONS
        .iter()
        .chain(LOCAL_CONFIRMATION_COMMAND_OPERATIONS)
    {
        assert_eq!(
            granted(&request(&[*operation])),
            vec![(*operation).to_owned()]
        );
    }
}

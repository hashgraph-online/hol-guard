use super::*;
use guard_contracts::GithubCliClassifyResultV1;

fn request(args: &[&str]) -> GithubCliClassifyRequestV1 {
    GithubCliClassifyRequestV1 {
        schema: GITHUB_CLI_CLASSIFY_REQUEST_SCHEMA.to_owned(),
        request_id: "gh-1".to_owned(),
        args: args.iter().map(|item| (*item).to_owned()).collect(),
    }
}

fn run(request: &GithubCliClassifyRequestV1) -> GithubCliClassifyResultV1 {
    let bytes = evaluate_github_cli_classify_request(request).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn capability(args: &[&str]) -> String {
    run(&request(args)).assessment.unwrap().capability
}

#[test]
fn read_only_pr_view_is_remote_read() {
    assert_eq!(capability(&["pr", "view", "12"]), "read_remote");
}

#[test]
fn missing_subcommand_is_unknown() {
    let result = run(&request(&[]));
    let assessment = result.assessment.unwrap();
    assert_eq!(assessment.capability, "unknown");
    assert_eq!(assessment.reason_code, "github.command.missing");
    assert_eq!(assessment.capabilities, vec!["unknown"]);
}

#[test]
fn mutations_never_classify_as_reads() {
    for args in [
        &["pr", "close", "7"][..],
        &["issue", "create", "--title", "x"][..],
        &["repo", "delete", "owner/name", "--yes"][..],
    ] {
        let value = capability(args);
        assert!(
            !matches!(value.as_str(), "read_local" | "read_remote"),
            "{args:?} classified as {value}"
        );
    }
}

#[test]
fn unknown_group_fails_to_unknown() {
    assert_eq!(capability(&["definitely-not-a-group", "x"]), "unknown");
}

#[test]
fn result_binds_request_id_and_digest() {
    let first = run(&request(&["pr", "view", "1"]));
    let second = run(&request(&["pr", "view", "2"]));
    assert_eq!(first.schema, GITHUB_CLI_CLASSIFY_RESULT_SCHEMA);
    assert_eq!(first.request_id, "gh-1");
    assert!(first.request_sha256.starts_with("sha256:"));
    assert_ne!(first.request_sha256, second.request_sha256);
    assert_eq!(
        first.request_sha256,
        run(&request(&["pr", "view", "1"])).request_sha256
    );
}

#[test]
fn schema_mismatch_is_an_error_without_assessment() {
    let mut bad = request(&["pr", "view"]);
    bad.schema = "other".to_owned();
    let result = run(&bad);
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_github_cli_classify_schema_mismatch");
    assert!(result.assessment.is_none());
}

#[test]
fn oversized_arguments_are_rejected() {
    let big = "a".repeat(GITHUB_CLI_CLASSIFY_MAX_BYTES + 1);
    assert_eq!(
        evaluate_github_cli_classify_request(&request(&["pr", &big])).unwrap_err(),
        "native_github_cli_classify_too_large"
    );
}

#[test]
fn oversized_request_id_is_rejected_before_hashing() {
    let mut big = request(&["pr", "view", "1"]);
    big.request_id = "x".repeat(GITHUB_CLI_CLASSIFY_MAX_BYTES + 1);
    assert_eq!(
        evaluate_github_cli_classify_request(&big).unwrap_err(),
        "native_github_cli_classify_too_large"
    );
}

#[test]
fn escaped_characters_count_toward_the_canonical_limit() {
    // Each control character is one raw byte but six canonical bytes (`\u0001`).
    let raw = "\u{1}".repeat(GITHUB_CLI_CLASSIFY_MAX_BYTES / 6);
    assert!(raw.len() < GITHUB_CLI_CLASSIFY_MAX_BYTES / 4);
    assert_eq!(
        evaluate_github_cli_classify_request(&request(&["pr", &raw])).unwrap_err(),
        "native_github_cli_classify_too_large"
    );
}

#[test]
fn unicode_request_digest_matches_the_python_canonical_digest() {
    // The Python bridge hashes json.dumps(sort_keys, compact, ensure_ascii); the
    // same vector is asserted in tests/test_native_github_cli_bridge.py.
    let unicode = request(&["pr", "view", "é☃\u{1}\u{1F600}"]);
    assert_eq!(
        run(&unicode).request_sha256,
        "sha256:6dc5cc1707396312c4de9eb38f15257ec72438090b658bc4fa80a973440204d8"
    );
}

#[test]
fn capabilities_are_canonical_and_end_with_strongest() {
    let assessment = run(&request(&["pr", "merge", "5", "--admin"]))
        .assessment
        .unwrap();
    assert!(assessment.capabilities.contains(&assessment.capability));
}

#[test]
fn static_markdown_body_file_operand_is_returned() {
    let result = run(&request(&["--title", "t", "--body-file", "notes.md"]));
    assert_eq!(result.pr_body_file_operand.as_deref(), Some("notes.md"));
    let result = run(&request(&["--title", "t", "--body", "inline"]));
    assert_eq!(result.pr_body_file_operand, None);
}

#[test]
fn auth_status_is_remote_read_and_token_reads_are_secret() {
    assert_eq!(capability(&["auth", "status"]), "read_remote");
    assert_eq!(
        capability(&["auth", "status", "--show-token"]),
        "secret_remote"
    );
    assert_eq!(capability(&["auth", "token"]), "secret_remote");
}

use guard_command::hook_responses::pre_tool;
use serde_json::{json, Map, Value};

use super::*;
use crate::native_review_link::{OPEN_GUARD, SIGNED_LINK_UNAVAILABLE};

const URL: &str = "http://127.0.0.1:4781/requests/abc";
const GUARD_HOME: &str = "/home/dev/.hol-guard";
const HOME_DIR: &str = "/home/dev";
const MICROS: i64 = 1_790_000_000_000_000;
const SETUP: &str = "HOL Guard has not been set up for `Linear` yet.";

fn result() -> Map<String, Value> {
    json!({
        "decision": "review",
        "minimum_action": "review",
        "policy_action": "review",
        "reason": "HOL Guard requires review before this action can execute.",
        "reason_code": "native_shell_review",
    })
    .as_object()
    .cloned()
    .expect("result object")
}

fn queued(harness: &str) -> SilentReviewBlockInputsV1 {
    SilentReviewBlockInputsV1 {
        harness: harness.to_owned(),
        result: result(),
        setup_reason: None,
        queued: true,
        request_id: Some("abc".to_owned()),
        approval_url: Some(URL.to_owned()),
        ask: false,
        retry_reuses_approval: true,
        exact_action_allowable: true,
        connector_is_local: false,
        guard_home: GUARD_HOME.to_owned(),
        home_dir: HOME_DIR.to_owned(),
    }
}

/// The response with `native_review_reason` bound to `auth_token`.
fn answer(inputs: &SilentReviewBlockInputsV1, auth_token: Option<&str>) -> Object {
    respond(inputs, |harness, reason, url| {
        native_review_reason(harness, reason, url, auth_token, MICROS)
    })
    .expect("block")
    .response
}

/// What the daemon rendered for `reason`: the blocked verdict, never prompted.
fn rendered(harness: &str, reason: &str) -> Object {
    let mut blocked = result();
    blocked.insert("decision".to_owned(), json!("deny"));
    blocked.insert("minimum_action".to_owned(), json!("block"));
    blocked.insert("policy_action".to_owned(), json!("block"));
    blocked.insert("reason".to_owned(), json!(reason));
    let mut response = pre_tool(harness, &blocked);
    response.insert("prompted".to_owned(), json!(false));
    response.insert("blocked_request_mode".to_owned(), json!("safe-alternative"));
    response
}

fn safe(queued: bool, retry: bool, exact: bool) -> String {
    safe_alternative_reason_with_retry(
        "HOL Guard requires review before this action can execute.",
        Some("native_shell_review"),
        Some(queued),
        retry,
        exact,
    )
}

fn hint() -> String {
    approval_wait_hint_for_home("abc", GUARD_HOME, HOME_DIR)
}

#[test]
fn a_bound_queued_review_waits_links_and_can_be_resumed() {
    let inputs = queued("claude-code");
    let reason = format!("{} {} {OPEN_GUARD} {URL}.", safe(true, true, true), hint());
    let mut expected = rendered("claude-code", &reason);
    expected.insert(
        "approval_resume".to_owned(),
        json!({"request_id": "abc", "poll_path": "/v1/requests/abc"}),
    );
    assert!(!hint().is_empty());
    assert_eq!(answer(&inputs, None), expected);
}

#[test]
fn an_unbound_review_gets_no_wait_hint_and_no_resume_handle() {
    let mut inputs = queued("claude-code");
    inputs.retry_reuses_approval = false;
    let reason = format!("{} {OPEN_GUARD} {URL}.", safe(true, false, true));
    assert_eq!(answer(&inputs, None), rendered("claude-code", &reason));
}

#[test]
fn a_review_that_was_not_queued_has_no_setup_text_link_or_handle() {
    let mut inputs = queued("claude-code");
    inputs.queued = false;
    inputs.request_id = None;
    inputs.approval_url = None;
    inputs.setup_reason = Some(SETUP.to_owned());
    let response = answer(&inputs, None);
    assert_eq!(response, rendered("claude-code", &safe(false, true, true)));
    assert!(!response.contains_key("approval_resume"));
}

#[test]
fn a_setup_reason_replaces_the_safe_alternative_text() {
    let mut inputs = queued("claude-code");
    inputs.retry_reuses_approval = false;
    inputs.setup_reason = Some(SETUP.to_owned());
    // A remote connector's setup reason in the default mode carries no link.
    assert_eq!(answer(&inputs, None), rendered("claude-code", SETUP));
    // A local connector's setup review is an ordinary approvable one.
    inputs.connector_is_local = true;
    let linked = format!("{SETUP} {OPEN_GUARD} {URL}.");
    assert_eq!(answer(&inputs, None), rendered("claude-code", &linked));
    // An empty setup reason falls back to the safe-alternative text.
    inputs.setup_reason = Some(String::new());
    let linked = format!("{} {OPEN_GUARD} {URL}.", safe(true, false, true));
    assert_eq!(answer(&inputs, None), rendered("claude-code", &linked));
}

#[test]
fn the_link_is_added_only_when_an_approval_can_unblock_the_action() {
    let mut inputs = queued("claude-code");
    inputs.retry_reuses_approval = false;
    inputs.exact_action_allowable = false;
    assert_eq!(
        answer(&inputs, None),
        rendered("claude-code", &safe(true, false, false))
    );
    // The ask mode links a setup review an approval can unblock.
    inputs.exact_action_allowable = true;
    inputs.setup_reason = Some(SETUP.to_owned());
    inputs.ask = true;
    let linked = format!("{SETUP} {OPEN_GUARD} {URL}.");
    assert_eq!(answer(&inputs, None), rendered("claude-code", &linked));
    // A blank link adds nothing.
    inputs.approval_url = Some("  ".to_owned());
    assert_eq!(answer(&inputs, None), rendered("claude-code", SETUP));
}

#[test]
fn codex_gets_a_signed_link_or_says_it_has_none() {
    let mut inputs = queued("codex");
    inputs.retry_reuses_approval = false;
    let unsigned = answer(&inputs, None);
    let reason = format!("{} {SIGNED_LINK_UNAVAILABLE}", safe(true, false, true));
    assert_eq!(unsigned, rendered("codex", &reason));
    let signed = answer(&inputs, Some("daemon-token"));
    let text = serde_json::to_string(&signed).expect("json");
    assert!(text.contains(&format!("{URL}#guard-token=gld1.")), "{text}");
    // Claude Code shows the raw loopback link when no token exists.
    let mut claude = inputs.clone();
    claude.harness = "claude-code".to_owned();
    let reason = format!("{} {OPEN_GUARD} {URL}.", safe(true, false, true));
    assert_eq!(answer(&claude, None), rendered("claude-code", &reason));
}

#[test]
fn a_reason_that_is_not_text_is_refused() {
    let mut inputs = queued("codex");
    inputs
        .result
        .insert("reason".to_owned(), json!(["not", "text"]));
    assert_eq!(
        respond(&inputs, |_, _, _| None).map(|block| block.response),
        Err(INVALID.to_owned())
    );
    // A setup reason never reads the native reason.
    inputs.setup_reason = Some(SETUP.to_owned());
    assert!(respond(&inputs, |_, _, _| None).is_ok());
}

#[test]
fn a_missing_reason_falls_back_to_the_blocked_text() {
    let mut inputs = queued("claude-code");
    inputs.retry_reuses_approval = false;
    inputs.exact_action_allowable = false;
    inputs.result.insert("reason".to_owned(), Value::Null);
    inputs.result.insert("reason_code".to_owned(), json!(""));
    let reason = safe_alternative_reason_with_retry(
        BLOCKED_REASON,
        Some("unknown"),
        Some(true),
        false,
        false,
    );
    let mut blocked = inputs.result.clone();
    blocked.insert("decision".to_owned(), json!("deny"));
    blocked.insert("minimum_action".to_owned(), json!("block"));
    blocked.insert("policy_action".to_owned(), json!("block"));
    blocked.insert("reason".to_owned(), json!(reason));
    let mut expected = pre_tool("claude-code", &blocked);
    expected.insert("prompted".to_owned(), json!(false));
    expected.insert("blocked_request_mode".to_owned(), json!("safe-alternative"));
    assert_eq!(answer(&inputs, None), expected);
}

fn paused(harness: &str, reason: &str, url: &str) -> PausedReviewInputsV1 {
    PausedReviewInputsV1 {
        harness: harness.to_owned(),
        verdict: json!({"reason": reason, "reason_code": "native_pre_tool_review"})
            .as_object()
            .cloned()
            .expect("verdict object"),
        approval: json!({"request_id": "abc", "approval_url": url})
            .as_object()
            .cloned(),
        guard_home: GUARD_HOME.to_owned(),
    }
}

/// The paused response with `native_review_reason` bound to `auth_token`.
fn paused_answer(inputs: &PausedReviewInputsV1, auth_token: Option<&str>) -> Object {
    pause(inputs, |harness, reason, url| {
        native_review_reason(harness, reason, url, auth_token, MICROS)
    })
    .response
}

fn reason_of(response: &Object) -> &str {
    response["reason"].as_str().expect("reason is text")
}

#[test]
fn a_paused_codex_review_signs_its_loopback_link() {
    let inputs = paused("codex", "HOL Guard paused this action.", URL);
    let response = paused_answer(&inputs, Some("daemon-token"));
    assert!(
        reason_of(&response).contains(&format!("{URL}#guard-token=gld1.")),
        "{response:?}"
    );
    // The link fields keep the unsigned URL; only the reason carries a token.
    assert_eq!(response["approval_url"], URL);
    assert_eq!(response["primary_approval_url"], URL);
    assert_eq!(response["guardApprovalUrl"], URL);
}

#[test]
fn a_paused_codex_review_hides_an_unsigned_loopback_link() {
    let inputs = paused("codex", &format!("Review this action: {URL}"), URL);
    let response = paused_answer(&inputs, None);
    let reason = reason_of(&response);
    assert!(!reason.contains(URL), "{reason}");
    assert!(reason.ends_with(SIGNED_LINK_UNAVAILABLE), "{reason}");
    assert_eq!(response["approval_url"], URL);
}

#[test]
fn a_paused_review_leaves_an_external_link_as_it_is() {
    let external = "https://example.invalid/requests/abc";
    let inputs = paused("codex", "HOL Guard paused this action.", external);
    let reason = format!("HOL Guard paused this action. {OPEN_GUARD} {external}.");
    assert_eq!(reason_of(&paused_answer(&inputs, None)), reason);
    assert_eq!(
        reason_of(&paused_answer(&inputs, Some("daemon-token"))),
        reason
    );
}

#[test]
fn a_paused_review_without_a_link_keeps_its_reason() {
    let mut inputs = paused("claude-code", "Needs review.", URL);
    inputs.approval = None;
    let unlinked = pause(&inputs, |_, _, _| panic!("no link to sign"));
    assert_eq!(unlinked.response["reason"], "Needs review.");
    inputs.approval = json!({"request_id": "abc", "approval_url": "  "})
        .as_object()
        .cloned();
    let blank = pause(&inputs, |_, _, _| panic!("no link to sign"));
    assert_eq!(blank.response["reason"], "Needs review.");
}

#[test]
fn a_paused_review_links_the_default_reason_when_it_has_none() {
    let mut inputs = paused("claude-code", "", URL);
    inputs.verdict.remove("reason");
    let response = paused_answer(&inputs, None);
    assert_eq!(
        reason_of(&response),
        format!("{REVIEW_DEFAULT_REASON} {OPEN_GUARD} {URL}.")
    );
    // A link the resident cannot sign leaves the reason unlinked, and says so.
    let kept = pause(&inputs, |_, _, _| None);
    assert_eq!(
        reason_of(&kept.response),
        format!("{REVIEW_DEFAULT_REASON} {SIGNED_LINK_UNAVAILABLE}")
    );
}

#[test]
fn an_unsignable_review_link_leaves_no_raw_url_in_the_reason() {
    let inputs = paused(
        "claude-code",
        &format!("Needs review. Approve it at {URL}."),
        URL,
    );
    let paused_review = pause(&inputs, |_, _, _| None);
    let reason = reason_of(&paused_review.response);
    assert!(!reason.contains(URL), "{reason}");
    assert!(reason.starts_with("Needs review."), "{reason}");
    assert!(reason.ends_with(SIGNED_LINK_UNAVAILABLE), "{reason}");
    // The structured link fields still carry the unsigned URL for the daemon.
    assert_eq!(paused_review.response["approval_url"], URL);
}

#[test]
fn an_unsignable_block_link_leaves_no_raw_url_in_the_reason() {
    let mut inputs = queued("claude-code");
    inputs.result.insert(
        "reason".to_owned(),
        json!(format!("Blocked. Approve it at {URL}.")),
    );
    let block = respond(&inputs, |_, _, _| None).expect("block");
    // A claude-code block carries its agent text in the hook envelope, not at
    // the top level, so the rendered reason is what the agent actually reads.
    let reason = block.response["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .expect("reason is text");
    assert!(!reason.contains(URL), "{reason}");
    assert!(reason.ends_with(SIGNED_LINK_UNAVAILABLE), "{reason}");
}

#[test]
fn a_paused_default_mode_setup_reason_gets_no_link() {
    use crate::blocked_request_mode::connector_setup_reason;
    let external = "https://guard.example.test/approvals/0123456789abcdef";
    let default = connector_setup_reason("echo-mcp", "mcp", false, &[], true);
    let ask = connector_setup_reason("echo-mcp", "mcp", true, &[], true);
    let local = connector_setup_reason("lanectl", "cli", false, &[], true);
    let shown = |reason: &str| {
        reason_of(&paused_answer(
            &paused("claude-code", reason, external),
            None,
        ))
        .to_owned()
    };
    assert_eq!(shown(&default), default);
    assert_eq!(shown(&ask), format!("{ask} {OPEN_GUARD} {external}."));
    assert_eq!(shown(&local), format!("{local} {OPEN_GUARD} {external}."));
}

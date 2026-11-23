//! The two facts the block answers for itself: the native prompt it is
//! allowed to read, and the link it names.

use guard_command::effect_decision::GuardAction;

use super::*;
use crate::mcp_tool_policy_decision::{Current, Decision};

fn decision(source: &str) -> Decision {
    Decision::plain(Current {
        action: GuardAction::RequireReapproval,
        source: source.to_owned(),
        signals: vec!["Opens an external site.".to_owned()],
        summary: "browser navigation".to_owned(),
        risk_categories: vec!["browser_navigation".to_owned()],
    })
}

fn row(approval_url: Value) -> Map<String, Value> {
    let mut row = Map::new();
    row.insert("request_id".to_owned(), json!("req-1"));
    row.insert("approval_url".to_owned(), approval_url);
    row
}

#[test]
fn the_native_prompt_answer_follows_the_harness_proxy_class() {
    let facts = |source: &str| crate::mcp_tool_policy_proxy::facts(&decision(source));
    // `_allow_after_native_prompt`: anything the saved policy itself decided
    // stays blocked after the prompt; every other source allows.
    assert!(!native_prompt_allows(OPENCODE, &facts("policy")));
    assert!(native_prompt_allows(OPENCODE, &facts("approval-gate")));
    // The base class answers `False`, which routes to an inline elicitation.
    for harness in ["codex", "copilot", "cursor", "hermes"] {
        assert!(
            !native_prompt_allows(harness, &facts("approval-gate")),
            "{harness}"
        );
    }
    // A pending decision is answered off the facts that reach the route, so
    // the saved-allow gate's replacement decides the prompt, not the policy
    // source the gate already replaced.
    let mut pending = decision("policy");
    pending.pending = Some(Map::new());
    let gated = McpToolFactsV1 {
        source: "tool-catalog-state".to_owned(),
        has_pending: false,
        ..crate::mcp_tool_policy_proxy::facts(&pending)
    };
    assert!(native_prompt_allows(OPENCODE, &gated));
}

#[test]
fn the_block_names_the_link_the_written_row_carries() {
    // The row's own link, which the center it was written against serves.
    let kept = row(json!("http://127.0.0.1:8787/requests/req-1?focus=1"));
    assert_eq!(
        review_url(&kept, "http://127.0.0.1:8787", "req-2"),
        "http://127.0.0.1:8787/requests/req-1?focus=1"
    );
    // A row written against an earlier port of this machine: the path is the
    // row's, the origin is the center the call is answered against.
    assert_eq!(
        review_url(&kept, "http://localhost:3000", "req-2"),
        "http://localhost:3000/requests/req-1?focus=1"
    );
}

#[test]
fn a_link_this_machine_does_not_serve_is_left_alone() {
    let hosted = "https://guard.example.test/requests/req-1";
    assert_eq!(
        canonical_local_approval_url(hosted, "http://127.0.0.1:8787"),
        hosted
    );
    // Both ends must be loopback for the rewrite, so a hosted center leaves a
    // local link as it was written.
    let local = "http://127.0.0.1:8787/requests/req-1";
    assert_eq!(
        canonical_local_approval_url(local, "https://guard.example.test"),
        local
    );
    // Userinfo and a bracketed IPv6 host still name this machine.
    assert_eq!(
        canonical_local_approval_url("http://user@[::1]:8787/requests/req-1", "http://localhost"),
        "http://localhost/requests/req-1"
    );
    // A scheme this machine does not serve approvals over.
    let other = "file://127.0.0.1/requests/req-1";
    assert_eq!(
        canonical_local_approval_url(other, "http://127.0.0.1:8787"),
        other
    );
}

#[test]
fn a_row_with_no_link_falls_back_to_this_center() {
    // `build_approval_request_url`, off the row's own request id.
    assert_eq!(
        review_url(&row(json!("   ")), "http://127.0.0.1:8787/", "req-2"),
        "http://127.0.0.1:8787/requests/req-1"
    );
    assert_eq!(
        review_url(&Map::new(), "http://127.0.0.1:8787", "req-2"),
        "http://127.0.0.1:8787/requests/req-2"
    );
    // A center the binding published empty leaves nothing to link to.
    assert_eq!(review_url(&Map::new(), "  ", "req-2"), "");
}

#[test]
fn the_queue_timestamp_matches_an_isoformat_utc_now() {
    let now = now_isoformat().expect("a timestamp");
    assert!(now.ends_with("+00:00"), "{now}");
    let (date, rest) = now.split_once('T').expect("a date and a time");
    assert_eq!(date.len(), 10, "{now}");
    // `datetime.now(timezone.utc).isoformat()` leaves the fraction out at
    // exactly zero microseconds and writes six digits otherwise.
    let time = rest.trim_end_matches("+00:00");
    assert!(
        time.len() == 8 || (time.len() == 15 && time.as_bytes()[8] == b'.'),
        "{now}"
    );
}

#[test]
fn post_claim_evidence_follows_the_decision_evidence_in_the_row() {
    let decided = json!({"source": "approval_reuse", "reason_code": "decided"});
    let appended = json!({"source": "approval_reuse", "reason_code": "appended"});
    let mut item = Map::new();
    item.insert("scanner_evidence".to_owned(), json!([decided]));
    append_scanner_evidence(&mut item, std::slice::from_ref(&appended));
    assert_eq!(item["scanner_evidence"], json!([decided, appended]));
    // A decision with no evidence of its own still carries the appended one.
    let mut item = Map::new();
    append_scanner_evidence(&mut item, std::slice::from_ref(&appended));
    assert_eq!(item["scanner_evidence"], json!([appended]));
    // Nothing to append leaves the key out, as the proxy does.
    let mut item = Map::new();
    append_scanner_evidence(&mut item, &[]);
    assert!(!item.contains_key("scanner_evidence"));
}

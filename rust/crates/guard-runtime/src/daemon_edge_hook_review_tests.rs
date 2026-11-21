use std::path::Path;

use serde_json::json;

use super::*;

fn unavailable(harness: &str, event: &str) -> Value {
    fail_safe(
        harness,
        event,
        WORKER_UNAVAILABLE_REASON,
        WORKER_UNAVAILABLE_CODE,
    )
}

#[test]
fn routes_name_the_harness_and_the_readiness_check() {
    assert_eq!(route("/v1/hooks/codex"), Some(("codex", false)));
    assert_eq!(route("/v1/hooks/pi/readiness"), Some(("pi", true)));
    assert_eq!(route("/v1/hooks/"), None);
    assert_eq!(route("/v1/hooks/pi/other"), None);
    assert_eq!(route("/v1/requests/pi"), None);
    assert!(owns("/v1/hooks/claude-code"));
}

#[test]
fn a_tool_event_fails_closed_with_the_worker_reason() {
    let body = unavailable("Claude_Code", "PreToolUse");
    assert_eq!(body["policy_action"], "block");
    assert_eq!(body["reason_code"], WORKER_UNAVAILABLE_CODE);
    assert_eq!(body["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        body["hookSpecificOutput"]["permissionDecisionReason"],
        WORKER_UNAVAILABLE_REASON
    );
}

#[test]
fn a_before_event_is_a_tool_event() {
    let body = unavailable("codex", "before_tool_call");
    assert_eq!(body["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn a_prompt_event_fails_closed_with_the_prompt_reason() {
    let body = unavailable("codex", "user_prompt_submit");
    assert_eq!(body["decision"], "block");
    let contract: serde_json::Value = serde_json::from_str(ENVELOPES).unwrap();
    assert_eq!(body["reason"], contract["defaults"]["prompt_reason"]);
    assert!(body["reason"]
        .as_str()
        .is_some_and(|reason| !reason.is_empty()));
}

#[test]
fn a_lifecycle_event_carries_no_verdict() {
    let body = unavailable("codex", "PostToolUse");
    assert_eq!(body["continue"], true);
    assert_eq!(body["hookSpecificOutput"]["hookEventName"], "PostToolUse");
    assert_eq!(body["reason_code"], WORKER_UNAVAILABLE_CODE);
}

#[test]
fn placeholders_fill_only_whole_strings() {
    let filled = fill(
        json!({"a": "$reason", "b": ["$reason", "x $reason"], "c": 1}),
        &[("$reason", "why")],
    );
    assert_eq!(
        filled,
        json!({"a": "why", "b": ["why", "x $reason"], "c": 1})
    );
}

#[test]
fn a_capacity_refusal_names_its_cause() {
    let body = fail_safe(
        "codex",
        "PreToolUse",
        &capacity_reason(
            hook_scheduler::DEADLINE_EXHAUSTED,
            Path::new("/home/dev/.hol-guard"),
            "/home/dev",
        ),
        hook_scheduler::DEADLINE_EXHAUSTED,
    );
    let text = body.to_string();
    assert!(text.contains("within the hook deadline"));
    assert!(text.contains(hook_scheduler::DEADLINE_EXHAUSTED));
    assert!(capacity_reason(
        hook_scheduler::QUEUE_CAPACITY,
        Path::new("/home/dev/.hol-guard"),
        "/home/dev"
    )
    .contains("queueing"));
}

#[test]
fn a_capacity_refusal_names_a_recovery_command() {
    for code in [
        hook_scheduler::DEADLINE_EXHAUSTED,
        hook_scheduler::QUEUE_CAPACITY,
    ] {
        let reason = capacity_reason(code, Path::new("/home/dev/.hol-guard"), "/home/dev");
        assert!(reason.contains("Retry this action"), "{reason}");
        assert!(reason.ends_with("run `hol-guard repair`."), "{reason}");
    }
}

#[test]
fn a_capacity_refusal_names_a_non_default_guard_home() {
    let reason = capacity_reason(
        hook_scheduler::DEADLINE_EXHAUSTED,
        Path::new("/srv/guard homes/one"),
        "/home/dev",
    );
    assert!(
        reason.ends_with("run `hol-guard repair --guard-home '/srv/guard homes/one'`."),
        "{reason}"
    );
    let unknown_home = capacity_reason(hook_scheduler::QUEUE_CAPACITY, Path::new("/srv/guard"), "");
    assert!(
        unknown_home.ends_with("run `hol-guard repair --guard-home /srv/guard`."),
        "{unknown_home}"
    );
}

#[test]
fn a_step_refusal_needs_a_reason_and_a_code() {
    assert_eq!(
        refusal(&json!({"reason": "r", "reason_code": "c"})),
        Some(("r", "c"))
    );
    assert_eq!(refusal(&json!({"reason": "r"})), None);
}

#[test]
fn an_unmanaged_app_passes_through_in_its_own_envelope() {
    assert_eq!(
        envelope("unmanaged", "PI", &[]),
        json!({"decision": "allow", "reason_code": "harness_not_managed"})
    );
    assert_eq!(envelope("unmanaged", "grok", &[]), json!({}));
    assert_eq!(
        envelope("unmanaged", "codex", &[]),
        json!({"continue": true, "reason_code": "harness_not_managed"})
    );
}

/// Every code the edge answers with when it has no native decision: the
/// worker could not review the hook, or the scheduler refused it.
const NO_DECISION_CODES: [&str; 4] = [
    WORKER_UNAVAILABLE_CODE,
    hook_scheduler::DEADLINE_EXHAUSTED,
    hook_scheduler::QUEUE_CAPACITY,
    hook_scheduler::QUEUE_BYTES,
];

/// The enforcing harnesses and the pre-execution events each one sends.
const PRE_TOOL_EVENTS: [(&str, &[&str]); 3] = [
    ("claude-code", &["PreToolUse"]),
    ("codex", &["PreToolUse", "pre_tool_use"]),
    (
        "cursor",
        &[
            "preToolUse",
            "beforeShellExecution",
            "beforeMCPExecution",
            "beforeReadFile",
        ],
    ),
];

/// The observation events that follow a tool call on the same harnesses.
const POST_TOOL_EVENTS: [(&str, &[&str]); 3] = [
    ("claude-code", &["PostToolUse"]),
    ("codex", &["PostToolUse"]),
    (
        "cursor",
        &["postToolUse", "afterShellExecution", "afterMCPExecution"],
    ),
];

#[test]
fn no_pre_tool_event_is_allowed_without_a_native_decision() {
    for (harness, events) in PRE_TOOL_EVENTS {
        for event in events {
            for code in NO_DECISION_CODES {
                let body = fail_safe(harness, event, WORKER_UNAVAILABLE_REASON, code);
                let context = format!("{harness} {event} {code}");
                assert_eq!(body["policy_action"], "block", "{context}");
                assert_eq!(body["reason_code"], code, "{context}");
                assert_eq!(
                    body["hookSpecificOutput"]["permissionDecision"], "deny",
                    "{context}"
                );
                assert_ne!(body["continue"], true, "{context}");
            }
        }
    }
}

#[test]
fn a_post_tool_event_without_a_native_decision_never_blocks() {
    for (harness, events) in POST_TOOL_EVENTS {
        for event in events {
            for code in NO_DECISION_CODES {
                let body = fail_safe(harness, event, WORKER_UNAVAILABLE_REASON, code);
                let context = format!("{harness} {event} {code}");
                assert_eq!(body["continue"], true, "{context}");
                assert_ne!(body["policy_action"], "block", "{context}");
                assert!(body.get("decision").is_none(), "{context}");
                assert_eq!(
                    body["hookSpecificOutput"]["hookEventName"], *event,
                    "{context}"
                );
            }
        }
    }
}

/// The shipped capability contract: every harness and the events it declares.
const HARNESS_CONTRACTS: &str = include_str!(
    "../../../../src/codex_plugin_scanner/guard/contracts/harness-protection-contracts.v1.json"
);

/// Whether a reply carries the denial field this harness itself reads for
/// this event family; another harness's shape never counts. `policy_action`
/// counts only for Cursor, whose bridge renders Cursor's `permission` key
/// from it (`cursor_hook_bridge_response::rendered`).
fn natively_refuses(harness: &str, family: &str, body: &Value) -> bool {
    let output = &body["hookSpecificOutput"];
    match (family, harness) {
        (_, "cursor") => matches!(
            body["policy_action"].as_str(),
            Some("block" | "sandbox-required")
        ),
        ("pre_tool" | "permission", "grok" | "omp" | "pi" | "openclaw") => {
            body["decision"] == "deny"
        }
        ("pre_tool" | "permission", "hermes") => body["decision"] == "block",
        ("pre_tool", _) => output["permissionDecision"] == "deny",
        ("permission" | "prompt", "copilot") => body["behavior"] == "deny",
        ("permission", _) => output["decision"]["behavior"] == "deny",
        ("prompt", _) => body["decision"] == "block",
        _ => false,
    }
}

/// Whether a reply lets the action through in any harness's envelope shape.
fn permits(body: &Value) -> bool {
    let output = &body["hookSpecificOutput"];
    body["continue"] == true
        || body["policy_action"] == "allow"
        || matches!(body["decision"].as_str(), Some("allow" | "approve"))
        || body["behavior"] == "allow"
        || output["permissionDecision"] == "allow"
        || output["decision"]["behavior"] == "allow"
}

/// Every blocking or approval event the contract declares for a harness that
/// reaches Guard through a hook, extension or plugin, plus every screening
/// event declared to fail closed.
fn enforced_events() -> Vec<(String, String)> {
    let contract: Value = serde_json::from_str(HARNESS_CONTRACTS).unwrap();
    let mut events = Vec::new();
    for row in contract["contracts"].as_array().unwrap() {
        let harness = row["harness"].as_str().unwrap();
        for event in row["capability_events"].as_array().into_iter().flatten() {
            let mode = event["mode"].as_str().unwrap_or_default();
            let fails_closed = event["failure_behavior"] == "fail_closed";
            if matches!(mode, "blocking" | "approval") || (mode == "screening" && fails_closed) {
                events.push((
                    harness.to_owned(),
                    event["event"].as_str().unwrap().to_owned(),
                ));
            }
        }
    }
    events
}

#[test]
fn no_adapter_turns_a_missing_native_decision_into_an_allow() {
    let events = enforced_events();
    // Guards against the contract shape drifting so the loop checks nothing.
    assert!(events.len() >= 15, "only {} enforced events", events.len());
    let harnesses: std::collections::BTreeSet<&str> =
        events.iter().map(|(harness, _)| harness.as_str()).collect();
    for expected in ["claude-code", "codex", "cursor", "grok", "pi", "omp"] {
        assert!(
            harnesses.contains(expected),
            "{expected} declares no enforced event"
        );
    }
    let envelopes: Value = serde_json::from_str(ENVELOPES).unwrap();
    for (harness, event) in &events {
        let family = event_kind(&envelopes, event);
        for code in NO_DECISION_CODES {
            let body = fail_safe(harness, event, WORKER_UNAVAILABLE_REASON, code);
            let context = format!("{harness} {event} {code}: {body}");
            assert!(
                natively_refuses(harness, &family, &body),
                "no native refusal for {context}"
            );
            assert!(!permits(&body), "an allow for {context}");
        }
    }
}

#[test]
fn every_enforced_event_name_resolves_to_a_refusing_envelope_family() {
    let contract: Value = serde_json::from_str(ENVELOPES).unwrap();
    for (harness, event) in enforced_events() {
        let kind = event_kind(&contract, &event);
        assert!(
            matches!(kind.as_str(), "pre_tool" | "permission" | "prompt"),
            "{harness} {event} falls into the {kind} family, which carries no verdict"
        );
    }
}

/// Where the host itself lets an action through when the hook crashes or
/// times out, Guard's refusing envelope cannot help. Such a row must say so
/// publicly and must never claim live block proof; adapters with no concrete
/// hook contract (Kimi, ZCode) must stay unsupported.
#[test]
fn a_host_that_fails_open_is_disclosed_and_never_claims_live_block_proof() {
    let contract: Value = serde_json::from_str(HARNESS_CONTRACTS).unwrap();
    let mut fail_open = 0;
    for row in contract["contracts"].as_array().unwrap() {
        let harness = row["harness"].as_str().unwrap();
        for event in row["capability_events"].as_array().into_iter().flatten() {
            let name = event["event"].as_str().unwrap();
            let state = event["claim"]["state"].as_str().unwrap();
            let failure = event["failure_behavior"].as_str().unwrap();
            if failure == "fail_open" {
                fail_open += 1;
                let disclosure = format!(
                    "{} {}",
                    event["error_behavior"].as_str().unwrap_or_default(),
                    event["known_blind_spots"]
                )
                .to_lowercase();
                assert!(
                    discloses_fail_open(&disclosure),
                    "{harness} {name} fails open without saying so"
                );
                assert_ne!(
                    state, "live_block_proven",
                    "{harness} {name} fails open yet claims live block proof"
                );
            }
            if matches!(harness, "kimi" | "zcode") {
                assert!(
                    matches!(state, "unsupported" | "observe_only") && failure != "fail_closed",
                    "{harness} {name} claims enforcement without a host hook contract"
                );
            }
        }
    }
    assert!(fail_open >= 1, "the contract lost its fail-open rows");
}

/// Whether public text tells the user the host lets the action continue when
/// the hook fails. A sentence that only mentions failures does not count.
fn discloses_fail_open(text: &str) -> bool {
    let text = text.to_lowercase();
    ["fails open", "fail open", "fail-open", "continue"]
        .iter()
        .any(|phrase| text.contains(phrase))
}

#[test]
fn fail_open_disclosure_must_say_the_host_continues() {
    assert!(!discloses_fail_open("Hook failures block the action."));
    assert!(discloses_fail_open(
        "Auto-wake and subagent prompts are passive; Grok fails open if the hook process crashes or times out."
    ));
    assert!(discloses_fail_open(
        "Prompt hook failures return a bounded response that lets the prompt continue."
    ));
}

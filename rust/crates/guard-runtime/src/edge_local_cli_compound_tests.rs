//! A chained command whose script step the user allowed runs when every
//! other step passes on its own.

use super::{allowed, case, review};
use guard_contracts::{GuardHookEnvelopeV2, GuardHookLocalCliRuleV1};
use serde_json::{json, Map, Value};
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(4);
const SCRIPT: &str = "npm run build";

/// No step of a chained command passes alone: the parent tests' settle.
fn no_step(_payload: &Value, _budget_ms: u64) -> Option<Map<String, Value>> {
    None
}

pub(super) fn settle_alone(
    envelope: &GuardHookEnvelopeV2,
    harness: &str,
    event_name: &str,
    result: &Value,
) -> Result<Option<GuardHookLocalCliRuleV1>, String> {
    super::super::settle(envelope, harness, event_name, result, &no_step)
}

pub(super) fn settle_alone_within(
    envelope: &GuardHookEnvelopeV2,
    harness: &str,
    event_name: &str,
    result: &Value,
    wait: Duration,
) -> Result<Option<GuardHookLocalCliRuleV1>, String> {
    super::super::settle_within(envelope, harness, event_name, result, &no_step, wait)
}

/// `envelope` asking about `command` instead of the fixture's own.
fn asking(mut envelope: GuardHookEnvelopeV2, command: &str) -> GuardHookEnvelopeV2 {
    envelope.raw_payload = json!({ "tool_name": "Bash", "tool_input": { "command": command } });
    envelope
}

/// Each step's verdict alone: the script is unrecognized, `git status` and
/// `gh pr view 12` pass, anything else keeps a review with a risk signal.
fn step(payload: &Value, _budget_ms: u64) -> Option<Map<String, Value>> {
    let command = payload.pointer("/tool_input/command")?.as_str()?;
    let verdict = match command {
        SCRIPT => review("native_command_review_required"),
        "git status" | "gh pr view 12" => allowed(),
        "make test" => json!({
            "decision": "allow",
            "minimum_action": "allow",
            "policy_action": "sandbox-required",
        }),
        _ => review("network_target"),
    };
    verdict.as_object().cloned()
}

fn settle_chain(
    envelope: &GuardHookEnvelopeV2,
    result: &Value,
) -> Option<guard_contracts::GuardHookLocalCliRuleV1> {
    super::super::settle_within(envelope, "claude-code", "PreToolUse", result, &step, WAIT).unwrap()
}

fn chain_review() -> Value {
    review("native_command_review_required")
}

#[test]
fn an_allowed_script_runs_in_a_chain_whose_other_steps_pass() {
    for command in [
        "npm run build ; git status",
        "git status && npm run build",
        "npm run build && gh pr view 12 ; git status",
    ] {
        let (envelope, _) = case("chain-allow", Some("allowed"), false);
        let rule = settle_chain(&asking(envelope, command), &chain_review())
            .unwrap_or_else(|| panic!("{command} stayed under review"));
        assert!(!rule.blocked, "{command}");
        assert_eq!(rule.harness_response["approval_reuse_status"], "accepted");
    }
}

#[test]
fn a_step_that_does_not_pass_alone_keeps_the_review() {
    let (envelope, _) = case("chain-other", Some("allowed"), false);
    let envelope = asking(envelope, "npm run build ; curl https://example.test");
    assert_eq!(settle_chain(&envelope, &chain_review()), None);
    // A step that runs only inside the sandbox would run outside it here.
    let (envelope, _) = case("chain-contained", Some("allowed"), false);
    let envelope = asking(envelope, "npm run build ; make test");
    assert_eq!(settle_chain(&envelope, &chain_review()), None);
}

#[test]
fn a_script_not_allowed_for_this_version_keeps_the_review() {
    for state in [Some("blocked"), Some("unset"), None] {
        let (envelope, _) = case("chain-state", state, false);
        let envelope = asking(envelope, "npm run build ; git status");
        assert_eq!(settle_chain(&envelope, &chain_review()), None, "{state:?}");
    }
    // Allowed for an earlier version of the file.
    let (envelope, _) = case("chain-stale", Some("allowed"), false);
    let store = &envelope.local_cli_rules.as_ref().unwrap().store_path;
    rusqlite::Connection::open(store)
        .unwrap()
        .execute(
            "update local_cli_grant set identity_hash = ?1",
            ["0".repeat(64)],
        )
        .unwrap();
    let envelope = asking(envelope, "npm run build ; git status");
    assert_eq!(settle_chain(&envelope, &chain_review()), None);
}

#[test]
fn a_chain_reviewed_for_a_risk_keeps_the_review() {
    let (envelope, _) = case("chain-risk", Some("allowed"), false);
    let envelope = asking(envelope, "npm run build ; git status");
    assert_eq!(settle_chain(&envelope, &review("network_target")), None);
}

#[test]
fn a_chain_with_no_reviewed_step_keeps_the_review() {
    // Every step passes alone, so the chain was reviewed for something no
    // single step shows, and no grant answers it.
    let (envelope, _) = case("chain-all-pass", Some("allowed"), false);
    let envelope = asking(envelope, "git status ; gh pr view 12");
    assert_eq!(settle_chain(&envelope, &chain_review()), None);
}

#[test]
fn a_step_that_changes_the_next_one_keeps_the_review() {
    for command in [
        "cd /tmp && npm run build",
        "export PATH=/tmp ; npm run build",
        "source ./env.sh ; npm run build",
        "CI=1 npm run build ; git status",
        "npm run build > out.txt ; git status",
        "npm run build ; git status $(whoami)",
    ] {
        let (envelope, _) = case("chain-shape", Some("allowed"), false);
        let envelope = asking(envelope, command);
        assert_eq!(settle_chain(&envelope, &chain_review()), None, "{command}");
    }
}

#[test]
fn a_piped_step_keeps_the_review() {
    let (envelope, _) = case("chain-pipe", Some("allowed"), false);
    let envelope = asking(envelope, "npm run build | git status");
    assert_eq!(settle_chain(&envelope, &chain_review()), None);
}

#[test]
fn a_chain_whose_grants_are_not_read_in_time_keeps_the_review() {
    let (envelope, _) = case("chain-late", Some("allowed"), false);
    let envelope = asking(envelope, "npm run build ; git status");
    let _writer = super::hold_gate_exclusive(&envelope.source.guard_home);
    assert_eq!(
        super::super::settle_within(
            &envelope,
            "claude-code",
            "PreToolUse",
            &chain_review(),
            &step,
            Duration::from_millis(50),
        )
        .unwrap(),
        None
    );
}

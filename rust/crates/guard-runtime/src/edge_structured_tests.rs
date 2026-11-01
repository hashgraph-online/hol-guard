use crate::edge::evaluate_envelope_with_snapshot;
use crate::edge::tests::envelope;
use crate::policy_enforcement::tests::{policy, snapshot};
use crate::policy_enforcement::AdmittedPolicySnapshot;
use guard_contracts::GuardHookEnvelopeV2;
use serde_json::json;
use serde_json::Value;

const VECTORS: &str = include_str!("../testdata/hook_direct_pi/pi_vectors.json");

/// The managed-policy view the daemon binds for a recorded policy.
fn view(recorded: &str) -> Value {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    vectors["structured_output"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["policy"] == recorded)
        .map(|vector| vector["view"].clone())
        .unwrap()
}

/// A locked policy that covers `omp` and `pi` and declares `note` an ordinary
/// string next to the protected `email`, so `{"note":"ordinary"}` is provably
/// clean.
fn locked_view_declaring_note() -> Value {
    let mut locked = view("active_locked_both");
    let covered = &mut locked["managed_policy"]["settings"]["data_control"]["structured_output"];
    covered["schema"]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"path": ["note"], "role": "ordinary", "valueType": "string"}));
    locked
}

/// A watched tool result the allowing policy lets through unchanged, so the
/// verdict is an allow whatever the view says.
fn notes(content: Option<&str>) -> Value {
    let mut payload = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "context_notes",
        "tool_input": {"text": "notes"},
        "tool_response": "Noted."
    });
    if let Some(content) = content {
        payload["structured_output_json"] = json!(content);
    }
    payload
}

/// The edge's answer for `request` under an allowing policy, as the daemon
/// decodes it.
fn answer(request: GuardHookEnvelopeV2) -> Value {
    let admitted = AdmittedPolicySnapshot::new(snapshot(policy("allow"))).unwrap();
    let guard_home = std::path::PathBuf::from(&request.source.guard_home);
    let bytes = evaluate_envelope_with_snapshot(request, &admitted);
    std::fs::remove_dir_all(guard_home).expect("remove edge generation fixture");
    serde_json::from_slice(&bytes.unwrap()).unwrap()
}

/// A watched `PostToolUse` from `harness` carrying `view`.
fn post_tool_use(harness: &str, payload: Value, view: Option<Value>) -> GuardHookEnvelopeV2 {
    let mut request = envelope("PostToolUse", payload);
    request.harness = harness.to_owned();
    request.recording_only = true;
    request.deadline_budget_ms = Some(9_000);
    request.structured_output_config = view;
    request
}

fn mediation(answered: &Value) -> &Value {
    &answered["harness_response"]["structured_content_mediation"]
}

#[test]
fn the_edge_answers_the_mediation_the_daemon_asked_for() {
    for harness in ["pi", "omp"] {
        let clean = answer(post_tool_use(
            harness,
            notes(Some(r#"{"note":"ordinary"}"#)),
            Some(locked_view_declaring_note()),
        ));
        assert_eq!(clean["result"]["decision"], "allow", "{harness}: {clean}");
        let disposition = mediation(&clean);
        assert_eq!(
            disposition["schema"], "guard-structured-content-mediation.v1",
            "{harness}: {clean}"
        );
        assert_eq!(disposition["action"], "forward", "{harness}: {clean}");
        assert_eq!(disposition["reason_code"], "structured_clean_forward");
        assert_eq!(
            disposition["content_sha256"],
            guard_hook_core::sha256_text(r#"{"note":"ordinary"}"#)
        );
        assert_eq!(
            disposition["native_decision_id"], clean["receipt"]["decision_id"],
            "{harness}"
        );
    }
}

#[test]
fn a_covered_policy_withholds_content_it_cannot_prove_clean() {
    let declared = locked_view_declaring_note();
    for (label, content, reason) in [
        ("absent", None, "structured_content_unproved"),
        (
            "not canonical",
            Some(r#"{ "note": "ordinary" }"#),
            "structured_content_unproved",
        ),
    ] {
        let answered = answer(post_tool_use("omp", notes(content), Some(declared.clone())));
        let disposition = mediation(&answered);
        assert_eq!(disposition["action"], "withhold", "{label}: {answered}");
        assert_eq!(disposition["reason_code"], reason, "{label}: {answered}");
        assert_eq!(disposition["content_sha256"], Value::Null, "{label}");
        assert_eq!(
            disposition["native_decision_id"], answered["receipt"]["decision_id"],
            "{label}"
        );
    }
    // A protected field the policy declares is never forwarded.
    let answered = answer(post_tool_use(
        "omp",
        notes(Some(r#"{"email":"someone@example.com"}"#)),
        Some(declared),
    ));
    let disposition = mediation(&answered);
    assert_eq!(disposition["action"], "withhold", "{answered}");
    assert!(disposition["reason_code"]
        .as_str()
        .is_some_and(|reason| reason.starts_with("structured_")));
    assert_eq!(disposition["content_sha256"], Value::Null);
}

#[test]
fn a_view_the_edge_cannot_resolve_withholds_as_an_unavailable_authority() {
    // `{}` is what the daemon sends when it could not read its config, and
    // an object that is not the resolution's shape resolves the same way.
    for unresolved in [json!({}), json!({"managed_policy_status": "active"})] {
        let answered = answer(post_tool_use(
            "omp",
            notes(Some(r#"{"note":"ordinary"}"#)),
            Some(unresolved),
        ));
        let disposition = mediation(&answered);
        assert_eq!(disposition["action"], "withhold", "{answered}");
        assert_eq!(
            disposition["reason_code"], "structured_managed_authority_unavailable",
            "{answered}"
        );
        assert_eq!(
            disposition["native_decision_id"], answered["receipt"]["decision_id"],
            "{answered}"
        );
    }
}

#[test]
fn a_managed_policy_that_cannot_be_trusted_withholds_naming_why() {
    let mut malformed = locked_view_declaring_note();
    malformed["managed_policy"]["settings"]["data_control"]["structured_output"]["onMatch"] =
        json!("allow");
    for (label, unresolved, reason) in [
        (
            "revoked",
            view("revoked"),
            "structured_managed_authority_revoked",
        ),
        (
            "tampered",
            view("tampered"),
            "structured_managed_authority_unavailable",
        ),
        (
            "reserved without its policy",
            view("active_locked_without_policy"),
            "structured_managed_policy_missing",
        ),
        (
            "hash mismatch",
            view("active_locked_hash_mismatch"),
            "structured_managed_policy_invalid",
        ),
        (
            "not withholding",
            malformed,
            "structured_managed_policy_invalid",
        ),
    ] {
        let answered = answer(post_tool_use(
            "pi",
            notes(Some(r#"{"note":"ordinary"}"#)),
            Some(unresolved),
        ));
        let disposition = mediation(&answered);
        assert_eq!(disposition["action"], "withhold", "{label}: {answered}");
        assert_eq!(disposition["reason_code"], reason, "{label}: {answered}");
        assert_eq!(disposition["content_sha256"], Value::Null, "{label}");
    }
}

#[test]
fn a_policy_that_requires_no_mediation_adds_nothing() {
    for recorded in ["absent", "no_status", "active_without_setting"] {
        let answered = answer(post_tool_use(
            "omp",
            notes(Some(r#"{"note":"ordinary"}"#)),
            Some(view(recorded)),
        ));
        assert_eq!(mediation(&answered), &Value::Null, "{recorded}: {answered}");
    }
}

#[test]
fn an_envelope_without_a_view_keeps_the_response_the_edge_rendered() {
    let answered = answer(post_tool_use("omp", notes(Some("{}")), None));
    assert_eq!(answered["result"]["decision"], "allow", "{answered}");
    assert_eq!(mediation(&answered), &Value::Null, "{answered}");
}

#[test]
fn only_an_allowed_pi_post_tool_use_is_mediated() {
    let locked = locked_view_declaring_note();
    // Another harness answers the same hook without mediation.
    let other = answer(post_tool_use(
        "claude",
        notes(Some(r#"{"note":"ordinary"}"#)),
        Some(locked.clone()),
    ));
    assert_eq!(mediation(&other), &Value::Null, "{other}");
    // So does another event of the same harness.
    let mut before = envelope(
        "PreToolUse",
        json!({"tool_name": "Bash", "tool_input": {"command": "pwd"}}),
    );
    before.harness = "omp".to_owned();
    before.structured_output_config = Some(locked.clone());
    let before = answer(before);
    assert_eq!(mediation(&before), &Value::Null, "{before}");
    // A native denial leaves no model-visible content to project.
    let token = format!("{}{}", ["gh", "p_"].concat(), "c".repeat(30));
    let denied = answer(post_tool_use(
        "omp",
        json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "bash",
            "tool_input": {"command": "cat config"},
            "tool_response": token,
            "structured_output_json": r#"{"note":"ordinary"}"#
        }),
        Some(locked),
    ));
    assert_eq!(denied["result"]["decision"], "deny", "{denied}");
    assert_eq!(mediation(&denied), &Value::Null, "{denied}");
}

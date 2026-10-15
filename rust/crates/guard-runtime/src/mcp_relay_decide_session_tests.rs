use super::super::saved::tests::{binding as store_binding, decide, guard_home, sync_state};
use super::*;
use crate::policy_store::policy_store_direct_lane::DirectLaneBinding;
use serde_json::{json, Value};

fn view(mode: &str, redaction: Option<&str>) -> Value {
    let mut harness = json!({"config": {"mode": mode}, "hash_config": {}});
    if let Some(level) = redaction {
        harness["receipt_redaction_level"] = json!(level);
    }
    json!({
        "schema": "guard-mcp-relay-view.v1",
        "harnesses": {"codex": harness},
        "extension_layers": [],
    })
}

/// A binding the resident decides every call of: an enforcing view with a
/// bound redaction level, under `safe-alternative`.
fn decidable(base: DirectLaneBinding) -> DirectLaneBinding {
    let mut binding = base;
    binding.mcp_relay = Some(view("enforce", Some("full")));
    binding.review.blocked_request_mode = Some("safe-alternative".to_owned());
    binding
}

fn no_store_home(tag: &str) -> String {
    let home = std::env::temp_dir().join(format!("mcp-relay-session-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    home.to_str().unwrap().to_owned()
}

#[test]
fn a_safe_alternative_session_without_saved_rows_is_decidable() {
    let home = no_store_home("none");
    let binding = decidable(DirectLaneBinding::empty_for_tests());
    assert_eq!(session_decidable(&binding, &home, "codex"), Ok(()));
    let (home, _connection) = guard_home("session-empty");
    let binding = decidable(store_binding());
    assert_eq!(
        session_decidable(&binding, home.to_str().unwrap(), "codex"),
        Ok(())
    );
}

#[test]
fn an_observing_safe_alternative_session_is_decidable() {
    let home = no_store_home("observe");
    let mut observe = decidable(DirectLaneBinding::empty_for_tests());
    observe.mcp_relay = Some(view("observe", Some("full")));
    assert_eq!(session_decidable(&observe, &home, "codex"), Ok(()));
}

#[test]
fn a_prompting_config_hands_the_session_off() {
    let home = no_store_home("config");
    for config_mode in ["enforce", "observe"] {
        for mode in [Some("ask"), None] {
            let mut prompting = decidable(DirectLaneBinding::empty_for_tests());
            prompting.mcp_relay = Some(view(config_mode, Some("full")));
            prompting.review.blocked_request_mode = mode.map(str::to_owned);
            assert_eq!(
                session_decidable(&prompting, &home, "codex"),
                Err("mcp_relay_session_review_mode"),
                "{config_mode} {mode:?}"
            );
        }
    }
    let mut unbound = decidable(DirectLaneBinding::empty_for_tests());
    unbound.mcp_relay = Some(view("enforce", None));
    assert_eq!(
        session_decidable(&unbound, &home, "codex"),
        Err("mcp_relay_session_redaction_unbound")
    );
}

#[test]
fn an_unbound_view_or_harness_hands_the_session_off() {
    let home = no_store_home("view");
    let binding = decidable(DirectLaneBinding::empty_for_tests());
    assert_eq!(
        session_decidable(&binding, &home, "cursor"),
        Err("mcp_relay_harness_unbound")
    );
    let mut missing = binding;
    missing.mcp_relay = None;
    assert_eq!(
        session_decidable(&missing, &home, "codex"),
        Err("mcp_relay_view_missing")
    );
}

#[test]
fn a_store_with_remote_policy_hands_the_session_off() {
    let (home, connection) = guard_home("session-bundle");
    sync_state(&connection, "policy_bundle", "{}");
    decide(&connection, "artifact", "block", None, "policy-bundle");
    let binding = decidable(store_binding());
    assert_eq!(
        session_decidable(&binding, home.to_str().unwrap(), "codex"),
        Err("mcp_relay_saved_remote_policy")
    );
}

#[test]
fn a_store_whose_integrity_the_daemon_did_not_publish_hands_the_session_off() {
    let (home, connection) = guard_home("session-unpublished");
    decide(&connection, "artifact", "block", None, "approval-gate");
    // No integrity key or state published for the saved block.
    let binding = decidable(DirectLaneBinding::empty_for_tests());
    assert_eq!(
        session_decidable(&binding, home.to_str().unwrap(), "codex"),
        Err("mcp_relay_saved_policy_unverifiable")
    );
}

use super::super::saved::tests::{binding as store_binding, decide, guard_home, sync_state};
use super::*;
use crate::policy_store::policy_store_direct_lane::DirectLaneBinding;
use serde_json::{json, Value};

fn view(mode: &str, redaction: Option<&str>) -> Value {
    view_for("codex", mode, redaction)
}

fn view_for(harness: &str, mode: &str, redaction: Option<&str>) -> Value {
    let mut bound = json!({"config": {"mode": mode}, "hash_config": {}});
    if let Some(level) = redaction {
        bound["receipt_redaction_level"] = json!(level);
    }
    json!({
        "schema": "guard-mcp-relay-view.v1",
        "harnesses": {harness: bound},
        "extension_layers": [],
    })
}

/// An `ask` binding whose approval request the resident writes.
fn asking(mode: &str) -> DirectLaneBinding {
    let mut binding = decidable(DirectLaneBinding::empty_for_tests());
    binding.mcp_relay = Some(view_for("opencode", mode, Some("full")));
    binding.review.blocked_request_mode = Some("ask".to_owned());
    binding.review.approval_center_origin = Some("http://127.0.0.1:8787".to_owned());
    binding.review.review_oauth_source = Some("device".to_owned());
    binding
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
fn an_asking_session_is_decidable_for_every_relay_harness() {
    let home = no_store_home("ask");
    assert_eq!(
        session_decidable(&asking("enforce"), &home, "opencode"),
        Ok(())
    );
    // Opencode answers the native prompt from the decision; the others
    // answer `False` and take the inline elicitation before this queue.
    for harness in ["codex", "copilot", "cursor"] {
        let mut binding = asking("enforce");
        binding.mcp_relay = Some(view_for(harness, "enforce", Some("full")));
        assert_eq!(
            session_decidable(&binding, &home, harness),
            Ok(()),
            "{harness}"
        );
    }
}

#[test]
fn an_asking_session_hands_off_what_the_resident_cannot_queue() {
    let home = no_store_home("ask-off");
    // The proxy prompts before it observes a call.
    assert_eq!(
        session_decidable(&asking("observe"), &home, "opencode"),
        Err("mcp_relay_session_review_mode")
    );
    // The center the request links and the source its row is written with.
    let mut no_center = asking("enforce");
    no_center.review.approval_center_origin = None;
    assert_eq!(
        session_decidable(&no_center, &home, "opencode"),
        Err("mcp_relay_session_review_mode")
    );
    let mut no_oauth = asking("enforce");
    no_oauth.review.review_oauth_source = None;
    assert_eq!(
        session_decidable(&no_oauth, &home, "opencode"),
        Err("mcp_relay_session_review_mode")
    );
    let mut unbound = asking("enforce");
    unbound.mcp_relay = Some(view_for("opencode", "enforce", None));
    assert_eq!(
        session_decidable(&unbound, &home, "opencode"),
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
fn a_cached_policy_bundle_hands_off_the_harnesses_its_rows_bind() {
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
fn a_bundle_bound_to_another_harness_leaves_the_session_native() {
    // No lookup of this harness reads such a row, so the identities the proxy
    // would keep or drop it with change nothing here.
    let (home, connection) = guard_home("session-bundle-elsewhere");
    sync_state(&connection, "policy_bundle", "{}");
    decide(&connection, "artifact", "block", None, "policy-bundle");
    connection
        .execute(
            "update policy_decisions set harness = 'opencode' where source = 'policy-bundle'",
            [],
        )
        .unwrap();
    let binding = decidable(store_binding());
    assert_eq!(
        session_decidable(&binding, home.to_str().unwrap(), "codex"),
        Ok(())
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

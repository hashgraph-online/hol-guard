use super::{exact_command_block, settle, settle_within};
use crate::context_digest_package_scripts::package_json_scripts;
use guard_contracts::{
    GuardHookEnvelopeV2, GuardHookLocalCliRulesV1, GuardHookSourceMetadataV2,
    GUARD_HOOK_ENVELOPE_V2_SCHEMA,
};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::time::Duration;

const SCHEMA: &str = "
create table local_cli_grant (
    cli_id text primary key,
    identity_hash text not null,
    state text not null
);
create table local_cli_command_grant (
    cli_id text not null,
    command_id text not null,
    state text not null
);
";

fn scratch(label: &str) -> String {
    let root = std::env::temp_dir().join(format!("edge-local-cli-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    fs::canonicalize(root).unwrap().to_str().unwrap().to_owned()
}

/// A workspace whose package scripts are a local CLI, and a Guard home whose
/// store holds the grant `state` for that CLI, or no grant row when `None`.
/// Returns the envelope that carries the daemon's rules and the CLI's name.
fn case(label: &str, state: Option<&str>, recording_only: bool) -> (GuardHookEnvelopeV2, String) {
    let workspace = scratch(&format!("{label}-work"));
    let guard_home = scratch(&format!("{label}-home"));
    fs::write(
        Path::new(&workspace).join("package.json"),
        br#"{"name": "demo", "scripts": {"build": "tsc"}}"#,
    )
    .unwrap();
    let identity = package_json_scripts("npm run build", &workspace, &workspace)
        .unwrap()
        .unwrap()
        .identity
        .unwrap();
    let store_path = Path::new(&guard_home).join("guard.db");
    let connection = rusqlite::Connection::open(&store_path).unwrap();
    connection.execute_batch(SCHEMA).unwrap();
    if let Some(state) = state {
        connection
            .execute(
                "insert into local_cli_grant values (?1, ?2, ?3)",
                [
                    identity.cli_id.as_str(),
                    identity.identity_hash.as_str(),
                    state,
                ],
            )
            .unwrap();
    }
    let envelope = GuardHookEnvelopeV2 {
        schema: GUARD_HOOK_ENVELOPE_V2_SCHEMA.to_owned(),
        request_id: Some("edge-local-cli".to_owned()),
        harness: "claude-code".to_owned(),
        event: "PreToolUse".to_owned(),
        raw_payload: json!({ "tool_name": "Bash", "tool_input": { "command": "npm run build" } }),
        deadline_budget_ms: Some(100),
        policy_generation: 1,
        policy_snapshot: Value::Null,
        source: GuardHookSourceMetadataV2 {
            cwd: Some(workspace.clone()),
            home_dir: workspace,
            guard_home,
            source_ref_external_allowed: false,
            execution_environment: None,
        },
        recording_only,
        local_cli_rules: Some(GuardHookLocalCliRulesV1 {
            store_path: store_path.to_str().unwrap().to_owned(),
            user_home: "/daemon/home".to_owned(),
            env: [("PATH".to_owned(), "/daemon/bin".to_owned())]
                .into_iter()
                .collect(),
            exact_action_control_digest: None,
        }),
        observe_local_cli: false,
        record_receipt: false,
        structured_output_config: None,
        containment_sink: None,
    };
    (envelope, identity.name)
}

fn allowed() -> Value {
    json!({ "decision": "allow", "minimum_action": "allow", "policy_action": "allow" })
}

fn review(reason_code: &str) -> Value {
    json!({
        "decision": "review",
        "minimum_action": "review",
        "policy_action": "review",
        "reason_code": reason_code,
        "action": { "action_type": "shell" },
    })
}

/// The rendered response as text, whatever shape the harness answers in.
fn reason(response: &Value) -> String {
    response.to_string()
}

#[test]
fn a_custom_block_replaces_an_allowed_answer() {
    let (envelope, name) = case("allow-block", Some("blocked"), false);
    let rule = settle(&envelope, "claude-code", "PreToolUse", &allowed())
        .unwrap()
        .unwrap();
    assert!(rule.blocked);
    assert_eq!(rule.harness_response["approval_reuse_status"], "blocked");
    assert!(reason(&rule.harness_response).contains(&name));
    // Watch records the block without stopping the call.
    let (watched, _) = case("allow-block-watch", Some("blocked"), true);
    let rule = settle(&watched, "claude-code", "PreToolUse", &allowed())
        .unwrap()
        .unwrap();
    assert!(rule.blocked);
    assert!(rule.harness_response.get("approval_reuse_status").is_none());
}

#[test]
fn an_unreadable_grant_blocks_an_allowed_call_as_unverified() {
    let (envelope, _) = case("allow-unverified", Some("blocked"), false);
    // A store the edge cannot read still counts as holding block rules, and
    // the grant behind it cannot be checked.
    fs::write(
        &envelope.local_cli_rules.as_ref().unwrap().store_path,
        b"not a sqlite store",
    )
    .unwrap();
    let rule = settle(&envelope, "claude-code", "PreToolUse", &allowed())
        .unwrap()
        .unwrap();
    assert!(rule.blocked);
    assert!(reason(&rule.harness_response).contains("could not check"));
}

/// An exclusive hold on the home's storage gate, as a writer takes it, so a
/// check that needs the shared hold waits behind it.
fn hold_gate_exclusive(guard_home: &str) -> fs::File {
    let gate = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(Path::new(guard_home).join(crate::hook_evidence_store_gate::STORAGE_GATE_FILE_NAME))
        .unwrap();
    fs2::FileExt::lock_exclusive(&gate).unwrap();
    gate
}

#[test]
fn a_rule_not_read_in_time_leaves_a_review_standing() {
    let (envelope, _) = case("review-late", Some("blocked"), false);
    let _writer = hold_gate_exclusive(&envelope.source.guard_home);
    assert_eq!(
        settle_within(
            &envelope,
            "claude-code",
            "PreToolUse",
            &review("network_target"),
            Duration::from_millis(50),
        ),
        Ok(None)
    );
}

#[test]
fn a_rule_not_read_in_time_blocks_an_allowed_call_as_unverified() {
    let (envelope, _) = case("allow-late", Some("blocked"), false);
    let _writer = hold_gate_exclusive(&envelope.source.guard_home);
    let rule = settle_within(
        &envelope,
        "claude-code",
        "PreToolUse",
        &allowed(),
        Duration::from_millis(50),
    )
    .unwrap()
    .unwrap();
    assert!(rule.blocked);
    assert!(reason(&rule.harness_response).contains("could not check"));
}

#[test]
fn without_a_block_rule_an_allowed_call_reads_nothing() {
    let (envelope, _) = case("allow-only", Some("allowed"), false);
    assert_eq!(
        settle(&envelope, "claude-code", "PreToolUse", &allowed()),
        Ok(None)
    );
}

#[test]
fn without_a_grant_a_review_reads_nothing() {
    let (envelope, _) = case("review-ungranted", None, false);
    assert_eq!(
        settle(
            &envelope,
            "claude-code",
            "PreToolUse",
            &review("native_command_review_required")
        ),
        Ok(None)
    );
}

#[test]
fn a_custom_rule_settles_a_review() {
    let (envelope, name) = case("review-block", Some("blocked"), false);
    let rule = settle(
        &envelope,
        "claude-code",
        "PreToolUse",
        &review("network_target"),
    )
    .unwrap()
    .unwrap();
    assert!(rule.blocked);
    assert!(reason(&rule.harness_response).contains(&name));

    let (envelope, _) = case("review-allow", Some("allowed"), false);
    let rule = settle(
        &envelope,
        "claude-code",
        "PreToolUse",
        &review("native_command_review_required"),
    )
    .unwrap()
    .unwrap();
    assert!(!rule.blocked);
    assert_eq!(rule.harness_response["approval_reuse_status"], "accepted");
    // A review with its own risk signal stands.
    assert_eq!(
        settle(
            &envelope,
            "claude-code",
            "PreToolUse",
            &review("network_target")
        ),
        Ok(None)
    );
    // Watch never asks, so it reads no rule for a review.
    let (watched, _) = case("review-watch", Some("blocked"), true);
    assert_eq!(
        settle(
            &watched,
            "claude-code",
            "PreToolUse",
            &review("network_target")
        ),
        Ok(None)
    );
}

#[test]
fn only_a_daemon_that_sends_its_rules_gets_an_answer() {
    let (mut envelope, _) = case("no-rules", Some("blocked"), false);
    assert_eq!(
        settle(&envelope, "claude-code", "UserPromptSubmit", &allowed()),
        Ok(None)
    );
    envelope.local_cli_rules = None;
    assert_eq!(
        settle(&envelope, "claude-code", "PreToolUse", &allowed()),
        Ok(None)
    );
}

#[test]
fn a_custom_allow_never_settles_a_block() {
    let (envelope, _) = case("block-allow", Some("allowed"), false);
    let blocked =
        json!({ "decision": "deny", "minimum_action": "block", "policy_action": "block" });
    assert_eq!(
        settle(&envelope, "claude-code", "PreToolUse", &blocked),
        Ok(None)
    );
}

/// `result` carrying an edge field too large to render beside a custom rule.
fn oversized(mut result: Value) -> Value {
    result["padding"] = json!("x".repeat(64 * 1024));
    result
}

#[test]
fn a_custom_block_too_large_to_render_still_blocks() {
    let (envelope, name) = case("allow-block-large", Some("blocked"), false);
    let rule = settle(
        &envelope,
        "claude-code",
        "PreToolUse",
        &oversized(allowed()),
    )
    .unwrap()
    .unwrap();
    assert!(rule.blocked);
    assert_eq!(rule.harness_response["approval_reuse_status"], "blocked");
    assert!(reason(&rule.harness_response).contains(&name));
    assert!(!reason(&rule.harness_response).contains("xxxx"));

    let (envelope, name) = case("review-block-large", Some("blocked"), false);
    let rule = settle(
        &envelope,
        "claude-code",
        "PreToolUse",
        &oversized(review("network_target")),
    )
    .unwrap()
    .unwrap();
    assert!(rule.blocked);
    assert!(reason(&rule.harness_response).contains(&name));
}

#[test]
fn an_unverified_block_too_large_to_render_still_blocks() {
    let (envelope, _) = case("allow-unverified-large", Some("blocked"), false);
    fs::write(
        &envelope.local_cli_rules.as_ref().unwrap().store_path,
        b"not a sqlite store",
    )
    .unwrap();
    let rule = settle(
        &envelope,
        "claude-code",
        "PreToolUse",
        &oversized(allowed()),
    )
    .unwrap()
    .unwrap();
    assert!(rule.blocked);
    assert!(reason(&rule.harness_response).contains("could not check"));
}

#[test]
fn a_custom_allow_too_large_to_render_leaves_the_review_standing() {
    let (envelope, _) = case("review-allow-large", Some("allowed"), false);
    assert_eq!(
        settle(
            &envelope,
            "claude-code",
            "PreToolUse",
            &oversized(review("native_command_review_required"))
        ),
        Ok(None)
    );
}

/// Saved decisions on `npm run build`'s first exact-command id, one
/// artifact-scoped row per `(harness, action)`, in the envelope's store.
fn with_decisions(envelope: &GuardHookEnvelopeV2, rows: &[(&str, &str)]) {
    let ids = crate::memory_pattern::verdict(&crate::memory_pattern::MemoryRequest {
        command: Some("npm run build"),
        artifact_type: Some("shell_command"),
        artifact_id: None,
        artifact_name: None,
        harness: None,
    })
    .exact_artifact_ids;
    let store_path = Path::new(&envelope.source.guard_home).join("guard.db");
    let connection = rusqlite::Connection::open(store_path).unwrap();
    connection
        .execute_batch(
            "create table policy_decisions (harness text, scope text, artifact_id text, action text)",
        )
        .unwrap();
    for (harness, action) in rows {
        connection
            .execute(
                "insert into policy_decisions values (?1, 'artifact', ?2, ?3)",
                [*harness, ids[0].as_str(), *action],
            )
            .unwrap();
    }
}

#[test]
fn a_saved_block_on_the_exact_command_reaches_the_daemon() {
    let (envelope, _) = case("ecb-block", None, false);
    with_decisions(&envelope, &[("*", "block")]);

    assert_eq!(
        exact_command_block(&envelope, "claude-code", "PreToolUse"),
        Some(true)
    );
}

#[test]
fn a_command_no_saved_block_names_skips_the_daemon_lookup() {
    let (envelope, _) = case("ecb-none", None, false);
    // A store without saved decisions holds no block.
    assert_eq!(
        exact_command_block(&envelope, "claude-code", "PreToolUse"),
        Some(false)
    );
    with_decisions(&envelope, &[("*", "allow"), ("codex", "block")]);

    assert_eq!(
        exact_command_block(&envelope, "claude-code", "PreToolUse"),
        Some(false)
    );
}

#[test]
fn a_store_the_edge_cannot_read_may_hold_a_block() {
    let (envelope, _) = case("ecb-unreadable", None, false);
    fs::write(
        Path::new(&envelope.source.guard_home).join("guard.db"),
        b"not a database",
    )
    .unwrap();

    assert_eq!(
        exact_command_block(&envelope, "claude-code", "PreToolUse"),
        Some(true)
    );
}

#[test]
fn the_edge_leaves_calls_it_does_not_read_to_the_daemon() {
    let (recorded, _) = case("ecb-watch", None, true);
    with_decisions(&recorded, &[("*", "block")]);
    assert_eq!(
        exact_command_block(&recorded, "claude-code", "PreToolUse"),
        None
    );

    let (mut envelope, _) = case("ecb-scope", None, false);
    with_decisions(&envelope, &[("*", "block")]);
    assert_eq!(
        exact_command_block(&envelope, "claude-code", "PostToolUse"),
        None
    );
    envelope.raw_payload =
        json!({ "tool_name": "Read", "tool_input": { "file_path": "notes.md" } });
    assert_eq!(
        exact_command_block(&envelope, "claude-code", "PreToolUse"),
        None
    );
    envelope.raw_payload =
        json!({ "tool_name": "Bash", "tool_input": { "command": "npm run build" } });
    envelope.local_cli_rules = None;
    assert_eq!(
        exact_command_block(&envelope, "claude-code", "PreToolUse"),
        None
    );
}

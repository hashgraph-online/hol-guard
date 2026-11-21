use serde_json::json;

use super::*;

#[test]
fn a_policy_refusal_renders_recovery_from_the_publisher_facts() {
    const PREFIX: &str = "HOL Guard could not prepare the native policy safely.";
    for (last_error, streak, reason) in [
        (
            "native_client_timed_out",
            1,
            format!("{PREFIX} native_client_timed_out. This is usually temporary. Retry this action."),
        ),
        (
            "native_overloaded",
            4,
            format!("{PREFIX} The native runtime is not answering. Retry once more; if it still fails, ask the user to run `hol-guard repair` in a terminal."),
        ),
        (
            "native_policy_snapshot_ack_mismatch",
            6,
            format!("{PREFIX} native_policy_snapshot_ack_mismatch. This is usually temporary. Retry this action."),
        ),
        (
            "native_command_program_binding_mismatch",
            1,
            format!("{PREFIX} native_command_program_binding_mismatch. Guard's installed files disagree, so retrying will not clear it. Ask the user to run `hol-guard doctor`."),
        ),
        (
            "native_business_source_mutation_in_progress",
            0,
            "Guard is finishing a policy update; this action was not run. Retry after 8 seconds.".to_owned(),
        ),
        (
            "untrusted diagnostic text",
            6,
            format!("{PREFIX} This is usually temporary. Retry this action."),
        ),
    ] {
        let refused = json!({
            "reason": "Compatibility refusal.",
            "reason_code": "native_policy_not_ready",
            "policy_failure": {"last_error": last_error, "resident_failure_streak": streak},
        });
        assert_eq!(
            prepare_refusal("cursor", "PreToolUse", &refused),
            Some(fail_safe("cursor", "PreToolUse", &reason, "native_policy_not_ready")),
        );
    }
}

#[test]
fn an_older_publisher_refusal_keeps_its_preformatted_reason() {
    let refused =
        json!({"reason": "Compatibility refusal.", "reason_code": "native_policy_not_ready"});
    assert_eq!(
        prepare_refusal("cursor", "PreToolUse", &refused),
        Some(fail_safe(
            "cursor",
            "PreToolUse",
            "Compatibility refusal.",
            "native_policy_not_ready"
        )),
    );
}

#[test]
fn the_native_daemon_checks_the_path_harness_against_managed_installs() {
    let home = tempfile::tempdir().unwrap();
    let guard_home = home.path().canonicalize().unwrap();
    let store = guard_home.join("guard.db");
    let connection = rusqlite::Connection::open(&store).unwrap();
    connection
        .execute_batch(
            "create table managed_installs (harness text primary key, active integer not null);",
        )
        .unwrap();
    let config = ReadConfig::from_line(
        &serde_json::to_vec(&json!({
            "schema": super::super::HANDSHAKE_SCHEMA,
            "auth_token": "hook-admission-test",
            "guard_home": guard_home,
            "store_path": store,
            "source": "default",
            "busy_timeout_ms": 1000,
        }))
        .unwrap(),
    )
    .unwrap();
    let reads = NativeReads::new(None);
    let cursor = Hook {
        config: &config,
        reads: &reads,
        port: 4781,
        daemon_pid: 0,
        path: "/v1/hooks/cursor",
        query: "harness=codex",
        harness: "cursor",
    };
    let selected = cursor.managed_harness();
    assert_eq!(selected, "cursor");
    assert!(!cursor.unmanaged(&selected, std::time::Instant::now()));
    connection
        .execute_batch("insert into managed_installs values ('cursor', 1), ('claude-code', 0);")
        .unwrap();
    assert!(!cursor.unmanaged(&selected, std::time::Instant::now()));
    let codex = Hook {
        path: "/v1/hooks/codex",
        harness: "codex",
        ..cursor
    };
    assert!(codex.unmanaged(&codex.managed_harness(), std::time::Instant::now()));
    let claude = Hook {
        path: "/v1/hooks/claude",
        harness: "claude",
        ..codex
    };
    assert_eq!(claude.managed_harness(), "claude-code");
    assert!(claude.unmanaged(&claude.managed_harness(), std::time::Instant::now()));
    connection
        .execute_batch(
            "drop table managed_installs; create table managed_installs (broken integer);",
        )
        .unwrap();
    assert!(!claude.unmanaged(&claude.managed_harness(), std::time::Instant::now()));
}

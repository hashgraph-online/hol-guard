//! Holds for an unanswered grant or contribution decision. The decisions
//! themselves are pinned by the `local_mcp_grant_op` and
//! `contributed_mcp_decision_op` tables; these cover only the composition.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use guard_contracts::{ContributedMcpLayerV1, LocalMcpServerMaterialV1, McpExtensionInputV1};
use rusqlite::Connection;
use serde_json::Value;

use super::extension_decision;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn home() -> PathBuf {
    let home = std::env::temp_dir().join(format!(
        "hol-guard-mcp-extension-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&home).unwrap();
    home.canonicalize().unwrap()
}

/// A store whose schema marker fails verification: the grant decision has no
/// answer, while the grant probe can still see the rows.
fn unreadable_store(rows: usize) -> PathBuf {
    store_with_marker(rows, 11, "tampered")
}

fn store_with_marker(rows: usize, version: i64, checksum: &str) -> PathBuf {
    let home = home();
    let connection = Connection::open(home.join("guard.db")).unwrap();
    connection
        .execute_batch(
            "create table local_cli_grant (cli_id text);
             create table local_cli_schema_migration (singleton integer, version integer, checksum text);",
        )
        .unwrap();
    connection
        .execute(
            "insert into local_cli_schema_migration values (1, ?1, ?2)",
            rusqlite::params![version, checksum],
        )
        .unwrap();
    for index in 0..rows {
        connection
            .execute(
                "insert into local_cli_grant values (?1)",
                [index.to_string()],
            )
            .unwrap();
    }
    home
}

fn input(home: &std::path::Path) -> McpExtensionInputV1 {
    McpExtensionInputV1 {
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        harness: "codex".to_owned(),
        tool_name: "read_file".to_owned(),
        // A configured server, so the grant decision reaches the store.
        server: LocalMcpServerMaterialV1 {
            identity_hash: Some("a".repeat(64)),
            transport: Some("stdio".to_owned()),
            ..LocalMcpServerMaterialV1::default()
        },
        connection_identity_hash: None,
        tool_authority_hash: None,
        launcher_path: None,
        launcher_home: None,
        local_unavailable: false,
        server_identity: None,
        artifact_transport: None,
        server_name: None,
        contributed_tool_name: None,
        layers: Vec::new(),
        layers_unavailable: false,
    }
}

fn summary(decided: &Value) -> Option<(&str, &str)> {
    Some((
        decided.get("action")?.as_str()?,
        decided.get("source")?.as_str()?,
    ))
}

#[test]
fn an_unanswered_grant_holds_allowed_warned_and_reviewed_calls_while_rows_exist() {
    let ext = input(&unreadable_store(1));
    for action in ["allow", "warn", "review"] {
        let held = extension_decision(&ext, action);
        assert_eq!(
            summary(&held),
            Some(("review", "local-mcp-extension")),
            "{action}"
        );
    }
}

#[test]
fn an_unanswered_grant_never_loosens_a_stricter_call() {
    let ext = input(&unreadable_store(1));
    for action in ["block", "require-reapproval", "sandbox-required"] {
        assert_eq!(extension_decision(&ext, action), Value::Null, "{action}");
    }
}

#[test]
fn an_unanswered_grant_with_no_rows_and_a_verified_marker_decides_nothing() {
    let mut ext = input(&store_with_marker(
        0,
        crate::local_store_read::SUPPORTED_SCHEMA_VERSION,
        &crate::local_store_read::schema_checksum(
            crate::local_store_read::SUPPORTED_SCHEMA_VERSION,
        ),
    ));
    ext.local_unavailable = true;
    assert_eq!(extension_decision(&ext, "allow"), Value::Null);
}

#[test]
fn a_tampered_schema_marker_holds_even_with_no_rows() {
    let ext = input(&unreadable_store(0));
    let held = extension_decision(&ext, "allow");
    assert_eq!(summary(&held), Some(("review", "local-mcp-extension")));
}

#[test]
fn a_newer_schema_marker_holds_even_with_no_rows() {
    let mut ext = input(&store_with_marker(
        0,
        crate::local_store_read::SUPPORTED_SCHEMA_VERSION + 1,
        "from-the-future",
    ));
    ext.local_unavailable = true;
    let held = extension_decision(&ext, "allow");
    assert_eq!(summary(&held), Some(("review", "local-mcp-extension")));
}

#[test]
fn an_unreadable_store_counts_as_holding_grants() {
    let mut ext = input(&unreadable_store(0));
    ext.store_path = "relative/guard.db".to_owned();
    // The unanswered contribution is held first and already decisive.
    let held = extension_decision(&ext, "allow");
    assert_eq!(summary(&held), Some(("review", "catalog-mcp-extension")));
}

#[test]
fn a_caller_that_cannot_anchor_the_launcher_path_is_held_like_no_answer() {
    let mut ext = input(&unreadable_store(1));
    ext.local_unavailable = true;
    let held = extension_decision(&ext, "review");
    assert_eq!(summary(&held), Some(("review", "local-mcp-extension")));
}

#[test]
fn an_unanswered_contribution_holds_but_never_loosens() {
    // No store file: the grant decision answers "none", so only the
    // contribution can fail (its layer kind is unknown).
    let mut ext = input(&home());
    ext.layers = vec![ContributedMcpLayerV1 {
        kind: "bogus".to_owned(),
        global_lockdown: false,
        controls: Vec::new(),
    }];
    for action in ["allow", "warn", "review"] {
        let held = extension_decision(&ext, action);
        assert_eq!(
            summary(&held),
            Some(("review", "catalog-mcp-extension")),
            "{action}"
        );
    }
    assert_eq!(extension_decision(&ext, "block"), Value::Null);
    assert_eq!(extension_decision(&ext, "require-reapproval"), Value::Null);
}

#[test]
fn no_grant_and_no_contribution_decides_nothing() {
    let ext = input(&home());
    for action in ["allow", "review", "block"] {
        assert_eq!(extension_decision(&ext, action), Value::Null, "{action}");
    }
}

#[test]
fn unreadable_control_layers_hold_instead_of_deciding_from_none() {
    let mut ext = input(&unreadable_store(0));
    ext.layers_unavailable = true;
    for action in ["allow", "warn", "review"] {
        let held = extension_decision(&ext, action);
        assert_eq!(
            summary(&held),
            Some(("review", "catalog-mcp-extension")),
            "{action}"
        );
    }
    for action in ["block", "require-reapproval"] {
        assert_eq!(extension_decision(&ext, action), Value::Null, "{action}");
    }
}

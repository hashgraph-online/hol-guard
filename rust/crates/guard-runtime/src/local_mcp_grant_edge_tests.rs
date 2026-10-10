//! Identity-parser, path-pin, schema, and request-validation vectors.

use std::fs;

use rusqlite::{params, Connection};
use serde_json::Value;

use super::{allowed_rig, hash, reply, state, Rig, TOOL};
use crate::local_mcp_grant_identity::{observed_mcp_tool, shlex_split, slug_command_id};
use crate::local_mcp_grant_op::evaluate_local_mcp_grant_request;

#[test]
fn observed_identity_rules_follow_the_python_parser() {
    assert!(observed_mcp_tool("codex", "mcp__github__create").is_some());
    assert!(observed_mcp_tool("codex", "mcp__github").is_none());
    assert!(observed_mcp_tool("codex", "mcp__git hub__create").is_none());
    assert!(observed_mcp_tool("not a harness", "mcp__github__create").is_none());
    let long = format!("mcp__github__{}", "a".repeat(150));
    assert!(observed_mcp_tool("codex", &long).is_none());
    let apps = observed_mcp_tool("codex", "mcp__codex_apps__github__a__b").unwrap();
    let plain = observed_mcp_tool("codex", "mcp__github__a__b").unwrap();
    assert_ne!(apps.identity_hash, plain.identity_hash);
    assert_eq!(
        observed_mcp_tool("claude", "mcp__github__a")
            .unwrap()
            .identity_hash,
        observed_mcp_tool("claude-code", "mcp__github__a")
            .unwrap()
            .identity_hash
    );
}

#[test]
fn command_ids_slug_like_python() {
    assert_eq!(slug_command_id("create_issue"), "create_issue");
    assert_eq!(
        slug_command_id("root"),
        format!("root-{}", &crate_digest("root")[..8])
    );
    assert_eq!(slug_command_id("a.b"), "a.b");
    assert_eq!(slug_command_id("1st"), "other");
    assert_eq!(
        slug_command_id("Get Thing!"),
        format!("get-thing-{}", &crate_digest("Get Thing!")[..8])
    );
    assert_eq!(
        slug_command_id(""),
        format!("tool-{}", &crate_digest("")[..8])
    );
    assert_eq!(slug_command_id("caf\u{e9}"), "other");
}

fn crate_digest(value: &str) -> String {
    guard_policy_snapshot::digest_bytes(value.as_bytes())
}

#[test]
fn shlex_split_follows_posix_rules() {
    let split = |input| shlex_split(input);
    assert_eq!(
        split("npx -y 'a b' \"c\\\"d\" e\\ f"),
        Some(
            vec!["npx", "-y", "a b", "c\"d", "e f"]
                .into_iter()
                .map(String::from)
                .collect()
        )
    );
    assert_eq!(
        split("a '' b"),
        Some(vec!["a".into(), String::new(), "b".into()])
    );
    assert_eq!(split("\"x\\y\""), Some(vec!["x\\y".into()]));
    assert_eq!(split("  "), Some(vec![]));
    assert_eq!(split("'open"), None);
    assert_eq!(split("trail\\"), None);
}

#[test]
fn unbound_environments_and_missing_pieces_match_nothing() {
    let (rig, server) = allowed_rig(Some("allow"));
    let mut request = rig.request(&server, TOOL, "allow");
    request.server.env_values_hash =
        Some("guard-context-unbound:configured-environment".to_owned());
    assert_eq!(state(&request), "none");
    let mut request = rig.request("not-a-hash", TOOL, "allow");
    request.server.transport = None;
    assert_eq!(state(&request), "none");
    // A grant row for a different identity than the observation is ignored.
    rig.connection
        .execute(
            "update local_cli_grant set identity_hash = ?1",
            params![hash('b')],
        )
        .unwrap();
    assert_eq!(state(&rig.request(&server, TOOL, "allow")), "none");
    // An unknown stored grant state is not a grant.
    rig.connection
        .execute(
            "update local_cli_grant set identity_hash = ?1, state = 'unset'",
            params![server],
        )
        .unwrap();
    assert_eq!(state(&rig.request(&server, TOOL, "allow")), "none");
}

#[test]
fn missing_store_and_missing_tables_match_nothing() {
    let rig = Rig::new();
    let server = hash('a');
    fs::remove_file(rig.home.join("guard.db")).unwrap();
    assert_eq!(state(&rig.request(&server, TOOL, "review")), "none");
    Connection::open(rig.home.join("guard.db"))
        .unwrap()
        .execute_batch("create table unrelated (x integer)")
        .unwrap();
    assert_eq!(state(&rig.request(&server, TOOL, "review")), "none");
}

#[test]
fn damaged_schema_marker_fails_instead_of_authorizing() {
    let (rig, server) = allowed_rig(Some("allow"));
    for (version, checksum) in [
        (11, "checksum".to_owned()),
        (11, crate::local_store_read::schema_checksum(10)),
        (0, crate::local_store_read::schema_checksum(0)),
    ] {
        rig.connection
            .execute(
                "update local_cli_schema_migration set version = ?1, checksum = ?2",
                params![version, checksum],
            )
            .unwrap();
        let reply = reply(&rig.request(&server, TOOL, "allow"));
        assert_eq!(reply["status"], "error", "{version} {checksum}");
        assert_eq!(reply["code"], "native_local_mcp_grant_schema_invalid");
        assert_eq!(reply["payload"], serde_json::Value::Null);
    }
}

#[test]
fn newer_and_outdated_schemas_fail_instead_of_guessing() {
    let (rig, server) = allowed_rig(Some("allow"));
    for (version, code) in [
        (12, "native_local_mcp_grant_schema_unsupported"),
        (10, "native_local_mcp_grant_schema_outdated"),
    ] {
        rig.connection
            .execute(
                "update local_cli_schema_migration set version = ?1, checksum = ?2",
                params![version, crate::local_store_read::schema_checksum(version)],
            )
            .unwrap();
        let reply = reply(&rig.request(&server, TOOL, "allow"));
        assert_eq!(reply["status"], "error");
        assert_eq!(reply["code"], code);
        assert_eq!(reply["payload"], Value::Null);
    }
}

#[test]
fn store_path_must_be_guard_db_directly_under_home() {
    let (rig, server) = allowed_rig(Some("allow"));
    let other = Rig::new();
    let mut cases = Vec::new();
    for edit in 0..4 {
        let mut request = rig.request(&server, TOOL, "review");
        match edit {
            0 => request.store_path = other.home.join("guard.db").to_string_lossy().into_owned(),
            1 => request.store_path = rig.home.join("other.db").to_string_lossy().into_owned(),
            2 => request.store_path = "guard.db".to_owned(),
            _ => request.guard_home = "relative".to_owned(),
        }
        cases.push(request);
    }
    for request in cases {
        let reply = reply(&request);
        assert_eq!(reply["status"], "error", "{request:?}");
        assert_eq!(reply["code"], "native_local_mcp_grant_path_invalid");
    }
}

#[test]
fn invalid_requests_are_rejected() {
    let (rig, server) = allowed_rig(Some("allow"));
    let mut request = rig.request(&server, TOOL, "allow");
    request.connection_identity_hash = Some("short".to_owned());
    assert_eq!(
        reply(&request)["code"],
        "native_local_mcp_grant_request_invalid"
    );
    let mut request = rig.request(&server, &"t".repeat(5000), "allow");
    request.server.command = None;
    assert_eq!(
        reply(&request)["code"],
        "native_local_mcp_grant_request_invalid"
    );
    let mut request = rig.request(&server, TOOL, "allow");
    request.schema = "wrong".to_owned();
    assert_eq!(
        evaluate_local_mcp_grant_request(&request).unwrap_err(),
        "native_local_mcp_grant_schema_mismatch"
    );
}

#[test]
fn reply_binds_to_the_request_digest() {
    let (rig, server) = allowed_rig(Some("allow"));
    let first = reply(&rig.request(&server, TOOL, "review"));
    let second = reply(&rig.request(&server, TOOL, "warn"));
    assert!(first["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_ne!(first["request_sha256"], second["request_sha256"]);
}

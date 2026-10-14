use super::store::require_no_saved_policy;
use super::subject::{connection_hash, server_identity_hash, tool_name};
use super::view::harness_view;
use super::*;
use crate::local_store_read::{schema_checksum, STORE_FILE_NAME, SUPPORTED_SCHEMA_VERSION};
use crate::mcp_tool_policy_decision::Current;
use guard_command::effect_decision::GuardAction;
use guard_contracts::McpToolCallArtifactV1;
use rusqlite::{params, Connection};
use std::path::PathBuf;

fn temp_home(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "mcp_relay_decide_{}_{}_{}",
        std::process::id(),
        tag,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn artifact(metadata: Value) -> McpToolCallArtifactV1 {
    McpToolCallArtifactV1 {
        artifact_id: "codex:project:files:read".to_owned(),
        name: "files:read".to_owned(),
        harness: "codex".to_owned(),
        source_scope: "project".to_owned(),
        config_path: "/work/.codex/config.toml".to_owned(),
        command: None,
        transport: Some("stdio".to_owned()),
        publisher: None,
        metadata: metadata.as_object().cloned().unwrap(),
    }
}

fn decision(action: GuardAction) -> Decision {
    Decision::plain(Current {
        action,
        source: "policy".to_owned(),
        signals: Vec::new(),
        summary: String::new(),
        risk_categories: Vec::new(),
    })
}

fn proxy(route: Value) -> Value {
    json!({
        "gate": {"disable": false},
        "route": {
            "need": null,
            "decision_override": null,
            "tool_policy_action": "allow",
            "route": route,
        },
    })
}

#[test]
fn connection_hash_matches_python() {
    let server = "a".repeat(64);
    let plain = artifact(json!({"server_name": "files"}));
    assert_eq!(
        connection_hash(&plain, &server).unwrap(),
        "ed35d46b2896eb2d0a3f807a5dfbe5e8a0d6c8b52d5f103e7401f6b59cc50929"
    );
    let escaped = artifact(json!({"server_name": "café"}));
    assert_eq!(
        connection_hash(&escaped, &server).unwrap(),
        "b656342759de5b4fb958d3f8d8b4161b2a0e77458c0dde60a09d664e93d18c7a"
    );
}

#[test]
fn server_identity_hash_takes_only_64_hex_digits() {
    let upper = "A".repeat(64);
    let server = json!({"identity_hash": upper});
    assert_eq!(
        server_identity_hash(server.as_object().unwrap()),
        Some("a".repeat(64))
    );
    for bad in [json!("abc"), json!("g".repeat(64)), json!(7), Value::Null] {
        let server = json!({"identity_hash": bad});
        assert_eq!(server_identity_hash(server.as_object().unwrap()), None);
    }
    assert_eq!(server_identity_hash(&Map::new()), None);
}

#[test]
fn tool_name_prefers_identity_then_command_then_name() {
    let identity = artifact(json!({"mcp_tool_identity": {"tool_name": "  read  "}}));
    assert_eq!(tool_name(&identity), "read");
    let mut command = artifact(json!({"mcp_tool_identity": {"tool_name": " "}}));
    command.command = Some(" list ".to_owned());
    assert_eq!(tool_name(&command), "list");
    let named = artifact(json!({}));
    assert_eq!(tool_name(&named), "read");
}

#[test]
fn empty_store_answers_only_saved_lookups() {
    assert_eq!(
        empty_store_answer(&json!({"kind": "grant_lookup"})).unwrap(),
        json!({"decision": null})
    );
    assert_eq!(
        empty_store_answer(&json!({"kind": "policy_lookup"})).unwrap(),
        json!({
            "decision": null,
            "ignored_local_integrity": false,
            "reuse_diagnostic": {"reason": null},
        })
    );
    for kind in [json!("approval_claim"), json!(null), json!(3)] {
        assert_eq!(empty_store_answer(&json!({"kind": kind})), Err(POLICY_NEED));
    }
}

#[test]
fn route_accepts_forward_terminal_and_stored_block() {
    let allow = decision(GuardAction::Allow);
    let forward = proxy(json!({
        "kind": "allow_and_forward",
        "decision_source": "policy",
        "policy_action": "allow",
        "remember": false,
        "pass_approval_decision": true,
    }));
    assert_eq!(
        route(&forward, &allow),
        Ok(Routed::Forward {
            source: "policy".to_owned(),
            policy_action: "allow".to_owned(),
        })
    );
    let block = decision(GuardAction::Block);
    let terminal = proxy(json!({"kind": "terminal", "policy_action": "block"}));
    assert_eq!(
        route(&terminal, &block),
        Ok(Routed::Terminal {
            policy_action: "block".to_owned(),
        })
    );
    let stored = proxy(json!({"kind": "stored_block"}));
    assert_eq!(route(&stored, &block), Ok(Routed::StoredBlock));
}

#[test]
fn route_defers_everything_else() {
    let allow = decision(GuardAction::Allow);
    let remembered = proxy(json!({
        "kind": "allow_and_forward",
        "decision_source": "policy",
        "policy_action": "allow",
        "remember": true,
    }));
    assert_eq!(route(&remembered, &allow), Err(ROUTE_UNSUPPORTED));
    for kind in ["queue", "observe", "inline_approval", "package"] {
        assert_eq!(
            route(&proxy(json!({"kind": kind})), &allow),
            Err(ROUTE_UNSUPPORTED)
        );
    }
    let mut disabled = proxy(json!({"kind": "stored_block"}));
    disabled["gate"]["disable"] = Value::Bool(true);
    assert_eq!(route(&disabled, &allow), Err(ROUTE_UNSUPPORTED));
    let mut needs = proxy(json!({"kind": "stored_block"}));
    needs["route"]["need"] = json!({"kind": "grant_lookup"});
    assert_eq!(route(&needs, &allow), Err(ROUTE_UNSUPPORTED));
    let mut overridden = proxy(json!({"kind": "stored_block"}));
    overridden["route"]["decision_override"] = json!({"action": "review"});
    assert_eq!(route(&overridden, &allow), Err(ROUTE_UNSUPPORTED));
    let mut pending = decision(GuardAction::Review);
    pending.pending = Some(Map::new());
    assert_eq!(
        route(&proxy(json!({"kind": "stored_block"})), &pending),
        Err(ROUTE_UNSUPPORTED)
    );
}

#[test]
fn view_binds_one_harness_with_layers() {
    let view = json!({
        "schema": "guard-mcp-relay-view.v1",
        "harnesses": {
            "codex": {
                "config": {"mode": "enforce"},
                "hash_config": {"mode": "enforce"},
            },
        },
        "extension_layers": [],
    });
    let bound = harness_view(Some(&view), "codex").unwrap();
    assert_eq!(bound.mode, "enforce");
    assert!(bound.layers.is_empty());
    assert_eq!(harness_view(None, "codex"), Err("mcp_relay_view_missing"));
    assert_eq!(
        harness_view(Some(&view), "cursor"),
        Err("mcp_relay_harness_unbound")
    );
    let mut unlayered = view.clone();
    unlayered["extension_layers"] = Value::Null;
    assert_eq!(
        harness_view(Some(&unlayered), "codex"),
        Err("mcp_relay_layers_unavailable")
    );
    let mut renamed = view.clone();
    renamed["schema"] = json!("guard-mcp-relay-view.v2");
    assert_eq!(
        harness_view(Some(&renamed), "codex"),
        Err("mcp_relay_view_invalid")
    );
    let mut extra = view;
    extra["unexpected"] = json!(true);
    assert_eq!(
        harness_view(Some(&extra), "codex"),
        Err("mcp_relay_view_invalid")
    );
}

fn store(tag: &str) -> (PathBuf, Connection) {
    let home = temp_home(tag);
    let connection = Connection::open(home.join(STORE_FILE_NAME)).unwrap();
    connection
        .execute_batch(
            "create table local_cli_schema_migration (singleton integer primary key,
               version integer not null, checksum text not null);
             create table policy_decisions (id integer primary key);
             create table guard_local_once_approvals (id integer primary key);
             create table sync_state (state_key text primary key, payload_json text not null);",
        )
        .unwrap();
    connection
        .execute(
            "insert into local_cli_schema_migration (singleton, version, checksum) values (1, ?1, ?2)",
            params![SUPPORTED_SCHEMA_VERSION, schema_checksum(SUPPORTED_SCHEMA_VERSION)],
        )
        .unwrap();
    (home, connection)
}

#[test]
fn store_without_saved_policy_answers_lookups() {
    assert_eq!(require_no_saved_policy(&temp_home("absent")), Ok(()));
    let (home, connection) = store("empty");
    connection
        .execute(
            "insert into sync_state (state_key, payload_json) values ('policy_integrity', '{}')",
            [],
        )
        .unwrap();
    assert_eq!(require_no_saved_policy(&home), Ok(()));
}

#[test]
fn store_with_saved_policy_defers() {
    let cases = [
        "insert into policy_decisions (id) values (1)",
        "insert into guard_local_once_approvals (id) values (1)",
        "insert into sync_state (state_key, payload_json) values ('policy_bundle', '{}')",
    ];
    for (index, change) in cases.into_iter().enumerate() {
        let (home, connection) = store(&format!("saved{index}"));
        connection.execute(change, []).unwrap();
        assert_eq!(
            require_no_saved_policy(&home),
            Err("mcp_relay_saved_policy")
        );
    }
}

#[test]
fn store_with_unknown_schema_defers() {
    let (home, connection) = store("newer");
    connection
        .execute(
            "update local_cli_schema_migration set version = ?1",
            params![SUPPORTED_SCHEMA_VERSION + 1],
        )
        .unwrap();
    assert_eq!(
        require_no_saved_policy(&home),
        Err("mcp_relay_store_unreadable")
    );
    let (home, connection) = store("unmarked");
    connection
        .execute("delete from local_cli_schema_migration", [])
        .unwrap();
    assert_eq!(
        require_no_saved_policy(&home),
        Err("mcp_relay_store_unreadable")
    );
}

#[test]
fn request_decodes_the_relay_wire_shape() {
    let mut wire = json!({
        "guard_home": "/guard",
        "hash_workspace": "/work",
        "build": {
            "harness": "codex",
            "server_name": "files",
            "tool_name": "read",
            "source_scope": "project",
            "config_path": "/work/.codex/config.toml",
            "transport": "stdio",
            "server_id": null,
            "server_fingerprint": null,
            "server_identity": null,
            "provider_catalog_hash": null,
            "tool": {"kind": "catalog", "entry": null},
        },
        "arguments": {"format": "mapping", "entries": [["path", "a.txt"]]},
        "launcher_home": "/home/user",
        "catalog_state": "present",
        "params": {"name": "read"},
    });
    let request: McpRelayDecideRequestV1 = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(request.workspace, None);
    assert_eq!(request.launcher_path, None);
    assert_eq!(request.build.harness, "codex");
    wire["unexpected"] = json!(true);
    assert!(serde_json::from_value::<McpRelayDecideRequestV1>(wire).is_err());
}

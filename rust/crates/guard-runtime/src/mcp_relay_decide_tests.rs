use super::subject::{connection_hash, server_identity_hash, tool_name};
use super::view::harness_view;
use super::*;
use crate::mcp_tool_policy_decision::Current;
use guard_command::effect_decision::GuardAction;
use guard_contracts::McpToolCallArtifactV1;

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
        policy::empty_store_answer(&json!({"kind": "grant_lookup"})).unwrap(),
        json!({"decision": null})
    );
    assert_eq!(
        policy::empty_store_answer(&json!({"kind": "policy_lookup"})).unwrap(),
        json!({
            "decision": null,
            "ignored_local_integrity": false,
            "reuse_diagnostic": {"reason": null},
        })
    );
    for kind in [json!("approval_claim"), json!(null), json!(3)] {
        assert_eq!(
            policy::empty_store_answer(&json!({"kind": kind})),
            Err(POLICY_NEED)
        );
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
        route(&forward, &allow, None),
        Ok(Routed::Forward {
            source: "policy".to_owned(),
            policy_action: "allow".to_owned(),
            remember: false,
        })
    );
    let block = decision(GuardAction::Block);
    let terminal = proxy(json!({"kind": "terminal", "policy_action": "block"}));
    assert_eq!(
        route(&terminal, &block, None),
        Ok(Routed::Terminal {
            policy_action: "block".to_owned(),
        })
    );
    let stored = proxy(json!({"kind": "stored_block"}));
    assert_eq!(
        route(&stored, &block, None),
        Ok(Routed::StoredBlock {
            package_request: false,
        })
    );
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
    assert_eq!(route(&remembered, &allow, None), Err(ROUTE_UNSUPPORTED));
    for kind in ["observe", "inline_approval", "package"] {
        assert_eq!(
            route(&proxy(json!({"kind": kind})), &allow, None),
            Err(ROUTE_UNSUPPORTED)
        );
    }
    let mut disabled = proxy(json!({"kind": "stored_block"}));
    disabled["gate"]["disable"] = Value::Bool(true);
    assert_eq!(route(&disabled, &allow, None), Err(ROUTE_UNSUPPORTED));
    let mut needs = proxy(json!({"kind": "stored_block"}));
    needs["route"]["need"] = json!({"kind": "grant_lookup"});
    assert_eq!(route(&needs, &allow, None), Err(ROUTE_UNSUPPORTED));
    let mut overridden = proxy(json!({"kind": "stored_block"}));
    overridden["route"]["decision_override"] = json!({"action": "review"});
    assert_eq!(route(&overridden, &allow, None), Err(ROUTE_UNSUPPORTED));
    let mut pending = decision(GuardAction::Review);
    pending.pending = Some(Map::new());
    assert_eq!(
        route(&proxy(json!({"kind": "stored_block"})), &pending, None),
        Err(ROUTE_UNSUPPORTED)
    );
    // A pending approval forwards only once it is claimed, and only when the
    // proxy would pass the decision to its claim.
    let claimed = |pass: Value| {
        route(
            &proxy(json!({
                "kind": "allow_and_forward",
                "decision_source": "policy",
                "policy_action": "allow",
                "remember": false,
                "pass_approval_decision": pass,
            })),
            &pending,
            None,
        )
    };
    assert_eq!(
        claimed(json!(true)),
        Ok(Routed::Claim {
            source: "policy".to_owned(),
            policy_action: "allow".to_owned(),
        })
    );
    assert_eq!(claimed(json!(false)), Err(ROUTE_UNSUPPORTED));
    assert_eq!(claimed(json!(null)), Err(ROUTE_UNSUPPORTED));
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
    assert_eq!(bound.receipt_redaction_level, None);
    let mut levelled = view.clone();
    levelled["harnesses"]["codex"]["receipt_redaction_level"] = json!("partial");
    let bound = harness_view(Some(&levelled), "codex").unwrap();
    assert_eq!(bound.receipt_redaction_level.as_deref(), Some("partial"));
    levelled["harnesses"]["codex"]["receipt_redaction_level"] = json!("bogus");
    let bound = harness_view(Some(&levelled), "codex").unwrap();
    assert_eq!(bound.receipt_redaction_level, None);
    let mut extra = view;
    extra["unexpected"] = json!(true);
    assert_eq!(
        harness_view(Some(&extra), "codex"),
        Err("mcp_relay_view_invalid")
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
    // The relay sets this only on a package call it could not evaluate.
    assert!(!request.package_evaluation_unsettled);
    let mut unsettled = wire.clone();
    unsettled["package_evaluation_unsettled"] = json!(true);
    let request: McpRelayDecideRequestV1 = serde_json::from_value(unsettled).unwrap();
    assert!(request.package_evaluation_unsettled);
    wire["unexpected"] = json!(true);
    assert!(serde_json::from_value::<McpRelayDecideRequestV1>(wire).is_err());
}

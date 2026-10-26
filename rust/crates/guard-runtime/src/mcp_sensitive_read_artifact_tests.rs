//! The content hash of a sensitive read, spelled from the artifact itself.
//!
//! `GuardStore` keys every saved approval for the read by this digest, so the
//! vector below records what `consumer.service.artifact_hash` computed for
//! this artifact before the resident took the hash over. A query carrying the
//! artifact and a query carrying that recorded text have to reach the same
//! approval token: a different spelling would silently invalidate the
//! approvals the user already granted.

use guard_contracts::{McpSensitiveReadContextQueryV1, MCP_SENSITIVE_READ_ARTIFACT_FEATURE};
use serde_json::{json, Value};

use crate::mcp_sensitive_read::context;

/// `artifact_hash(artifact())` under the Python oracle the resident replaces.
const RECORDED_CONTENT_HASH: &str =
    "34a9621644ab1750a654fa9662466156e8e49a608299318b534bfb85bccffd4d";

/// The fields a caller ships, as the resident's own file-read artifact builder
/// spelled them: raw, because the resident redacts before it hashes.
fn artifact() -> Value {
    json!({
        "artifact_id": "codex:project:file-read:e11ea28d56441b4475a5c8052c26462479558576",
        "name": "read_file .env",
        "harness": "codex",
        "artifact_type": "file_read_request",
        "source_scope": "project",
        "config_path": "/tmp/ws/.mcp.json",
        "command": null,
        "args": [],
        "url": null,
        "transport": null,
        "publisher": null,
        "metadata": {
            "path_class": "local .env file",
            "tool_name": "read_file",
            "normalized_path": "/tmp/ws/.env",
            "env_keys": ["OPENAI_API_KEY"]
        }
    })
}

fn query(content: Value) -> McpSensitiveReadContextQueryV1 {
    let mut wire = json!({
        "config": null,
        "identity": {
            "artifact_id": "codex:project:file-read:e11ea28d56441b4475a5c8052c26462479558576",
            "config_path": "/tmp/ws/.mcp.json",
            "harness": "codex",
            "publisher": null,
            "server_launch_identity": {},
            "configured_env_values_hash": null,
            "source_scope": "project",
            "workspace": "/tmp/ws"
        },
        "capabilities": {
            "artifact_type": "file_read_request",
            "path_class": "local .env file",
            "tool_name": "read_file"
        },
        "extension_control_digest": "20d45a0efad04c26d4bf5e490d0b1924cdc34bc4e2b8b09f4b732bdce8c49043"
    });
    let object = wire.as_object_mut().expect("the query is an object");
    if let Some(fields) = content.as_object() {
        object.extend(fields.clone());
    }
    serde_json::from_value(wire).expect("the query deserializes")
}

#[test]
fn the_artifact_reaches_the_token_the_recorded_hash_reached() {
    let from_artifact = context(&query(json!({ "artifact": artifact() })));
    let from_recorded = context(&query(json!({ "content": RECORDED_CONTENT_HASH })));

    assert_eq!(
        from_artifact["artifact_hash"],
        from_recorded["artifact_hash"]
    );
    assert!(
        from_artifact["artifact_hash"].is_string(),
        "the token is built, not absent: {from_artifact}"
    );
    assert_eq!(
        from_artifact["current_action"],
        from_recorded["current_action"]
    );
}

#[test]
fn the_artifact_wins_over_a_hash_the_caller_also_sent() {
    let both = context(&query(json!({
        "artifact": artifact(),
        "content": "0".repeat(64)
    })));

    assert_eq!(
        both["artifact_hash"],
        context(&query(json!({ "artifact": artifact() })))["artifact_hash"]
    );
}

#[test]
fn a_query_naming_no_artifact_and_no_hash_has_no_token() {
    assert_eq!(context(&query(json!({}))), Value::Null);
}

#[test]
fn feature_is_advertised() {
    assert!(crate::resident_op_features::RESIDENT_OP_FEATURES
        .contains(&MCP_SENSITIVE_READ_ARTIFACT_FEATURE));
}

/// The op answers a request whose `request_sha256` it recomputes by serializing
/// the query it parsed. A field the caller left out that came back as `null`
/// would change those bytes, and every answer would fail the caller's binding
/// check rather than reach a verdict.
#[test]
fn a_query_round_trips_to_the_bytes_the_caller_sent() {
    for sent in [
        json!({ "artifact": artifact() }),
        json!({ "content": RECORDED_CONTENT_HASH }),
    ] {
        let wire = serde_json::to_value(query(sent.clone())).expect("the query serializes");
        let parsed = wire.as_object().expect("the query is an object");
        let fields = sent.as_object().expect("the fields are an object");
        for name in ["artifact", "content"] {
            assert_eq!(
                parsed.get(name),
                fields.get(name),
                "{name} came back differently than it was sent: {wire}"
            );
        }
    }
}

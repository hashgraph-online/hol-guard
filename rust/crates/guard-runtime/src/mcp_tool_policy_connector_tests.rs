//! Which MCP reviews name a connector to set up. Only a review due solely to
//! non-recognition of a server with no answer on this device does; anything
//! carrying a signal, a floor, a decision or an unverified state keeps its
//! generic review.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use guard_command::effect_decision::GuardAction;
use guard_contracts::{
    BrowserMcpArtifactV1, LocalMcpServerMaterialV1, McpExtensionInputV1, McpToolArgumentsV1,
    McpToolPolicySubjectV1,
};
use rusqlite::{params, Connection};
use serde_json::{json, Map, Value};

use super::connector_setup;
use crate::local_mcp_grant_identity::observed_mcp_tool;
use crate::mcp_tool_policy_decision::{Current, Decision};

const STDIO_HASH: &str = "5d0a8f3b9c2e47a1b6d4c8e2f0a1b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3f5a7";
static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn home() -> PathBuf {
    let home = std::env::temp_dir().join(format!(
        "hol-guard-mcp-connector-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&home).unwrap();
    home.canonicalize().unwrap()
}

/// A store carrying one grant row for `identity_hash`.
fn granted_home(identity_hash: &str, state: &str) -> PathBuf {
    let home = home();
    let connection = Connection::open(home.join("guard.db")).unwrap();
    connection
        .execute_batch(
            "create table local_cli_schema_migration (singleton integer primary key, \
               version integer not null, checksum text not null);
             create table local_cli_grant (cli_id text primary key, identity_hash text not null, \
               state text not null, revision integer not null, updated_at text not null);
             create table local_cli_observation (cli_id text primary key, identity_hash text not null, \
               example_label text not null, last_seen_at text not null, \
               surface text not null default 'cli', server_identity_hash text, server_command text);
             create table local_cli_command (cli_id text not null, command_id text not null, \
               name text not null, usage text not null, description text not null, parent_id text, \
               sort_index integer not null, primary key (cli_id, command_id));
             create table local_cli_command_grant (cli_id text not null, command_id text not null, \
               state text not null, primary key (cli_id, command_id));
             create table local_mcp_catalog (cli_id text primary key, identity_hash text not null, \
               catalog_json text not null, revision integer not null);
             create table local_mcp_tool_authority (cli_id text not null, identity_hash text not null, \
               tool_name text not null, catalog_revision integer not null, authority_hash text not null, \
               primary key (cli_id, identity_hash, tool_name));",
        )
        .unwrap();
    let version = crate::local_store_read::SUPPORTED_SCHEMA_VERSION;
    connection
        .execute(
            "insert into local_cli_schema_migration values (1, ?1, ?2)",
            params![version, crate::local_store_read::schema_checksum(version)],
        )
        .unwrap();
    connection
        .execute(
            "insert into local_cli_observation values ('local-cli.echo', ?1, 'echo-mcp', \
             '2026-01-01T00:00:00Z', 'mcp', ?1, null)",
            params![identity_hash],
        )
        .unwrap();
    connection
        .execute(
            "insert into local_cli_grant values ('local-cli.echo', ?1, ?2, 1, '2026-01-01')",
            params![identity_hash, state],
        )
        .unwrap();
    home
}

fn extension(
    home: &std::path::Path,
    server: LocalMcpServerMaterialV1,
    tool: &str,
) -> McpExtensionInputV1 {
    McpExtensionInputV1 {
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        harness: "codex".to_owned(),
        tool_name: tool.to_owned(),
        server,
        connection_identity_hash: None,
        tool_authority_hash: None,
        launcher_path: None,
        launcher_home: None,
        local_unavailable: false,
        server_identity: None,
        artifact_transport: None,
        server_name: Some(json!("echo-mcp")),
        contributed_tool_name: None,
        layers: Vec::new(),
        layers_unavailable: false,
    }
}

fn stdio(home: &std::path::Path) -> McpExtensionInputV1 {
    let server = LocalMcpServerMaterialV1 {
        identity_hash: Some(STDIO_HASH.to_owned()),
        transport: Some("stdio".to_owned()),
        command: Some("echo-mcp".to_owned()),
        ..LocalMcpServerMaterialV1::default()
    };
    extension(home, server, "lookup")
}

fn remote(home: &std::path::Path, url: &str) -> McpExtensionInputV1 {
    let server = LocalMcpServerMaterialV1 {
        identity_hash: Some("f".repeat(64)),
        transport: Some("streamable-http".to_owned()),
        command: Some(url.to_owned()),
        ..LocalMcpServerMaterialV1::default()
    };
    extension(home, server, "mcp__echo-mcp__lookup")
}

fn subject(ext: McpExtensionInputV1) -> McpToolPolicySubjectV1 {
    McpToolPolicySubjectV1 {
        config: Map::new(),
        workspace: None,
        artifact: BrowserMcpArtifactV1 {
            name: "lookup".to_owned(),
            command: Some("lookup".to_owned()),
            metadata: Map::new(),
        },
        artifact_type: "mcp_tool".to_owned(),
        artifact_id: "codex:echo-mcp:lookup".to_owned(),
        harness: "codex".to_owned(),
        publisher: None,
        artifact_hash: "h".to_owned(),
        arguments: McpToolArgumentsV1::Other { value: Value::Null },
        extension: Some(ext),
    }
}

fn review(source: &str, risk: &[&str]) -> Decision {
    Decision::plain(Current {
        action: GuardAction::Review,
        source: source.to_owned(),
        signals: Vec::new(),
        summary: "Review this tool call.".to_owned(),
        risk_categories: risk.iter().map(|item| (*item).to_owned()).collect(),
    })
}

#[test]
fn unrecognised_stdio_server_names_its_launch_identity() {
    let home = home();
    let found = connector_setup(&subject(stdio(&home)), &review("policy", &[])).unwrap();
    assert_eq!(found["reason_code"], "connector_setup_required");
    assert_eq!(found["identity_hash"], STDIO_HASH);
    assert_eq!(found["surface"], "mcp");
    assert_eq!(found["name"], "echo-mcp");
    assert_eq!(found["queue_group_id"], format!("connector:{STDIO_HASH}"));
}

#[test]
fn unrecognised_remote_server_identity_carries_no_url_or_query() {
    let home = home();
    let plain = remote(&home, "https://mcp.example.test/mcp");
    let with_query = remote(&home, "https://mcp.example.test/mcp?token=secret-value");
    let first = connector_setup(&subject(plain), &review("heuristic", &[])).unwrap();
    let second = connector_setup(&subject(with_query), &review("heuristic", &[])).unwrap();
    let observed = observed_mcp_tool("codex", "mcp__echo-mcp__lookup").unwrap();
    assert_eq!(first["identity_hash"], observed.identity_hash);
    assert_eq!(first, second);
    assert!(!first.to_string().contains("example.test"));
    assert!(!first.to_string().contains("secret-value"));
}

#[test]
fn a_proxied_remote_call_with_a_bare_tool_name_names_the_same_connector() {
    let home = home();
    let mut bare = remote(&home, "https://mcp.example.test/mcp");
    bare.tool_name = "lookup".to_owned();
    let found = connector_setup(&subject(bare), &review("heuristic", &[])).unwrap();
    let observed = observed_mcp_tool("codex", "mcp__echo-mcp__lookup").unwrap();
    assert_eq!(found["identity_hash"], observed.identity_hash);
    assert!(!found.to_string().contains("example.test"));
}

#[test]
fn a_grant_under_either_remote_identity_is_an_answer() {
    let configured = "f".repeat(64);
    let observed = observed_mcp_tool("codex", "mcp__echo-mcp__lookup")
        .unwrap()
        .identity_hash;
    for identity in [configured, observed] {
        for state in ["allowed", "blocked"] {
            let home = granted_home(&identity, state);
            let mut bare = remote(&home, "https://mcp.example.test/mcp");
            bare.tool_name = "lookup".to_owned();
            assert!(
                connector_setup(&subject(bare), &review("heuristic", &[])).is_none(),
                "{identity} {state}"
            );
        }
    }
}

#[test]
fn recognised_but_risky_call_stays_a_generic_review() {
    let home = home();
    let risky = review("risk-policy", &["destructive_operation"]);
    assert!(connector_setup(&subject(stdio(&home)), &risky).is_none());
    let mut signalled = review("policy", &[]);
    signalled.signals.push("network".to_owned());
    assert!(connector_setup(&subject(stdio(&home)), &signalled).is_none());
}

#[test]
fn decided_or_unverified_calls_are_unchanged() {
    let home = home();
    for source in [
        "local-mcp-extension",
        "catalog-mcp-extension",
        "composio-action-review",
        "temporary-mcp-grant",
    ] {
        assert!(
            connector_setup(&subject(stdio(&home)), &review(source, &[])).is_none(),
            "{source}"
        );
    }
    let mut unavailable = stdio(&home);
    unavailable.layers_unavailable = true;
    assert!(connector_setup(&subject(unavailable), &review("policy", &[])).is_none());
    let mut stricter = review("policy", &[]);
    stricter.action = GuardAction::RequireReapproval;
    assert!(connector_setup(&subject(stdio(&home)), &stricter).is_none());
}

#[test]
fn a_grant_row_in_any_state_is_an_answer() {
    for state in ["allowed", "blocked"] {
        let home = granted_home(STDIO_HASH, state);
        assert!(
            connector_setup(&subject(stdio(&home)), &review("policy", &[])).is_none(),
            "{state}"
        );
    }
}

#[test]
fn an_explicit_tool_or_publisher_choice_is_not_non_recognition() {
    let home = home();
    let mut explicit = subject(stdio(&home));
    explicit.config.insert(
        "artifact_actions".to_owned(),
        json!({"codex:echo-mcp:lookup": "review"}),
    );
    assert!(connector_setup(&explicit, &review("policy", &[])).is_none());
    let mut publisher = subject(stdio(&home));
    publisher.publisher = Some("example".to_owned());
    publisher
        .config
        .insert("publisher_actions".to_owned(), json!({"example": "review"}));
    assert!(connector_setup(&publisher, &review("policy", &[])).is_none());
}

#[test]
fn no_extension_input_names_no_connector() {
    let mut bare = subject(stdio(&home()));
    bare.extension = None;
    assert!(connector_setup(&bare, &review("policy", &[])).is_none());
}

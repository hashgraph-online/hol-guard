//! The op against a temporary `guard.db` carrying the local CLI schema at the
//! version this build supports.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use guard_contracts::{ConnectorSetupContextRequestV1, CONNECTOR_SETUP_CONTEXT_REQUEST_SCHEMA};
use rusqlite::{params, Connection};
use serde_json::{json, Value};

use super::evaluate_connector_setup_context_request;
use crate::local_store_read::{schema_checksum, SUPPORTED_SCHEMA_VERSION};

pub(super) const CLI_ID: &str = "local-cli.lanectl-1";
const MCP_ID: &str = "local-cli.echomcp-1";
const HASH: &str = "abababababababababababababababababababababababababababababababab";
const NOW: &str = "2026-01-02T03:04:05Z";
const SCHEMA: &str = "
create table guard_review_outbox_events (
    stream_sequence integer primary key,
    payload_hash text not null default ''
);
create table local_cli_schema_migration (
    singleton integer primary key check (singleton = 1),
    version integer not null,
    checksum text not null
);
create table local_cli_grant (
    cli_id text primary key,
    identity_hash text not null,
    state text not null check (state in ('allowed', 'blocked')),
    revision integer not null check (revision >= 1),
    updated_at text not null
);
create table local_cli_grant_capability (
    cli_id text not null,
    capability text not null,
    state text not null,
    primary key (cli_id, capability)
);
create table local_cli_observation (
    cli_id text primary key,
    identity_hash text not null,
    kind text not null,
    name text not null,
    example_label text not null,
    observed_count integer not null,
    last_seen_at text not null,
    surface text not null default 'cli',
    first_blocked_cause text,
    last_trigger_summary text,
    last_why_now text,
    last_harness text,
    last_workspace_label text,
    last_context_at text
);
create table local_cli_command (
    cli_id text not null,
    command_id text not null,
    name text not null,
    usage text not null,
    description text not null,
    parent_id text,
    sort_index integer not null,
    primary key (cli_id, command_id)
);
create table local_cli_command_grant (
    cli_id text not null,
    command_id text not null,
    state text not null,
    primary key (cli_id, command_id)
);
create table local_mcp_catalog (
    cli_id text primary key,
    identity_hash text not null,
    catalog_json text not null,
    revision integer not null
);
create table local_mcp_tool_authority (
    cli_id text not null, identity_hash text not null, tool_name text not null,
    catalog_revision integer not null, authority_hash text not null,
    primary key (cli_id, identity_hash, tool_name)
);
";

static COUNTER: AtomicUsize = AtomicUsize::new(0);

pub(super) struct Fixture {
    home: PathBuf,
    pub(super) connection: Connection,
}

impl Fixture {
    pub(super) fn new() -> Self {
        Self::at_version(SUPPORTED_SCHEMA_VERSION)
    }

    pub(super) fn at_version(version: i64) -> Self {
        let home = std::env::temp_dir().join(format!(
            "hol-guard-connector-setup-context-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&home).unwrap();
        let connection = Connection::open(home.join("guard.db")).unwrap();
        connection.execute_batch(SCHEMA).unwrap();
        let fixture = Self { home, connection };
        fixture.marker(version, &schema_checksum(version));
        fixture
    }

    pub(super) fn marker(&self, version: i64, checksum: &str) {
        self.connection
            .execute("delete from local_cli_schema_migration", [])
            .unwrap();
        self.connection
            .execute(
                "insert into local_cli_schema_migration values (1, ?1, ?2)",
                params![version, checksum],
            )
            .unwrap();
    }

    pub(super) fn observe(&self, cli_id: &str, surface: &str) {
        self.connection
            .execute(
                "insert into local_cli_observation (cli_id, identity_hash, kind, name, \
                 example_label, observed_count, last_seen_at, surface) \
                 values (?1, ?2, 'executable', 'n', 'n', 1, '2026-01-01T00:00:00Z', ?3)",
                params![cli_id, HASH, surface],
            )
            .unwrap();
    }

    fn grant(&self, cli_id: &str, state: &str, hash: &str) {
        self.connection
            .execute(
                "insert into local_cli_grant values (?1, ?2, ?3, 1, '2026-01-01T00:00:00Z')",
                params![cli_id, hash, state],
            )
            .unwrap();
    }

    fn command(&self, cli_id: &str, command_id: &str, name: &str, state: Option<&str>) {
        self.connection
            .execute(
                "insert into local_cli_command values (?1, ?2, ?3, ?3, 'd', null, 0)",
                params![cli_id, command_id, name],
            )
            .unwrap();
        if let Some(state) = state {
            self.connection
                .execute(
                    "insert into local_cli_command_grant values (?1, ?2, ?3)",
                    params![cli_id, command_id, state],
                )
                .unwrap();
        }
    }

    fn catalog(&self, cli_id: &str, revision: i64, tools: &[&str]) {
        self.connection
            .execute(
                "insert into local_mcp_catalog values (?1, ?2, '{}', ?3)",
                params![cli_id, HASH, revision],
            )
            .unwrap();
        for tool in tools {
            self.connection
                .execute(
                    "insert into local_mcp_tool_authority values (?1, ?2, ?3, ?4, 'a')",
                    params![cli_id, HASH, tool, revision],
                )
                .unwrap();
        }
    }

    pub(super) fn request(&self, cli_id: &str, extra: Value) -> ConnectorSetupContextRequestV1 {
        let text = |name: &str| extra[name].as_str().map(str::to_owned);
        ConnectorSetupContextRequestV1 {
            schema: CONNECTOR_SETUP_CONTEXT_REQUEST_SCHEMA.to_owned(),
            request_id: "context-op-test".to_owned(),
            store_path: self.home.join("guard.db").to_string_lossy().into_owned(),
            guard_home: self.home.to_string_lossy().into_owned(),
            source: "local".to_owned(),
            busy_timeout_ms: 5000,
            cli_id: cli_id.to_owned(),
            identity_hash: text("identity_hash").unwrap_or_else(|| HASH.to_owned()),
            first_blocked_cause: text("first_blocked_cause"),
            trigger_summary: text("trigger_summary"),
            why_now: text("why_now"),
            harness: text("harness"),
            workspace_label: text("workspace_label"),
            observed_at: NOW.to_owned(),
        }
    }

    pub(super) fn call(&self, cli_id: &str, extra: Value) -> Value {
        let request = self.request(cli_id, extra);
        serde_json::from_slice(&evaluate_connector_setup_context_request(&request).unwrap())
            .unwrap()
    }

    fn payload(&self, cli_id: &str, extra: Value) -> Value {
        let reply = self.call(cli_id, extra);
        assert_eq!(reply["status"], "ok", "{reply}");
        reply["payload"].clone()
    }

    fn count(&self, table: &str) -> i64 {
        self.connection
            .query_row(&format!("select count(*) from {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    pub(super) fn stored_cause(&self, cli_id: &str) -> Option<String> {
        self.connection
            .query_row(
                "select first_blocked_cause from local_cli_observation where cli_id = ?1",
                [cli_id],
                |row| row.get(0),
            )
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.home);
    }
}

pub(super) fn error_code(reply: &Value) -> &str {
    assert_eq!(reply["status"], "error", "{reply}");
    assert!(reply["payload"].is_null(), "{reply}");
    reply["code"].as_str().unwrap()
}

#[test]
fn records_context_and_reports_the_first_cause() {
    let fixture = Fixture::new();
    fixture.observe(CLI_ID, "cli");
    let payload = fixture.payload(
        CLI_ID,
        json!({
            "first_blocked_cause": "connect_loopback",
            "trigger_summary": "lanectl sync",
            "harness": "codex",
        }),
    );
    assert_eq!(payload["first_blocked_cause"], "connect_loopback");
    assert_eq!(payload["surface"], "cli");
    assert_eq!(payload["resolution_state"], "unset");
    assert_eq!(
        fixture.stored_cause(CLI_ID).as_deref(),
        Some("connect_loopback")
    );
    // A later, different cause never replaces the first.
    let payload = fixture.payload(CLI_ID, json!({"first_blocked_cause": "read_home_state"}));
    assert_eq!(payload["first_blocked_cause"], "connect_loopback");
    assert_eq!(
        payload["card_recommendation"]["capability"],
        "loopback-network"
    );
}

#[test]
fn recommendation_follows_the_first_cause_and_is_never_preselected() {
    for (cause, capability) in [
        ("connect_loopback", json!("loopback-network")),
        ("read_home_state", json!("state-dir-read")),
        ("write_home_state", json!("state-dir-write")),
        ("exec_outside_roots", Value::Null),
        ("unrecognised_tool", Value::Null),
    ] {
        let fixture = Fixture::new();
        fixture.observe(CLI_ID, "cli");
        let card = fixture.payload(CLI_ID, json!({"first_blocked_cause": cause}))
            ["card_recommendation"]
            .clone();
        assert_eq!(card["kind"], "cli-capability", "{cause}");
        assert_eq!(card["capability"], capability, "{cause}");
        assert_eq!(card["preselected"], false, "{cause}");
    }
    let fixture = Fixture::new();
    fixture.observe(CLI_ID, "cli");
    let card = fixture.payload(CLI_ID, json!({}))["card_recommendation"].clone();
    assert_eq!(card["capability"], Value::Null);
}

#[test]
fn mcp_recommendation_allows_seen_tools_and_reviews_the_rest() {
    let fixture = Fixture::new();
    fixture.observe(MCP_ID, "mcp");
    for tool in ["list_items", "create_item", "delete_item"] {
        fixture.command(MCP_ID, tool, tool, None);
    }
    let card = fixture.payload(MCP_ID, json!({"first_blocked_cause": "unrecognised_tool"}))
        ["card_recommendation"]
        .clone();
    assert_eq!(card["kind"], "mcp-tools");
    assert_eq!(
        card["seen_tools"],
        json!(["create_item", "delete_item", "list_items"])
    );
    assert_eq!(card["seen_tools_action"], "allow");
    assert_eq!(card["other_tools_action"], "review");
    assert_eq!(card["preselected"], false);
}

#[test]
fn allowed_tools_need_the_grant_the_command_state_and_the_current_catalog() {
    let fixture = Fixture::new();
    fixture.observe(MCP_ID, "mcp");
    fixture.command(MCP_ID, "list_items", "list_items", Some("allow"));
    fixture.command(MCP_ID, "create_item", "create_item", Some("allow"));
    fixture.command(MCP_ID, "delete_item", "delete_item", Some("review"));
    fixture.catalog(MCP_ID, 3, &["list_items", "delete_item"]);
    // Without an allowed grant, no tool counts as allowed.
    let payload = fixture.payload(MCP_ID, json!({}));
    assert_eq!(payload["allowed_alternatives"]["tools"], json!([]));
    fixture.grant(MCP_ID, "allowed", HASH);
    let payload = fixture.payload(MCP_ID, json!({}));
    assert_eq!(payload["resolution_state"], "allowed");
    // `create_item` is allowed but not in the current catalog snapshot, and
    // `delete_item` is in it but not allowed.
    assert_eq!(
        payload["allowed_alternatives"]["tools"],
        json!(["list_items"])
    );
    assert_eq!(payload["allowed_alternatives"]["subcommands"], json!([]));
    assert_eq!(
        payload["allowed_alternatives"]["catalog_contributions"],
        json!([])
    );
}

#[test]
fn a_connector_without_a_catalog_snapshot_applies_no_snapshot_check() {
    let fixture = Fixture::new();
    fixture.observe(MCP_ID, "mcp");
    fixture.command(MCP_ID, "list_items", "list_items", Some("allow"));
    fixture.command(MCP_ID, "create_item", "create_item", None);
    fixture.grant(MCP_ID, "allowed", HASH);
    let payload = fixture.payload(MCP_ID, json!({}));
    assert_eq!(
        payload["allowed_alternatives"]["tools"],
        json!(["list_items"])
    );
}

#[test]
fn a_tool_the_live_decision_always_reviews_is_not_listed_as_allowed() {
    let fixture = Fixture::new();
    fixture.observe(MCP_ID, "mcp");
    fixture.command(MCP_ID, "list_items", "list_items", Some("allow"));
    fixture.command(
        MCP_ID,
        "composio_multi_execute_tool",
        "composio_multi_execute_tool",
        Some("allow"),
    );
    fixture.grant(MCP_ID, "allowed", HASH);
    let payload = fixture.payload(MCP_ID, json!({}));
    assert_eq!(
        payload["allowed_alternatives"]["tools"],
        json!(["list_items"])
    );
}

#[test]
fn allowed_subcommands_are_listed_for_a_cli() {
    let fixture = Fixture::new();
    fixture.observe(CLI_ID, "cli");
    fixture.command(CLI_ID, "root", "lanectl", None);
    fixture.command(CLI_ID, "other", "other", Some("allow"));
    fixture.command(CLI_ID, "repo.list", "list", Some("allow"));
    fixture.command(CLI_ID, "repo.delete", "delete", Some("block"));
    fixture.grant(CLI_ID, "allowed", HASH);
    let payload = fixture.payload(CLI_ID, json!({}));
    assert_eq!(
        payload["allowed_alternatives"]["subcommands"],
        json!(["repo.list"])
    );
    assert_eq!(payload["allowed_alternatives"]["tools"], json!([]));
}

#[test]
fn resolution_state_is_derived_from_the_grant() {
    let fixture = Fixture::new();
    fixture.observe(CLI_ID, "cli");
    assert_eq!(
        fixture.payload(CLI_ID, json!({}))["resolution_state"],
        "unset"
    );
    fixture.grant(CLI_ID, "blocked", HASH);
    let payload = fixture.payload(CLI_ID, json!({}));
    assert_eq!(payload["resolution_state"], "blocked");
    assert_eq!(payload["allowed_alternatives"]["subcommands"], json!([]));
    // A grant recorded for another identity does not decide this one.
    fixture
        .connection
        .execute("delete from local_cli_grant", [])
        .unwrap();
    fixture.grant(CLI_ID, "allowed", "cdcdcdcd");
    assert_eq!(
        fixture.payload(CLI_ID, json!({}))["resolution_state"],
        "unset"
    );
}

#[test]
fn the_op_never_writes_a_grant_command_state_or_capability() {
    let fixture = Fixture::new();
    fixture.observe(CLI_ID, "cli");
    fixture.command(CLI_ID, "repo.list", "list", None);
    fixture.grant(CLI_ID, "blocked", HASH);
    let tables = [
        "local_cli_grant",
        "local_cli_command_grant",
        "local_cli_grant_capability",
        "local_cli_command",
    ];
    let before: Vec<i64> = tables.iter().map(|table| fixture.count(table)).collect();
    for cause in ["connect_loopback", "read_home_state", "write_home_state"] {
        fixture.payload(CLI_ID, json!({"first_blocked_cause": cause}));
    }
    let after: Vec<i64> = tables.iter().map(|table| fixture.count(table)).collect();
    assert_eq!(before, after);
    let state: String = fixture
        .connection
        .query_row("select state from local_cli_grant", [], |row| row.get(0))
        .unwrap();
    assert_eq!(state, "blocked");
}

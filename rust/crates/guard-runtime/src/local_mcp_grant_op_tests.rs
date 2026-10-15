//! Decision table against a temporary `guard.db` carrying the local CLI and
//! MCP catalog schema that `store_local_cli_schema.py` creates. Vectors follow
//! the Python `matching_local_mcp_grant` behavior this op replaced.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use guard_contracts::{
    LocalMcpGrantRequestV1, LocalMcpServerMaterialV1, LOCAL_MCP_GRANT_REQUEST_SCHEMA,
};
use rusqlite::{params, Connection};
use serde_json::Value;

use super::evaluate_local_mcp_grant_request;
use crate::local_mcp_grant_identity::{observed_mcp_tool, slug_command_id};

const SCHEMA: &str = "
create table local_cli_schema_migration (
    singleton integer primary key check (singleton = 1),
    version integer not null,
    checksum text not null
);
create table local_cli_grant (
    cli_id text primary key,
    identity_hash text not null,
    state text not null,
    revision integer not null,
    updated_at text not null
);
create table local_cli_observation (
    cli_id text primary key,
    identity_hash text not null,
    example_label text not null,
    last_seen_at text not null,
    surface text not null default 'cli',
    server_identity_hash text,
    server_command text
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

pub(super) const TOOL: &str = "create_issue";
pub(super) const LIVE: &str =
    "livelivelivelivelivelivelivelivelivelivelivelivelivelivelivelivelive";
static COUNTER: AtomicUsize = AtomicUsize::new(0);

pub(super) struct Rig {
    pub(super) home: PathBuf,
    pub(super) connection: Connection,
}

impl Rig {
    pub(super) fn new() -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let home = std::env::temp_dir().join(format!(
            "hol-guard-local-mcp-grant-{}-{suffix}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&home).unwrap();
        let connection = Connection::open(home.join("guard.db")).unwrap();
        connection.execute_batch(SCHEMA).unwrap();
        connection
            .execute(
                "insert into local_cli_schema_migration values (1, 11, ?1)",
                [crate::local_store_read::schema_checksum(11)],
            )
            .unwrap();
        Self { home, connection }
    }

    /// Observation (and optionally its grant) for a server identity.
    pub(super) fn enroll(
        &self,
        cli_id: &str,
        hash: &str,
        server_hash: Option<&str>,
        state: Option<&str>,
    ) {
        self.connection
            .execute(
                "insert into local_cli_observation values (?1, ?2, 'label', \
                 '2026-01-01T00:00:00Z', 'mcp', ?3, null)",
                params![cli_id, hash, server_hash],
            )
            .unwrap();
        if let Some(state) = state {
            self.connection
                .execute(
                    "insert into local_cli_grant values (?1, ?2, ?3, 1, '2026-01-01')",
                    params![cli_id, hash, state],
                )
                .unwrap();
        }
    }

    pub(super) fn command(&self, cli_id: &str, command_id: &str, state: Option<&str>) {
        self.connection
            .execute(
                "insert into local_cli_command values (?1, ?2, ?2, ?2, 'd', null, 0)",
                params![cli_id, command_id],
            )
            .unwrap();
        if let Some(state) = state {
            self.state(cli_id, command_id, state);
        }
    }

    pub(super) fn state(&self, cli_id: &str, command_id: &str, state: &str) {
        self.connection
            .execute(
                "insert into local_cli_command_grant values (?1, ?2, ?3)",
                params![cli_id, command_id, state],
            )
            .unwrap();
    }

    pub(super) fn authority(&self, cli_id: &str, hash: &str, tool: &str, stored: &str) {
        self.connection
            .execute(
                "insert into local_mcp_catalog values (?1, ?2, '{}', 3)",
                params![cli_id, hash],
            )
            .unwrap();
        self.connection
            .execute(
                "insert into local_mcp_tool_authority values (?1, ?2, ?3, 3, ?4)",
                params![cli_id, hash, tool, stored],
            )
            .unwrap();
    }

    pub(super) fn request(
        &self,
        server_hash: &str,
        tool: &str,
        action: &str,
    ) -> LocalMcpGrantRequestV1 {
        LocalMcpGrantRequestV1 {
            schema: LOCAL_MCP_GRANT_REQUEST_SCHEMA.to_owned(),
            request_id: "mcp-grant-test".to_owned(),
            store_path: self.home.join("guard.db").to_string_lossy().into_owned(),
            guard_home: self.home.to_string_lossy().into_owned(),
            current_action: action.to_owned(),
            harness: "codex".to_owned(),
            tool_name: tool.to_owned(),
            server: LocalMcpServerMaterialV1 {
                identity_hash: Some(server_hash.to_owned()),
                transport: Some("stdio".to_owned()),
                ..Default::default()
            },
            connection_identity_hash: None,
            tool_authority_hash: None,
            launcher_path: None,
            launcher_home: None,
        }
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.home);
    }
}

pub(super) fn hash(seed: char) -> String {
    seed.to_string().repeat(64)
}

pub(super) fn reply(request: &LocalMcpGrantRequestV1) -> Value {
    serde_json::from_slice(&evaluate_local_mcp_grant_request(request).unwrap()).unwrap()
}

pub(super) fn state(request: &LocalMcpGrantRequestV1) -> String {
    let reply = reply(request);
    assert_eq!(reply["status"], "ok", "{reply}");
    reply["payload"]["state"].as_str().unwrap().to_owned()
}

/// A server with an allowed grant and the tool in its catalog.
pub(super) fn allowed_rig(tool_state: Option<&str>) -> (Rig, String) {
    let rig = Rig::new();
    let server = hash('a');
    rig.enroll("local-cli.mcp-a", &server, Some(&server), Some("allowed"));
    rig.command("local-cli.mcp-a", &slug_command_id(TOOL), tool_state);
    (rig, server)
}

#[test]
fn no_observation_or_grant_row_matches_nothing() {
    let rig = Rig::new();
    let server = hash('a');
    assert_eq!(state(&rig.request(&server, TOOL, "allow")), "none");
    rig.enroll("local-cli.mcp-a", &server, Some(&server), None);
    assert_eq!(state(&rig.request(&server, TOOL, "allow")), "none");
}

#[test]
fn blocked_grant_blocks_every_refinable_action_and_reports_the_row() {
    let rig = Rig::new();
    let server = hash('a');
    rig.enroll("local-cli.mcp-a", &server, Some(&server), Some("blocked"));
    for action in ["allow", "review", "require-reapproval", "warn"] {
        assert_eq!(state(&rig.request(&server, TOOL, action)), "blocked");
    }
    let payload = &reply(&rig.request(&server, TOOL, "allow"))["payload"];
    assert_eq!(payload["cli_id"], "local-cli.mcp-a");
    assert_eq!(payload["identity_hash"], server.as_str());
}

#[test]
fn other_actions_are_never_refined() {
    let rig = Rig::new();
    let server = hash('a');
    rig.enroll("local-cli.mcp-a", &server, Some(&server), Some("blocked"));
    for action in ["block", "deny", ""] {
        assert_eq!(state(&rig.request(&server, TOOL, action)), "none");
    }
}

#[test]
fn unseen_tools_review_unless_a_retired_deny_survives() {
    let rig = Rig::new();
    let server = hash('a');
    rig.enroll("local-cli.mcp-a", &server, Some(&server), Some("allowed"));
    assert_eq!(state(&rig.request(&server, TOOL, "allow")), "review");
    rig.state("local-cli.mcp-a", &slug_command_id(TOOL), "allow");
    assert_eq!(state(&rig.request(&server, TOOL, "allow")), "review");
    rig.connection
        .execute("update local_cli_command_grant set state = 'block'", [])
        .unwrap();
    assert_eq!(state(&rig.request(&server, TOOL, "allow")), "blocked");
    rig.connection
        .execute("delete from local_cli_command_grant", [])
        .unwrap();
    rig.state("local-cli.mcp-a", "other", "block");
    assert_eq!(state(&rig.request(&server, TOOL, "allow")), "blocked");
    assert_eq!(
        state(&rig.request(&server, "other_tool", "allow")),
        "blocked"
    );
}

#[test]
fn damaged_catalog_rows_do_not_count_as_known_tools() {
    let (rig, server) = allowed_rig(Some("allow"));
    assert_eq!(state(&rig.request(&server, TOOL, "allow")), "allowed");
    rig.connection
        .execute("update local_cli_command set usage = x'00'", [])
        .unwrap();
    assert_eq!(state(&rig.request(&server, TOOL, "allow")), "review");
}

#[test]
fn tool_states_decide_known_tools() {
    for (stored, expected) in [
        (Some("review"), "review"),
        (Some("block"), "blocked"),
        (Some("inherit"), "none"),
        (Some("bogus"), "none"),
        (None, "none"),
        (Some("allow"), "allowed"),
    ] {
        let (rig, server) = allowed_rig(stored);
        assert_eq!(
            state(&rig.request(&server, TOOL, "allow")),
            expected,
            "{stored:?}"
        );
    }
}

#[test]
fn allow_needs_matching_catalog_authority_once_a_catalog_exists() {
    let (rig, server) = allowed_rig(Some("allow"));
    let mut request = rig.request(&server, TOOL, "allow");
    request.tool_authority_hash = Some(LIVE.to_owned());
    // Legacy server-wide grant without any catalog or connection binding.
    assert_eq!(state(&request), "allowed");
    rig.authority("local-cli.mcp-a", &server, TOOL, LIVE);
    assert_eq!(state(&request), "allowed");
    request.tool_authority_hash = Some(hash('f'));
    assert_eq!(state(&request), "review");
    request.tool_authority_hash = None;
    assert_eq!(state(&request), "review");
    request.tool_authority_hash = Some(String::new());
    assert_eq!(state(&request), "review");
}

#[test]
fn catalog_without_the_tool_digest_reviews() {
    let (rig, server) = allowed_rig(Some("allow"));
    rig.authority("local-cli.mcp-a", &server, "another_tool", LIVE);
    let mut request = rig.request(&server, TOOL, "allow");
    request.tool_authority_hash = Some(LIVE.to_owned());
    assert_eq!(state(&request), "review");
}

#[test]
fn composio_wrappers_and_reapproval_never_allow() {
    let tool = "composio_multi_execute_tool";
    let rig = Rig::new();
    let server = hash('a');
    rig.enroll("local-cli.mcp-a", &server, Some(&server), Some("allowed"));
    rig.command("local-cli.mcp-a", &slug_command_id(tool), Some("allow"));
    assert_eq!(state(&rig.request(&server, tool, "allow")), "none");
    assert_eq!(
        state(&rig.request(&server, "mcp__x__composio_search_tools", "allow")),
        "review"
    );
    let (rig, server) = allowed_rig(Some("allow"));
    assert_eq!(
        state(&rig.request(&server, TOOL, "require-reapproval")),
        "none"
    );
    assert_eq!(state(&rig.request(&server, TOOL, "warn")), "allowed");
}

#[test]
fn connection_bound_grants_need_authority_and_exact_observations() {
    let rig = Rig::new();
    let (server, connection) = (hash('a'), hash('c'));
    rig.enroll(
        "local-cli.mcp-c",
        &connection,
        Some(&server),
        Some("allowed"),
    );
    rig.command("local-cli.mcp-c", &slug_command_id(TOOL), Some("allow"));
    let mut request = rig.request(&server, TOOL, "allow");
    request.connection_identity_hash = Some(connection.clone());
    // A connection-scoped grant is never allowed without catalog authority.
    assert_eq!(state(&request), "review");
    rig.authority("local-cli.mcp-c", &connection, TOOL, LIVE);
    request.tool_authority_hash = Some(LIVE.to_owned());
    assert_eq!(state(&request), "allowed");
    // A different connection does not inherit the grant.
    request.connection_identity_hash = Some(hash('d'));
    assert_eq!(state(&request), "none");
    // Without a connection, the server hash alone matches nothing here.
    request.connection_identity_hash = None;
    assert_eq!(state(&request), "none");
}

#[test]
fn legacy_server_wide_grants_only_serve_unconfigured_servers() {
    let rig = Rig::new();
    let server = hash('a');
    rig.enroll("local-cli.mcp-a", &server, Some(&server), Some("allowed"));
    rig.command("local-cli.mcp-a", &slug_command_id(TOOL), Some("allow"));
    let mut request = rig.request(&server, TOOL, "allow");
    request.connection_identity_hash = Some(hash('c'));
    request.tool_authority_hash = Some(LIVE.to_owned());
    // No configured connection yet: the pre-connection grant still resolves.
    assert_eq!(state(&request), "allowed");
    rig.enroll("local-cli.mcp-z", &hash('e'), Some(&server), None);
    assert_eq!(state(&request), "none");
}

#[test]
fn observed_connectors_derive_identity_natively() {
    let tool = "mcp__codex_apps__github__create_issue";
    let observed = observed_mcp_tool("codex", tool).unwrap();
    let rig = Rig::new();
    rig.enroll(
        "local-cli.mcp-o",
        &observed.identity_hash,
        Some(&observed.identity_hash),
        Some("allowed"),
    );
    rig.command("local-cli.mcp-o", &observed.command_id, Some("allow"));
    let mut request = rig.request(&hash('9'), tool, "allow");
    request.server.identity_hash = None;
    request.server.transport = None;
    assert_eq!(state(&request), "allowed");
    // The recorded transport also selects the observed identity.
    request.server.identity_hash = Some(hash('9'));
    request.server.transport = Some("observed".to_owned());
    assert_eq!(state(&request), "allowed");
    request.harness = "claude".to_owned();
    assert_eq!(state(&request), "none");
    // Not a qualified connector name: no identity, so no grant.
    request.harness = "codex".to_owned();
    request.tool_name = "create_issue".to_owned();
    assert_eq!(state(&request), "none");
    // Unseen observed tools review and a retired exact deny still blocks.
    request.tool_name = "mcp__codex_apps__github__other".to_owned();
    assert_eq!(state(&request), "review");
    let other = observed_mcp_tool("codex", &request.tool_name).unwrap();
    rig.state("local-cli.mcp-o", &other.command_id, "block");
    assert_eq!(state(&request), "blocked");
}

#[path = "local_mcp_grant_edge_tests.rs"]
mod edge;
#[cfg(unix)]
#[path = "local_mcp_grant_launcher_tests.rs"]
mod launcher;

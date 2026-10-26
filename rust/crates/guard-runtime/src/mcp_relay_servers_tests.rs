use super::*;

fn server(name: &str) -> RelayServerV1 {
    RelayServerV1 {
        harness: "codex".to_owned(),
        server_name: name.to_owned(),
        source_scope: "global".to_owned(),
        config_path: "/home/user/.codex/config.toml".to_owned(),
        server_id: None,
        identity_hash: "a".repeat(64),
    }
}

#[test]
fn an_unreported_server_is_unknown() {
    let servers = RelayServers::default();
    assert_eq!(servers.relayable(&server("docs")), Err(SERVER_UNKNOWN));
}

#[test]
fn a_server_without_proxy_tools_is_relayable_and_a_mark_sticks() {
    let servers = RelayServers::default();
    assert!(servers.record(&server("docs"), false));
    assert_eq!(servers.relayable(&server("docs")), Ok(()));
    assert!(servers.record(&server("docs"), true));
    assert_eq!(servers.relayable(&server("docs")), Err(SERVER_PROXY_TOOLS));
    assert!(servers.record(&server("docs"), false));
    assert_eq!(servers.relayable(&server("docs")), Err(SERVER_PROXY_TOOLS));
}

#[test]
fn every_identity_field_names_another_server() {
    let servers = RelayServers::default();
    servers.record(&server("docs"), false);
    let mut other = server("docs");
    other.identity_hash = "b".repeat(64);
    assert_eq!(servers.relayable(&other), Err(SERVER_UNKNOWN));
    let mut other = server("docs");
    other.harness = "cursor".to_owned();
    assert_eq!(servers.relayable(&other), Err(SERVER_UNKNOWN));
    let mut other = server("docs");
    other.server_id = Some("docs".to_owned());
    assert_eq!(servers.relayable(&other), Err(SERVER_UNKNOWN));
}

#[test]
fn a_server_past_the_bound_stays_unknown() {
    let servers = RelayServers::default();
    for index in 0..MAX_SERVERS {
        assert!(servers.record(&server(&format!("s{index}")), false));
    }
    assert!(!servers.record(&server("late"), false));
    assert_eq!(servers.relayable(&server("late")), Err(SERVER_UNKNOWN));
    // A known server is still updated.
    assert!(servers.record(&server("s0"), true));
    assert_eq!(servers.relayable(&server("s0")), Err(SERVER_PROXY_TOOLS));
    let mut long = server("long");
    long.config_path = "x".repeat(MAX_KEY_BYTES);
    assert!(!RelayServers::default().record(&long, false));
}

#[test]
fn only_tools_the_relay_cannot_send_are_decided_by_the_proxy() {
    // The relay never sends a call to an empty or non-ASCII name.
    for tool in [
        json!({"description": "no name"}),
        json!({"name": 7}),
        json!({"name": ""}),
        json!({"name": "composio_\u{e9}"}),
        json!({"name": "lire_\u{e9}t\u{e9}"}),
    ] {
        assert!(proxy_tool(&tool), "{tool}");
    }
    // The resident reads a Composio wrapper's provider catalog hash itself.
    for tool in [
        json!({"name": "COMPOSIO_SEARCH_TOOLS"}),
        json!({"name": "github__composio_execute"}),
    ] {
        assert!(!proxy_tool(&tool), "{tool}");
    }
}

#[test]
fn a_shell_or_command_tool_no_longer_holds_its_server_back() {
    // The resident decides a package call itself, and a package call it
    // cannot settle marks the server on its way to the fail-closed answer.
    for tool in [
        json!({"name": "bash"}),
        json!({"name": " Run_Command "}),
        json!({"name": "\u{1c}shell"}),
        json!({"name": "exec", "inputSchema": {"properties": {"cmd": {"type": "string"}}}}),
        json!({"name": "exec", "input_schema": {"properties": {"shellCommand": {}}}}),
        json!({"name": "run", "inputSchema": {"$ref": "#/$defs/Run"}}),
        json!({"name": "run", "inputSchema": {"allOf": [{"properties": {"command": {}}}]}}),
        json!({"name": "run", "inputSchema": {"patternProperties": {"^comm": {}}}}),
        json!({"name": "read_file", "inputSchema": {"properties": {"path": {}}}}),
        json!({"name": "read_file", "inputSchema": "object"}),
    ] {
        assert!(!proxy_tool(&tool), "{tool}");
    }
}

#[test]
fn a_report_records_whether_any_tool_is_decided_by_the_proxy() {
    let servers = RelayServers::default();
    let request = McpRelayServerReportRequestV1 {
        guard_home: "/tmp/guard".to_owned(),
        server: server("docs"),
        tools: vec![json!({"name": "read_file"}), json!({"name": "search"})],
    };
    let answer: Value = serde_json::from_slice(&report(&request, &servers).unwrap()).unwrap();
    assert_eq!(answer, json!({"schema": REPORT_SCHEMA, "recorded": true}));
    assert_eq!(servers.relayable(&server("docs")), Ok(()));
    let request = McpRelayServerReportRequestV1 {
        tools: vec![
            json!({"name": "read_file"}),
            json!({"description": "nameless"}),
        ],
        ..request
    };
    report(&request, &servers).unwrap();
    assert_eq!(servers.relayable(&server("docs")), Err(SERVER_PROXY_TOOLS));
}

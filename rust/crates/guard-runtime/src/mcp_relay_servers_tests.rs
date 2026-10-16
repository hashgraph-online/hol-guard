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
fn shell_composio_command_and_nameless_tools_are_decided_by_the_proxy() {
    for tool in [
        json!({"name": "bash"}),
        json!({"name": " Run_Command "}),
        json!({"name": "\u{1c}shell"}),
        json!({"name": "COMPOSIO_SEARCH_TOOLS"}),
        json!({"name": "github__composio_execute"}),
        json!({"name": "exec", "inputSchema": {"properties": {"cmd": {"type": "string"}}}}),
        json!({"name": "exec", "input_schema": {"properties": {"shellCommand": {}}}}),
        // A schema that names its properties elsewhere: the host fills the
        // schema it resolved, so a command argument reaches the call.
        json!({"name": "run", "inputSchema": {"$ref": "#/$defs/Run"}}),
        json!({"name": "run", "inputSchema": {"allOf": [{"properties": {"command": {}}}]}}),
        json!({"name": "run", "inputSchema": {"type": "object", "anyOf": []}}),
        json!({"name": "run", "input_schema": {"properties": {"path": {}}, "oneOf": []}}),
        json!({"name": "run", "inputSchema": {"if": {}, "then": {}}}),
        json!({"name": "run", "inputSchema": {"if": {}, "else": {}}}),
        json!({"name": "run", "inputSchema": {"$dynamicRef": "#run"}}),
        json!({"name": "run", "inputSchema": {"$recursiveRef": "#"}}),
        json!({
            "name": "run",
            "inputSchema": {
                "properties": {"path": {}},
                "dependentSchemas": {"path": {"properties": {"command": {}}}}
            }
        }),
        json!({
            "name": "run",
            "input_schema": {"properties": {"path": {}}, "dependencies": {"path": ["command"]}}
        }),
        json!({"name": "run", "inputSchema": {"patternProperties": {"^comm": {}}}}),
        json!({"description": "no name"}),
        json!({"name": 7}),
    ] {
        assert!(proxy_tool(&tool), "{tool}");
    }
    for tool in [
        json!({"name": "read_file", "inputSchema": {"properties": {"path": {}}}}),
        json!({"name": "bash_history_search"}),
        json!({"name": "commands", "inputSchema": {"properties": {"commands": {}}}}),
        // `$defs` alone names no property of this object, and a schema the
        // relay cannot read as an object declares nothing either.
        json!({"name": "read_file", "inputSchema": {"properties": {}, "$defs": {"X": {}}}}),
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
        tools: vec![json!({"name": "read_file"}), json!({"name": "terminal"})],
        ..request
    };
    report(&request, &servers).unwrap();
    assert_eq!(servers.relayable(&server("docs")), Err(SERVER_PROXY_TOOLS));
}

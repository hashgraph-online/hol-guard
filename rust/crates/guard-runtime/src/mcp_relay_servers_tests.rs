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
fn a_reported_server_is_relayable() {
    let servers = RelayServers::default();
    assert!(servers.record(&server("docs")));
    assert_eq!(servers.relayable(&server("docs")), Ok(()));
    assert!(servers.record(&server("docs")));
    assert_eq!(servers.relayable(&server("docs")), Ok(()));
}

#[test]
fn every_identity_field_names_another_server() {
    let servers = RelayServers::default();
    servers.record(&server("docs"));
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
        assert!(servers.record(&server(&format!("s{index}"))));
    }
    assert!(!servers.record(&server("late")));
    assert_eq!(servers.relayable(&server("late")), Err(SERVER_UNKNOWN));
    // A known server is still recorded.
    assert!(servers.record(&server("s0")));
    assert_eq!(servers.relayable(&server("s0")), Ok(()));
    let mut long = server("long");
    long.config_path = "x".repeat(MAX_KEY_BYTES);
    assert!(!RelayServers::default().record(&long));
}

#[test]
fn a_catalog_never_hands_its_server_to_the_proxy() {
    // A nameless tool, a shell tool and a command-shaped schema all leave the
    // server relayable: the resident decides or refuses each call itself.
    let servers = RelayServers::default();
    let request = McpRelayServerReportRequestV1 {
        guard_home: "/tmp/guard".to_owned(),
        server: server("docs"),
        tools: vec![
            json!({"name": "read_file"}),
            json!({"description": "nameless"}),
            json!({"name": ""}),
            json!({"name": "bash"}),
            json!({"name": "exec", "inputSchema": {"properties": {"cmd": {"type": "string"}}}}),
        ],
    };
    let answer: Value = serde_json::from_slice(&report(&request, &servers).unwrap()).unwrap();
    assert_eq!(answer, json!({"schema": REPORT_SCHEMA, "recorded": true}));
    assert_eq!(servers.relayable(&server("docs")), Ok(()));
}

#[test]
fn the_relay_never_sends_a_call_to_an_empty_name() {
    assert!(!sendable_name(""));
    assert!(sendable_name("read_file"));
    assert!(sendable_name("lire_\u{e9}t\u{e9}"));
}

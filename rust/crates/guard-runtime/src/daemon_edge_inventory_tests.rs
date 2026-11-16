use super::super::ReadConfig;
use super::*;

fn edge() -> (tempfile::TempDir, ReadConfig, NativeReads) {
    let home = tempfile::tempdir().unwrap();
    let guard_home = home.path().canonicalize().unwrap();
    rusqlite::Connection::open(guard_home.join("guard.db"))
        .unwrap()
        .execute_batch(
            "create table guard_review_outbox_events (
                 stream_sequence integer primary key, payload_hash text not null default '');
             create table artifact_inventory (
                 artifact_id text not null, harness text not null, artifact_name text not null,
                 artifact_type text not null, source_scope text not null,
                 config_path text not null, publisher text, origin_url text,
                 launch_command text, transport text, first_seen_at text not null,
                 last_seen_at text not null, last_changed_at text, last_approved_at text,
                 removed_at text, present integer not null default 1,
                 last_policy_action text not null, artifact_hash text not null,
                 primary key (artifact_id, harness));
             insert into artifact_inventory values ('codex:mcp:a', 'codex', 'a', 'mcp_server',
                 'global', '/c', null, null, null, 'stdio', 't1', 't2', null, null, null, 1,
                 'allow', 'h1');
             insert into artifact_inventory values ('zz:x', 'zz', 'x', 'skill', 'project',
                 '/z', null, null, null, null, 't1', 't2', null, null, null, 0, 'block', 'h2');",
        )
        .unwrap();
    let handshake = json!({
        "schema": super::super::HANDSHAKE_SCHEMA,
        format!("{}_token", "auth"): "inventory-test-value",
        "guard_home": guard_home.to_str().unwrap(),
        "store_path": guard_home.join("guard.db").to_str().unwrap(),
        "source": "default",
        "busy_timeout_ms": 2000,
    });
    let config = ReadConfig::from_line(&serde_json::to_vec(&handshake).unwrap()).unwrap();
    (home, config, NativeReads::new(None))
}

#[test]
fn enriches_installed_items_and_lists_the_rest_in_registry_order() {
    let (_home, config, reads) = edge();
    let (status, body) = list(&config, &reads).unwrap();
    assert_eq!(status, 200);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    let codex = items
        .iter()
        .find(|item| item["harness"] == "codex")
        .unwrap();
    assert_eq!(codex["artifact_name"], "a");
    assert_eq!(codex["contract"]["display_name"], "Codex");
    assert_eq!(codex["contract"]["install_aliases"], json!(["codex"]));
    let unknown = items.iter().find(|item| item["harness"] == "zz").unwrap();
    assert_eq!(unknown["contract"], json!({}));
    let available: Vec<&str> = body["available"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["harness"].as_str().unwrap())
        .collect();
    let registry: Vec<String> = contracts()
        .unwrap()
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert_eq!(
        available,
        registry
            .iter()
            .filter(|name| *name != "codex")
            .map(String::as_str)
            .collect::<Vec<_>>()
    );
    assert!(body["available"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["status"] == "unknown" && row["contract"]["harness"] == row["harness"]));
}

#[test]
fn a_store_the_edge_cannot_read_goes_to_the_daemon() {
    let (home, config, reads) = edge();
    std::fs::remove_file(home.path().join("guard.db")).unwrap();
    std::fs::write(home.path().join("guard.db"), b"not a database").unwrap();
    assert_eq!(list(&config, &reads), None);
}

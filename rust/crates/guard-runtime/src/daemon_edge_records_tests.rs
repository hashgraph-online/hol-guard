use super::super::ReadConfig;
use super::*;

struct Store {
    config: ReadConfig,
    reads: NativeReads,
    _home: tempfile::TempDir,
}

fn store(operation_metadata: &str) -> Store {
    let home = tempfile::tempdir().unwrap();
    let guard_home = home.path().canonicalize().unwrap();
    let connection = rusqlite::Connection::open(guard_home.join("guard.db")).unwrap();
    let token_column = format!("{}_token", "resume");
    connection
        .execute_batch(&format!(
            "create table guard_review_outbox_events (
                 stream_sequence integer primary key autoincrement,
                 payload_hash text not null default '');
             create table guard_sessions (
                 session_id text primary key, harness text not null, surface text not null,
                 status text not null, client_name text not null, client_title text,
                 client_version text, workspace text, capabilities_json text not null,
                 created_at text not null, updated_at text not null);
             create table guard_operations (
                 operation_id text primary key, session_id text not null,
                 harness text not null, operation_type text not null, status text not null,
                 approval_request_ids_json text not null, {token_column} text,
                 metadata_json text not null, created_at text not null,
                 updated_at text not null);
             create table guard_client_attachments (
                 client_id text primary key, surface text not null, session_id text,
                 metadata_json text not null default '{{}}', lease_id text not null default '',
                 lease_expires_at text, attached_at text not null, last_seen_at text not null);
             insert into guard_client_attachments values ('c-live', 'cli', 's-1',
                 '{{\"pid\": 7}}', 'l-1', '2999-01-01T00:00:00+00:00', 't1',
                 '2999-01-01T00:00:00+00:00');
             insert into guard_client_attachments values ('c-gone', 'cli', 's-1', '{{}}',
                 'l-2', '2000-01-01T00:00:00+00:00', 't1', '2000-01-01T00:00:00+00:00');
             insert into guard_sessions values ('s-1', 'codex', 'cli', 'active', 'Codex',
                 null, '1.2', '/work', '[\"approvals\"]', 't1', 't2');",
        ))
        .unwrap();
    connection
        .execute(
            "insert into guard_operations values ('op-1', 's-1', 'codex', 'install',
             'pending', '[\"req-1\"]', null, ?1, 't1', 't2')",
            [operation_metadata],
        )
        .unwrap();
    drop(connection);
    let handshake = json!({
        "schema": super::super::HANDSHAKE_SCHEMA,
        "auth_token": "records-test-token",
        "guard_home": guard_home.to_str().unwrap(),
        "store_path": guard_home.join("guard.db").to_str().unwrap(),
        "source": "default",
        "busy_timeout_ms": 2000,
    });
    let config = ReadConfig::from_line(&serde_json::to_vec(&handshake).unwrap()).unwrap();
    Store {
        config,
        reads: NativeReads::new(None),
        _home: home,
    }
}

#[test]
fn lists_sessions_as_the_daemon_maps_their_rows() {
    let store = store("{}");
    let (status, body) = sessions(&store.config, &store.reads).unwrap();
    assert_eq!(status, 200);
    assert_eq!(
        body,
        json!({"items": [{
            "session_id": "s-1", "harness": "codex", "surface": "cli", "status": "active",
            "client_name": "Codex", "client_title": null, "client_version": "1.2",
            "workspace": "/work", "capabilities": ["approvals"],
            "created_at": "t1", "updated_at": "t2",
        }]})
    );
}

#[test]
fn reads_an_operation_or_answers_not_found() {
    let store = store("{\"step\": 2}");
    let (status, body) = operation("op-1", &store.config, &store.reads).unwrap();
    assert_eq!(status, 200);
    assert_eq!(body["approval_request_ids"], json!(["req-1"]));
    assert_eq!(body["metadata"], json!({"step": 2}));
    assert_eq!(body[format!("{}_token", "resume")], Value::Null);
    assert_eq!(body["operation_type"], json!("install"));
    assert_eq!(
        operation("op-2", &store.config, &store.reads),
        Some((404, json!({"error": "not_found"})))
    );
}

#[test]
fn resumes_a_session_with_its_live_attachments_and_operations() {
    let store = store("{}");
    let (status, body) = session_resume("s-1", &store.config, &store.reads).unwrap();
    assert_eq!(status, 200);
    assert_eq!(body["session"]["session_id"], "s-1");
    assert_eq!(
        body["attachments"],
        json!([{
            "client_id": "c-live", "surface": "cli", "session_id": "s-1",
            "metadata": {"pid": 7}, "lease_id": "l-1",
            "lease_expires_at": "2999-01-01T00:00:00+00:00", "attached_at": "t1",
            "last_seen_at": "2999-01-01T00:00:00+00:00",
        }])
    );
    assert_eq!(body["operations"][0]["operation_id"], "op-1");
    assert_eq!(
        session_resume("s-2", &store.config, &store.reads),
        Some((404, json!({"error": "not_found"})))
    );
}

#[test]
fn relays_operations_whose_json_python_reads_or_prints_differently() {
    for metadata in ["{\"ratio\": 0.5}", "{\"big\": 1e400}", "NaN", "{bad"] {
        let store = store(metadata);
        assert_eq!(
            operation("op-1", &store.config, &store.reads),
            None,
            "{metadata}"
        );
    }
}

#[test]
fn relays_analytics_windows_python_parses_its_own_way() {
    let store = store("{}");
    for query in ["activity_days=x", "trend_days=1.5", "top_limit="] {
        assert_eq!(
            receipt_analytics(query, &store.config, &store.reads),
            None,
            "{query}"
        );
    }
}

#[test]
fn stamps_now_with_the_microseconds_python_always_prints() {
    let now = now_isoformat().unwrap();
    assert!(now.ends_with("+00:00"), "{now}");
    let fraction = now.split('.').nth(1).unwrap();
    assert_eq!(fraction.len(), "000000+00:00".len(), "{now}");
}

#[test]
fn routes_record_paths_the_way_the_daemon_dispatches_them() {
    let store = store("{}");
    let route =
        |path: &str, query: &str| super::super::route(path, query, &store.config, &store.reads);
    assert_eq!(route("/v1/operations/op-1", "").unwrap().0, 200);
    assert_eq!(route("/v1/operations/op-1/items", ""), None);
    assert_eq!(route("/v1/sessions", "").unwrap().0, 200);
    assert_eq!(route("/v1/sessions/s-1/resume", "").unwrap().0, 200);
    assert_eq!(route("/v1/sessions/s-1/archive", ""), None);
    // Analytics never falls through to a receipt lookup.
    assert_eq!(route("/v1/receipts/analytics", "top_limit=x"), None);
    assert_eq!(
        route("/v1/connect/state", ""),
        Some((
            410,
            json!({
                "error": "legacy_pairing_disabled",
                "message": "Use hol-guard connect for browser OAuth.",
            })
        ))
    );
}

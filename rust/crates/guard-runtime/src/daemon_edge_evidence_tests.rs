use super::super::ReadConfig;
use super::*;

const HOME: &str = "/home/tester";

struct Store {
    config: ReadConfig,
    reads: NativeReads,
    _home: tempfile::TempDir,
}

fn store(user_home: Option<&str>) -> Store {
    let home = tempfile::tempdir().unwrap();
    let guard_home = home.path().canonicalize().unwrap();
    let connection = rusqlite::Connection::open(guard_home.join("guard.db")).unwrap();
    connection
        .execute_batch(
            "create table guard_evidence (
                 evidence_id text not null primary key,
                 action_id text not null default '', request_id text not null default '',
                 harness text not null default '', workspace text not null default '',
                 signal_id text not null default '', category text not null default '',
                 severity text not null default '', confidence real not null default 0.0,
                 summary text not null default '', details_json text not null default '{}',
                 action_identity text, created_at text not null);",
        )
        .unwrap();
    let secret = format!("pass{}=hunter2 near /Users/alice/x", "word");
    let bearer = format!("Bear{} abcdefghijklmnop1234 sent", "er");
    for (id, harness, workspace, summary, created_at) in [
        ("ev-1", "codex", "/home/tester/repo", secret.as_str(), "t1"),
        ("ev-2", "codex", "/work", bearer.as_str(), "t2"),
        ("ev-3", "cursor", "/work", "plain", "t3"),
    ] {
        connection
            .execute(
                "insert into guard_evidence values (?1, 'a', 'r', ?2, ?3, 's', 'secrets',
                 'high', 0.75, ?4, '{\"raw\": 1}', null, ?5)",
                rusqlite::params![id, harness, workspace, summary, created_at],
            )
            .unwrap();
    }
    drop(connection);
    let mut handshake = json!({
        "schema": super::super::HANDSHAKE_SCHEMA,
        "auth_token": "evidence-test-token",
        "guard_home": guard_home.to_str().unwrap(),
        "store_path": guard_home.join("guard.db").to_str().unwrap(),
        "source": "default",
        "busy_timeout_ms": 2000,
    });
    if let Some(user_home) = user_home {
        handshake["user_home"] = json!(user_home);
    }
    let config = ReadConfig::from_line(&serde_json::to_vec(&handshake).unwrap()).unwrap();
    Store {
        config,
        reads: NativeReads::new(None),
        _home: home,
    }
}

fn read(store: &Store, query: &str) -> Option<(u16, Value)> {
    list(query, &store.config, &store.reads)
}

#[test]
fn lists_evidence_newest_first_redacted_as_the_daemon_writes_it() {
    let store = store(Some(HOME));
    let (status, body) = read(&store, "harness=codex").unwrap();
    assert_eq!(status, 200);
    assert_eq!(body["total"], json!(2));
    let items = body["items"].as_array().unwrap();
    // `store_evidence._redact_export_value` gives the same text for each.
    assert_eq!(items[0]["summary"], json!("Bearer ***** sent"));
    assert_eq!(items[0]["workspace"], json!("/work"));
    assert_eq!(items[1]["summary"], json!("password=*****"));
    assert_eq!(items[1]["workspace"], json!("~/repo"));
    assert_eq!(items[1]["confidence"], json!(0.75));
    assert_eq!(items[1]["action_identity"], Value::Null);
    let keys: Vec<&str> = items[1]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let mut expected = FIELDS.to_vec();
    expected.sort_unstable();
    assert_eq!(keys, expected);
}

#[test]
fn takes_the_limit_and_filters_the_daemon_reads() {
    let store = store(Some(HOME));
    let (_, body) = read(&store, "limit=1").unwrap();
    assert_eq!(body["total"], json!(3));
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
    assert_eq!(body["items"][0]["evidence_id"], json!("ev-3"));
    let (_, body) = read(&store, "limit=0&severity=low").unwrap();
    assert_eq!(body, json!({"items": [], "total": 0}));
}

#[test]
fn leaves_what_it_cannot_read_the_same_way_to_the_daemon() {
    // The daemon reads a limit it cannot parse as its default.
    assert!(read(&store(Some(HOME)), "limit=ten").is_none());
    assert!(read(&store(Some(HOME)), "harness=%zz").is_none());
    // Without the daemon's home the edge cannot shorten paths as it does.
    assert!(read(&store(None), "").is_none());
}

#[test]
fn leaves_text_that_is_not_ascii_to_the_daemon() {
    let store = store(Some(HOME));
    let token = format!("seen \u{301}gh{}_abcdefgh12345678", "p");
    rusqlite::Connection::open(&store.config.store_path)
        .unwrap()
        .execute(
            "update guard_evidence set summary = ?1 where evidence_id = 'ev-3'",
            [token],
        )
        .unwrap();
    assert!(read(&store, "harness=cursor").is_none());
    assert!(read(&store, "harness=codex").is_some());
}

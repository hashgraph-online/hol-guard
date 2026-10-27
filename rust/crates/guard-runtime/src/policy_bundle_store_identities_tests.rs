use serde_json::json;

use super::*;

const NOW: &str = "2026-01-01T00:00:00+00:00";

fn store() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table sync_state (state_key text primary key, payload_json text not null, \
             updated_at text not null);
             create table guard_devices (device_key text primary key, installation_id text, \
             device_label text);",
        )
        .unwrap();
    connection
}

fn sync_state(connection: &Connection, key: &str, payload: &str) {
    connection
        .execute(
            "insert or replace into sync_state values (?1, ?2, ?3)",
            rusqlite::params![key, payload, NOW],
        )
        .unwrap();
}

#[test]
fn a_missing_or_empty_bundle_authorizes_nothing() {
    let connection = store();
    assert_eq!(cached_bundle_identities(&connection, NOW), Some(Vec::new()));
    for payload in ["{}", "[1]", "\"text\"", "null"] {
        sync_state(&connection, "policy_bundle", payload);
        assert_eq!(
            cached_bundle_identities(&connection, NOW),
            Some(Vec::new()),
            "{payload}"
        );
    }
}

#[test]
fn a_bundle_the_store_cannot_parse_defers() {
    let connection = store();
    sync_state(&connection, "policy_bundle", "not json");
    assert_eq!(cached_bundle_identities(&connection, NOW), None);
    sync_state(&connection, "policy_bundle", "{}");
    assert_eq!(
        cached_bundle_identities(&connection, "not a time"),
        Some(Vec::new())
    );
    sync_state(&connection, "policy_bundle", r#"{"bundleVersion": 1}"#);
    assert_eq!(cached_bundle_identities(&connection, "not a time"), None);
}

#[cfg(unix)]
#[test]
fn an_unsigned_bundle_authorizes_nothing() {
    let connection = store();
    sync_state(
        &connection,
        "policy_bundle",
        r#"{"bundleVersion": 1, "decisions": [{"harness": "codex"}]}"#,
    );
    assert_eq!(cached_bundle_identities(&connection, NOW), Some(Vec::new()));
}

#[test]
fn an_identity_is_keyed_the_way_the_store_saves_the_row() {
    let decision = |scope: &str, expires: Value| {
        json!({
            "harness": "codex",
            "scope": scope,
            "action": "block",
            "artifact_id": "codex:project:server",
            "workspace": "/work/space",
            "reason": "managed",
            "owner": "team",
            "source": "policy-bundle",
            "expires_at": expires,
        })
    };
    let artifact = identity(decision("artifact", Value::Null).as_object().unwrap()).unwrap();
    assert_eq!(
        artifact,
        vec![
            json!("codex"),
            json!("artifact"),
            json!("codex:project:server"),
            Value::Null,
            Value::Null,
            Value::Null,
            json!("block"),
            json!("managed"),
            json!("team"),
            json!("policy-bundle"),
            Value::Null,
        ]
    );
    let harness = identity(decision("harness", Value::Null).as_object().unwrap()).unwrap();
    assert_eq!(
        harness[2],
        json!(artifact_family_key(Some("codex:project:server")))
    );
    let workspace = identity(
        decision("workspace", json!("2026-02-01T00:00:00Z"))
            .as_object()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        workspace[4],
        json!(workspace_policy_key(Some("/work/space")))
    );
    assert_eq!(
        workspace[10],
        json!(canonical_utc_timestamp("2026-02-01T00:00:00Z").unwrap())
    );
    let global = identity(decision("global", Value::Null).as_object().unwrap()).unwrap();
    assert_eq!(global[4], Value::Null);
    let publisher = identity(decision("publisher", Value::Null).as_object().unwrap()).unwrap();
    assert_eq!(publisher[2], Value::Null);
    // An expiry the store cannot canonicalize defers.
    assert_eq!(
        identity(decision("artifact", json!("tomorrow")).as_object().unwrap()),
        None
    );
}

#[test]
fn a_generic_label_yields_to_the_host_name() {
    assert_eq!(
        machine_display_name("Dev-Box.example.com").as_deref(),
        Some("Dev-Box")
    );
    assert_eq!(machine_display_name(" localhost.local "), None);
    assert_eq!(machine_display_name(""), None);
    assert_eq!(
        machine_display_name(&"h".repeat(200)).map(|name| name.chars().count()),
        Some(DEVICE_NAME_CHARS)
    );
    assert!(generic_label(" Local Machine "));
    assert!(!generic_label("build-agent"));

    let connection = store();
    assert_eq!(
        device_display_name(&connection, "build-agent").as_deref(),
        Some("build-agent")
    );
    // A generic label the user chose stays.
    sync_state(
        &connection,
        DEVICE_LABEL_CHOICE_KEY,
        r#"{"label": "localhost"}"#,
    );
    assert_eq!(
        device_display_name(&connection, "localhost").as_deref(),
        Some("localhost")
    );
}

#[test]
fn chunks_split_compact_json_by_characters() {
    assert_eq!(chunks(&json!({})), Some(vec!["{}".to_owned()]));
    let long = json!("é".repeat(CHUNK_CHARS));
    let parts = chunks(&long).unwrap();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].chars().count(), CHUNK_CHARS);
    assert_eq!(parts.concat(), serde_json::to_string(&long).unwrap());
}

#[test]
fn the_ordering_view_keeps_only_the_ordering_keys() {
    assert_eq!(
        ordering_view(&json!({"bundleVersion": 2, "issuedAt": "t", "decisions": []})),
        json!({"bundleVersion": 2, "issuedAt": "t"})
    );
}

/// A document past the store's limit is refused, as `policy_bundle_chunks`
/// refuses it, so the bundle authorizes nothing.
#[test]
fn a_document_past_the_limit_is_not_chunked() {
    let at_limit = json!("é".repeat(MAX_DOCUMENT_CHARS - 2));
    assert_eq!(
        chunks(&at_limit).map(|chunks| chunks.concat().chars().count()),
        Some(MAX_DOCUMENT_CHARS)
    );
    assert_eq!(chunks(&json!("é".repeat(MAX_DOCUMENT_CHARS - 1))), None);
}

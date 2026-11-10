use rusqlite::Connection;

use super::*;
use crate::guard_store_cmd_vectors_tests::temp_home;

struct Edge {
    home: std::path::PathBuf,
    config: ReadConfig,
    reads: NativeReads,
}

fn edge(tag: &str, toml: &str) -> Edge {
    let home = temp_home(&format!("edge-settings-write-{tag}"));
    if !toml.is_empty() {
        std::fs::write(home.join("config.toml"), toml).unwrap();
    }
    let db = home.join("guard.db");
    Connection::open(&db)
        .unwrap()
        .execute_batch(
            "create table guard_review_outbox_events (
                 stream_sequence integer primary key, payload_hash text not null default '');
             create table guard_events (
                 event_id integer primary key autoincrement, event_name text not null,
                 payload_json text not null, occurred_at text not null);",
        )
        .unwrap();
    let handshake = json!({
        "schema": super::super::super::HANDSHAKE_SCHEMA,
        format!("{}_token", "auth"): "settings-write-test-value",
        "guard_home": home.to_str().unwrap(),
        "store_path": db.to_str().unwrap(),
        "source": "default",
        "busy_timeout_ms": 2000,
        "session_signals": ["sid=1"],
    });
    Edge {
        config: ReadConfig::from_line(&serde_json::to_vec(&handshake).unwrap()).unwrap(),
        reads: NativeReads::new(None),
        home,
    }
}

fn entries(value: Value) -> Vec<(String, PyVal)> {
    match crate::pyjson::parse(&value.to_string()).unwrap() {
        PyVal::Dict(entries) => entries,
        _ => unreachable!(),
    }
}

fn post(edge: &Edge, payload: Value, missing_error: &str) -> Option<(u16, Value)> {
    let Value::Object(map) = payload.clone() else {
        unreachable!()
    };
    apply(
        &entries(payload),
        &map,
        missing_error,
        &edge.config,
        &edge.reads,
    )
}

fn events(edge: &Edge) -> Vec<(String, String)> {
    let connection = Connection::open(edge.home.join("guard.db")).unwrap();
    let mut statement = connection
        .prepare("select event_name, payload_json from guard_events order by event_id")
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn a_presentation_change_is_written_without_a_gate_check() {
    let edge = edge("presentation", "");
    let (status, body) = post(
        &edge,
        json!({"settings": {"presentation_mode": "technical", "presentation_mode_explicit": true}}),
        "invalid_settings",
    )
    .unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["settings"]["presentation_mode"], "technical");
    let written = std::fs::read_to_string(edge.home.join("config.toml")).unwrap();
    assert!(
        written.contains("presentation_mode = \"technical\""),
        "{written}"
    );
    assert!(events(&edge).is_empty());
}

#[test]
fn an_invalid_presentation_change_is_refused_as_the_daemon_refuses_it() {
    let edge = edge("invalid", "");
    let (status, body) = post(
        &edge,
        json!({"settings": {"presentation_mode": "loud"}}),
        "invalid_settings_import",
    )
    .unwrap();
    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_settings");
    assert!(body["message"]
        .as_str()
        .is_some_and(|text| !text.is_empty()));
    assert!(!edge.home.join("config.toml").exists());
}

#[test]
fn a_payload_without_settings_names_the_route_error() {
    let edge = edge("missing", "");
    for (missing_error, payload) in [
        ("invalid_settings", json!({})),
        ("invalid_settings_import", json!({"settings": []})),
    ] {
        assert_eq!(
            post(&edge, payload, missing_error),
            Some((400, json!({"error": missing_error})))
        );
    }
}

#[test]
fn an_unset_gate_without_a_resident_still_refuses_unentitled_sync() {
    let edge = edge("relay", "mode = \"prompt\"\n");
    let answer = post(
        &edge,
        json!({"settings": {"sync": true}}),
        "invalid_settings",
    );
    assert_eq!(
        answer
            .as_ref()
            .map(|(status, body)| (*status, body["error"].clone())),
        Some((400, json!("invalid_settings")))
    );
    let kept = std::fs::read_to_string(edge.home.join("config.toml")).unwrap();
    assert_eq!(kept, "mode = \"prompt\"\n");
}

#[test]
fn a_reset_needs_its_confirmation() {
    let edge = edge("reset", "");
    let Value::Object(payload) = json!({"confirm": "yes"}) else {
        unreachable!()
    };
    assert_eq!(
        reset(&payload, &edge.config, &edge.reads),
        Some((
            400,
            json!({"error": "confirmation_required", "confirm": "reset-local-settings"})
        ))
    );
}

#[test]
fn posture_changes_are_recorded_as_the_daemon_records_them() {
    let edge = edge(
        "events",
        "protection_posture = \"watch\"\nprotection_posture_explicit = true\n\
         [harness_postures]\ncursor = \"extra_careful\"\n",
    );
    let updated = Loaded::read(&edge.home).unwrap();
    let written = json!({
        "previous": "protected",
        "previous_explicit": false,
        "selected": true,
        "harness_postures": {"codex": "watch"},
    });
    record_posture_events(&edge.config, &edge.reads, &written, &updated).unwrap();
    let recorded: Vec<(String, String)> = events(&edge);
    assert_eq!(
        recorded,
        vec![
            (
                "guard.protection.posture_selected".to_owned(),
                r#"{"previous": "protected", "value": "watch", "source": "settings", "auto": false}"#
                    .to_owned()
            ),
            (
                "guard.protection.watch_entered".to_owned(),
                r#"{"previous": "protected", "source": "settings"}"#.to_owned()
            ),
            (
                "guard.protection.harness_posture_selected".to_owned(),
                r#"{"harness": "codex", "previous": "watch", "value": "inherit", "source": "settings", "auto": false}"#
                    .to_owned()
            ),
            (
                "guard.protection.harness_posture_selected".to_owned(),
                r#"{"harness": "cursor", "previous": "inherit", "value": "extra_careful", "source": "settings", "auto": false}"#
                    .to_owned()
            ),
        ]
    );
}

#[test]
fn truthiness_matches_python() {
    for value in [
        json!(null),
        json!(false),
        json!(0),
        json!(""),
        json!([]),
        json!({}),
    ] {
        assert!(!truthy(&value), "{value}");
    }
    for value in [
        json!(true),
        json!(1),
        json!("x"),
        json!([0]),
        json!({"a": 0}),
    ] {
        assert!(truthy(&value), "{value}");
    }
}

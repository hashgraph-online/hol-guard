use super::super::HANDSHAKE_SCHEMA;
use super::*;
use crate::guard_store_cmd_vectors_tests::temp_home;

/// Recorded from the daemon's `_settings_response_payload(guard_home,
/// editable_guard_settings(load_guard_config(guard_home)))` and
/// `_settings_export_payload`, with the Guard home written as `{HOME}`.
const VECTORS: &str = include_str!("../testdata/daemon_edge_settings_vectors.json");

fn config(home: &Path) -> ReadConfig {
    let mut handshake = json!({
        "schema": HANDSHAKE_SCHEMA,
        "auth_token": "settings-test-value",
        "guard_home": home.to_str().unwrap(),
        "store_path": home.join("guard.db").to_str().unwrap(),
        "source": "default",
        "busy_timeout_ms": 2000,
    });
    handshake["session_signals"] = json!(["sid=1"]);
    ReadConfig::from_line(&serde_json::to_vec(&handshake).unwrap()).unwrap()
}

#[test]
fn settings_without_the_daemon_session_are_left_to_the_daemon() {
    let home = temp_home("edge-settings-no-session");
    let mut config = config(&home);
    config.session_signals = None;
    assert_eq!(settings(&config), None);
    assert_eq!(export(&config), None);
}

fn with_home(value: Value, home: &Path) -> Value {
    let text = serde_json::to_string(&value).unwrap();
    serde_json::from_str(&text.replace(home.to_str().unwrap(), "{HOME}")).unwrap()
}

#[test]
fn settings_match_the_recorded_daemon_answers() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let home = temp_home(&format!("edge-settings-{name}"));
        let toml = case["config_toml"].as_str().unwrap();
        if !toml.is_empty() {
            std::fs::write(home.join("config.toml"), toml).unwrap();
        }
        let config = config(&home);
        let (status, body) = settings(&config).expect(name);
        assert_eq!(status, 200, "{name}");
        assert_eq!(with_home(body, &home), case["settings"], "{name}");
        let (status, body) = export(&config).expect(name);
        assert_eq!(status, 200, "{name}");
        assert_eq!(with_home(body, &home), case["export"], "{name}");
    }
}

#[test]
fn a_watch_to_stamp_or_revert_goes_to_the_daemon() {
    for (name, toml) in [
        (
            "unstamped",
            "protection_posture = \"watch\"\nwatch_auto_revert_hours = 4\n",
        ),
        (
            "expired",
            "protection_posture = \"watch\"\nwatch_entered_at = \"2000-01-01T00:00:00+00:00\"\n",
        ),
        (
            "harness-expired",
            "[harness_postures]\ncursor = \"watch\"\n[harness_watch_entered_at]\ncursor = \"2000-01-01T00:00:00+00:00\"\n",
        ),
    ] {
        let home = temp_home(&format!("edge-settings-watch-{name}"));
        std::fs::write(home.join("config.toml"), toml).unwrap();
        let config = config(&home);
        assert_eq!(settings(&config), None, "{name}");
        assert!(export(&config).is_some(), "{name}");
    }
}

#[test]
fn an_unreadable_configuration_goes_to_the_daemon() {
    let home = temp_home("edge-settings-unreadable");
    std::fs::write(home.join("config.toml"), "mode = [").unwrap();
    let config = config(&home);
    assert_eq!(settings(&config), None);
    assert_eq!(export(&config), None);
}

#[test]
fn every_registered_harness_has_a_capability_row() {
    let rows = protection_capabilities().unwrap();
    let harnesses: Vec<&str> = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["harness"].as_str().unwrap())
        .collect();
    assert_eq!(harnesses, registered_harness_ids().collect::<Vec<_>>());
}

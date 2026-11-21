//! `setup_detection` and `canonical_managed_installs` against a store file
//! the runtime reads itself.

use std::fs;

use rusqlite::Connection;
use serde_json::{json, Value};

use super::super::dispatch;
use super::Home;

const NOW: &str = "2026-03-10T12:00:00Z";
const INSTALLED: &str = "2026-03-10T10:00:00+00:00";

fn store(home: &Home) -> Connection {
    let connection = Connection::open(home.guard().join("guard.db")).unwrap();
    connection
        .execute_batch(
            "create table if not exists managed_installs (
               harness text primary key, active integer not null, workspace text,
               manifest_json text not null, updated_at text not null);
             create table if not exists sync_state (
               state_key text primary key, payload_json text not null);",
        )
        .unwrap();
    connection
}

fn install(home: &Home, harness: &str, active: bool, manifest: &Value, updated_at: &str) {
    store(home)
        .execute(
            "insert into managed_installs values (?1, ?2, null, ?3, ?4)",
            rusqlite::params![harness, active, manifest.to_string(), updated_at],
        )
        .unwrap();
}

fn cached_check(home: &Home, harness: &str, at: &str, status: &str) {
    let payload = json!({harness: {"at": at, "diagnostics": {"setup_status": status}}});
    store(home)
        .execute(
            "insert into sync_state values ('fleet_posture_diagnostics', ?1)",
            [payload.to_string()],
        )
        .unwrap();
}

fn detect(home: &Home, harness: &str, extra: Value) -> Value {
    let mut fields = json!({"store_home": home.guard(), "now": NOW});
    for (key, value) in extra.as_object().unwrap() {
        fields[key] = value.clone();
    }
    home.ask(harness, "setup_detection", fields)
}

fn fleet(home: &Home) -> Value {
    detect(home, "gemini", json!({"use_fleet_check": true}))
}

fn canonical(home: &Home) -> Value {
    let request = json!({
        "op": "canonical_managed_installs",
        "context": home.context(json!({})),
        "store_home": home.guard(),
    });
    dispatch(&request).unwrap()["installs"].clone()
}

#[test]
fn a_canonical_install_supersedes_its_legacy_alias() {
    let home = Home::new();
    install(&home, "claude", true, &json!({}), INSTALLED);
    install(
        &home,
        "claude-code",
        true,
        &json!({"canonical": true}),
        INSTALLED,
    );
    let installs = canonical(&home);
    assert_eq!(installs.as_array().unwrap().len(), 1);
    assert_eq!(installs[0]["harness"], json!("claude-code"));
    assert_eq!(installs[0]["manifest"], json!({"canonical": true}));
}

#[test]
fn an_active_alias_beats_an_inactive_canonical_row_and_is_renamed() {
    let home = Home::new();
    install(&home, "claude", true, &json!({"alias": true}), INSTALLED);
    install(
        &home,
        "claude-code",
        false,
        &json!({"canonical": true}),
        INSTALLED,
    );
    let installs = canonical(&home);
    assert_eq!(installs.as_array().unwrap().len(), 1);
    assert_eq!(installs[0]["harness"], json!("claude-code"));
    assert_eq!(installs[0]["active"], json!(true));
    assert_eq!(installs[0]["manifest"], json!({"alias": true}));
}

#[test]
fn canonical_installs_are_sorted_and_an_unknown_name_stays_as_stored() {
    let home = Home::new();
    for harness in ["zeta-tool", "codex", "cursor"] {
        install(&home, harness, true, &json!({}), INSTALLED);
    }
    let names: Vec<_> = canonical(&home)
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["harness"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(names, ["codex", "cursor", "zeta-tool"]);
}

#[test]
fn a_home_with_no_store_has_no_installs_and_no_store_is_created() {
    let home = Home::new();
    assert_eq!(canonical(&home), json!([]));
    assert!(!home.guard().join("guard.db").exists());
}

#[test]
fn every_adapter_alias_names_exactly_one_adapter() {
    for spec in super::super::describe::SPECS.iter() {
        for alias in spec.aliases {
            let found = super::super::describe::resolve(alias).unwrap();
            assert_eq!(found.harness, spec.harness, "{alias}");
        }
        assert_eq!(
            super::super::describe::resolve(spec.harness)
                .unwrap()
                .harness,
            spec.harness
        );
    }
}

#[test]
fn the_install_record_alone_says_whether_an_app_is_installed() {
    let home = Home::new();
    let none = detect(&home, "gemini", json!({}));
    assert_eq!(none["installed"], json!(false));
    assert_eq!(none["managed_active"], json!(false));
    assert_eq!(none["needs_repair"], json!(false));
    assert_eq!(none["command_available"], json!(false));
    assert_eq!(none["config_paths"], json!([]));
    install(&home, "gemini", true, &json!({}), INSTALLED);
    let installed = detect(&home, "gemini", json!({}));
    assert_eq!(installed["installed"], json!(true));
    assert_eq!(installed["managed_active"], json!(true));
    let without_store = home.ask("gemini", "setup_detection", json!({"now": NOW}));
    assert_eq!(without_store["installed"], json!(false));
}

#[test]
fn an_inactive_install_is_not_installed() {
    let home = Home::new();
    install(&home, "gemini", false, &json!({}), INSTALLED);
    assert_eq!(
        detect(&home, "gemini", json!({}))["installed"],
        json!(false)
    );
}

#[test]
fn verification_ignores_a_cached_fleet_check() {
    let home = Home::new();
    install(&home, "gemini", true, &json!({}), INSTALLED);
    cached_check(&home, "gemini", "2026-03-10T11:00:00Z", "broken");
    let answer = detect(&home, "gemini", json!({}));
    assert_eq!(answer["installed"], json!(true));
    assert_eq!(answer["needs_repair"], json!(false));
}

#[test]
fn a_current_fleet_check_decides_the_list() {
    let home = Home::new();
    install(&home, "gemini", false, &json!({}), INSTALLED);
    cached_check(&home, "gemini", "2026-03-10T11:00:00Z", "active");
    let answer = fleet(&home);
    assert_eq!(answer["installed"], json!(true));
    assert_eq!(answer["needs_repair"], json!(false));
}

#[test]
fn a_lowercase_zulu_check_time_is_read() {
    let home = Home::new();
    cached_check(&home, "gemini", "2026-03-10T11:00:00z", "active");
    assert_eq!(fleet(&home)["installed"], json!(true));
}

#[test]
fn a_broken_check_needs_repair_even_for_an_inactive_install() {
    let home = Home::new();
    install(&home, "gemini", false, &json!({}), INSTALLED);
    cached_check(&home, "gemini", "2026-03-10T11:00:00Z", "broken");
    let answer = fleet(&home);
    assert_eq!(answer["installed"], json!(false));
    assert_eq!(answer["needs_repair"], json!(true));
}

#[test]
fn a_partial_or_missing_check_needs_repair_only_for_an_active_install() {
    for status in ["partial", "not_found"] {
        let home = Home::new();
        install(&home, "gemini", true, &json!({}), INSTALLED);
        cached_check(&home, "gemini", "2026-03-10T11:00:00Z", status);
        let answer = fleet(&home);
        assert_eq!(answer["installed"], json!(false), "{status}");
        assert_eq!(answer["needs_repair"], json!(true), "{status}");

        let inactive = Home::new();
        install(&inactive, "gemini", false, &json!({}), INSTALLED);
        cached_check(&inactive, "gemini", "2026-03-10T11:00:00Z", status);
        assert_eq!(fleet(&inactive)["needs_repair"], json!(false), "{status}");
    }
}

#[test]
fn a_check_older_than_a_day_or_from_the_future_is_ignored() {
    for at in ["2026-03-09T11:59:00Z", "2026-03-10T12:00:01Z"] {
        let home = Home::new();
        install(&home, "gemini", true, &json!({}), INSTALLED);
        cached_check(&home, "gemini", at, "broken");
        let answer = fleet(&home);
        assert_eq!(answer["installed"], json!(true), "{at}");
        assert_eq!(answer["needs_repair"], json!(false), "{at}");
    }
}

#[test]
fn a_check_just_inside_the_day_still_counts() {
    let home = Home::new();
    cached_check(&home, "gemini", "2026-03-09T12:00:00Z", "active");
    assert_eq!(fleet(&home)["installed"], json!(true));
}

#[test]
fn an_install_change_wins_until_a_check_has_settled_after_it() {
    let home = Home::new();
    install(&home, "gemini", true, &json!({}), INSTALLED);
    cached_check(&home, "gemini", "2026-03-10T10:04:59+00:00", "broken");
    assert_eq!(fleet(&home)["needs_repair"], json!(false));

    let settled = Home::new();
    install(&settled, "gemini", true, &json!({}), INSTALLED);
    cached_check(&settled, "gemini", "2026-03-10T10:05:00+00:00", "broken");
    assert_eq!(fleet(&settled)["needs_repair"], json!(true));
}

#[test]
fn an_unknown_status_or_a_malformed_cache_falls_back_to_the_record() {
    let home = Home::new();
    install(&home, "gemini", true, &json!({}), INSTALLED);
    cached_check(&home, "gemini", "2026-03-10T11:00:00Z", "weird");
    assert_eq!(fleet(&home)["installed"], json!(true));

    let malformed = Home::new();
    install(&malformed, "gemini", true, &json!({}), INSTALLED);
    store(&malformed)
        .execute(
            "insert into sync_state values ('fleet_posture_diagnostics', 'not json')",
            [],
        )
        .unwrap();
    assert_eq!(fleet(&malformed)["installed"], json!(true));

    let other = Home::new();
    install(&other, "gemini", true, &json!({}), INSTALLED);
    cached_check(&other, "cursor", "2026-03-10T11:00:00Z", "broken");
    assert_eq!(fleet(&other)["needs_repair"], json!(false));
}

#[test]
fn a_check_with_no_time_is_ignored() {
    let home = Home::new();
    install(&home, "gemini", true, &json!({}), INSTALLED);
    let payload = json!({"gemini": {"diagnostics": {"setup_status": "broken"}}});
    store(&home)
        .execute(
            "insert into sync_state values ('fleet_posture_diagnostics', ?1)",
            [payload.to_string()],
        )
        .unwrap();
    assert_eq!(fleet(&home)["needs_repair"], json!(false));
}

fn bound_manifest(home: &Home) -> (std::path::PathBuf, Value) {
    let config = home.home().join("settings.json");
    fs::write(&config, "{}").unwrap();
    let request = json!({
        "op": "proof_bind",
        "context": home.context(json!({})),
        "manifest": {"config_path": config},
    });
    let bound = dispatch(&request).unwrap();
    let proof: Value = serde_json::from_str(bound["proof"].as_str().unwrap()).unwrap();
    (config, json!({"protection_artifact_proof": proof}))
}

fn paseo(home: &Home, status: &str) -> Value {
    detect(
        home,
        "paseo",
        json!({"diagnostics": {
            "setup_status": status,
            "command_available": true,
            "config_paths": ["/p/config.json"],
        }}),
    )
}

#[test]
fn paseo_is_installed_only_with_an_active_proven_install_and_an_active_check() {
    let home = Home::new();
    let (config, manifest) = bound_manifest(&home);
    install(&home, "paseo", true, &manifest, INSTALLED);
    let answer = paseo(&home, "active");
    assert_eq!(answer["installed"], json!(true));
    assert_eq!(answer["needs_repair"], json!(false));
    assert_eq!(answer["command_available"], json!(true));
    assert_eq!(answer["config_paths"], json!(["/p/config.json"]));
    assert_eq!(paseo(&home, "partial")["installed"], json!(false));
    fs::write(&config, "{\"changed\": 1}").unwrap();
    assert_eq!(paseo(&home, "active")["installed"], json!(false));
}

#[test]
fn paseo_without_a_proof_or_an_active_record_is_not_installed() {
    let home = Home::new();
    install(&home, "paseo", true, &json!({}), INSTALLED);
    assert_eq!(paseo(&home, "active")["installed"], json!(false));
    let inactive = Home::new();
    let (_, manifest) = bound_manifest(&inactive);
    install(&inactive, "paseo", false, &manifest, INSTALLED);
    assert_eq!(paseo(&inactive, "active")["installed"], json!(false));
}

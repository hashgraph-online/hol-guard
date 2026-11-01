//! Off-state saved evidence inspection/repair needs no interpreter or SDK.
use super::*;
use guard_context_assistance::EvidenceCache;
#[path = "context_assistance_saved_scope_tests.rs"]
mod scope_repair;

fn seed(fixture: &Fixture) -> PathBuf {
    let cache = EvidenceCache::open(&fixture.home).unwrap();
    let key = EvidenceCache::key("dashboard", &fixture.home, &"b".repeat(64)).unwrap();
    drop(
        cache
            .open_slot(&key, 1, crate::context_assistance_data::now_ms())
            .unwrap(),
    );
    fixture
        .home
        .join("context-assistance/saved-evidence")
        .join(key)
        .join("state.json")
}
fn result(value: serde_json::Value) -> serde_json::Value {
    assert_eq!(value["status"], "ok", "{}", value["code"]);
    assert_eq!(value["payload"]["state"]["effective_enabled"], false);
    assert!(value["payload"]["state"]["runtime"].is_null());
    value["payload"]["data"]["result"].clone()
}
fn expire(path: &std::path::Path) {
    let now = crate::context_assistance_data::now_ms();
    age_with_saved_expiry(path, now - 3_600_000);
}
fn age_with_saved_expiry(path: &std::path::Path, expires_at: u64) {
    let now = crate::context_assistance_data::now_ms();
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    record["created_at_ms"] = json!(now - 7_200_000);
    record["last_seen_ms"] = record["created_at_ms"].clone();
    record["expires_at_ms"] = json!(expires_at);
    std::fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
}

#[test]
fn off_state_data_and_removal_work_without_installation_but_read_routes_cannot_delete() {
    let fixture = Fixture::new();
    let path = seed(&fixture);
    let data = result(fixture.ask_input("workspace", json!({"action":"data"})));
    assert_eq!(data["schema"], "guard-cigar-data-summary.v2");
    assert_eq!(data["saved_evidence"]["slots"], 1);
    assert_eq!(data["saved_evidence"]["authority_restored"], false);
    assert_eq!(data["history_entries"], 0);
    assert!(!data.to_string().contains(fixture.home.to_str().unwrap()));
    for action in ["clear", "forget_saved", "forget_history"] {
        assert_eq!(
            fixture.ask_input("workspace", json!({"action":action}))["code"],
            "native_context_assistance_workspace_input_invalid"
        );
        assert!(path.exists());
    }
    let removed = result(fixture.ask_input("workspace_access", json!({"action":"forget_saved"})));
    assert_eq!(removed["cleared_saved"], true);
    assert_eq!(removed["saved_evidence"]["status"], "empty");
    assert!(!path.exists());
    assert!(!fixture
        .home
        .join("context-assistance/installations")
        .exists());
    assert!(fixture.ask("status")["payload"]["state"]["job"].is_null());
}

#[test]
fn corrupt_records_and_configuration_can_be_removed_without_sdk_or_raw_text_disclosure() {
    let fixture = Fixture::new();
    let path = seed(&fixture);
    std::fs::write(&path, b"{private-corrupt-metadata-must-not-render").unwrap();
    std::fs::write(fixture.home.join("config.toml"), b"broken = [").unwrap();
    let data = result(fixture.ask_input("workspace", json!({"action":"data"})));
    assert_eq!(data["saved_evidence"]["status"], "repair_required");
    assert!(!data.to_string().contains("private-corrupt"));
    assert_eq!(
        fixture.ask("activate")["code"],
        "native_context_assistance_configuration_unavailable"
    );
    result(fixture.ask_input("workspace_access", json!({"action":"clear"})));
    assert!(!path.exists());
    assert!(!fixture
        .home
        .join("context-assistance/installations")
        .exists());
}

#[test]
fn expired_inactive_data_is_removed_before_inspection() {
    let fixture = Fixture::new();
    let path = seed(&fixture);
    expire(&path);
    let data = result(fixture.ask_input("workspace", json!({"action":"data"})));
    assert_eq!(data["saved_evidence"]["status"], "empty");
    assert!(!path.exists());
    assert!(!fixture.home.join("cigar-erasure.json").exists());
}

#[test]
fn busy_full_erase_keeps_its_intent_until_explicit_retry_without_activating() {
    let fixture = Fixture::new();
    let path = seed(&fixture);
    let held = EvidenceCache::existing(&fixture.home).unwrap().unwrap();
    assert_eq!(
        fixture.ask_input("workspace_access", json!({"action":"forget_saved"}))["code"],
        "native_context_assistance_context_busy"
    );
    assert!(path.exists());
    let marker = fixture.home.join("cigar-erasure.json");
    let intent = std::fs::read(&marker).unwrap();
    drop(held);
    let data = result(fixture.ask_input("workspace", json!({"action":"data"})));
    assert_eq!(data["saved_evidence"]["status"], "repair_required");
    assert!(path.exists());
    assert_eq!(std::fs::read(&marker).unwrap(), intent);
    let erased = result(fixture.ask_input("workspace_access", json!({"action":"forget_saved"})));
    assert_eq!(erased["saved_evidence"]["status"], "empty");
    assert_eq!(erased["cleared_saved"], true);
    assert!(!path.exists());
    assert!(!marker.exists());
    let state = fixture.ask("status");
    for field in ["runtime", "last_check", "job"] {
        assert!(state["payload"]["state"][field].is_null());
    }
}

#[test]
fn off_state_retention_housekeeper_removes_expired_data_without_status_polling_or_runtime() {
    let fixture = Fixture::new();
    let path = seed(&fixture);
    age_with_saved_expiry(
        &path,
        crate::context_assistance_data::now_ms() + 22 * 3_600_000,
    );
    assert_eq!(
        fixture.ask("status")["payload"]["state"]["availability"],
        "off"
    );
    std::fs::write(
        fixture.home.join("config.toml"),
        "[context_assistance.storage]\nmode='memory'\nretention_hours=1\n",
    )
    .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(35);
    while path.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "native retention worker did not remove expired saved data"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let state = fixture.store.context_assistance().status().unwrap();
    assert_eq!(
        state["preferences"]["storage"]["retention_hours"], 24,
        "retention maintenance must not configure or activate the optional service"
    );
    assert!(!state["effective_enabled"].as_bool().unwrap());
    assert!(state["runtime"].is_null());
    assert!(state["last_check"].is_null());
    assert!(state["job"].is_null());
    assert!(!fixture
        .home
        .join("context-assistance/installations")
        .exists());
}

#[test]
fn resident_startup_sweeps_existing_data_with_current_retention_without_any_context_request() {
    let fixture = Fixture::new();
    assert!(!fixture.home.join("context-assistance").exists());
    let path = seed(&fixture);
    // The original saved expiry is still in the future. A newly shortened
    // off-state preference must apply even when no context surface is used.
    age_with_saved_expiry(
        &path,
        crate::context_assistance_data::now_ms() + 22 * 3_600_000,
    );
    std::fs::write(
        fixture.home.join("config.toml"),
        "[context_assistance.storage]\nmode='memory'\nretention_hours=1\n",
    )
    .unwrap();
    assert_eq!(
        crate::guard_config_load::context_assistance_config(&fixture.home)
            .unwrap()
            .effective
            .storage
            .retention_hours,
        1
    );
    let replacement = PolicySnapshotStore::new(&fixture.home, &"a".repeat(64)).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while path.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "headless startup did not sweep expired data"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    // Direct in-memory status cannot load settings or arm housekeeping.
    let state = replacement.context_assistance().status().unwrap();
    assert_eq!(state["availability"], "off");
    for field in ["runtime", "last_check", "job"] {
        assert!(state[field].is_null());
    }
    assert!(!fixture
        .home
        .join("context-assistance/installations")
        .exists());
    replacement.context_assistance().shutdown();
}

#[test]
fn off_state_prepared_metadata_repair_and_forget_need_no_sdk_or_usable_authentication_key() {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let fixture = Fixture::new();
    let store = guard_context_assistance::EvidenceGenerationStore::open(&fixture.home).unwrap();
    drop(store);
    let root = fixture.home.join("context-assistance/evidence-generations");
    let generation = root.join("e".repeat(64));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&generation)
        .unwrap();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(generation.join("state.json"))
        .unwrap();
    file.write_all(b"{private-broken-preparation-must-not-render")
        .unwrap();
    drop(file);
    let data = result(fixture.ask_input("workspace", json!({"action":"data"})));
    assert_eq!(data["saved_evidence"]["status"], "repair_required");
    assert!(!data.to_string().contains("private-broken"));
    std::fs::remove_file(root.join("authority.key")).unwrap();
    let data = result(fixture.ask_input("workspace", json!({"action":"data"})));
    assert_eq!(data["saved_evidence"]["status"], "repair_required");
    let cleared = result(fixture.ask_input("workspace_access", json!({"action":"forget_saved"})));
    assert_eq!(cleared["cleared_saved"], true);
    assert_eq!(cleared["saved_evidence"]["status"], "empty");
    assert!(!generation.exists());
    assert!(!root.join("authority.key").exists());
    assert!(!fixture
        .home
        .join("context-assistance/installations")
        .exists());
    for field in ["runtime", "last_check", "job"] {
        assert!(fixture.ask("status")["payload"]["state"][field].is_null());
    }
    fixture.store.context_assistance().shutdown();
}

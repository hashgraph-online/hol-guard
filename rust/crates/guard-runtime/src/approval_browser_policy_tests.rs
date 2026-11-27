use std::fs;

#[test]
fn native_only_disables_automatic_browser_fallback() {
    let home = std::env::temp_dir().join(format!(
        "guard-browser-policy-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    fs::create_dir_all(&home).unwrap();
    let mut source = crate::managed_policy_load::ManagedPolicySource::native();
    source.machine_root = Some(home.join("machine-root"));
    fs::create_dir_all(source.machine_root.as_ref().unwrap()).unwrap();
    let config = home.join("config.toml");
    for (policy, allowed) in [
        ("native-only", false),
        ("attention-aware", true),
        ("approval-center", true),
    ] {
        fs::write(&config, format!("approval_surface_policy = {policy:?}\n")).unwrap();
        assert_eq!(
            crate::guard_config_load::approval_browser_allowed_under(&home, &source).unwrap(),
            allowed
        );
    }
    fs::write(&config, "approval_surface_policy = [\n").unwrap();
    assert!(crate::guard_config_load::approval_browser_allowed_under(&home, &source).is_err());
    fs::remove_file(config).unwrap();
    assert!(crate::guard_config_load::approval_browser_allowed_under(&home, &source).unwrap());
    fs::remove_dir_all(home).unwrap();
}

fn surface_home() -> std::path::PathBuf {
    let home = std::env::temp_dir().join(format!(
        "guard-browser-surface-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    fs::create_dir_all(&home).unwrap();
    home
}

fn record_session(home: &std::path::Path, digest: &str, mode: BrowserProfileModeV1, seen: i64) {
    let connection = rusqlite::Connection::open(home.join("guard.db")).unwrap();
    ensure_browser_session_schema(&connection).unwrap();
    record_browser_session(
        &connection,
        &BrowserSessionObservation {
            session_digest: digest,
            harness: "codex",
            harness_session_digest: &"1".repeat(64),
            driver_identity_hash: &"2".repeat(64),
            profile_mode: mode,
            origin: None,
            debugging_port: None,
            now_unix: seen,
        },
    )
    .unwrap();
}

use crate::approval_browser_surface::{approval_page_held, dispatch, withheld};
use crate::browser_session_store::{
    ensure_browser_session_schema, record_browser_session, BrowserSessionObservation,
    BROWSER_SESSION_IDLE_SECONDS,
};
use guard_contracts::BrowserProfileModeV1;

const NOW: i64 = 1_800_000_000;

#[test]
fn no_store_and_no_session_table_hold_nothing() {
    let home = surface_home();
    assert!(!approval_page_held(&home, NOW));
    rusqlite::Connection::open(home.join("guard.db"))
        .unwrap()
        .execute_batch("create table unrelated (id integer)")
        .unwrap();
    assert!(!approval_page_held(&home, NOW));
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn a_live_shared_or_remote_debugging_session_holds_the_page() {
    for (mode, held) in [
        (BrowserProfileModeV1::Shared, true),
        (BrowserProfileModeV1::RemoteDebugging, true),
        (BrowserProfileModeV1::Unknown, true),
        (BrowserProfileModeV1::Isolated, false),
        (BrowserProfileModeV1::Dedicated, false),
    ] {
        let home = surface_home();
        record_session(&home, &"a".repeat(64), mode, NOW - 60);
        assert_eq!(approval_page_held(&home, NOW), held, "{mode:?}");
        fs::remove_dir_all(home).unwrap();
    }
}

#[test]
fn an_idle_session_no_longer_holds_the_page() {
    let home = surface_home();
    record_session(
        &home,
        &"a".repeat(64),
        BrowserProfileModeV1::Shared,
        NOW - BROWSER_SESSION_IDLE_SECONDS - 1,
    );
    assert!(!approval_page_held(&home, NOW));
    record_session(&home, &"b".repeat(64), BrowserProfileModeV1::Isolated, NOW);
    assert!(!approval_page_held(&home, NOW));
    record_session(
        &home,
        &"c".repeat(64),
        BrowserProfileModeV1::Shared,
        NOW - BROWSER_SESSION_IDLE_SECONDS,
    );
    assert!(approval_page_held(&home, NOW));
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn a_withheld_page_prints_the_link_for_the_person() {
    let home = surface_home();
    let link = "http://127.0.0.1:4781/requests/request_123";
    let mut out = Vec::new();
    assert!(!withheld(&home, link, &mut out));
    assert!(out.is_empty());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    record_session(&home, &"a".repeat(64), BrowserProfileModeV1::Shared, now);
    assert!(withheld(&home, link, &mut out));
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("did not open the approval page"));
    assert!(text.ends_with(&format!("Approval link: {link}\n")));
    let answer = dispatch(&serde_json::json!({"guard_home": home.to_str().unwrap()})).unwrap();
    assert_eq!(answer, serde_json::json!({"approval_page_held": true}));
    assert!(dispatch(&serde_json::json!({"guard_home": ""})).is_err());
    assert!(dispatch(&serde_json::json!({"guard_home": "x", "extra": 1})).is_err());
    fs::remove_dir_all(home).unwrap();
}

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::Connection;
use serde_json::{json, Value};

use super::migration::{copy_database, migrate_state, migrate_transactionally, Failed};
use super::{resolve, run_command};

const LEGACY: &str = ".ai-plugin-scanner-guard";

fn user_home() -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::tempdir().expect("tempdir");
    let home = root.path().join("home");
    fs::create_dir(&home).expect("mkdir");
    (root, home)
}

fn write_text(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    fs::write(path, text).expect("write");
}

fn database(path: &Path, sql: &str) {
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    Connection::open(path)
        .expect("open")
        .execute_batch(sql)
        .expect("seed");
}

fn probe_database(path: &Path, value: &str) {
    database(
        path,
        &format!("create table migration_probe (value text); insert into migration_probe values ('{value}');"),
    );
}

fn sync_database(path: &Path, keys: &[&str]) {
    let rows: String = keys
        .iter()
        .map(|key| format!("insert into sync_state values ('{key}', '{{}}');"))
        .collect();
    database(
        path,
        &format!("create table sync_state (state_key text primary key, payload_json text); {rows}"),
    );
}

fn query(path: &Path, sql: &str) -> Option<String> {
    let connection = Connection::open(path).expect("open");
    connection
        .query_row(sql, [], |row| row.get::<_, String>(0))
        .ok()
}

#[test]
fn malformed_requests_fail_the_command() {
    let absolute = std::env::temp_dir();
    for request in [
        json!({"schema": "guard-home-resolve.v0", "user_home": absolute}),
        json!({"schema": "guard-home-resolve.v1", "user_home": "home"}),
        json!({"schema": "guard-home-resolve.v1", "user_home": absolute, "extra": 1}),
        json!({"schema": "guard-home-resolve.v1"}),
    ] {
        let bytes = serde_json::to_vec(&request).expect("encode");
        assert_eq!(
            run_command(bytes.as_slice()).unwrap_err(),
            "guard_home_resolve_request_invalid",
            "{request}"
        );
    }
}

#[test]
fn answers_the_canonical_home_without_a_legacy_home() {
    let (_root, home) = user_home();
    let request = json!({"schema": "guard-home-resolve.v1", "user_home": home});
    let bytes = serde_json::to_vec(&request).expect("encode");
    let answer: Value =
        serde_json::from_slice(&run_command(bytes.as_slice()).expect("answer")).expect("decode");
    let canonical = home.join(".hol-guard");
    assert_eq!(answer, json!({"guard_home": canonical.to_string_lossy()}));
    assert!(!canonical.exists());
}

#[test]
fn an_empty_legacy_home_is_left_behind() {
    let (_root, home) = user_home();
    fs::create_dir_all(home.join(".config/.ai-plugin-scanner-guard")).expect("mkdir");
    assert_eq!(resolve(&home), home.join(".hol-guard"));
}

#[test]
fn a_legacy_home_with_state_moves_into_the_canonical_home() {
    let (_root, home) = user_home();
    let legacy = home.join(LEGACY);
    write_text(&legacy.join("config.toml"), "default_action = \"warn\"\n");
    write_text(&legacy.join("bin/tool.txt"), "legacy");
    probe_database(&legacy.join("guard.db"), "legacy");
    let canonical = home.join(".hol-guard");
    assert_eq!(resolve(&home), canonical);
    assert_eq!(
        fs::read_to_string(canonical.join("config.toml")).expect("read"),
        "default_action = \"warn\"\n"
    );
    assert_eq!(
        fs::read_to_string(canonical.join("bin/tool.txt")).expect("read"),
        "legacy"
    );
    assert_eq!(
        query(
            &canonical.join("guard.db"),
            "select value from migration_probe"
        )
        .as_deref(),
        Some("legacy")
    );
    let leftovers: Vec<_> = fs::read_dir(&home)
        .expect("list")
        .map(|entry| entry.expect("entry").file_name())
        .filter(|name| name.to_string_lossy().contains("-migration-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn signed_in_legacy_credentials_move_and_retired_ones_are_dropped() {
    let (_root, home) = user_home();
    let legacy = home.join(LEGACY);
    sync_database(
        &legacy.join("guard.db"),
        &["oauth_local_credentials", "credentials"],
    );
    let canonical = home.join(".hol-guard");
    sync_database(&canonical.join("guard.db"), &["credentials"]);
    assert_eq!(resolve(&home), canonical);
    let database = canonical.join("guard.db");
    assert_eq!(
        query(
            &database,
            "select state_key from sync_state where state_key = 'oauth_local_credentials'"
        )
        .as_deref(),
        Some("oauth_local_credentials")
    );
    assert_eq!(
        query(
            &database,
            "select state_key from sync_state where state_key = 'credentials'"
        ),
        None
    );
}

#[test]
fn retired_legacy_credentials_alone_are_not_moved() {
    let (_root, home) = user_home();
    sync_database(&home.join(LEGACY).join("guard.db"), &["credentials"]);
    let canonical = home.join(".hol-guard");
    assert_eq!(resolve(&home), canonical);
    assert!(!canonical.exists());
}

#[test]
fn canonical_state_wins_over_legacy_credentials() {
    let (_root, home) = user_home();
    let canonical = home.join(".hol-guard");
    write_text(&canonical.join("guard.db"), "sqlite placeholder");
    sync_database(
        &home.join(LEGACY).join("guard.db"),
        &["oauth_local_credentials"],
    );
    assert_eq!(resolve(&home), canonical);
    assert_eq!(
        fs::read_to_string(canonical.join("guard.db")).expect("read"),
        "sqlite placeholder"
    );
}

#[test]
fn a_failed_database_move_keeps_the_legacy_home() {
    let (_root, home) = user_home();
    let legacy = home.join(LEGACY);
    write_text(&legacy.join("guard.db"), "legacy-db");
    write_text(&legacy.join("config.toml"), "default_action = \"warn\"\n");
    assert_eq!(resolve(&home), legacy);
    assert!(!home.join(".hol-guard").exists());
}

#[test]
fn a_canonical_home_with_a_live_log_keeps_the_legacy_home() {
    let (_root, home) = user_home();
    let legacy = home.join(LEGACY);
    write_text(&legacy.join("config.toml"), "default_action = \"warn\"\n");
    let canonical = home.join(".hol-guard");
    database(
        &canonical.join("guard.db"),
        "create table empty (value text);",
    );
    fs::write(canonical.join("guard.db-wal"), b"live-log-frames").expect("write");
    assert_eq!(resolve(&home), legacy);
    assert!(!canonical.join("config.toml").exists());
}

#[test]
fn a_destination_with_a_live_log_is_never_replaced() {
    for log in ["guard.db-wal", "guard.db-journal"] {
        let root = tempfile::tempdir().expect("tempdir");
        let source = root.path().join("source-home");
        let destination = root.path().join("guard-home");
        probe_database(&source.join("guard.db"), "source");
        probe_database(&destination.join("guard.db"), "destination");
        fs::write(destination.join(log), b"live-log-frames").expect("write");
        let before = fs::read(destination.join("guard.db")).expect("read");
        assert_eq!(
            migrate_transactionally(&source, &destination),
            Err(Failed),
            "{log}"
        );
        assert_eq!(
            fs::read(destination.join("guard.db")).expect("read"),
            before
        );
        assert_eq!(
            fs::read(destination.join(log)).expect("read"),
            b"live-log-frames"
        );
    }
}

#[test]
fn a_destination_without_a_live_log_is_replaced() {
    let root = tempfile::tempdir().expect("tempdir");
    let source = root.path().join("source-home");
    let destination = root.path().join("guard-home");
    probe_database(&source.join("guard.db"), "source");
    probe_database(&destination.join("guard.db"), "destination");
    assert_eq!(migrate_transactionally(&source, &destination), Ok(()));
    assert_eq!(
        query(
            &destination.join("guard.db"),
            "select value from migration_probe"
        )
        .as_deref(),
        Some("source")
    );
}

#[test]
fn merging_keeps_canonical_files_and_skips_live_process_files() {
    let root = tempfile::tempdir().expect("tempdir");
    let canonical = root.path().join(".hol-guard");
    let legacy = root.path().join(LEGACY);
    write_text(&canonical.join("bin/keep.txt"), "canonical");
    write_text(&legacy.join("bin/legacy.txt"), "legacy");
    write_text(&legacy.join("daemon-state.json"), "{\"port\": 1}");
    for log in ["guard.db-wal", "guard.db-shm", "guard.db-journal"] {
        write_text(&legacy.join(log), "log");
    }
    assert_eq!(
        migrate_state(&legacy, &canonical, Duration::from_secs(5)),
        Ok(())
    );
    assert_eq!(
        fs::read_to_string(canonical.join("bin/keep.txt")).expect("read"),
        "canonical"
    );
    assert_eq!(
        fs::read_to_string(canonical.join("bin/legacy.txt")).expect("read"),
        "legacy"
    );
    for skipped in [
        "daemon-state.json",
        "guard.db-wal",
        "guard.db-shm",
        "guard.db-journal",
    ] {
        assert!(!canonical.join(skipped).exists(), "{skipped}");
    }
}

#[test]
fn saved_extension_authority_keeps_the_canonical_database() {
    let root = tempfile::tempdir().expect("tempdir");
    let canonical = root.path().join(".hol-guard");
    let legacy = root.path().join(".config/.ai-plugin-scanner-guard");
    database(
        &legacy.join("guard.db"),
        "create table migration_probe (value text);",
    );
    database(
        &canonical.join("guard.db"),
        "create table extension_control_authority_snapshot (singleton integer, layers_json text);
         insert into extension_control_authority_snapshot values (1, '[{\"kind\":\"local\"}]');",
    );
    assert_eq!(
        migrate_state(&legacy, &canonical, Duration::from_secs(5)),
        Ok(())
    );
    let database = canonical.join("guard.db");
    assert_eq!(
        query(
            &database,
            "select cast(singleton as text) from extension_control_authority_snapshot"
        )
        .as_deref(),
        Some("1")
    );
    assert_eq!(
        query(
            &database,
            "select name from sqlite_master where type = 'table' and name = 'migration_probe'"
        ),
        None
    );
}

#[test]
fn a_database_that_sqlite_cannot_read_is_never_raw_copied() {
    let root = tempfile::tempdir().expect("tempdir");
    let source = root.path().join("legacy/guard.db");
    let destination = root.path().join("canonical/guard.db");
    write_text(&source, "legacy");
    assert_eq!(
        copy_database(&source, &destination, Duration::from_secs(5)),
        Err(Failed)
    );
    assert!(!destination.exists());
    assert!(!root.path().join("canonical/guard.db.migrating").exists());
}

#[test]
fn a_backup_past_its_deadline_is_abandoned() {
    let root = tempfile::tempdir().expect("tempdir");
    let source = root.path().join("legacy/guard.db");
    let destination = root.path().join("canonical/guard.db");
    database(
        &source,
        "create table payload (data blob); insert into payload values (zeroblob(1048576));",
    );
    assert_eq!(
        copy_database(&source, &destination, Duration::ZERO),
        Err(Failed)
    );
    assert!(!destination.exists());
    assert!(!root.path().join("canonical/guard.db.migrating").exists());
}

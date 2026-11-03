use super::*;

use std::fs::OpenOptions;
use std::time::Duration;

const DAY: f64 = 24.0 * 60.0 * 60.0;

fn now() -> f64 {
    epoch_seconds(SystemTime::now()) + 1.0
}

/// Write `size` bytes to `name` and move its mtime `age_seconds` back.
fn snapshot(home: &Path, name: &str, age_seconds: f64, size: usize) -> PathBuf {
    let path = home.join(name);
    fs::write(&path, vec![b's'; size]).expect("snapshot");
    age(&path, age_seconds);
    path
}

/// Move `path`'s mtime `age_seconds` back (forward when negative).
fn age(path: &Path, age_seconds: f64) {
    let file = OpenOptions::new().write(true).open(path).expect("open");
    let modified = file
        .metadata()
        .expect("metadata")
        .modified()
        .expect("mtime");
    let shift = Duration::from_secs_f64(age_seconds.abs());
    let moved = if age_seconds < 0.0 {
        modified + shift
    } else {
        modified - shift
    };
    file.set_modified(moved).expect("set mtime");
}

fn prune(home: &Path, min_keep: u64, max_age_seconds: f64, max_total_bytes: i64) -> u64 {
    prune_quarantine(
        home,
        &Retention {
            now: now(),
            min_keep,
            max_age_seconds,
            max_total_bytes,
        },
    )
}

const BUDGET: i64 = 2 * 1024 * 1024 * 1024;

#[test]
fn requests_are_validated() {
    for request in [
        json!({ "schema": "storage-retention.v0", "op": "quarantine-summary", "guard_home": "/g" }),
        json!({ "schema": SCHEMA, "op": "quarantine-summary", "guard_home": "relative" }),
        json!({ "schema": SCHEMA, "op": "quarantine-summary", "guard_home": "/g", "now": 1.0 }),
        json!({ "schema": SCHEMA, "op": "quarantine-summary", "guard_home": "/g", "extra": 1 }),
        json!({ "schema": SCHEMA, "op": "quarantine-prune", "guard_home": "/g", "min_keep": 2 }),
        json!({
            "schema": SCHEMA, "op": "quarantine-prune", "guard_home": "/g",
            "min_keep": -1, "max_age_seconds": 1.0, "max_total_bytes": 1
        }),
        json!({
            "schema": SCHEMA, "op": "quarantine-prune", "guard_home": "/g",
            "min_keep": 2, "max_age_seconds": 1.0, "max_total_bytes": 1, "age_seconds": 1.0
        }),
        json!({ "schema": SCHEMA, "op": "staging-prune", "guard_home": "/g" }),
        json!({ "schema": SCHEMA, "op": "staging-prune", "guard_home": "/g", "age_seconds": 1.0, "min_keep": 1 }),
        json!({ "schema": SCHEMA, "op": "unknown", "guard_home": "/g" }),
    ] {
        assert_eq!(
            run_command(request.to_string().as_bytes()).expect_err("refused"),
            "storage_retention_request_invalid",
            "{request}"
        );
    }
    let infinite = Request {
        schema: SCHEMA.to_owned(),
        op: "staging-prune".to_owned(),
        guard_home: "/g".to_owned(),
        now: None,
        min_keep: None,
        max_age_seconds: None,
        max_total_bytes: None,
        age_seconds: Some(f64::INFINITY),
    };
    assert_eq!(answer(&infinite, 0.0), Err(invalid()));
    let oversized = vec![b' '; usize::try_from(MAX_REQUEST_BYTES).expect("fits") + 1];
    assert_eq!(
        run_command(oversized.as_slice()).expect_err("refused"),
        "storage_retention_request_too_large"
    );
}

#[test]
fn the_command_answers_each_op() {
    let directory = tempfile::tempdir().expect("tempdir");
    let home = directory.path().to_str().expect("utf-8");
    snapshot(directory.path(), "guard.db.corrupt-a", 60.0, 8);
    snapshot(directory.path(), "guard.db.corrupt-b", 0.0, 8);
    let ask = |request: Value| -> Value {
        serde_json::from_slice(&run_command(request.to_string().as_bytes()).expect("answer"))
            .expect("json")
    };
    assert_eq!(
        ask(json!({ "schema": SCHEMA, "op": "quarantine-summary", "guard_home": home }))["count"],
        2
    );
    assert_eq!(
        ask(json!({
            "schema": SCHEMA, "op": "quarantine-prune", "guard_home": home,
            "min_keep": 1, "max_age_seconds": 0.0, "max_total_bytes": BUDGET, "now": now()
        })),
        json!({ "removed": 1 })
    );
    assert_eq!(
        ask(
            json!({ "schema": SCHEMA, "op": "staging-prune", "guard_home": home, "age_seconds": 1.0 })
        ),
        json!({})
    );
}

#[test]
fn prune_keeps_the_newest_two_quarantine_events() {
    let directory = tempfile::tempdir().expect("tempdir");
    let home = directory.path();
    snapshot(home, "guard.db.corrupt-a", 500.0, 8);
    snapshot(home, "guard.db.corrupt-a-wal", 500.0, 8);
    snapshot(home, "guard.db.corrupt-b", 300.0, 8);
    snapshot(home, "guard.db.corrupt-c", 100.0, 8);
    snapshot(home, "guard.db.corrupt-c-shm", 100.0, 8);
    snapshot(home, "guard.db.corrupt-d", 50.0, 8);
    fs::write(home.join("guard.db"), b"live").expect("live");

    // Event "a" removes its base plus -wal sidecar, event "b" its base.
    assert_eq!(prune(home, 2, 0.0, BUDGET), 3);
    for gone in [
        "guard.db.corrupt-a",
        "guard.db.corrupt-a-wal",
        "guard.db.corrupt-b",
    ] {
        assert!(!home.join(gone).exists(), "{gone}");
    }
    for kept in [
        "guard.db.corrupt-c",
        "guard.db.corrupt-c-shm",
        "guard.db.corrupt-d",
    ] {
        assert!(home.join(kept).exists(), "{kept}");
    }
    assert_eq!(fs::read(home.join("guard.db")).expect("live"), b"live");
}

#[test]
fn prune_is_a_noop_below_the_retention_count() {
    let directory = tempfile::tempdir().expect("tempdir");
    snapshot(directory.path(), "guard.db.corrupt-only", 0.0, 8);
    assert_eq!(prune(directory.path(), 2, 7.0 * DAY, BUDGET), 0);
    assert!(directory.path().join("guard.db.corrupt-only").exists());
    assert_eq!(prune(&directory.path().join("missing"), 2, 0.0, BUDGET), 0);
}

#[test]
fn prune_keeps_recent_events_within_age_and_budget() {
    let directory = tempfile::tempdir().expect("tempdir");
    let home = directory.path();
    snapshot(home, "guard.db.corrupt-old", 10.0 * DAY, 8);
    snapshot(home, "guard.db.corrupt-recent-a", 100.0, 8);
    snapshot(home, "guard.db.corrupt-recent-b", 200.0, 8);
    snapshot(home, "guard.db.corrupt-new", 0.0, 8);

    assert_eq!(prune(home, 1, 7.0 * DAY, BUDGET), 1);
    assert!(!home.join("guard.db.corrupt-old").exists());
    for kept in [
        "guard.db.corrupt-recent-a",
        "guard.db.corrupt-recent-b",
        "guard.db.corrupt-new",
    ] {
        assert!(home.join(kept).exists(), "{kept}");
    }
}

#[test]
fn prune_evicts_events_over_the_byte_budget() {
    let directory = tempfile::tempdir().expect("tempdir");
    let home = directory.path();
    snapshot(home, "guard.db.corrupt-new", 0.0, 100);
    snapshot(home, "guard.db.corrupt-middle", 10.0, 100);
    snapshot(home, "guard.db.corrupt-oldest", 20.0, 100);

    // The newest is kept by `min_keep`; 250 bytes then admits the middle
    // event but not the oldest.
    assert_eq!(prune(home, 1, 7.0 * DAY, 250), 1);
    assert!(home.join("guard.db.corrupt-new").exists());
    assert!(home.join("guard.db.corrupt-middle").exists());
    assert!(!home.join("guard.db.corrupt-oldest").exists());
}

#[test]
fn prune_never_deletes_forensics_records() {
    let directory = tempfile::tempdir().expect("tempdir");
    let home = directory.path();
    snapshot(home, "guard.db.corrupt-old", 60.0, 8);
    snapshot(home, "guard.db.corrupt-old-wal", 60.0, 8);
    snapshot(home, "guard.db.corrupt-old.forensics.json", 60.0, 8);
    snapshot(home, "guard.db.corrupt-new", 0.0, 8);

    assert_eq!(prune(home, 1, 0.0, BUDGET), 2);
    assert!(!home.join("guard.db.corrupt-old").exists());
    assert!(!home.join("guard.db.corrupt-old-wal").exists());
    assert!(home.join("guard.db.corrupt-old.forensics.json").exists());
}

#[test]
fn a_forensics_record_alone_is_not_an_event() {
    let directory = tempfile::tempdir().expect("tempdir");
    let home = directory.path();
    snapshot(home, "guard.db.corrupt-gone.forensics.json", 30.0 * DAY, 8);
    snapshot(home, "guard.db.corrupt-new", 0.0, 8);

    assert_eq!(prune(home, 0, 0.0, BUDGET), 1);
    assert!(home.join("guard.db.corrupt-gone.forensics.json").exists());
    let summary = quarantine_summary(home);
    assert_eq!(summary["count"], 0);
    assert_eq!(summary["forensic_record_count"], 1);
}

#[test]
fn quarantined_store_summary_reports_events_and_forensics() {
    let directory = tempfile::tempdir().expect("tempdir");
    let home = directory.path();
    snapshot(home, "guard.db.corrupt-20260101T000000000000Z-aaa", 0.0, 16);
    snapshot(
        home,
        "guard.db.corrupt-20260101T000000000000Z-aaa-wal",
        0.0,
        8,
    );
    snapshot(
        home,
        "guard.db.corrupt-20260101T000000000000Z-aaa.forensics.json",
        0.0,
        4,
    );
    snapshot(home, "guard.db.corrupt-20260905T132908303335Z-bbb", 0.0, 32);
    snapshot(
        home,
        "guard.db.corrupt-20260905T132908303335Z-bbb.forensics.json",
        0.0,
        4,
    );
    fs::write(home.join("guard.db"), b"live").expect("live");

    assert_eq!(
        quarantine_summary(home),
        json!({
            "count": 2,
            "total_bytes": 16 + 8 + 4 + 32 + 4,
            "newest_quarantined_at": "2026-09-05T13:29:08.303335+00:00",
            "forensic_record_count": 2,
        })
    );
}

#[test]
fn quarantined_store_summary_handles_an_empty_guard_home() {
    let directory = tempfile::tempdir().expect("tempdir");
    assert_eq!(
        quarantine_summary(&directory.path().join("missing")),
        json!({
            "count": 0,
            "total_bytes": 0,
            "newest_quarantined_at": null,
            "forensic_record_count": 0,
        })
    );
}

#[test]
fn summary_times_round_like_python_fromtimestamp() {
    assert_eq!(
        utc_isoformat(0.0).as_deref(),
        Some("1970-01-01T00:00:00+00:00")
    );
    assert_eq!(
        utc_isoformat(1.5).as_deref(),
        Some("1970-01-01T00:00:01.500000+00:00")
    );
    assert_eq!(
        utc_isoformat(-0.25).as_deref(),
        Some("1969-12-31T23:59:59.750000+00:00")
    );
    assert_eq!(
        utc_isoformat(0.999_999_9).as_deref(),
        Some("1970-01-01T00:00:01+00:00")
    );
    assert_eq!(utc_isoformat(1.0e18), None);
}

#[test]
fn prune_orders_events_by_quarantine_stamp_not_file_mtime() {
    // `Path.replace` keeps the source database's mtime, so a freshly
    // quarantined long-idle database must not sort older than an earlier
    // event whose database was written until it died.
    let directory = tempfile::tempdir().expect("tempdir");
    let home = directory.path();
    snapshot(
        home,
        "guard.db.corrupt-20260101T000000000000Z-old-event",
        0.0,
        8,
    );
    snapshot(
        home,
        "guard.db.corrupt-20260905T132908303335Z-new-event",
        30.0 * DAY,
        8,
    );

    prune(home, 1, 0.0, BUDGET);
    assert!(home
        .join("guard.db.corrupt-20260905T132908303335Z-new-event")
        .exists());
    assert!(!home
        .join("guard.db.corrupt-20260101T000000000000Z-old-event")
        .exists());
}

#[test]
fn prune_keeps_unstamped_snapshots_furthest_back() {
    let directory = tempfile::tempdir().expect("tempdir");
    let home = directory.path();
    snapshot(
        home,
        "guard.db.corrupt-20260905T132908303335Z-stamped",
        100.0 * DAY,
        8,
    );
    snapshot(home, "guard.db.corrupt-legacy-unstamped", 60.0, 8);

    prune(home, 1, 0.0, BUDGET);
    assert!(home
        .join("guard.db.corrupt-20260905T132908303335Z-stamped")
        .exists());
    assert!(!home.join("guard.db.corrupt-legacy-unstamped").exists());
}

#[test]
fn malformed_or_truncated_stamps_do_not_outrank_real_stamps() {
    for malformed in [
        "guard.db.corrupt-9-legacy",
        "guard.db.corrupt-20260101T00000000000",
        "guard.db.corrupt-20260101T000000000000X-x",
        "guard.db.corrupt-2026010１T000000000000Z-x",
    ] {
        let directory = tempfile::tempdir().expect("tempdir");
        let home = directory.path();
        snapshot(home, malformed, 0.0, 8);
        snapshot(
            home,
            "guard.db.corrupt-20260905T132908303335Z-real",
            99.0 * DAY,
            8,
        );

        assert_eq!(prune(home, 1, 0.0, BUDGET), 1, "{malformed}");
        assert!(home
            .join("guard.db.corrupt-20260905T132908303335Z-real")
            .exists());
        assert!(!home.join(malformed).exists(), "{malformed}");
    }
}

#[test]
fn an_impossible_stamp_still_ranks_but_ages_by_mtime() {
    let base = "guard.db.corrupt-20261399T000000000000Z-x";
    assert!(event_stamp(base).is_some());
    assert_eq!(event_epoch_seconds(base, 42.0), 42.0);
    assert_eq!(
        event_epoch_seconds("guard.db.corrupt-20260905T132908303335Z-x", 0.0),
        1_788_614_948.303_335
    );
}

#[test]
fn the_prefix_match_is_case_sensitive() {
    let directory = tempfile::tempdir().expect("tempdir");
    let home = directory.path();
    snapshot(home, "GUARD.DB.CORRUPT-old", 30.0 * DAY, 8);
    assert_eq!(prune(home, 0, 0.0, BUDGET), 0);
    assert!(home.join("GUARD.DB.CORRUPT-old").exists());
}

/// A temporary directory spelled without links: the staging sweep refuses
/// any linked component, and macOS spells its temporary directory through
/// the `/var` link.
fn canonical_tempdir() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = fs::canonicalize(directory.path()).expect("canonical");
    (directory, root)
}

fn staging(home: &Path) -> PathBuf {
    let runtime = home.join("guard-home").join(UPDATE_RUNTIME_DIR_NAME);
    fs::create_dir_all(&runtime).expect("runtime");
    runtime
}

#[test]
fn stale_update_staging_is_pruned_but_recent_staging_stays() {
    let (_directory, root) = canonical_tempdir();
    let runtime = staging(root.as_path());
    let stale_home = runtime.join("home");
    fs::create_dir_all(stale_home.join("Library")).expect("stale tree");
    fs::write(stale_home.join("Library").join("cache.db"), b"stale").expect("stale");
    let stale_file = runtime.join("hol_guard.whl");
    fs::write(&stale_file, b"wheel").expect("wheel");
    // An update still writing its staging is newer than the cutoff.
    let fresh = runtime.join("in-flight.tmp");
    fs::write(&fresh, b"fresh").expect("fresh");
    age(&fresh, -DAY);

    prune_staging(&root.as_path().join("guard-home"), 0.0, now() + 1.0);

    assert!(!stale_home.exists());
    assert!(!stale_file.exists());
    assert_eq!(fs::read(&fresh).expect("fresh"), b"fresh");
}

#[test]
fn fresh_update_activity_marker_blocks_the_staging_sweep() {
    let (_directory, root) = canonical_tempdir();
    let guard_home = root.as_path().join("guard-home");
    let runtime = staging(root.as_path());
    let stale_home = runtime.join("home");
    fs::create_dir(&stale_home).expect("stale");
    let marker = runtime.join(ACTIVITY_MARKER_NAME);
    fs::write(&marker, b"{\"staging\": \"active\"}\n").expect("marker");

    // Every child is past a zero-second age gate, but the fresh marker
    // protects the tree: reused staging roots keep old mtimes while an
    // update writes deep inside them.
    prune_staging(&guard_home, 0.0, now() + 1.0);
    assert!(stale_home.exists());

    age(&marker, 8.0 * DAY);
    prune_staging(&guard_home, 0.0, now() + 1.0);
    assert!(!stale_home.exists());
    assert!(marker.exists());
}

#[test]
fn stale_update_staging_prune_tolerates_missing_directories() {
    let (_directory, root) = canonical_tempdir();
    prune_staging(&root.as_path().join("guard-home"), 0.0, now());
    assert!(!root.as_path().join("guard-home").exists());
}

#[cfg(unix)]
#[path = "storage_retention_links_tests.rs"]
mod links;

use serde_json::{json, Value};

use super::*;

const SITE: &str = "https://cloud.example.test:8443";
const NOW: &str = "2026-11-03T12:00:00+00:00";

fn home() -> tempfile::TempDir {
    tempfile::tempdir().expect("home")
}

fn run(home: &Path, args: Value) -> KindResult {
    dispatch(&args, home.to_str().expect("home path"))
}

fn pairing(origin: &str) -> Value {
    json!({
        "origin": origin,
        "workspace_id": "ws-1",
        "cloud_actions": "on",
        "cloud_base_url": null,
    })
}

fn project_at(home: &Path, origin: &str, now: &str) -> Value {
    run(
        home,
        json!({"op": "project", "pairing": pairing(origin), "now": now}),
    )
    .expect("project")
}

fn record(home: &Path, origin: &str, checked_at: &str, service: Value) {
    let answer = run(
        home,
        json!({"op": "record", "origin": origin, "checked_at": checked_at, "service": service}),
    )
    .expect("record");
    assert_eq!(answer, json!({}));
}

fn current() -> Value {
    json!({"state": "current", "message": "Guard Cloud offers Cloud actions.", "http_status": 200})
}

#[test]
fn before_connect_reports_not_paired_and_no_numbers() {
    let home = home();
    let answer = run(
        home.path(),
        json!({"op": "project", "pairing": null, "now": "2026-11-03T12:00:00.5+00:00"}),
    )
    .expect("project");
    assert_eq!(
        answer,
        json!({
            "status": {
                "schema": "guard.cloud-actions.local-status.v2",
                "generated_at": "2026-11-03T12:00:00Z",
                "stale_after_seconds": 300,
                "check_interval_seconds": 60,
                "next_check_allowed_at": null,
                "connection": {"state": "not_paired", "check": {"state": "not_checked"}},
                "included_actions": "not_available_yet",
                "accounts": "not_available_yet",
            },
            "retry_after_seconds": null,
        })
    );
}

#[test]
fn the_pairing_is_shown_unchecked_with_host_only() {
    let home = home();
    let answer = project_at(home.path(), SITE, NOW);
    assert_eq!(
        answer["status"]["connection"],
        json!({
            "state": "on",
            "workspace": "ws-1",
            "site": "cloud.example.test:8443",
            "cloud_url": SITE,
            "cloud_base_url": null,
            "check": {"state": "not_checked"},
        })
    );
}

#[test]
fn a_saved_check_is_private_and_labelled_stale_after_five_minutes() {
    let home = home();
    record(
        home.path(),
        SITE,
        "2026-11-03T12:00:00.250+00:00",
        current(),
    );
    // The check is saved to the whole second, as the page shows it.
    let fresh = project_at(home.path(), SITE, "2026-11-03T12:05:00+00:00");
    let stale = project_at(home.path(), SITE, "2026-11-03T12:05:00.001+00:00");
    assert_eq!(
        fresh["status"]["connection"]["check"],
        json!({"checked_at": "2026-11-03T12:00:00Z", "stale": false, "service": current()})
    );
    assert_eq!(
        fresh["status"]["next_check_allowed_at"],
        "2026-11-03T12:01:00Z"
    );
    assert_eq!(stale["status"]["connection"]["check"]["stale"], true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path| std::fs::metadata(path).expect("mode").permissions().mode();
        assert_eq!(mode(&home.path().join("cloud-actions")) & 0o777, 0o700);
        assert_eq!(mode(&cache_path(home.path())) & 0o077, 0);
    }
}

#[test]
fn a_new_check_waits_out_the_minute() {
    let home = home();
    record(home.path(), SITE, NOW, current());
    let retry = |now: &str| project_at(home.path(), SITE, now)["retry_after_seconds"].clone();
    assert_eq!(retry(NOW), json!(60));
    assert_eq!(retry("2026-11-03T12:00:20+00:00"), json!(40));
    assert_eq!(retry("2026-11-03T12:00:59.9+00:00"), json!(1));
    assert_eq!(retry("2026-11-03T12:01:00+00:00"), Value::Null);
    // A check saved in the future does not hold the next one back.
    assert_eq!(retry("2026-11-03T11:59:59+00:00"), Value::Null);
}

#[test]
fn a_check_of_another_guard_cloud_is_not_shown() {
    let home = home();
    record(home.path(), SITE, NOW, current());
    let answer = project_at(home.path(), "https://hol.org", "2026-11-03T12:00:30+00:00");
    assert_eq!(
        answer["status"]["connection"]["check"],
        json!({"state": "not_checked"})
    );
    assert_eq!(answer["status"]["next_check_allowed_at"], Value::Null);
    assert_eq!(answer["retry_after_seconds"], Value::Null);
}

#[test]
fn damaged_or_oversized_saved_checks_read_as_not_checked() {
    let home = home();
    let path = cache_path(home.path());
    std::fs::create_dir_all(path.parent().expect("parent")).expect("directory");
    let entry = |service: Value, checked_at: Value| {
        json!({"schema": CACHE_SCHEMA, "origin": SITE, "checked_at": checked_at, "service": service})
            .to_string()
    };
    for text in [
        "{not json".to_owned(),
        "[]".to_owned(),
        entry(current(), json!("2026-11-03T12:00:00")),
        entry(current(), json!(1)),
        entry(json!({"state": 1, "message": "m"}), json!(NOW)),
        entry(json!({"state": "current"}), json!(NOW)),
        entry(json!("current"), json!(NOW)),
        format!("{}{}", entry(current(), json!(NOW)), " ".repeat(16 * 1024)),
    ] {
        std::fs::write(&path, &text).expect("write");
        let answer = project_at(home.path(), SITE, NOW);
        assert_eq!(
            answer["status"]["connection"]["check"],
            json!({"state": "not_checked"}),
            "{text:.80}"
        );
    }
}

#[test]
fn a_saved_message_is_cut_and_a_non_integer_status_dropped() {
    let home = home();
    let path = cache_path(home.path());
    std::fs::create_dir_all(path.parent().expect("parent")).expect("directory");
    let entry = json!({
        "schema": CACHE_SCHEMA,
        "origin": SITE,
        "checked_at": "2026-11-03T13:00:00+01:00",
        "service": {"state": "offline", "message": "é".repeat(300), "http_status": "500"},
    });
    std::fs::write(&path, entry.to_string()).expect("write");
    let check = project_at(home.path(), SITE, NOW)["status"]["connection"]["check"].clone();
    assert_eq!(check["checked_at"], "2026-11-03T12:00:00Z");
    assert_eq!(
        check["service"],
        json!({"state": "offline", "message": "é".repeat(240)})
    );
}

#[test]
fn a_recorded_check_replaces_the_last_and_omits_a_missing_status() {
    let home = home();
    record(home.path(), SITE, NOW, current());
    let offline =
        json!({"state": "offline", "message": "Guard Cloud did not answer.", "http_status": null});
    record(home.path(), SITE, "2026-11-03T12:02:00Z", offline);
    let saved: Value =
        serde_json::from_str(&std::fs::read_to_string(cache_path(home.path())).expect("read"))
            .expect("json");
    assert_eq!(
        saved,
        json!({
            "schema": CACHE_SCHEMA,
            "origin": SITE,
            "checked_at": "2026-11-03T12:02:00Z",
            "service": {"state": "offline", "message": "Guard Cloud did not answer."},
        })
    );
}

#[test]
fn site_host_reads_the_origin_as_urlsplit_does() {
    for (origin, expected) in [
        (
            "https://Cloud.Example.test:8443",
            Some("cloud.example.test:8443"),
        ),
        ("https://hol.org", Some("hol.org")),
        ("https://hol.org:443", Some("hol.org:443")),
        ("http://127.0.0.1:03017", Some("127.0.0.1:3017")),
        ("http://[::1]:3017", Some("::1:3017")),
        ("http://user@host.test", Some("host.test")),
        ("http://host.test:", Some("host.test")),
        ("http://host.test:x", None),
        ("http://host.test:65536", None),
        ("http://[::1", None),
        ("hol.org", None),
        ("https://", None),
    ] {
        assert_eq!(site_host(origin).as_deref(), expected, "{origin}");
    }
}

#[test]
fn requests_are_exact() {
    let home = home();
    for args in [
        json!({"op": "project", "pairing": null}),
        json!({"op": "project", "pairing": null, "now": "2026-11-03T12:00:00"}),
        json!({"op": "project", "pairing": null, "now": NOW, "extra": 1}),
        json!({"op": "project", "pairing": {"origin": SITE}, "now": NOW}),
        json!({"op": "record", "origin": SITE, "checked_at": "later", "service": current()}),
        json!({"op": "remove"}),
    ] {
        assert_eq!(run(home.path(), args.clone()), Err(ERR_INVALID), "{args}");
    }
    let relative = dispatch(
        &json!({"op": "project", "pairing": null, "now": NOW}),
        "relative/home",
    );
    assert_eq!(relative, Err(ERR_INVALID));
    assert!(!cache_path(home.path()).exists());
}

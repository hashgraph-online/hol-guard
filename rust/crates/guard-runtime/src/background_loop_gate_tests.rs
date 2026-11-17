use super::*;
use serde_json::Value;

const MINUTE: u64 = 60 * 1_000;
const HOUR: u64 = 60 * MINUTE;
const START: u64 = 1_800_000_000_000;

fn call(home: &Path, body: Value) -> Result<Value, String> {
    let mut request = body;
    request["schema"] = json!(REQUEST_SCHEMA);
    request["guard_home"] = json!(home);
    let bytes = run_command(serde_json::to_vec(&request).unwrap().as_slice())?;
    Ok(serde_json::from_slice(&bytes).unwrap())
}

fn attempt(home: &Path, now: u64) -> bool {
    let answer = call(
        home,
        json!({"op": "attempt", "loop": "catalog_publication_refresh", "now_ms": now}),
    )
    .expect("an attempt answer");
    answer["run"].as_bool().expect("a run flag")
}

fn fail(home: &Path, key: &str, now: u64) -> Value {
    call(
        home,
        json!({"op": "outcome", "loop": "catalog_publication_refresh", "failure_key": key, "now_ms": now}),
    )
    .expect("an outcome answer")
}

fn succeed(home: &Path, now: u64) -> Value {
    call(
        home,
        json!({"op": "outcome", "loop": "catalog_publication_refresh", "now_ms": now}),
    )
    .expect("an outcome answer")
}

#[test]
fn a_healthy_loop_is_never_held_back() {
    let home = tempfile::tempdir().unwrap();
    for step in 0..5 {
        assert!(attempt(home.path(), START + step * 1_000));
        assert_eq!(succeed(home.path(), START + step * 1_000)["log"], false);
    }
}

#[test]
fn a_failing_loop_waits_longer_after_each_failure_across_restarts() {
    // Every call is a fresh process reading the ledger, the way a replaced
    // library process starts over. The wait must survive it.
    let home = tempfile::tempdir().unwrap();
    let mut now = START;
    let mut waits = Vec::new();
    for _ in 0..6 {
        assert!(attempt(home.path(), now));
        fail(home.path(), "refresh:ValueError", now);
        assert!(
            !attempt(home.path(), now + 3 * MINUTE),
            "a restart three minutes later must not refetch"
        );
        let wait = backoff_ms(
            call(home.path(), json!({"op": "status", "now_ms": now})).unwrap()["loops"][0]
                ["failures"]
                .as_u64()
                .unwrap(),
        );
        waits.push(wait / MINUTE);
        now += wait;
    }
    assert_eq!(waits, vec![5, 10, 20, 40, 60, 60]);
}

#[test]
fn a_wait_reports_how_long_is_left() {
    let home = tempfile::tempdir().unwrap();
    assert!(attempt(home.path(), START));
    fail(home.path(), "refresh:HTTPError:404", START);
    let answer = call(
        home.path(),
        json!({"op": "attempt", "loop": "catalog_publication_refresh", "now_ms": START + MINUTE}),
    )
    .unwrap();
    assert_eq!(answer["run"], false);
    assert_eq!(answer["retry_after_seconds"], 4 * 60);
}

#[test]
fn a_clock_that_went_backwards_does_not_hold_a_loop() {
    let home = tempfile::tempdir().unwrap();
    assert!(attempt(home.path(), START));
    fail(home.path(), "refresh:ValueError", START);
    assert!(attempt(home.path(), START - HOUR));
}

#[test]
fn an_unchanged_failure_is_logged_once_then_every_six_hours_with_its_repeats() {
    let home = tempfile::tempdir().unwrap();
    let first = fail(home.path(), "refresh:ValueError", START);
    assert_eq!(first["log"], true);
    let mut logged = 1;
    let mut now = START;
    // A day of failures every five minutes, as the live host produced.
    for _ in 0..(24 * 12) {
        now += 5 * MINUTE;
        let answer = fail(home.path(), "refresh:ValueError", now);
        if answer["log"] == true {
            logged += 1;
            assert_eq!(answer["repeats"], 6 * 12 - 1);
        }
    }
    assert_eq!(logged, 5);
}

#[test]
fn a_changed_failure_is_logged_at_once() {
    let home = tempfile::tempdir().unwrap();
    assert_eq!(fail(home.path(), "refresh:ValueError", START)["log"], true);
    assert_eq!(
        fail(home.path(), "refresh:ValueError", START + MINUTE)["log"],
        false
    );
    assert_eq!(
        fail(home.path(), "refresh:HTTPError:404", START + 2 * MINUTE)["log"],
        true
    );
}

#[test]
fn recovery_is_reported_once_and_clears_the_wait() {
    let home = tempfile::tempdir().unwrap();
    fail(home.path(), "refresh:ValueError", START);
    fail(home.path(), "refresh:ValueError", START + MINUTE);
    let recovered = succeed(home.path(), START + 2 * MINUTE);
    assert_eq!(recovered["recovered"], true);
    assert_eq!(recovered["failures"], 2);
    assert_eq!(succeed(home.path(), START + 3 * MINUTE)["recovered"], false);
    assert!(attempt(home.path(), START + 3 * MINUTE));
    assert_eq!(
        fail(home.path(), "refresh:ValueError", START + 4 * MINUTE)["log"],
        true
    );
}

#[test]
fn the_ledger_keeps_a_digest_and_no_failure_text() {
    let home = tempfile::tempdir().unwrap();
    fail(home.path(), "refresh:HTTPError:404 releases", START);
    let text = fs::read_to_string(home.path().join(LEDGER_FILE)).unwrap();
    assert!(!text.contains("HTTPError"));
    assert!(!text.contains("releases"));
    assert!(text.len() < 1_024);
}

#[cfg(unix)]
#[test]
fn the_ledger_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    fail(home.path(), "refresh:ValueError", START);
    let mode = fs::metadata(home.path().join(LEDGER_FILE))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn a_damaged_ledger_reads_as_empty() {
    let home = tempfile::tempdir().unwrap();
    fs::write(home.path().join(LEDGER_FILE), b"{not json").unwrap();
    assert!(attempt(home.path(), START));
    assert_eq!(fail(home.path(), "refresh:ValueError", START)["log"], true);
}

#[cfg(unix)]
#[test]
fn a_linked_ledger_is_not_followed() {
    let home = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let target = elsewhere.path().join("target.json");
    fs::write(&target, b"untouched").unwrap();
    std::os::unix::fs::symlink(&target, home.path().join(LEDGER_FILE)).unwrap();
    fail(home.path(), "refresh:ValueError", START);
    assert_eq!(fs::read(&target).unwrap(), b"untouched");
}

#[test]
fn status_names_every_loop() {
    let home = tempfile::tempdir().unwrap();
    assert!(attempt(home.path(), START));
    fail(home.path(), "refresh:ValueError", START);
    let status = call(
        home.path(),
        json!({"op": "status", "now_ms": START + MINUTE}),
    )
    .unwrap();
    let loops = status["loops"].as_array().unwrap();
    assert_eq!(loops.len(), LOOPS.len());
    assert_eq!(loops[0]["loop"], "catalog_publication_refresh");
    assert_eq!(loops[0]["state"], "failing");
    assert_eq!(loops[0]["failing_for_seconds"], 60);
    assert_eq!(loops[0]["next_attempt_in_seconds"], 4 * 60);
    assert_eq!(loops[1]["state"], "healthy");
}

#[test]
fn bad_requests_are_refused() {
    let home = tempfile::tempdir().unwrap();
    let unknown = call(home.path(), json!({"op": "attempt", "loop": "anything"}));
    assert_eq!(unknown.unwrap_err(), "background_loop_gate_loop_unknown");
    let key = call(
        home.path(),
        json!({"op": "outcome", "loop": "catalog_publication_refresh", "failure_key": "a\nb"}),
    );
    assert_eq!(key.unwrap_err(), "background_loop_gate_failure_key_invalid");
    let relative = run_command(
        serde_json::to_vec(
            &json!({"schema": REQUEST_SCHEMA, "guard_home": "relative", "op": "status"}),
        )
        .unwrap()
        .as_slice(),
    );
    assert_eq!(
        relative.unwrap_err(),
        "background_loop_gate_guard_home_invalid"
    );
    let extra = run_command(
        serde_json::to_vec(&json!({"schema": REQUEST_SCHEMA, "guard_home": home.path(), "op": "status", "path": "x"}))
            .unwrap()
            .as_slice(),
    );
    assert_eq!(extra.unwrap_err(), "background_loop_gate_request_invalid");
}

#[test]
fn a_busy_ledger_answers_an_error_instead_of_waiting() {
    let home = tempfile::tempdir().unwrap();
    let held = lock(home.path()).unwrap();
    let started = Instant::now();
    assert_eq!(
        call(home.path(), json!({"op": "status"})).unwrap_err(),
        "background_loop_gate_busy"
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    drop(held);
    assert!(call(home.path(), json!({"op": "status"})).is_ok());
}

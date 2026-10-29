use super::*;
use std::fs;
use std::path::PathBuf;

fn scope_named(label: &str) -> PathBuf {
    let scope = std::env::temp_dir().join(format!(
        "hol-guard-lifecycle-{label}-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    ));
    fs::create_dir(&scope).unwrap();
    scope
}

fn stored(scope: &Path) -> Journal {
    let encoded = fs::read(scope.join(JOURNAL_FILE)).unwrap();
    serde_json::from_slice(&encoded).unwrap()
}

fn record_at_time(scope: &Path, event: Event, at_ms: u64) {
    record_at(scope, event, Some(at_ms), true).unwrap();
}

#[test]
fn an_install_with_no_history_reports_nothing_rather_than_a_healthy_day() {
    let scope = scope_named("empty");

    assert!(health(&scope).unwrap().is_none());

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_day_of_runs_reads_back_as_counts() {
    let scope = scope_named("counts");

    record(&scope, Event::Started);
    record(&scope, Event::ExitedOrderly);
    record(&scope, Event::Started);
    record(&scope, Event::ExitedOrderly);

    let health = health(&scope).unwrap().unwrap();
    assert_eq!(health.state, "healthy");
    assert_eq!(health.starts, 2);
    assert_eq!(health.orderly_exits, 2);
    assert_eq!(health.failed_exits, 0);
    assert_eq!(health.last_event, "exited_orderly");
    assert!(health.last_event_age_seconds < 60);

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_refused_start_is_the_state_that_says_nothing_took_its_place() {
    let scope = scope_named("refused");

    record(&scope, Event::Started);
    record(&scope, Event::ExitedFailed);
    record(&scope, Event::StartRefused);

    assert_eq!(health(&scope).unwrap().unwrap().state, "critical");

    // A start that succeeds after the circuit closes is no longer critical,
    // but the day it happened in is still not a healthy one.
    record(&scope, Event::Started);
    assert_eq!(health(&scope).unwrap().unwrap().state, "degraded");

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_crash_earlier_in_the_day_is_not_erased_by_a_good_run_after_it() {
    let scope = scope_named("degraded");

    record(&scope, Event::Started);
    record(&scope, Event::ExitedFailed);
    record(&scope, Event::Started);
    record(&scope, Event::ExitedOrderly);

    let health = health(&scope).unwrap().unwrap();
    assert_eq!(health.state, "degraded");
    assert_eq!(health.failed_exits, 1);
    assert_eq!(health.orderly_exits, 1);
    assert_eq!(health.last_event, "exited_orderly");

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_run_that_reports_success_too_early_is_counted_apart_from_a_healthy_one() {
    let scope = scope_named("premature");

    record(&scope, Event::ExitedPremature);

    let health = health(&scope).unwrap().unwrap();
    assert_eq!(health.state, "degraded");
    assert_eq!(health.premature_exits, 1);
    assert_eq!(health.orderly_exits, 0);

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn the_journal_holds_nothing_but_counts_and_this_module_s_own_vocabulary() {
    // The scope path carries something a support bundle must never repeat, so
    // a journal that reached for its surroundings would be caught here.
    let scope = scope_named("private-home-of-a-person-s3cr3t");

    for event in [
        Event::Started,
        Event::ExitedOrderly,
        Event::ExitedFailed,
        Event::ExitedPremature,
        Event::StartRefused,
    ] {
        record(&scope, event);
    }

    let encoded = fs::read(scope.join(JOURNAL_FILE)).unwrap();
    let text = String::from_utf8(encoded.clone()).unwrap();
    assert!(!text.contains("s3cr3t"), "{text}");
    assert!(!text.contains("private-home"), "{text}");

    let allowed_keys = ["schema", "hours", "last_event", "last_event_ms"];
    let allowed_hour_keys = [
        "hour",
        "starts",
        "orderly_exits",
        "failed_exits",
        "premature_exits",
        "refused_starts",
    ];
    let allowed_strings = [
        JOURNAL_SCHEMA,
        Event::Started.code(),
        Event::ExitedOrderly.code(),
        Event::ExitedFailed.code(),
        Event::ExitedPremature.code(),
        Event::StartRefused.code(),
    ];
    let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    let object = value.as_object().unwrap();
    for (key, field) in object {
        assert!(allowed_keys.contains(&key.as_str()), "{key}");
        match field {
            serde_json::Value::Number(_) => {}
            serde_json::Value::String(text) => {
                assert!(allowed_strings.contains(&text.as_str()), "{text}");
            }
            serde_json::Value::Array(hours) => {
                for hour in hours {
                    for (key, count) in hour.as_object().unwrap() {
                        assert!(allowed_hour_keys.contains(&key.as_str()), "{key}");
                        assert!(count.is_number(), "{count}");
                    }
                }
            }
            other => panic!("unexpected journal value {other}"),
        }
    }
    assert_eq!(object.len(), allowed_keys.len());

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn an_hour_leaves_the_day_on_its_own_rather_than_taking_the_rest_with_it() {
    let scope = scope_named("window");
    let now = now_ms().unwrap();

    record_at_time(&scope, Event::ExitedFailed, now - JOURNAL_WINDOW_MS);
    record_at_time(&scope, Event::Started, now - JOURNAL_BUCKET_MS);
    record_at_time(&scope, Event::ExitedOrderly, now);

    // The failure's own hour is a day old and is gone. The two hours after it
    // are not, and they are still counted.
    let journal = stored(&scope);
    let totals = journal.totals();
    assert_eq!(totals.failed_exits, 0);
    assert_eq!(totals.starts, 1);
    assert_eq!(totals.orderly_exits, 1);
    assert_eq!(journal.hours.len(), 2);

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_failure_minutes_old_is_still_reported_a_day_after_the_first_event() {
    // The bug this guards against: a window pinned to the first event drops
    // everything at its boundary, so a refusal seconds before it reads back as
    // no history at all, and the next event reads back as a healthy day.
    let scope = scope_named("rolling");
    let now = now_ms().unwrap();

    record_at_time(
        &scope,
        Event::Started,
        now - JOURNAL_WINDOW_MS + JOURNAL_BUCKET_MS,
    );
    record_at_time(&scope, Event::StartRefused, now - JOURNAL_BUCKET_MS);

    let health = health(&scope).unwrap().unwrap();
    assert_eq!(health.state, "critical");
    assert_eq!(health.refused_starts, 1);

    // And a start after it leaves the refusal in the day it happened in.
    record_at_time(&scope, Event::Started, now);
    let journal = stored(&scope);
    assert_eq!(journal.totals().refused_starts, 1);
    assert_eq!(health_state(&journal, &journal.totals()), "degraded");

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_journal_whose_every_hour_is_a_day_old_is_not_reported_as_today() {
    let scope = scope_named("stale");
    let stale = now_ms().unwrap() - JOURNAL_WINDOW_MS;

    record_at_time(&scope, Event::ExitedFailed, stale);

    assert!(health(&scope).unwrap().is_none());

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_clock_set_back_does_not_leave_counts_that_never_expire() {
    // An hour the clock has not reached yet cannot age out by waiting, so a
    // journal written before a rollback would otherwise report its failures
    // for as long as the clock took to catch up.
    let scope = scope_named("rollback");
    let now = now_ms().unwrap();

    record_at_time(&scope, Event::ExitedFailed, now + JOURNAL_WINDOW_MS);
    assert!(health(&scope).unwrap().is_none());

    record_at_time(&scope, Event::Started, now);
    let journal = stored(&scope);
    assert_eq!(journal.hours.len(), 1);
    assert_eq!(journal.totals().failed_exits, 0);
    assert_eq!(journal.totals().starts, 1);

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_journal_naming_an_event_this_module_never_writes_reaches_no_reader() {
    // A same-user process can edit this file. The reader refuses its word
    // rather than republishing it in a snapshot meant to be shareable unread.
    let scope = scope_named("vocabulary");
    record(&scope, Event::Started);
    let smuggled = stored(&scope);
    let mut value = serde_json::to_value(&smuggled).unwrap();
    value["last_event"] = serde_json::Value::String("/home/a-person/secret-project".to_owned());
    fs::write(
        scope.join(JOURNAL_FILE),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();

    assert!(health(&scope).unwrap().is_none());

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_hand_written_journal_cannot_make_the_file_grow_without_bound() {
    let scope = scope_named("bounded");
    let now = now_ms().unwrap();
    let mut journal = Journal::new();
    for index in 0..200u64 {
        journal.hours.push(HourCounts {
            hour: hour_of(now) - index % 12,
            starts: 1,
            ..HourCounts::default()
        });
    }

    journal.retain_window(now);

    assert_eq!(journal.hours.len(), 12);
    assert_eq!(journal.totals().starts, 200);

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_damaged_journal_costs_its_own_day_and_nothing_else() {
    let scope = scope_named("damaged");

    record(&scope, Event::Started);
    fs::write(scope.join(JOURNAL_FILE), b"{\"schema\":\"something else\"}").unwrap();

    record(&scope, Event::ExitedOrderly);

    let health = health(&scope).unwrap().unwrap();
    assert_eq!(health.state, "healthy");
    assert_eq!(health.starts, 0);
    assert_eq!(health.orderly_exits, 1);

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_journal_that_cannot_be_written_does_not_make_a_caller_fail() {
    // `record` is called from paths whose answer the runtime has already
    // decided, so a journal it cannot write has to be dropped in silence.
    let scope = scope_named("unwritable");
    // A directory standing where the file belongs fails every write without
    // needing a permission the test suite may itself be running as root over.
    fs::create_dir(scope.join(JOURNAL_FILE)).unwrap();

    record(&scope, Event::Started);

    assert!(health(&scope).is_err() || health(&scope).unwrap().is_none());

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn every_event_has_its_own_counter() {
    let scope = scope_named("distinct");

    record(&scope, Event::Started);
    record(&scope, Event::ExitedOrderly);
    record(&scope, Event::ExitedFailed);
    record(&scope, Event::ExitedPremature);
    record(&scope, Event::StartRefused);

    let totals = stored(&scope).totals();
    assert_eq!(
        (
            totals.starts,
            totals.orderly_exits,
            totals.failed_exits,
            totals.premature_exits,
            totals.refused_starts,
        ),
        (1, 1, 1, 1, 1)
    );

    fs::remove_dir_all(scope).unwrap();
}

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use serde_json::json;

use super::{recorded, CatalogReport, Progress, MAX_ATTEMPTS, RETRY_INTERVAL};
use crate::mcp_relay_servers::REPORT_SCHEMA;

fn answered(recorded: bool) -> Receiver<bool> {
    let (sender, answer) = mpsc::channel();
    sender.send(recorded).unwrap();
    answer
}

fn records(_: &Path, _: &[u8]) -> Receiver<bool> {
    answered(true)
}

fn declines(_: &Path, _: &[u8]) -> Receiver<bool> {
    answered(false)
}

fn never_finishes(_: &Path, _: &[u8]) -> Receiver<bool> {
    mpsc::channel().1
}

fn report(deliver: super::Deliver) -> CatalogReport {
    CatalogReport::new(PathBuf::from("/g"), b"{}".to_vec(), deliver)
}

#[test]
fn a_recorded_report_is_done_after_one_attempt() {
    let mut report = report(records);
    let now = Instant::now();
    assert_eq!(report.poll(now), Progress::Pending);
    assert_eq!(report.poll(now), Progress::Recorded);
    assert_eq!(report.attempts, 1);
}

#[test]
fn a_report_the_resident_did_not_record_is_retried_after_the_interval() {
    let mut report = report(declines);
    let start = Instant::now();
    assert_eq!(report.poll(start), Progress::Pending);
    assert_eq!(report.poll(start), Progress::Pending);
    assert_eq!(report.attempts, 1, "no retry before the interval passes");
    assert_eq!(report.poll(start + RETRY_INTERVAL), Progress::Pending);
    assert_eq!(report.attempts, 2);
}

#[test]
fn a_failed_attempt_is_retried_like_a_declined_one() {
    let mut report = report(never_finishes);
    let start = Instant::now();
    assert_eq!(report.poll(start), Progress::Pending);
    assert_eq!(report.poll(start + RETRY_INTERVAL), Progress::Pending);
    assert_eq!(report.attempts, 2);
}

#[test]
fn a_report_that_is_never_recorded_stops_after_its_attempts() {
    let mut report = report(declines);
    let mut now = Instant::now();
    for _ in 0..MAX_ATTEMPTS {
        assert_eq!(report.poll(now), Progress::Pending);
        now += RETRY_INTERVAL;
    }
    assert_eq!(report.poll(now), Progress::Abandoned);
    assert_eq!(report.attempts, MAX_ATTEMPTS);
}

#[test]
fn an_attempt_in_flight_is_never_waited_on_by_poll() {
    let (sender, answer) = mpsc::channel();
    let mut report = report(never_finishes);
    report.answer = Some(answer);
    report.attempts = 1;
    report.last = Some(Instant::now());
    let started = Instant::now();
    assert_eq!(report.poll(Instant::now()), Progress::Pending);
    assert!(started.elapsed() < Duration::from_millis(50));
    sender.send(true).unwrap();
    assert_eq!(report.poll(Instant::now()), Progress::Recorded);
}

#[test]
fn a_superseded_report_does_not_wait_for_its_attempt() {
    let (sender, answer) = mpsc::channel::<bool>();
    let mut report = report(never_finishes);
    report.answer = Some(answer);
    let started = Instant::now();
    report.supersede();
    assert!(started.elapsed() < Duration::from_millis(250));
    drop(sender);
}

#[test]
fn only_a_recorded_answer_counts() {
    let answer = |value: serde_json::Value| serde_json::to_vec(&value).unwrap();
    assert!(recorded(&answer(
        json!({"schema": REPORT_SCHEMA, "recorded": true})
    )));
    assert!(!recorded(&answer(
        json!({"schema": REPORT_SCHEMA, "recorded": false})
    )));
    assert!(!recorded(&answer(
        json!({"schema": "other", "recorded": true})
    )));
    assert!(!recorded(b"not json"));
}

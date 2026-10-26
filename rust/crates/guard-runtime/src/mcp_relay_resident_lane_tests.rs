use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::super::tests::facts;
use super::super::{defer, Commits, ResidentRelayAuthority, RESULT_SCHEMA};
use super::ready_answer;
use crate::mcp_relay_lane::{Kick, LaneKick};
use crate::mcp_relay_ready::MCP_RELAY_READY_SCHEMA;

/// Answers each kick with `answer` and counts them.
struct FakeKick {
    answer: Kick,
    kicks: std::rc::Rc<std::cell::Cell<usize>>,
}

impl LaneKick for FakeKick {
    fn kick(&mut self, _deadline: Instant) -> Kick {
        self.kicks.set(self.kicks.get() + 1);
        self.answer
    }
}

fn kicked(answer: Kick) -> (ResidentRelayAuthority, std::rc::Rc<std::cell::Cell<usize>>) {
    let kicks = std::rc::Rc::default();
    let authority = ResidentRelayAuthority {
        facts: Some(facts()),
        resident: None,
        commits: Commits::default(),
        kick: None,
        warming: false,
        report: None,
        inline_available: false,
        inline_answer: None,
    }
    .with_kick(Box::new(FakeKick {
        answer,
        kicks: std::rc::Rc::clone(&kicks),
    }));
    (authority, kicks)
}

fn bytes(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).unwrap()
}

fn deferred(reason: &str) -> Vec<u8> {
    bytes(json!({"schema": RESULT_SCHEMA, "outcome": "defer", "reason": reason}))
}

#[test]
fn a_lane_defer_the_daemon_took_gets_one_retry() {
    let (mut authority, kicks) = kicked(Kick::Requested);
    assert!(authority.rekick(Some(deferred("direct_lane_unbound").as_slice())));
    assert!(authority.rekick(Some(deferred("mcp_relay_harness_unbound").as_slice())));
    assert_eq!(kicks.get(), 2);
}

#[test]
fn other_answers_are_refused_without_a_retry() {
    let (mut authority, kicks) = kicked(Kick::Requested);
    assert!(!authority.rekick(None));
    assert!(!authority.rekick(Some(deferred("mcp_relay_policy_need").as_slice())));
    assert!(!authority.rekick(Some(deferred("direct_lane_unsupported").as_slice())));
    assert!(!authority.rekick(Some(&b"not json"[..])));
    assert_eq!(kicks.get(), 0);
    for answer in [Kick::Refused, Kick::DaemonUnreachable, Kick::Skipped] {
        let (mut authority, kicks) = kicked(answer);
        assert!(!authority.rekick(Some(deferred("direct_lane_unbound").as_slice())));
        assert_eq!(kicks.get(), 1);
    }
}

#[test]
fn without_a_kick_a_deferral_is_never_retried() {
    let (mut authority, _) = kicked(Kick::Requested);
    authority.kick = None;
    assert!(!authority.rekick(Some(deferred("direct_lane_unbound").as_slice())));
}

#[test]
fn only_the_first_call_of_a_warming_session_waits_for_the_lane() {
    let (mut authority, kicks) = kicked(Kick::Requested);
    authority.warm_up_within(Duration::from_millis(150));
    assert_eq!(kicks.get(), 0, "a session that started ready never waits");
    let mut authority = authority.warming(true);
    let started = Instant::now();
    authority.warm_up_within(Duration::from_millis(150));
    assert!(started.elapsed() >= Duration::from_millis(150));
    assert!(kicks.get() >= 1);
    assert!(!authority.warming);
    let asked = kicks.get();
    authority.warm_up_within(Duration::from_millis(150));
    assert_eq!(kicks.get(), asked);
}

#[test]
fn a_refusing_daemon_ends_the_warm_up_but_a_skipped_kick_does_not() {
    let (authority, kicks) = kicked(Kick::Refused);
    let mut authority = authority.warming(true);
    let started = Instant::now();
    authority.warm_up_within(Duration::from_secs(5));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(kicks.get(), 1);
    let (authority, kicks) = kicked(Kick::Skipped);
    let mut authority = authority.warming(true);
    let started = Instant::now();
    authority.warm_up_within(Duration::from_millis(150));
    assert!(started.elapsed() >= Duration::from_millis(150));
    assert!(kicks.get() >= 1);
}

#[test]
fn a_catalog_report_is_pending_until_the_resident_records_it() {
    let (mut authority, _) = kicked(Kick::Requested);
    let started = Instant::now();
    authority.report_server(&[json!({"name": "read"})]);
    assert!(
        started.elapsed() < Duration::from_millis(250),
        "the report never blocks the relay loop"
    );
    assert!(authority.report.is_some(), "no resident recorded it yet");
    authority.facts = None;
    authority.report = None;
    authority.report_server(&[json!({"name": "read"})]);
    assert!(authority.report.is_none(), "without facts nothing is sent");
}

#[test]
fn a_lane_no_wait_can_clear_ends_the_warm_up_at_once() {
    let (mut authority, kicks) = kicked(Kick::Requested);
    authority.facts = None;
    let mut authority = authority.warming(true);
    let started = Instant::now();
    authority.warm_up_within(Duration::from_secs(5));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(kicks.get(), 0);
}

#[test]
fn the_probe_names_why_it_could_not_ask() {
    let mut unbound = ResidentRelayAuthority {
        facts: None,
        resident: None,
        commits: Commits::default(),
        kick: None,
        warming: false,
        report: None,
        inline_available: false,
        inline_answer: None,
    };
    let deadline = Instant::now() + Duration::from_millis(200);
    assert_eq!(
        unbound.lane_ready(deadline),
        Err(defer::FACTS_UNAVAILABLE.to_owned())
    );
    assert_eq!(unbound.lane_workspace(), None);
    let (mut unreachable, _) = kicked(Kick::Requested);
    assert!(unreachable.lane_workspace().is_some());
    assert_eq!(
        unreachable.lane_ready(deadline),
        Err(defer::RESIDENT_UNREACHABLE.to_owned())
    );
}

#[test]
fn the_readiness_answer_is_ready_or_a_code() {
    let answer = |value: Value| ready_answer(&bytes(value));
    assert_eq!(
        answer(json!({"schema": MCP_RELAY_READY_SCHEMA, "ready": true})),
        Ok(())
    );
    assert_eq!(
        answer(
            json!({"schema": MCP_RELAY_READY_SCHEMA, "ready": false, "reason": "direct_lane_unbound"})
        ),
        Err("direct_lane_unbound".to_owned())
    );
    for invalid in [
        json!({"schema": "other", "ready": true}),
        json!({"schema": MCP_RELAY_READY_SCHEMA}),
        json!({"schema": MCP_RELAY_READY_SCHEMA, "ready": false, "reason": "Not A Code"}),
        json!({"schema": MCP_RELAY_READY_SCHEMA, "ready": false}),
    ] {
        assert_eq!(answer(invalid), Err(defer::REPLY_INVALID.to_owned()));
    }
    assert_eq!(ready_answer(b"{"), Err(defer::REPLY_INVALID.to_owned()));
}

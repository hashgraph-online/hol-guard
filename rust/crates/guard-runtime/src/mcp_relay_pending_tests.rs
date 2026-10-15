use super::*;
use crate::hook_direct_evidence::{drain, HookDirectEvidenceDrainRequestV1};

fn page(queue: &DirectEvidenceQueue, ack: Option<&Value>) -> Value {
    let mut request = json!({"guard_home": "/home"});
    if let Some(previous) = ack {
        request["ack_through"] = previous["through"].clone();
        request["ack_epoch"] = previous["epoch"].clone();
    }
    let request: HookDirectEvidenceDrainRequestV1 = serde_json::from_value(request).unwrap();
    serde_json::from_slice(&drain(&request, queue).unwrap()).unwrap()
}

fn drained(queue: &DirectEvidenceQueue) -> Vec<Value> {
    page(queue, None)["records"].as_array().unwrap().clone()
}

/// Acknowledge every queued record, as the daemon's drain does.
fn acknowledge_all(queue: &DirectEvidenceQueue) {
    let mut previous = page(queue, None);
    while !previous["records"].as_array().unwrap().is_empty() {
        previous = page(queue, Some(&previous));
    }
}

fn commit_ticket(
    ticket: &str,
    pending: &PendingRelayEvidence,
    queue: &DirectEvidenceQueue,
) -> Value {
    let request = McpRelayCommitRequestV1 {
        guard_home: "/home".to_owned(),
        ticket: ticket.to_owned(),
    };
    let result: Value = serde_json::from_slice(&commit(&request, pending, queue).unwrap()).unwrap();
    assert_eq!(result["schema"], json!(COMMIT_RESULT_SCHEMA));
    json!([result["committed"], result["retained"]])
}

const COMMITTED: [bool; 2] = [true, false];
const RETAINED: [bool; 2] = [false, true];
const UNKNOWN: [bool; 2] = [false, false];

#[test]
fn only_a_committed_forward_reaches_the_drain_and_only_once() {
    let pending = PendingRelayEvidence::default();
    let queue = DirectEvidenceQueue::default();
    let now = Instant::now();
    let committed = pending.hold(json!({"call": 1}), now).unwrap();
    let later = pending.hold(json!({"call": 2}), now).unwrap();
    assert_ne!(committed, later);
    assert!(drained(&queue).is_empty());

    assert_eq!(
        commit_ticket(&committed, &pending, &queue),
        json!(COMMITTED)
    );
    assert_eq!(commit_ticket(&committed, &pending, &queue), json!(UNKNOWN));
    assert_eq!(drained(&queue), vec![json!({"call": 1})]);
    assert_eq!(commit_ticket(&later, &pending, &queue), json!(COMMITTED));
}

#[test]
fn a_ticket_from_another_resident_releases_nothing() {
    let pending = PendingRelayEvidence::default();
    let other = PendingRelayEvidence::default();
    let queue = DirectEvidenceQueue::default();
    let ticket = other.hold(json!({"call": 1}), Instant::now()).unwrap();
    pending.hold(json!({"call": 2}), Instant::now()).unwrap();

    assert_eq!(commit_ticket(&ticket, &pending, &queue), json!(UNKNOWN));
    let no_sequence = format!("{}:", pending.epoch);
    for forged in ["", "1", ":1", "x:1", no_sequence.as_str()] {
        assert_eq!(
            commit_ticket(forged, &pending, &queue),
            json!(UNKNOWN),
            "{forged}"
        );
    }
    assert!(drained(&queue).is_empty());
}

#[test]
fn a_full_hold_refuses_until_uncommitted_tickets_expire() {
    let pending = PendingRelayEvidence::default();
    let queue = DirectEvidenceQueue::default();
    let start = Instant::now();
    let first = pending.hold(json!({"call": 0}), start).unwrap();
    for call in 1..MAX_HELD_RECORDS {
        assert!(pending.hold(json!({"call": call}), start).is_some());
    }
    assert!(pending.hold(json!({"call": "late"}), start).is_none());
    let later = start + HOLD_TTL;
    assert_eq!(pending.commit_into(&first, &queue, later), Commit::Unknown);
    let ticket = pending.hold(json!({"call": "fresh"}), later).unwrap();
    assert_eq!(
        pending.commit_into(&ticket, &queue, later),
        Commit::Committed
    );
    assert_eq!(drained(&queue), vec![json!({"call": "fresh"})]);
}

#[test]
fn a_full_drain_keeps_the_record_for_a_later_commit() {
    let pending = PendingRelayEvidence::default();
    let queue = DirectEvidenceQueue::default();
    let mut filler = 0_u64;
    while queue.offer(json!({"filler": filler})) {
        filler += 1;
    }
    let ticket = pending
        .hold(json!({"call": "ran"}), Instant::now())
        .unwrap();

    assert_eq!(commit_ticket(&ticket, &pending, &queue), json!(RETAINED));
    assert_eq!(commit_ticket(&ticket, &pending, &queue), json!(RETAINED));
    acknowledge_all(&queue);
    assert_eq!(commit_ticket(&ticket, &pending, &queue), json!(COMMITTED));
    assert_eq!(commit_ticket(&ticket, &pending, &queue), json!(UNKNOWN));
    assert_eq!(drained(&queue), vec![json!({"call": "ran"})]);
}

#[test]
fn an_oversized_record_is_not_held() {
    let pending = PendingRelayEvidence::default();
    let large = "x".repeat(MAX_RECORD_BYTES);
    assert!(pending
        .hold(json!({"blob": large}), Instant::now())
        .is_none());
}

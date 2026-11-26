use serde_json::json;

use super::super::{DirectEvidenceQueue, MAX_QUEUED_RECORDS};

#[test]
fn a_reserved_slot_is_kept_from_every_other_offer() {
    let queue = DirectEvidenceQueue::default();
    let reserved = queue.reserve().expect("an empty queue reserves");
    let mut taken = 0;
    while queue.offer(json!({"n": taken})) {
        taken += 1;
    }
    assert_eq!(taken, MAX_QUEUED_RECORDS - 1);
    assert!(reserved.offer(json!({"receipt": true})));
    assert!(!queue.offer(json!({"after": true})));
}

#[test]
fn an_unspent_reservation_returns_its_room() {
    let queue = DirectEvidenceQueue::default();
    drop(queue.reserve().expect("an empty queue reserves"));
    let mut taken = 0;
    while queue.offer(json!({"n": taken})) {
        taken += 1;
    }
    assert_eq!(taken, MAX_QUEUED_RECORDS);
}

#[test]
fn a_full_queue_promises_nothing() {
    let queue = DirectEvidenceQueue::default();
    while queue.offer(json!({})) {}
    assert!(queue.reserve().is_none());
}

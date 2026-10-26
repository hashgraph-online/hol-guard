use super::{
    drain, DirectEvidenceQueue, HookDirectEvidenceDrainRequestV1, HEADROOM_RECORDS,
    MAX_QUEUED_RECORDS, MAX_RECORD_BYTES,
};
use serde_json::{json, Value};

fn request(
    max_records: Option<usize>,
    ack_through: Option<u64>,
    ack_epoch: Option<&str>,
) -> HookDirectEvidenceDrainRequestV1 {
    HookDirectEvidenceDrainRequestV1 {
        guard_home: "/home/guard/.hol-guard".to_owned(),
        max_records,
        ack_through,
        ack_epoch: ack_epoch.map(str::to_owned),
    }
}

fn drained_from(
    queue: &DirectEvidenceQueue,
    max_records: Option<usize>,
    ack_through: Option<u64>,
    ack_epoch: Option<&str>,
) -> Value {
    let request = request(max_records, ack_through, ack_epoch);
    serde_json::from_slice(&drain(&request, queue).unwrap()).unwrap()
}

/// A page from `queue`, acknowledging `ack_through` from the same queue.
fn drained(
    queue: &DirectEvidenceQueue,
    max_records: Option<usize>,
    ack_through: Option<u64>,
) -> Value {
    drained_from(queue, max_records, ack_through, Some(&queue.epoch))
}

#[test]
fn records_drain_once_in_order() {
    let queue = DirectEvidenceQueue::default();
    for index in 0..3 {
        assert!(queue.offer(json!({ "index": index })));
    }
    let page = drained(&queue, Some(2), None);
    assert_eq!(page["schema"], "guard-hook-direct-evidence.v1");
    assert_eq!(page["records"], json!([{ "index": 0 }, { "index": 1 }]));
    assert_eq!(page["remaining"], 1);
    let acknowledged = page["through"].as_u64();
    let page = drained(&queue, None, acknowledged);
    assert_eq!(page["records"], json!([{ "index": 2 }]));
    assert_eq!(page["remaining"], 0);
    assert_eq!(
        drained(&queue, None, page["through"].as_u64())["records"],
        json!([])
    );
}

#[test]
fn a_page_stays_queued_until_the_daemon_acknowledges_it() {
    let queue = DirectEvidenceQueue::default();
    assert!(queue.offer(json!({ "index": 0 })));
    let page = drained(&queue, None, None);
    assert_eq!(page["records"], json!([{ "index": 0 }]));
    assert_eq!(
        drained(&queue, None, None)["records"],
        json!([{ "index": 0 }])
    );
    let page = drained(&queue, None, page["through"].as_u64());
    assert_eq!(page["records"], json!([]));
    assert_eq!(page["remaining"], 0);
}

#[test]
fn a_full_queue_refuses_new_records() {
    let queue = DirectEvidenceQueue::default();
    for index in 0..MAX_QUEUED_RECORDS {
        assert!(queue.offer(json!(index)));
    }
    assert!(!queue.offer(json!("overflow")));
    let page = drained(&queue, Some(1), None);
    assert!(!queue.offer(json!("still full")));
    drained(&queue, Some(1), page["through"].as_u64());
    assert!(queue.offer(json!("fits again")));
}

#[test]
fn an_oversized_record_is_refused() {
    let queue = DirectEvidenceQueue::default();
    let large = "x".repeat(MAX_RECORD_BYTES);
    assert!(!queue.offer(json!({ "payload": large })));
    assert_eq!(drained(&queue, None, None)["remaining"], 0);
}

#[test]
fn a_page_stops_before_the_response_cap() {
    let queue = DirectEvidenceQueue::default();
    let large = "x".repeat(MAX_RECORD_BYTES - 64);
    assert!(queue.offer(json!({ "payload": large.clone() })));
    assert!(queue.offer(json!({ "payload": large })));
    let page = drained(&queue, None, None);
    assert_eq!(page["records"].as_array().unwrap().len(), 1);
    assert_eq!(page["remaining"], 1);
}

#[test]
fn a_cursor_from_another_resident_drops_nothing() {
    let earlier = DirectEvidenceQueue::default();
    for index in 0..3 {
        assert!(earlier.offer(json!({ "earlier": index })));
    }
    let stale = drained(&earlier, None, None);
    let restarted = DirectEvidenceQueue::default();
    assert_ne!(restarted.epoch, earlier.epoch);
    assert!(restarted.offer(json!({ "restarted": 0 })));
    let epoch = stale["epoch"].as_str();
    for _ in 0..2 {
        let page = drained_from(&restarted, None, stale["through"].as_u64(), epoch);
        assert_eq!(page["records"], json!([{ "restarted": 0 }]));
        assert_eq!(page["epoch"], json!(restarted.epoch));
    }
    let page = drained_from(&restarted, None, Some(1), None);
    assert_eq!(page["records"], json!([{ "restarted": 0 }]));
}

#[test]
fn headroom_keeps_a_worst_case_record_and_spare_slots_free() {
    let queue = DirectEvidenceQueue::default();
    assert!(queue.has_headroom());
    let large = "x".repeat(MAX_RECORD_BYTES - 64);
    for _ in 0..6 {
        assert!(queue.offer(json!({ "payload": large.clone() })));
    }
    assert!(queue.has_headroom());
    assert!(queue.offer(json!({ "payload": large })));
    assert!(!queue.has_headroom());
    // Headroom only gates the caller that asks; ordinary records still fit.
    assert!(queue.offer(json!({ "small": 0 })));

    let crowded = DirectEvidenceQueue::default();
    for index in 0..MAX_QUEUED_RECORDS - HEADROOM_RECORDS {
        assert!(crowded.offer(json!({ "index": index })));
    }
    assert!(crowded.has_headroom());
    assert!(crowded.offer(json!({ "index": "one more" })));
    assert!(!crowded.has_headroom());
}

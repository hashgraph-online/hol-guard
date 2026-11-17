use super::*;

fn need(n: usize) -> Failure {
    Failure::Need(json!({"sha256": format!("{n:064x}")}))
}

#[test]
fn a_batch_holds_at_most_thirty_two_distinct_requests() {
    let mut misses = Misses::default();
    for n in 0..40 {
        assert!(misses.take::<()>(Err(need(n))).is_none());
    }
    assert_eq!(misses.requests.len(), BATCH);
    assert!(misses.stopped);
}

#[test]
fn a_shared_miss_is_requested_once() {
    let mut misses = Misses::default();
    misses.take::<()>(Err(need(1)));
    misses.take::<()>(Err(need(1)));
    misses.take::<()>(Err(Failure::Batch(vec![
        json!({"need": {"sha256": format!("{:064x}", 1)}}),
    ])));
    misses.take::<()>(Err(Failure::Archives(json!([{"sha256": "a"}]))));
    misses.take::<()>(Err(Failure::Archives(json!([{"sha256": "a"}]))));
    assert_eq!(misses.requests.len(), 2);
    assert!(!misses.stopped);
}

#[test]
fn nothing_is_queued_after_an_invalid_proof() {
    let mut misses = Misses::default();
    misses.take::<()>(Err(need(1)));
    misses.take::<()>(Err(Failure::Invalid("active_security_proof_invalid")));
    misses.take::<()>(Err(need(2)));
    misses.take::<()>(Err(Failure::Archives(json!([{"sha256": "b"}]))));
    misses.take::<()>(Err(Failure::Batch(vec![json!({"need": {"sha256": "c"}})])));
    assert!(misses.stopped);
    assert_eq!(
        misses.requests,
        vec![json!({"need": {"sha256": format!("{:064x}", 1)}})]
    );
    assert_eq!(misses.take(Ok(7)), Some(7));
}

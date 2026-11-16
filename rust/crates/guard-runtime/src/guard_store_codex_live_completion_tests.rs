//! The pieces of a Codex live completion that need no store: which resume
//! replays a decision, which correlation the continuation carries, and the
//! evidence id it records.

use super::*;

const CORRELATION: &str = "gcr_0f1e2d3c-4b5a-4968-8776-655443322110";

#[test]
fn only_a_terminal_resume_of_the_same_action_replays() {
    for status in ["resumed", "sent"] {
        let resume = json!({"resolution_action": "allow", "status": status});
        assert!(terminal_matches(&resume, "allow"), "{status}");
        assert!(!terminal_matches(&resume, "block"), "{status}");
    }
    for status in ["blocked", "skipped"] {
        let resume = json!({"resolution_action": "block", "status": status});
        assert!(terminal_matches(&resume, "block"), "{status}");
    }
    for resume in [
        json!({"resolution_action": "allow", "status": "waiting"}),
        json!({"resolution_action": "allow", "status": "blocked"}),
        json!({"resolution_action": "block", "status": "resumed"}),
        json!({"resolution_action": "allow"}),
        Value::Null,
    ] {
        assert!(!terminal_matches(&resume, "allow"), "{resume}");
        assert!(!terminal_matches(&resume, "block"), "{resume}");
    }
}

#[test]
fn the_first_carried_correlation_wins() {
    let request = json!({
        "continuation_snapshot": {"correlationId": "not-a-correlation"},
        "decision_v2_json": {"correlation_id": format!(" {CORRELATION} ")},
        "correlation_id": "gcr_ffffffff-ffff-4fff-8fff-ffffffffffff",
    });
    assert_eq!(
        correlation(&request, &Value::Null, "req-1").unwrap(),
        CORRELATION
    );
    let metadata = json!({"correlationId": "gcr_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"});
    assert_eq!(
        correlation(&request, &metadata, "req-1").unwrap(),
        "gcr_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    );
}

#[test]
fn a_request_without_a_carried_correlation_derives_its_own() {
    let derived = correlation(&json!({}), &Value::Null, "req-1").unwrap();
    assert!(correlation_shaped(&derived), "{derived}");
    assert_eq!(derived, correlation_id("req-1").unwrap());
}

#[test]
fn evidence_ids_are_random_v4_uuids() {
    let first = evidence_id().unwrap();
    let hex = first.strip_prefix("evidence-").unwrap();
    assert_eq!(hex.len(), 32);
    assert!(hex
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
    assert_eq!(&hex[12..13], "4");
    assert!(matches!(&hex[16..17], "8" | "9" | "a" | "b"));
    assert_ne!(first, evidence_id().unwrap());
}

#[test]
fn a_failure_names_its_code() {
    assert_eq!(
        failure("request_not_found"),
        json!({"completed": false, "error": "request_not_found"})
    );
}

fn allow(revision: i64) -> Value {
    json!({"approval_id": "approval-1", "_approval_authority_revision": revision})
}

/// Runs `settle_on_fresh_authority` over scripted reads and spends, returning
/// its answer and how many times the authority was read.
fn settle(reads: Vec<Result<Value, Value>>, spends: Vec<bool>, current: i64) -> (Value, usize) {
    let reads = std::cell::RefCell::new(reads.into_iter());
    let spends = std::cell::RefCell::new(spends.into_iter());
    let count = std::cell::Cell::new(0);
    let answer = settle_on_fresh_authority(
        || {
            count.set(count.get() + 1);
            Ok(reads.borrow_mut().next().expect("no read left"))
        },
        |decision| {
            let spent = spends.borrow_mut().next().expect("no spend left");
            Ok(spent.then(|| json!({"completed": true, "spent": decision.clone()})))
        },
        |decision| Ok(decision["_approval_authority_revision"].as_i64() != Some(current)),
    )
    .unwrap();
    (answer, count.get())
}

#[test]
fn an_allow_refused_after_another_allow_moved_the_revision_is_read_again_and_spent() {
    let (answer, reads) = settle(vec![Ok(allow(7)), Ok(allow(8))], vec![false, true], 8);
    assert_eq!(answer, json!({"completed": true, "spent": allow(8)}));
    assert_eq!(reads, 2);
}

#[test]
fn a_refused_spend_at_the_same_revision_is_not_read_again() {
    let (answer, reads) = settle(vec![Ok(allow(7))], vec![false], 7);
    assert_eq!(answer, failure("continuation_not_recorded"));
    assert_eq!(reads, 1);
}

#[test]
fn a_block_saved_before_the_second_read_answers_instead_of_the_old_allow() {
    let (answer, reads) = settle(
        vec![
            Ok(allow(7)),
            Err(failure("exact_approval_authority_missing")),
        ],
        vec![false],
        8,
    );
    assert_eq!(answer, failure("exact_approval_authority_missing"));
    assert_eq!(reads, 2);
}

#[test]
fn the_authority_is_read_a_bounded_number_of_times() {
    let (answer, reads) = settle(
        vec![Ok(allow(1)); AUTHORITY_READS],
        vec![false; AUTHORITY_READS],
        9,
    );
    assert_eq!(answer, failure("continuation_not_recorded"));
    assert_eq!(reads, AUTHORITY_READS);
}

#[test]
fn the_revision_has_moved_only_when_the_store_holds_another() {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table guard_approval_authority_revision (singleton integer primary key,
               revision integer);
             insert into guard_approval_authority_revision values (1, 7);",
        )
        .unwrap();
    assert!(!authority_moved(&connection, &allow(7)).unwrap());
    assert!(authority_moved(&connection, &allow(6)).unwrap());
    assert!(!authority_moved(&connection, &Value::Null).unwrap());
}

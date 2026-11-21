//! The stored resume reads answer as `store_resume.py` answered: one
//! request's row, or the most recently attempted one.

use super::*;
use serde_json::Map;

fn store() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table guard_request_resumes (
               request_id text primary key, operation_id text, harness text not null,
               resolution_action text, strategy text not null,
               supported integer not null default 0, status text not null, thread_id text,
               reason text, message text, last_error text,
               attempt_count integer not null default 0, created_at text not null,
               updated_at text not null, last_attempt_at text, sent_at text,
               continuation_contract_version text, continuation_capability text,
               continuation_status text, continuation_reason text,
               continuation_evidence_json text not null default '[]',
               continuation_offer_hash text, continuation_action text,
               continuation_completed_at text, continuation_cancelled_at text);
             insert into guard_request_resumes
               (request_id, harness, strategy, supported, status, created_at, updated_at,
                last_attempt_at, continuation_evidence_json)
             values
               ('req-a', 'codex', 'thread', 1, 'sent', 't0', 't1', 't5', '[{\"id\": 1}, 2]'),
               ('req-b', 'codex', 'thread', 0, 'pending', 't0', 't3', null, 'not json'),
               ('req-c', 'pi', 'manual-only', 0, 'pending', 't0', 't9', null, '[]');",
        )
        .unwrap();
    connection
}

fn call(op: fn(&Connection, &Args<'_>) -> StoreResult<Value>, args: Value) -> Value {
    let Value::Object(args) = args else {
        unreachable!()
    };
    op(&store(), &Args(&args)).unwrap()
}

#[test]
fn one_request_reads_its_row_with_decoded_evidence() {
    let resume = call(get, json!({"request_id": "req-a"}));
    assert_eq!(resume["supported"], json!(true));
    assert_eq!(resume["continuation_evidence"], json!([{"id": 1}]));
    assert!(resume.get("continuation_evidence_json").is_none());
    assert_eq!(
        call(get, json!({"request_id": "req-b"}))["continuation_evidence"],
        json!([])
    );
    assert_eq!(call(get, json!({"request_id": "missing"})), Value::Null);
}

#[test]
fn the_latest_resume_orders_by_its_last_attempt() {
    assert_eq!(call(latest, json!({}))["request_id"], json!("req-c"));
    assert_eq!(
        call(latest, json!({"harness": "codex"}))["request_id"],
        json!("req-a")
    );
    assert_eq!(call(latest, json!({"harness": "claude-code"})), Value::Null);
}

#[test]
fn a_request_id_is_required() {
    let args = Map::new();
    assert!(get(&store(), &Args(&args)).is_err());
}

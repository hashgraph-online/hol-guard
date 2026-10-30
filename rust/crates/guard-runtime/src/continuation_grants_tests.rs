//! A continuation spends only the authority it read: an approval authority
//! revision that moved after the read refuses the spend before any grant row
//! is touched.

use super::*;

fn store(revision: i64) -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table guard_approval_authority_revision \
             (singleton integer primary key, revision integer)",
        )
        .unwrap();
    connection
        .execute(
            "insert into guard_approval_authority_revision values (1, ?)",
            [revision],
        )
        .unwrap();
    connection
}

fn decision(revision: i64) -> Value {
    json!({
        "action": "allow",
        "approval_id": "approval-1",
        "artifact_id": "codex:project:bash",
        "authority_kind": "legacy",
        "_approval_authority_revision": revision,
    })
}

const NOW: &str = "2026-10-30T12:00:00+00:00";

#[test]
fn authority_whose_revision_moved_after_the_read_is_not_spent() {
    // No grant table exists: a refusal that reached the grant rows would fail.
    let connection = store(5);
    assert!(!consume(&connection, "req-1", &decision(4), NOW, b"key", "key-1").unwrap());
    // The same authority at the current revision does read the grant rows.
    assert!(consume(&connection, "req-1", &decision(5), NOW, b"key", "key-1").is_err());
}

#[test]
fn authority_without_a_read_revision_is_not_spent() {
    let connection = store(5);
    let mut unread = decision(5);
    unread["_approval_authority_revision"] = Value::Null;
    assert!(!consume(&connection, "req-1", &unread, NOW, b"key", "key-1").unwrap());
    unread["_approval_authority_revision"] = json!(-1);
    assert!(!consume(&connection, "req-1", &unread, NOW, b"key", "key-1").unwrap());
}

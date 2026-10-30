//! The Codex live authority answers only the valid one-shot allow its request
//! names, and refuses a lookup that could spend or bypass anything.

use super::*;
use serde_json::{json, Map};

const NOW: &str = "2026-10-30T12:00:00+00:00";

fn allow() -> Value {
    json!({
        "action": "allow",
        "source": "approval-gate-once",
        "request_id": "req-1",
        "integrity_status": "valid",
        "approval_id": "approval-1",
    })
}

fn lookup(change: &[(&str, Value)]) -> Value {
    let mut lookup = json!({
        "schema": guard_contracts::POLICY_DECISION_LOOKUP_REQUEST_SCHEMA,
        "store_path": "/elsewhere/guard.db",
        "guard_home": "/elsewhere",
        "harness": "codex",
        "artifact_id": "codex:bash",
        "artifact_hash": "sha256:abc",
        "now": NOW,
        "consume_one_shot": false,
    });
    for (field, value) in change {
        lookup[*field] = value.clone();
    }
    lookup
}

fn resolve_with(lookup: Option<Value>) -> StoreResult<Value> {
    let connection = Connection::open_in_memory().unwrap();
    let mut args = Map::new();
    args.insert("request_id".into(), json!("req-1"));
    args.insert("now".into(), json!(NOW));
    if let Some(lookup) = lookup {
        args.insert("lookup".into(), lookup);
    }
    resolve(&connection, "/nonexistent-guard-home", &Args(&args), None)
}

#[test]
fn only_the_valid_one_shot_allow_of_this_request_answers() {
    assert!(answers(&allow(), "req-1"));
    assert!(!answers(&allow(), "req-2"));
    for (field, value) in [
        ("action", json!("block")),
        ("source", json!("approval-gate")),
        ("integrity_status", json!("invalid")),
        ("approval_id", Value::Null),
        ("request_id", Value::Null),
    ] {
        let mut decision = allow();
        decision[field] = value;
        assert!(!answers(&decision, "req-1"), "{field}");
    }
    assert!(!answers(&Value::Null, "req-1"));
}

#[test]
fn no_key_and_no_lookup_is_no_authority() {
    assert_eq!(resolve_with(None).unwrap(), Value::Null);
}

#[test]
fn a_lookup_that_cannot_read_its_store_is_no_authority() {
    assert_eq!(resolve_with(Some(lookup(&[]))).unwrap(), Value::Null);
}

#[test]
fn a_lookup_that_could_spend_or_bypass_authority_is_refused() {
    for change in [
        ("consume_one_shot", json!(true)),
        ("local_once_only", json!(true)),
        ("portable_workspace", json!("git-project:v1:caller-chosen")),
        ("unknown_field", json!(1)),
        ("integrity_key_b64", json!("a2V5")),
        ("local_once_integrity_key_b64", json!("a2V5")),
    ] {
        assert!(
            matches!(
                resolve_with(Some(lookup(&[change.clone()]))),
                Err(StoreError::Invalid("codex_live_authority_lookup_invalid"))
            ),
            "{}",
            change.0
        );
    }
}

#[test]
fn the_lookup_gets_the_call_key_only_when_it_names_that_key() {
    assert_eq!(
        carried(Some("a2V5"), Some("key-1"), Some("key-1")),
        Some("a2V5".to_owned())
    );
    assert_eq!(carried(Some("a2V5"), Some("key-1"), Some("key-2")), None);
    assert_eq!(carried(Some("a2V5"), Some("key-1"), None), None);
    assert_eq!(carried(Some("a2V5"), None, None), None);
    assert_eq!(carried(None, Some("key-1"), Some("key-1")), None);
}

#[test]
fn a_workspace_without_a_name_has_no_portable_identity() {
    assert_eq!(identity(None, None), PortableIdentity::Absent);
    assert_eq!(
        identity(Some("  "), Some("/work")),
        PortableIdentity::Absent
    );
    let named = format!("git-project:v1:{}", "a".repeat(64));
    assert_eq!(
        identity(Some(&format!(" {named} ")), Some("/work")),
        PortableIdentity::Identity(named.clone())
    );
    assert_eq!(
        identity(Some(&named), None),
        PortableIdentity::Identity(named)
    );
}

fn native_with(extra: &[(&str, Value)]) -> StoreResult<Value> {
    let connection = Connection::open_in_memory().unwrap();
    let mut args = Map::new();
    args.insert("request_id".into(), json!("req-1"));
    args.insert("now".into(), json!(NOW));
    args.insert("native_evidence".into(), json!(true));
    for (field, value) in extra {
        args.insert((*field).into(), value.clone());
    }
    resolve(&connection, "/nonexistent-guard-home", &Args(&args), None)
}

#[test]
fn native_evidence_without_a_published_binding_asks_the_caller_for_it() {
    assert!(matches!(
        native_with(&[]),
        Err(StoreError::Invalid(EVIDENCE_REQUIRED))
    ));
}

#[test]
fn native_evidence_refuses_a_caller_key_or_lookup() {
    for field in ["lookup", "integrity_key_b64"] {
        let value = if field == "lookup" {
            lookup(&[])
        } else {
            json!("a2V5")
        };
        assert!(
            matches!(
                native_with(&[(field, value)]),
                Err(StoreError::Invalid("codex_live_authority_lookup_invalid"))
            ),
            "{field}"
        );
    }
}

#[test]
fn the_op_reports_a_missing_binding_with_a_code_the_transport_passes_on() {
    let connection = Connection::open_in_memory().unwrap();
    let mut args = Map::new();
    args.insert("request_id".into(), json!("req-1"));
    args.insert("now".into(), json!(NOW));
    args.insert("native_evidence".into(), json!(true));
    assert!(matches!(
        op(&connection, "/nonexistent-guard-home", &Args(&args), None),
        Err(StoreError::Invalid(NATIVE_EVIDENCE_REQUIRED))
    ));
    // `native_guard_store.py` keeps a resident reason only in this shape.
    let suffix = NATIVE_EVIDENCE_REQUIRED
        .strip_prefix("native_guard_store_")
        .unwrap();
    assert!(suffix.len() <= 48);
    assert!(suffix
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte == b'_'));
}

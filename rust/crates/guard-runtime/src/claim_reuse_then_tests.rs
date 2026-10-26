//! A claim that runs more work before it commits: the claim commits only with
//! that work's answer, and every refusal or failure leaves the store exactly as
//! it was, so the approval stays claimable.

use guard_contracts::ClaimEvidenceBindingV1;
use rusqlite::{params, Connection};
use serde_json::Value;

use crate::claim_reuse::{claim_approval_reuse_decisions_then, ClaimEvidence};
use crate::claim_reuse_binding::evidence_is_bound;
use crate::store_vectors_support_tests::{decode_key, dump_store, gunzip_json, seeded_store};

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/claim_vectors.json.gz");
/// A one-shot approval: its first claim consumes it.
pub(crate) const ONE_SHOT: &str = "lo-basic-packageFalse";
/// A saved local policy row: a claim retains it.
pub(crate) const LOCAL_POLICY: &str = "pol-basic-approval-gate-False";

pub(crate) struct Case {
    pub(crate) connection: Connection,
    request: Value,
}

pub(crate) fn case(id: &str) -> Case {
    let document = gunzip_json(VECTORS);
    let vector = document["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["id"] == id)
        .unwrap_or_else(|| panic!("vector {id} missing"))
        .clone();
    assert_eq!(vector["expected"]["claimed"], Value::Bool(true));
    let connection = seeded_store(&document["schema_sql"], &vector["seed"]);
    connection
        .execute_batch(
            "create table sync_state (state_key text primary key, payload_json text not null);
             create table guard_devices (
               device_key text primary key, installation_id text not null, device_label text not null
             );
             insert into guard_devices values ('local-device', 'install-1', 'laptop');",
        )
        .unwrap();
    let request = vector["request"].clone();
    if !request["integrity_state"].is_null() {
        connection
            .execute(
                "insert into sync_state (state_key, payload_json) values ('policy_integrity', ?1)",
                params![request["integrity_state"].to_string()],
            )
            .unwrap();
    }
    Case {
        connection,
        request,
    }
}

/// Claim the case's rows the way the relay claim does, running `after` inside
/// the claim's transaction.
pub(crate) fn claim<T>(
    case: &Case,
    after: &mut dyn FnMut(&Connection) -> rusqlite::Result<Option<T>>,
) -> rusqlite::Result<Option<T>> {
    let request = &case.request;
    let policy_key = decode_key(&request["integrity_key_b64"]);
    let local_key = decode_key(&request["local_once_integrity_key_b64"]);
    let state = (!request["integrity_state"].is_null()).then(|| request["integrity_state"].clone());
    let evidence = ClaimEvidence {
        integrity_state: state.as_ref(),
        integrity_key: policy_key.as_deref(),
        integrity_key_id: request["integrity_key_id"].as_str(),
        local_once_key: local_key.as_deref(),
        local_once_key_id: request["local_once_integrity_key_id"].as_str(),
        policy_bundle_identities: None,
    };
    let binding = ClaimEvidenceBindingV1::default();
    let now = guard_contracts::canonical_utc_timestamp(request["now"].as_str().unwrap())
        .expect("recorded now must canonicalize");
    claim_approval_reuse_decisions_then(
        &case.connection,
        request["decisions"].as_array().unwrap(),
        &now,
        &evidence,
        &|connection, members| evidence_is_bound(connection, members, &evidence, Some(&binding)),
        false,
        after,
    )
}

#[test]
fn a_committed_one_shot_claim_is_refused_the_second_time() {
    let case = case(ONE_SHOT);
    let before = dump_store(&case.connection);
    assert_eq!(
        claim(&case, &mut |_| Ok(Some("forward"))).unwrap(),
        Some("forward")
    );
    assert_ne!(dump_store(&case.connection), before, "the claim committed");
    let mut ran = false;
    let second = claim(&case, &mut |_| {
        ran = true;
        Ok(Some("forward"))
    });
    assert_eq!(second.unwrap(), None);
    assert!(!ran, "nothing runs after a refused claim");
}

#[test]
fn work_after_the_claim_sees_the_claimed_store() {
    for id in [ONE_SHOT, LOCAL_POLICY] {
        let case = case(id);
        let before = dump_store(&case.connection);
        let mut inside = None;
        let answer = claim(&case, &mut |connection| {
            inside = Some(dump_store(connection));
            Ok(Some(()))
        });
        assert_eq!(answer.unwrap(), Some(()), "{id}");
        assert_ne!(
            inside.as_ref(),
            Some(&before),
            "{id}: claimed in the transaction"
        );
        assert_eq!(
            inside,
            Some(dump_store(&case.connection)),
            "{id}: committed as seen"
        );
    }
}

#[test]
fn a_refusal_after_the_claim_rolls_it_back() {
    for id in [ONE_SHOT, LOCAL_POLICY] {
        let case = case(id);
        let before = dump_store(&case.connection);
        assert_eq!(claim::<()>(&case, &mut |_| Ok(None)).unwrap(), None, "{id}");
        assert_eq!(dump_store(&case.connection), before, "{id}: nothing spent");
        assert!(case.connection.is_autocommit(), "{id}: no open transaction");
        assert_eq!(
            claim(&case, &mut |_| Ok(Some(()))).unwrap(),
            Some(()),
            "{id}: still claimable"
        );
    }
}

#[test]
fn a_failure_after_the_claim_rolls_it_back() {
    for id in [ONE_SHOT, LOCAL_POLICY] {
        let case = case(id);
        let before = dump_store(&case.connection);
        let failed = claim::<()>(&case, &mut |connection| {
            connection.execute_batch("select * from no_such_table")?;
            Ok(Some(()))
        });
        assert!(failed.is_err(), "{id}");
        assert_eq!(dump_store(&case.connection), before, "{id}: nothing spent");
        assert!(case.connection.is_autocommit(), "{id}: no open transaction");
        assert_eq!(
            claim(&case, &mut |_| Ok(Some(()))).unwrap(),
            Some(()),
            "{id}: still claimable"
        );
    }
}

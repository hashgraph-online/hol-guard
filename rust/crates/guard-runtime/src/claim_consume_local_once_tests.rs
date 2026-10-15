//! `consume_local_once` settles a package-request approval that the shared
//! disposition otherwise retains for replay (the legacy package claim).

use crate::claim_reuse::{claim_approval_reuse_decisions_with, ClaimEvidence};
use crate::store_vectors_support_tests::{decode_key, gunzip_json, seeded_store};

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/claim_vectors.json.gz");

fn claim_package_request(consume_local_once: bool) -> Option<String> {
    let document = gunzip_json(VECTORS);
    let vector = document["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["id"] == "lo-basic-packageTrue")
        .expect("package-request vector missing")
        .clone();
    let connection = seeded_store(&document["schema_sql"], &vector["seed"]);
    let request = &vector["request"];
    let key = decode_key(&request["local_once_integrity_key_b64"]);
    let evidence = ClaimEvidence {
        integrity_state: None,
        integrity_key: None,
        integrity_key_id: None,
        local_once_key: key.as_deref(),
        local_once_key_id: request["local_once_integrity_key_id"].as_str(),
        policy_bundle_identities: None,
    };
    let now = guard_contracts::canonical_utc_timestamp(request["now"].as_str().unwrap()).unwrap();
    let claimed = claim_approval_reuse_decisions_with(
        &connection,
        request["decisions"].as_array().unwrap(),
        &now,
        &evidence,
        &|_, _| Ok(true),
        consume_local_once,
    )
    .unwrap();
    assert!(claimed, "the recorded package-request claim must succeed");
    let approval_id = request["decisions"][0]["approval_id"].as_str().unwrap();
    connection
        .query_row(
            "select claimed_at from guard_local_once_approvals where approval_id = ?1",
            [approval_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .unwrap()
}

#[test]
fn package_request_approval_is_retained_by_default() {
    assert_eq!(claim_package_request(false), None);
}

#[test]
fn consume_local_once_settles_the_package_request_approval() {
    assert!(claim_package_request(true).is_some());
}

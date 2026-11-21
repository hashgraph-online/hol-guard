use super::*;
use crate::store_vectors_support_tests::{dump_store, gunzip_json, seeded_store};

#[test]
fn launch_clock_is_sampled_under_the_write_lock_and_failure_rolls_back() {
    let document = gunzip_json(include_bytes!("../tests/fixtures/claim_vectors.json.gz"));
    let vector = document["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["id"] == crate::claim_reuse_then_tests::ONE_SHOT)
        .unwrap();
    let connection = seeded_store(&document["schema_sql"], &vector["seed"]);
    let before = dump_store(&connection);
    let evidence = ClaimEvidence {
        integrity_state: None,
        integrity_key: None,
        integrity_key_id: None,
        local_once_key: None,
        local_once_key_id: None,
        policy_bundle_identities: None,
    };
    let sampled = std::cell::Cell::new(false);
    let result: rusqlite::Result<Option<()>> = claim_with_clock(
        &connection,
        vector["request"]["decisions"].as_array().unwrap(),
        &|connection| {
            assert!(
                !connection.is_autocommit(),
                "native clock must follow BEGIN IMMEDIATE"
            );
            sampled.set(true);
            Err(rusqlite::Error::InvalidQuery)
        },
        &evidence,
        &|_, _| panic!("clock failure must not reach claim"),
        true,
        &mut |_| panic!("clock failure must not reach dispatch"),
    );
    assert!(result.is_err());
    assert!(sampled.get());
    assert!(connection.is_autocommit());
    assert_eq!(dump_store(&connection), before);
}

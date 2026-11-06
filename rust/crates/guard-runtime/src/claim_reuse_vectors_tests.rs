//! Parity vectors recorded from the retired Python
//! `GuardStore.claim_approval_reuse_decisions`: each one seeded a real store,
//! ran the claim with the evidence the Python consulted, and recorded the
//! verdict plus the full store state afterwards.

use serde_json::Value;

use crate::claim_reuse::{claim_approval_reuse_decisions, ClaimEvidence};
use crate::store_vectors_support_tests::{decode_key, dump_store, gunzip_json, seeded_store};

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/claim_vectors.json.gz");

fn identities(request: &Value) -> Option<Vec<Vec<Value>>> {
    let list = request["policy_bundle_decision_identities"].as_array()?;
    Some(
        list.iter()
            .map(|row| row.as_array().cloned().unwrap_or_default())
            .collect(),
    )
}

#[test]
fn claim_matches_every_recorded_vector() {
    let document = gunzip_json(VECTORS);
    let vectors = document["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 219, "corpus changed size");
    for vector in vectors {
        let request = &vector["request"];
        let connection = seeded_store(&document["schema_sql"], &vector["seed"]);
        let policy_key = decode_key(&request["integrity_key_b64"]);
        let local_key = decode_key(&request["local_once_integrity_key_b64"]);
        let bundle = identities(request);
        let state =
            (!request["integrity_state"].is_null()).then(|| request["integrity_state"].clone());
        let evidence = ClaimEvidence {
            integrity_state: state.as_ref(),
            integrity_key: policy_key.as_deref(),
            integrity_key_id: request["integrity_key_id"].as_str(),
            local_once_key: local_key.as_deref(),
            local_once_key_id: request["local_once_integrity_key_id"].as_str(),
            policy_bundle_identities: bundle.as_deref(),
        };
        let now = guard_contracts::canonical_utc_timestamp(request["now"].as_str().unwrap())
            .expect("recorded now must canonicalize");
        let decisions = request["decisions"].as_array().unwrap();
        let claimed =
            claim_approval_reuse_decisions(&connection, decisions, &now, &evidence, &|_, _| {
                Ok(true)
            })
            .unwrap_or_else(|error| panic!("vector {} errored: {error}", vector["id"]));
        assert_eq!(
            Value::Bool(claimed),
            vector["expected"]["claimed"],
            "vector {} verdict diverged",
            vector["id"]
        );
        assert_eq!(
            dump_store(&connection),
            vector["expected"]["after"],
            "vector {} store state diverged",
            vector["id"]
        );
    }
}

#[test]
fn corpus_covers_every_claim_family() {
    let document = gunzip_json(VECTORS);
    let vectors = document["vectors"].as_array().unwrap();
    for group in ["local_once", "revision", "batch", "policy", "remote"] {
        for verdict in [true, false] {
            assert!(
                vectors.iter().any(
                    |v| v["group"] == group && v["expected"]["claimed"] == Value::Bool(verdict)
                ),
                "no {verdict} vector for {group}"
            );
        }
    }
}

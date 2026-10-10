//! Parity vectors recorded from the retired Python
//! `GuardStore._approval_reuse_diagnostic_inner`: each one seeded a real store
//! "world", asked for a diagnosis, and recorded the reason, the stored hash and
//! which integrity evidence the Python had to procure to get there.

use guard_contracts::{
    ApprovalReuseDiagnosticEvidenceV1, ApprovalReuseDiagnosticRequestV1,
    APPROVAL_REUSE_DIAGNOSTIC_REQUEST_SCHEMA,
};
use serde_json::{json, Value};

use crate::approval_reuse_diagnostic_op::diagnose;
use crate::store_vectors_support_tests::{gunzip_json, seeded_store};

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/diag_vectors.json.gz");

fn text(value: &Value) -> Option<String> {
    value.as_str().map(str::to_owned)
}

fn request(vector: &Value, with_evidence: bool) -> ApprovalReuseDiagnosticRequestV1 {
    let input = &vector["request"];
    let evidence = &input["evidence"];
    ApprovalReuseDiagnosticRequestV1 {
        schema: APPROVAL_REUSE_DIAGNOSTIC_REQUEST_SCHEMA.to_owned(),
        request_id: String::new(),
        store_path: String::new(),
        guard_home: String::new(),
        harness: text(&input["harness"]).unwrap(),
        artifact_id: text(&input["artifact_id"]).unwrap(),
        artifact_hash: text(&input["artifact_hash"]),
        workspace: text(&input["workspace"]),
        publisher: text(&input["publisher"]),
        now: text(&input["now"]).unwrap(),
        evidence: with_evidence.then(|| ApprovalReuseDiagnosticEvidenceV1 {
            integrity_state: (!evidence["integrity_state"].is_null())
                .then(|| evidence["integrity_state"].clone()),
            integrity_key_b64: text(&evidence["integrity_key_b64"]),
            integrity_key_id: text(&evidence["integrity_key_id"]),
            local_once_integrity_key_b64: text(&evidence["local_once_integrity_key_b64"]),
            local_once_integrity_key_id: text(&evidence["local_once_integrity_key_id"]),
        }),
    }
}

#[test]
fn diagnostic_matches_every_recorded_vector() {
    let document = gunzip_json(VECTORS);
    let worlds = document["worlds"].as_array().unwrap();
    let vectors = document["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 811, "corpus changed size");
    let stores: Vec<_> = worlds
        .iter()
        .map(|world| seeded_store(&document["schema_sql"], &world["seed"]))
        .collect();
    for vector in vectors {
        let world = vector["world"].as_u64().unwrap() as usize;
        let connection = &stores[world];
        if vector["request"]["artifact_id"].is_null() {
            // The Python wrapper answers a missing artifact id without the resident.
            assert_eq!(
                vector["expected"],
                json!({"reason": null, "stored_hash": null})
            );
            continue;
        }
        let now =
            guard_contracts::canonical_utc_timestamp(vector["request"]["now"].as_str().unwrap())
                .expect("recorded now must canonicalize");
        let needs = &vector["request"]["needs"];
        let any_need = needs["policy"] == json!(true) || needs["local_once"] == json!(true);
        if any_need {
            let asked = diagnose(connection, &request(vector, false), now.clone()).unwrap();
            assert_eq!(
                asked,
                json!({
                    "need": "integrity_evidence",
                    "policy": needs["policy"],
                    "local_once": needs["local_once"],
                }),
                "vector {:?} asked for different evidence",
                vector["label"]
            );
        }
        if !any_need {
            let direct = diagnose(connection, &request(vector, false), now.clone()).unwrap();
            assert_eq!(
                direct["reason"], vector["expected"]["reason"],
                "no-evidence call diverged"
            );
        }
        let answered = diagnose(connection, &request(vector, true), now).unwrap();
        assert_eq!(
            answered,
            json!({
                "reason": vector["expected"]["reason"],
                "stored_hash": vector["expected"]["stored_hash"],
            }),
            "world {world} vector {:?} diverged",
            vector["label"]
        );
    }
}

#[test]
fn corpus_covers_every_reason() {
    let document = gunzip_json(VECTORS);
    let vectors = document["vectors"].as_array().unwrap();
    for reason in [
        json!(null),
        json!("approval_reuse_expired"),
        json!("approval_reuse_content_changed"),
        json!("approval_reuse_identity_changed"),
        json!("approval_reuse_integrity_failure"),
    ] {
        assert!(
            vectors.iter().any(|v| v["expected"]["reason"] == reason),
            "no vector for {reason}"
        );
    }
}

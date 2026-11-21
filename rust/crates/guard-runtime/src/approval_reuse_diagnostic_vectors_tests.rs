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

/// Vectors the recorded Python answered `approval_reuse_expired` and the
/// current diagnosis answers with the mismatch that was already there.
///
/// The Python asked whether the row had expired before it compared the row's
/// payload, workspace and publisher against the request. A row that had gone
/// stale *and* named different content or a different workspace therefore came
/// back as "expired", which tells the reader their approval lapsed when in
/// truth it never covered this request. World 9 shows the cost plainly: one
/// unclaimed row and one request produce `approval_reuse_identity_changed` at
/// 12:00 and 13:00 and `approval_reuse_expired` at 18:00, though nothing moved
/// but the clock.
///
/// Expiry is now the last question asked, so `approval_reuse_expired` is
/// reserved for a row that matched on every other count. These are the recorded
/// vectors that answer differently because of it; the other sixteen recorded
/// `approval_reuse_expired` vectors are unchanged, and no other vector moves.
const REORDERED_EXPIRY: &[(usize, &str)] = &[
    (66, "approval_reuse_content_changed"),
    (67, "approval_reuse_content_changed"),
    (68, "approval_reuse_content_changed"),
    (69, "approval_reuse_content_changed"),
    (74, "approval_reuse_content_changed"),
    (75, "approval_reuse_content_changed"),
    (76, "approval_reuse_content_changed"),
    (77, "approval_reuse_content_changed"),
    (78, "approval_reuse_content_changed"),
    (79, "approval_reuse_content_changed"),
    (80, "approval_reuse_content_changed"),
    (81, "approval_reuse_content_changed"),
    (82, "approval_reuse_content_changed"),
    (83, "approval_reuse_content_changed"),
    (84, "approval_reuse_content_changed"),
    (85, "approval_reuse_content_changed"),
    (86, "approval_reuse_content_changed"),
    (87, "approval_reuse_content_changed"),
    (88, "approval_reuse_content_changed"),
    (89, "approval_reuse_content_changed"),
    (90, "approval_reuse_content_changed"),
    (91, "approval_reuse_content_changed"),
    (92, "approval_reuse_content_changed"),
    (93, "approval_reuse_content_changed"),
    (346, "approval_reuse_content_changed"),
    (347, "approval_reuse_content_changed"),
    (348, "approval_reuse_content_changed"),
    (349, "approval_reuse_content_changed"),
    (354, "approval_reuse_content_changed"),
    (355, "approval_reuse_content_changed"),
    (356, "approval_reuse_content_changed"),
    (357, "approval_reuse_content_changed"),
    (358, "approval_reuse_content_changed"),
    (359, "approval_reuse_content_changed"),
    (360, "approval_reuse_content_changed"),
    (361, "approval_reuse_content_changed"),
    (362, "approval_reuse_content_changed"),
    (363, "approval_reuse_content_changed"),
    (364, "approval_reuse_content_changed"),
    (365, "approval_reuse_content_changed"),
    (366, "approval_reuse_content_changed"),
    (367, "approval_reuse_content_changed"),
    (368, "approval_reuse_content_changed"),
    (369, "approval_reuse_content_changed"),
    (370, "approval_reuse_content_changed"),
    (371, "approval_reuse_content_changed"),
    (372, "approval_reuse_content_changed"),
    (373, "approval_reuse_content_changed"),
    (805, "approval_reuse_identity_changed"),
    (806, "approval_reuse_identity_changed"),
    (809, "approval_reuse_identity_changed"),
    (810, "approval_reuse_identity_changed"),
];

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
        current_action: None,
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
    for (index, vector) in vectors.iter().enumerate() {
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
        let reordered = REORDERED_EXPIRY
            .iter()
            .find(|(recorded, _)| *recorded == index)
            .map(|(_, reason)| *reason);
        let expected_reason = match reordered {
            Some(reason) => {
                assert_eq!(
                    vector["expected"]["reason"],
                    json!("approval_reuse_expired"),
                    "vector {index} is pinned as a reordered expiry but was not recorded expired"
                );
                json!(reason)
            }
            None => vector["expected"]["reason"].clone(),
        };
        assert_eq!(
            answered,
            json!({
                "reason": expected_reason,
                "stored_hash": vector["expected"]["stored_hash"],
            }),
            "world {world} vector {index} {:?} diverged",
            vector["label"]
        );
    }
}

/// A row either covers a request or it does not, and the clock cannot change
/// which. World 9 holds one unclaimed allow scoped to a workspace and a
/// publisher the request never names, so the diagnosis is the same before and
/// after that row goes stale.
#[test]
fn the_clock_alone_never_changes_why_a_row_was_rejected() {
    let document = gunzip_json(VECTORS);
    let world = &document["worlds"][9];
    let connection = seeded_store(&document["schema_sql"], &world["seed"]);
    let vectors = document["vectors"].as_array().unwrap();
    let fresh = &vectors[803];
    let stale = &vectors[809];
    assert_eq!(
        fresh["request"]["artifact_id"],
        stale["request"]["artifact_id"]
    );
    let answer = |vector: &Value| {
        let now =
            guard_contracts::canonical_utc_timestamp(vector["request"]["now"].as_str().unwrap())
                .expect("recorded now must canonicalize");
        diagnose(&connection, &request(vector, true), now).unwrap()["reason"].clone()
    };
    assert_eq!(answer(fresh), json!("approval_reuse_identity_changed"));
    assert_eq!(answer(stale), answer(fresh));
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

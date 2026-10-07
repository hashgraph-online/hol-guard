use super::*;
use serde_json::json;

fn source() -> Value {
    json!({
        "apiVersion":"guard.hashgraphonline.com/v1alpha1", "kind":"GuardPolicy",
        "metadata":{"id":"policy.source", "name":"Source", "revision":1},
        "spec":{"defaults":{"mode":"enforce", "defaultAction":"block"},
            "rules":[{"id":"mail.rule", "enabled":true, "effect":"review",
                "match":{"business":{"schema":"guard.business-policy-match.v1", "version":1,
                    "services":["google_gmail"], "operations":["mail_send"]}},
                "lifetime":{"mode":"until", "expiresAt":"2026-07-16T00:00:00.000000001Z"},
                "provenance":{"source":"local", "createdAt":"2026-07-15T00:00:00Z"}}]}
    })
}

#[test]
fn authentic_source_recompiles_exact_binding_and_retains_nanoseconds() {
    let source = source();
    let bytes = sign_business_source(&source, 7, &[1; 32]).unwrap();
    let verified = verify_business_source(&bytes, &[1; 32]).unwrap();
    assert_eq!(verified.mutation_revision(), 7);
    assert_eq!(verified.record_digest(), digest_bytes(&bytes));
    assert_eq!(
        verified.compiled().canonical_source(),
        canonical_json_bytes(&source).unwrap()
    );
    assert_eq!(
        verified.compiled().binding().rules[0].expires_at.as_deref(),
        Some("2026-07-16T00:00:00.000000001Z")
    );
}

#[test]
fn wrong_key_and_mutated_source_revision_or_mode_cannot_authenticate() {
    let bytes = sign_business_source(&source(), 1, &[2; 32]).unwrap();
    assert!(matches!(
        verify_business_source(&bytes, &[3; 32]),
        Err(BusinessSourceError::Authentication)
    ));
    for field in ["source", "mutation_revision", "import_mode", "digest"] {
        let mut record: Value = serde_json::from_slice(&bytes).unwrap();
        match field {
            "source" => record["source_document"]["metadata"]["name"] = json!("Changed"),
            "mutation_revision" => record["mutation_revision"] = json!(2),
            "import_mode" => record["import_mode"] = json!("merge"),
            _ => record["source_digest"] = json!("f".repeat(64)),
        }
        assert!(verify_business_source(&canonical_json_bytes(&record).unwrap(), &[2; 32]).is_err());
    }
}

#[test]
fn authentic_mac_does_not_bypass_source_digest_or_native_semantics() {
    let bytes = sign_business_source(&source(), 1, &[4; 32]).unwrap();
    for change in ["digest", "selector"] {
        let mut record: BusinessSourceRecord = serde_json::from_slice(&bytes).unwrap();
        if change == "digest" {
            record.source_digest = "f".repeat(64);
        } else {
            record.source_document["spec"]["rules"][0]["match"]["actors"] = json!(["hidden-scope"]);
        }
        record.mac = signing_mac(&record, &[4; 32]).unwrap();
        assert!(verify_business_source(&record_bytes(&record).unwrap(), &[4; 32]).is_err());
    }
}

#[test]
fn noncanonical_duplicate_and_unbounded_records_are_refused() {
    let bytes = sign_business_source(&source(), 1, &[5; 32]).unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(verify_business_source(&serde_json::to_vec_pretty(&value).unwrap(), &[5; 32]).is_err());
    let duplicate = String::from_utf8(bytes).unwrap().replacen(
        "\"revision\":1",
        "\"revision\":1,\"revision\":1",
        1,
    );
    assert_eq!(duplicate.matches("\"revision\":1").count(), 2);
    assert!(verify_business_source(duplicate.as_bytes(), &[5; 32]).is_err());
    assert!(matches!(
        verify_business_source(&vec![0; MAX_BUSINESS_SOURCE_AUTHORITY_BYTES + 1], &[5; 32]),
        Err(BusinessSourceError::Bounds)
    ));
    assert!(sign_business_source(&source(), 0, &[5; 32]).is_err());
}

#[test]
fn retained_floor_refuses_signed_rollback_and_conflicting_exact_replay() {
    let original = source();
    let bytes = sign_business_source(&original, 7, &[6; 32]).unwrap();
    let accepted = verify_business_source(&bytes, &[6; 32]).unwrap();
    let floor = accepted.floor();
    accepted.check_retained_floor(&floor).unwrap();
    let older = sign_business_source(&original, 6, &[6; 32]).unwrap();
    assert_eq!(
        verify_business_source(&older, &[6; 32])
            .unwrap()
            .check_retained_floor(&floor),
        Err(BusinessSourceError::Rollback)
    );
    let mut changed = original;
    changed["metadata"]["name"] = json!("Another name");
    let conflicting = sign_business_source(&changed, 7, &[6; 32]).unwrap();
    assert_eq!(
        verify_business_source(&conflicting, &[6; 32])
            .unwrap()
            .check_retained_floor(&floor),
        Err(BusinessSourceError::Rollback)
    );
}

#[test]
fn newer_mutation_cannot_substitute_document_revision_content() {
    let original = source();
    let bytes = sign_business_source(&original, 7, &[7; 32]).unwrap();
    let floor = verify_business_source(&bytes, &[7; 32]).unwrap().floor();
    let mut changed = original;
    changed["metadata"]["name"] = json!("Another name");
    let conflicting = sign_business_source(&changed, 8, &[7; 32]).unwrap();
    assert_eq!(
        verify_business_source(&conflicting, &[7; 32])
            .unwrap()
            .check_retained_floor(&floor),
        Err(BusinessSourceError::RevisionConflict)
    );
    changed["metadata"]["revision"] = json!(2);
    let next = sign_business_source(&changed, 8, &[7; 32]).unwrap();
    let verified = verify_business_source(&next, &[7; 32]).unwrap();
    verified.check_retained_floor(&floor).unwrap();
    let newer_floor = verified.floor();
    let rewound_document = sign_business_source(&source(), 9, &[7; 32]).unwrap();
    assert_eq!(
        verify_business_source(&rewound_document, &[7; 32])
            .unwrap()
            .check_retained_floor(&newer_floor),
        Err(BusinessSourceError::RevisionConflict)
    );
}

#[test]
fn malformed_retained_floor_is_not_treated_as_unarmed() {
    let bytes = sign_business_source(&source(), 1, &[8; 32]).unwrap();
    let verified = verify_business_source(&bytes, &[8; 32]).unwrap();
    let floor = verified.floor();
    for field in ["source_id", "record_digest", "source_digest"] {
        let mut value = serde_json::to_value(&floor).unwrap();
        value[field] = json!("");
        let malformed: BusinessSourceFloor = serde_json::from_value(value).unwrap();
        assert_eq!(
            verified.check_retained_floor(&malformed),
            Err(BusinessSourceError::InvalidRecord)
        );
    }
}

#[test]
fn schema_valid_zero_source_revision_remains_authenticated_and_retained() {
    let mut document = source();
    document["metadata"]["revision"] = json!(0);
    let bytes = sign_business_source(&document, 1, &[9; 32]).unwrap();
    let zero = verify_business_source(&bytes, &[9; 32]).unwrap();
    zero.check_retained_floor(&zero.floor()).unwrap();
    let mut changed = document.clone();
    changed["metadata"]["name"] = json!("Substituted zero revision");
    let conflicting = sign_business_source(&changed, 2, &[9; 32]).unwrap();
    assert_eq!(
        verify_business_source(&conflicting, &[9; 32])
            .unwrap()
            .check_retained_floor(&zero.floor()),
        Err(BusinessSourceError::RevisionConflict)
    );
    document["metadata"]["revision"] = json!(1);
    let next = sign_business_source(&document, 2, &[9; 32]).unwrap();
    verify_business_source(&next, &[9; 32])
        .unwrap()
        .check_retained_floor(&zero.floor())
        .unwrap();
}

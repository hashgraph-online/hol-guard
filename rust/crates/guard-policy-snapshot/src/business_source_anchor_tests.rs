use super::*;
use crate::business_source_authority::{sign_business_source, verify_business_source};
use serde_json::{json, Value};

fn source(revision: u64) -> VerifiedBusinessSource {
    let mut document: Value = serde_json::from_str(include_str!(
        "../../../../contracts/business-policy/source-authority-v1-fixture.json"
    ))
    .unwrap();
    document["metadata"]["revision"] = json!(revision);
    let wire = sign_business_source(&document, revision, &[1; 32]).unwrap();
    verify_business_source(&wire, &[1; 32]).unwrap()
}

#[test]
fn closed_marker_authenticates_identity_but_never_admits_source() {
    let source = source(1);
    let wire = sign_business_source_anchor(&source, BusinessSourcePhase::Closed, &[1; 32]).unwrap();
    let marker = verify_business_source_anchor(&wire, &[1; 32]).unwrap();
    assert_eq!(marker.phase(), BusinessSourcePhase::Closed);
    assert_eq!(marker.floor(), &source.floor());
    assert!(marker.check_committed_source(&source).is_err());
    assert!(!String::from_utf8(wire)
        .unwrap()
        .contains("private-source-marker"));
}

#[test]
fn committed_marker_binds_exact_source_and_native_policy_digest() {
    let source = source(1);
    let wire =
        sign_business_source_anchor(&source, BusinessSourcePhase::Committed, &[1; 32]).unwrap();
    let marker = verify_business_source_anchor(&wire, &[1; 32]).unwrap();
    marker.check_committed_source(&source).unwrap();
    assert_eq!(marker.anchor_digest(), digest_bytes(&wire));
    assert_eq!(
        marker.floor().source_digest(),
        source.compiled().source_digest()
    );
    assert_eq!(marker.floor().business_policy_digest().len(), 64);
    assert!(marker
        .check_committed_source(&super::tests::source(2))
        .is_err());
}

#[test]
fn wrong_key_and_phase_or_floor_tampering_refuse() {
    let source = source(1);
    assert!(
        sign_business_source_anchor(&source, BusinessSourcePhase::Committed, &[2; 32]).is_err()
    );
    let wire = sign_business_source_anchor(&source, BusinessSourcePhase::Closed, &[1; 32]).unwrap();
    assert!(verify_business_source_anchor(&wire, &[2; 32]).is_err());
    for field in ["phase", "floor"] {
        let mut record: Value = serde_json::from_slice(&wire).unwrap();
        if field == "phase" {
            record["phase"] = json!("committed");
        } else {
            record["floor"]["business_policy_digest"] = json!("f".repeat(64));
        }
        assert!(
            verify_business_source_anchor(&canonical_json_bytes(&record).unwrap(), &[1; 32])
                .is_err()
        );
    }
}

#[test]
fn valid_mac_on_invalid_floor_and_noncanonical_or_oversized_marker_refuse() {
    let source = source(1);
    let wire =
        sign_business_source_anchor(&source, BusinessSourcePhase::Committed, &[1; 32]).unwrap();
    let mut record: AnchorRecord = serde_json::from_slice(&wire).unwrap();
    let mut floor = serde_json::to_value(&record.floor).unwrap();
    floor["mutation_revision"] = json!(0);
    record.floor = serde_json::from_value(floor).unwrap();
    record.mac = mac(&record, &[1; 32]).unwrap();
    assert!(verify_business_source_anchor(&bytes(&record).unwrap(), &[1; 32]).is_err());
    let pretty =
        serde_json::to_vec_pretty(&serde_json::from_slice::<Value>(&wire).unwrap()).unwrap();
    assert!(verify_business_source_anchor(&pretty, &[1; 32]).is_err());
    assert!(verify_business_source_anchor(
        &vec![0; MAX_BUSINESS_SOURCE_ANCHOR_BYTES + 1],
        &[1; 32]
    )
    .is_err());
}

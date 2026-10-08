use super::*;

#[test]
fn committed_core_without_cloud_positive_cannot_restore_or_renew_after_restart() {
    use crate::approval::approval_v4::ApprovalConsumptionCommit;
    let mut fixture = CloudFixture::new("aged-cloud-consumed-positive-write-failure");
    let original = fixture.age();
    let renewed = fixture.renew().unwrap();
    let challenge: ApprovalChallengeV4 =
        serde_json::from_value(renewed["challenge"].clone()).unwrap();
    fixture.install(&challenge, 0x05).unwrap();
    let artifact = serde_json::from_value(
        fixture.journal()["records"][&fixture.request_id]["installed"]["artifact"].clone(),
    )
    .unwrap();
    let failure = crate::approval::approval_v4::consume_approval_with_emit(
        ApprovalConsumeRequestV4 {
            schema: NATIVE_APPROVAL_CONSUME_REQUEST_V4_SCHEMA.into(),
            version: 4,
            envelope: fixture.envelope.clone(),
            artifact,
        },
        &fixture.store,
        None,
        |commit| match commit {
            ApprovalConsumptionCommit::Prepared {
                nonce_digest,
                consumed_at_ms,
            } => {
                let mut journal = fixture.journal();
                journal["records"][&fixture.request_id]["consumption_started"] = json!({
                    "nonce_digest":nonce_digest, "started_at_ms":consumed_at_ms,
                });
                fixture.write_journal(&journal);
                Ok(())
            }
            ApprovalConsumptionCommit::Consumed { receipt, .. } => {
                let actual: ApprovalResultV4 = serde_json::from_slice(receipt).unwrap();
                assert_eq!(actual.receipt.phase, "consumed");
                // Fail the private positive-write callback after core committed. This is
                // a unit callback seam, not a production fault-control or fake receipt.
                Err("native_cloud_review_v4_state_unavailable".into())
            }
        },
    )
    .unwrap_err();
    assert_eq!(failure, "native_cloud_review_v4_state_unavailable");
    assert_eq!(fixture.query()["phase"], "recovery_required");
    assert!(fixture.query()["receipt"].is_null());
    assert_eq!(
        fixture.renew().unwrap_err(),
        "native_cloud_review_v4_consumption_recovery_required"
    );
    assert_eq!(
        fixture.install(&challenge, 0x05).unwrap_err(),
        "native_cloud_review_v4_consumption_recovery_required"
    );
    fixture.restart();
    assert_eq!(fixture.query()["phase"], "recovery_required");
    assert_eq!(
        fixture.renew().unwrap_err(),
        "native_cloud_review_v4_consumption_recovery_required"
    );
    let mut retry = fixture.envelope.clone();
    retry.request_id = Some("new-harness-id-after-unknown-outcome".into());
    assert_eq!(
        crate::edge::evaluate_envelope_with_store(retry, &fixture.store).unwrap_err(),
        "native_cloud_review_v4_consumption_recovery_required"
    );
    assert_eq!(
        fixture.journal()["records"][&fixture.request_id]["challenge"],
        original["challenge"]
    );
    fs::remove_dir_all(fixture.root).unwrap();
}
#[test]
fn pending_renewal_restart_requires_new_assertion_and_unknown_outcome_never_renews() {
    let mut fixture = CloudFixture::new("aged-cloud-renew-pending-restart");
    fixture.age();
    let before = fixture.renew().unwrap();
    let old_challenge: ApprovalChallengeV4 =
        serde_json::from_value(before["challenge"].clone()).unwrap();
    fixture.restart();
    let after = fixture.renew().unwrap();
    assert_ne!(after["challenge"]["nonce"], before["challenge"]["nonce"]);
    assert_ne!(
        after["challenge"]["resident_epoch"],
        before["challenge"]["resident_epoch"]
    );
    assert_eq!(after["decision_receipt_id"], before["decision_receipt_id"]);
    assert_eq!(after["source_claim_hash"], before["source_claim_hash"]);
    assert_eq!(
        fixture.install(&old_challenge, 0x05).unwrap_err(),
        "native_cloud_review_v4_original_challenge_mismatch"
    );
    let challenge: ApprovalChallengeV4 =
        serde_json::from_value(after["challenge"].clone()).unwrap();
    assert_eq!(
        fixture.install(&challenge, 0x05).unwrap()["phase"],
        "waiting_for_hook"
    );
    write_private(
        &fixture.root,
        &fixture.root.join("cloud-review-v4-journal.test.json"),
        b"{",
    );
    assert!(fixture.renew().is_err());
    assert!(
        crate::edge::evaluate_envelope_with_store(fixture.envelope.clone(), &fixture.store)
            .is_err()
    );
    assert_eq!(
        fs::read(fixture.root.join("cloud-review-v4-journal.test.json")).unwrap(),
        b"{"
    );
    fs::remove_dir_all(fixture.root).unwrap();
}

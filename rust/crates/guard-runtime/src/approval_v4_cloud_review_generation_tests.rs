use super::*;

fn enrolled_record(fixture: &CloudFixture) -> ApprovalAuthorityV4 {
    serde_json::from_slice(&fs::read(fixture.root.join("approval-authority-v4.json")).unwrap())
        .unwrap()
}

fn next_record(
    fixture: &CloudFixture,
    key: &Ed25519KeyPair,
    credential: &[u8],
) -> ApprovalAuthorityV4 {
    let mut record = enrolled_record(fixture);
    record.previous_key_id = Some(record.key_id.clone());
    record.enrollment_generation += 1;
    let cose = cose_ed25519(key.public_key().as_ref());
    record.key_id = digest_bytes(&cose);
    record.cose_public_key = hex::encode(cose);
    record.credential_id = hex::encode(credential);
    record.enrollment_signature.clear();
    record
}

fn submit_record(fixture: &CloudFixture, record: &ApprovalAuthorityV4) -> Result<(), String> {
    let bytes =
        crate::policy_store::approval_v4_authority::tests::test_record_bytes(record).unwrap();
    let path = fixture.root.join("candidate-generation-v4.json");
    write_private(&fixture.root, &path, &bytes);
    crate::policy_store::approval_v4_authority::install_record(&fixture.root, &path)
}

fn rotate(fixture: &mut CloudFixture, key: &Ed25519KeyPair, credential: &[u8]) {
    submit_record(fixture, &next_record(fixture, key, credential)).unwrap();
    fixture.restart();
}

fn install_signed(
    fixture: &CloudFixture,
    challenge: &ApprovalChallengeV4,
    credential: &[u8],
    key: &Ed25519KeyPair,
    flags: u8,
) -> Result<Value, String> {
    let assertion = assertion_with_values(
        challenge,
        credential,
        1,
        &challenge.webauthn.origin,
        &challenge.webauthn.challenge,
        flags,
        |message| key.sign(message).as_ref().to_vec(),
    );
    let request = serde_json::from_value(json!({
        "schema":"guard-native-cloud-review-install-request.v4", "version":4,
        "request_id":fixture.request_id, "decision_receipt_id":DECISION, "source_claim_hash":fixture.source,
        "proof":{"schema":"guard-native-approval-proof.v4", "challenge":challenge, "assertion":assertion}
    })).unwrap();
    native::install(request, &fixture.store).map(|bytes| serde_json::from_slice(&bytes).unwrap())
}

#[test]
fn root_signed_generation_chain_renews_saved_decision_and_requires_current_up_uv() {
    let mut fixture = CloudFixture::new("cloud-renew-current-generation-chain");
    let original = fixture.age();
    let intermediate = Ed25519KeyPair::from_seed_unchecked(&[72; 32]).unwrap();
    let current = Ed25519KeyPair::from_seed_unchecked(&[74; 32]).unwrap();
    let credential = [75; 32];
    rotate(&mut fixture, &intermediate, &[73; 32]);
    rotate(&mut fixture, &current, &credential);
    fixture.refresh_policy();
    fixture.consent(2, 0, true);
    let renewed = fixture.renew().unwrap();
    let challenge: ApprovalChallengeV4 =
        serde_json::from_value(renewed["challenge"].clone()).unwrap();
    assert_eq!(challenge.signing_key_id, enrolled_record(&fixture).key_id);
    assert_eq!(
        challenge.webauthn.credential_id,
        encode_base64url(&credential)
    );
    assert_ne!(
        challenge.signing_key_id,
        original["challenge"]["signing_key_id"]
    );
    assert_eq!(renewed["decision_receipt_id"], DECISION);
    assert_eq!(renewed["source_claim_hash"], fixture.source);
    assert_eq!(
        renewed["original_nonce_digest"],
        fixture.original_nonce_digest
    );
    assert_eq!(renewed["consent_revision"], 2);
    assert_eq!(fixture.query()["phase"], "waiting_for_authorization");

    let before = fixture.journal();
    assert!(fixture.install(&challenge, 0x05).is_err());
    assert_eq!(fixture.journal(), before);
    assert!(install_signed(&fixture, &challenge, &credential, &fixture.key, 0x05).is_err());
    assert_eq!(fixture.journal(), before);
    for flags in [0x01, 0x04] {
        assert!(install_signed(&fixture, &challenge, &credential, &current, flags).is_err());
        assert_eq!(fixture.journal(), before);
    }
    assert_eq!(
        install_signed(&fixture, &challenge, &credential, &current, 0x05).unwrap()["phase"],
        "waiting_for_hook"
    );
    assert!(fixture.query()["receipt"].is_null());

    let mut wrong_action = fixture.envelope.clone();
    wrong_action.request_id = Some("different-generation-action".into());
    wrong_action.raw_payload["command"] = json!("git diff");
    let denied: Value = serde_json::from_slice(
        &crate::edge::evaluate_envelope_with_store(wrong_action, &fixture.store).unwrap(),
    )
    .unwrap();
    assert_eq!(denied["result"]["decision"], "deny");
    assert!(denied.get("native_application_v4").is_none());
    assert_eq!(fixture.query()["phase"], "waiting_for_hook");

    let consumed: Value = serde_json::from_slice(
        &crate::edge::evaluate_envelope_with_store(fixture.envelope.clone(), &fixture.store)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(consumed["result"]["decision"], "allow");
    assert_eq!(
        consumed["native_application_v4"]["receipt"]["phase"],
        "consumed"
    );
    let positive = fixture.query();
    assert_eq!(positive["phase"], "consumed");
    assert_eq!(positive["decision_receipt_id"], DECISION);
    assert_eq!(positive["source_claim_hash"], fixture.source);
    assert_eq!(
        positive["receipt"]["credential_id_digest"],
        digest_bytes(&credential)
    );
    assert_eq!(
        positive["receipt"]["nonce_digest"],
        digest_bytes(&hex::decode(&challenge.nonce).unwrap())
    );
    assert_eq!(
        fixture.journal()["records"][&fixture.request_id]["challenge"],
        original["challenge"]
    );
    assert!(fixture.renew().is_err());
    let replay: Value = serde_json::from_slice(
        &crate::edge::evaluate_envelope_with_store(fixture.envelope.clone(), &fixture.store)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(replay["result"]["decision"], "deny");
    assert!(replay.get("native_application_v4").is_none());
    assert_eq!(fixture.query(), positive);
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn pending_aged_renewal_moves_to_current_generation_without_replacing_original() {
    let mut fixture = CloudFixture::new("cloud-renew-pending-generation-rotation");
    let original = fixture.age();
    let pending = fixture.renew().unwrap();
    let old: ApprovalChallengeV4 = serde_json::from_value(pending["challenge"].clone()).unwrap();
    let current = Ed25519KeyPair::from_seed_unchecked(&[76; 32]).unwrap();
    let credential = [77; 32];
    rotate(&mut fixture, &current, &credential);
    let renewed = fixture.renew().unwrap();
    let fresh: ApprovalChallengeV4 = serde_json::from_value(renewed["challenge"].clone()).unwrap();
    assert_eq!(fresh.webauthn.credential_id, encode_base64url(&credential));
    assert_ne!(fresh.nonce, old.nonce);
    assert_ne!(fresh.signing_key_id, old.signing_key_id);
    assert!(fixture.install(&old, 0x05).is_err());
    assert_eq!(
        install_signed(&fixture, &fresh, &credential, &current, 0x05).unwrap()["phase"],
        "waiting_for_hook"
    );
    assert_eq!(
        fixture.journal()["records"][&fixture.request_id]["challenge"],
        original["challenge"]
    );
    assert_eq!(fixture.query()["decision_receipt_id"], DECISION);
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn generation_rotation_rejects_wrong_lineage_device_and_untrusted_root_without_mutation() {
    let fixture = CloudFixture::new("cloud-renew-generation-lineage-rejection");
    fixture.age();
    fixture.renew().unwrap();
    let key = Ed25519KeyPair::from_seed_unchecked(&[78; 32]).unwrap();
    let candidate = next_record(&fixture, &key, &[79; 32]);
    let original_authority = fs::read(fixture.root.join("approval-authority-v4.json")).unwrap();
    let original_journal = fixture.journal();
    let mut wrong_lineage = candidate.clone();
    wrong_lineage.previous_key_id = Some("f".repeat(64));
    assert!(submit_record(&fixture, &wrong_lineage).is_err());
    let mut wrong_device = candidate.clone();
    wrong_device.device_binding = "c".repeat(64);
    assert!(submit_record(&fixture, &wrong_device).is_err());
    let mut wrong_installation = candidate.clone();
    wrong_installation.installation_binding = "b".repeat(64);
    assert!(submit_record(&fixture, &wrong_installation).is_err());

    let mut signed: Value = serde_json::from_slice(
        &crate::policy_store::approval_v4_authority::tests::test_record_bytes(&candidate).unwrap(),
    )
    .unwrap();
    signed
        .as_object_mut()
        .unwrap()
        .remove("enrollment_signature");
    let signing_bytes = guard_policy_snapshot::canonical_json_bytes(&signed).unwrap();
    let mut message = guard_contracts::NATIVE_APPROVAL_V4_ENROLLMENT_DOMAIN.to_vec();
    message.extend_from_slice(&signing_bytes);
    let unrelated_root = Ed25519KeyPair::from_seed_unchecked(&[80; 32]).unwrap();
    signed["enrollment_signature"] = json!(hex::encode(unrelated_root.sign(&message).as_ref()));
    let path = fixture.root.join("untrusted-root-generation-v4.json");
    write_private(
        &fixture.root,
        &path,
        &guard_policy_snapshot::canonical_json_bytes(&signed).unwrap(),
    );
    assert!(
        crate::policy_store::approval_v4_authority::install_record(&fixture.root, &path).is_err()
    );
    assert_eq!(
        fs::read(fixture.root.join("approval-authority-v4.json")).unwrap(),
        original_authority
    );
    assert_eq!(fixture.journal(), original_journal);
    assert!(fixture.query()["receipt"].is_null());
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn authenticated_rotation_never_weakens_original_pin_or_action_binding() {
    let mut fixture = CloudFixture::new("cloud-renew-generation-original-binding");
    fixture.age();
    let current = Ed25519KeyPair::from_seed_unchecked(&[81; 32]).unwrap();
    rotate(&mut fixture, &current, &[82; 32]);
    let original = fixture.journal();
    let mut wrong_pin = original.clone();
    wrong_pin["records"][&fixture.request_id]["authority_fingerprint"] = json!("e".repeat(64));
    fixture.write_journal(&wrong_pin);
    assert!(fixture.renew().is_err());
    assert_eq!(fixture.journal(), wrong_pin);
    let mut wrong_action = original;
    wrong_action["records"][&fixture.request_id]["challenge"]["action_digest"] =
        json!("b".repeat(64));
    fixture.write_journal(&wrong_action);
    assert!(fixture.renew().is_err());
    assert_eq!(fixture.journal(), wrong_action);
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn revoked_generation_cannot_be_reactivated_by_deleting_public_authority() {
    let fixture = CloudFixture::new("cloud-renew-generation-revoked-floor");
    fixture.age();
    fixture.renew().unwrap();
    let mut revoked = enrolled_record(&fixture);
    revoked.enrollment_generation += 1;
    revoked.status = "revoked".into();
    revoked.previous_key_id = None;
    submit_record(&fixture, &revoked).unwrap();
    assert!(crate::policy_store::approval_v4_authority::load(&fixture.root).is_err());
    assert!(fixture.renew().is_err());
    assert!(
        crate::policy_store::approval_v4_authority::prepare_enrollment(
            &fixture.root,
            &revoked.rp_id,
            &revoked.origin,
        )
        .is_err()
    );
    let key = Ed25519KeyPair::from_seed_unchecked(&[83; 32]).unwrap();
    let candidate = next_record(&fixture, &key, &[84; 32]);
    let mut candidate = candidate;
    candidate.status = "active".into();
    assert!(submit_record(&fixture, &candidate).is_err());
    fs::remove_file(fixture.root.join("approval-authority-v4.json")).unwrap();
    assert!(submit_record(&fixture, &candidate).is_err());
    assert!(
        crate::policy_store::approval_v4_authority::prepare_enrollment(
            &fixture.root,
            &revoked.rp_id,
            &revoked.origin,
        )
        .is_err()
    );
    assert!(fixture.query()["receipt"].is_null());
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn native_enrollment_prepares_successor_generation_and_pins_existing_realm() {
    let mut fixture = CloudFixture::new("cloud-renew-successor-enrollment-request");
    let initial = enrolled_record(&fixture);
    let prepare = |fixture: &CloudFixture| -> Value {
        serde_json::from_slice(
            &crate::policy_store::approval_v4_authority::prepare_enrollment(
                &fixture.root,
                &initial.rp_id,
                &initial.origin,
            )
            .unwrap(),
        )
        .unwrap()
    };
    let request = prepare(&fixture);
    assert_eq!(
        request["enrollment_generation"],
        initial.enrollment_generation + 1
    );
    assert_eq!(request["device_binding"], initial.device_binding);
    assert_eq!(
        request["installation_binding"],
        initial.installation_binding
    );
    let next = Ed25519KeyPair::from_seed_unchecked(&[85; 32]).unwrap();
    rotate(&mut fixture, &next, &[86; 32]);
    let successor = prepare(&fixture);
    assert_eq!(
        successor["enrollment_generation"],
        enrolled_record(&fixture).enrollment_generation + 1
    );
    assert_eq!(successor["device_binding"], initial.device_binding);
    assert_eq!(
        successor["installation_binding"],
        initial.installation_binding
    );
    assert!(
        crate::policy_store::approval_v4_authority::prepare_enrollment(
            &fixture.root,
            "example.com",
            "https://example.com:9443",
        )
        .is_err()
    );
    fs::remove_dir_all(fixture.root).unwrap();
}

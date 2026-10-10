use super::*;
use crate::policy_store::native_cloud_review_v4 as native;
use serde_json::{json, Value};
use std::io::Write;

const DECISION: &str = "saved-offline-decision";
const CREDENTIAL: [u8; 32] = [71; 32];

struct CloudFixture {
    root: std::path::PathBuf,
    store: crate::policy_store::PolicySnapshotStore,
    envelope: GuardHookEnvelopeV2,
    key: Ed25519KeyPair,
    request_id: String,
    source: String,
    original_nonce_digest: String,
}

fn write_private(root: &Path, path: &Path, bytes: &[u8]) {
    let mut file = crate::resident_state::private_file(path, false, root).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

impl CloudFixture {
    fn new(label: &str) -> Self {
        let key = Ed25519KeyPair::from_seed_unchecked(&[70; 32]).unwrap();
        let (root, store, envelope) = store_and_envelope_v4(
            label,
            &cose_ed25519(key.public_key().as_ref()),
            -8,
            &CREDENTIAL,
        );
        let request_id = crate::edge::request_identity(&envelope).unwrap().0;
        let mut fixture = Self {
            root,
            store,
            envelope,
            key,
            request_id,
            source: "a".repeat(64),
            original_nonce_digest: String::new(),
        };
        fixture.consent(1, 0, true);
        let denied: Value = serde_json::from_slice(
            &crate::edge::evaluate_envelope_with_store(fixture.envelope.clone(), &fixture.store)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(denied["result"]["decision"], "deny");
        assert!(denied.get("native_application_v4").is_none());
        let nonce = fixture.journal()["records"][&fixture.request_id]["challenge"]["nonce"]
            .as_str()
            .unwrap()
            .to_owned();
        fixture.original_nonce_digest =
            guard_policy_snapshot::digest_bytes(&hex::decode(nonce).unwrap());
        fixture
    }

    fn consent(&self, revision: u64, epoch: u64, enabled: bool) {
        let now = now_ms().unwrap();
        let state = json!({"schema":"guard-native-cloud-review-consent-state.v1", "version":1,
            "revision":revision, "revocation_epoch":epoch, "enabled":enabled,
            "issued_at_ms":now.saturating_sub(1), "expires_at_ms":now + 3_600_000});
        write_private(
            &self.root,
            &self.root.join("cloud-review-consent.test.json"),
            &serde_json::to_vec(&state).unwrap(),
        );
    }

    fn journal(&self) -> Value {
        serde_json::from_slice(
            &fs::read(self.root.join("cloud-review-v4-journal.test.json")).unwrap(),
        )
        .unwrap()
    }

    fn write_journal(&self, journal: &Value) {
        write_private(
            &self.root,
            &self.root.join("cloud-review-v4-journal.test.json"),
            &serde_json::to_vec(journal).unwrap(),
        );
    }

    fn age(&self) -> Value {
        // Historical-clock fixture only: no production journal or physical UV proof.
        let mut journal = self.journal();
        let now = now_ms().unwrap();
        let original = &mut journal["records"][&self.request_id]["challenge"];
        original["issued_at_ms"] = json!(now - 300_001);
        original["expires_at_ms"] = json!(now - 1);
        if journal["records"][&self.request_id]["installed"].is_object() {
            let installed = &mut journal["records"][&self.request_id]["installed"];
            installed["artifact"]["issued_at_ms"] = json!(now - 300_001);
            installed["artifact"]["expires_at_ms"] = json!(now - 1);
            installed["validated"]["receipt"]["issued_at_ms"] = json!(now - 300_001);
            installed["validated"]["receipt"]["expires_at_ms"] = json!(now - 1);
        }
        self.write_journal(&journal);
        journal["records"][&self.request_id].clone()
    }

    fn renew(&self) -> Result<Value, String> {
        native::renew(
            self.renewal_request(
                "guard-native-cloud-review-renewal-request.v4",
                DECISION,
                &self.source,
            ),
            &self.store,
        )
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
    }

    fn renewal_request(
        &self,
        schema: &str,
        decision: &str,
        source: &str,
    ) -> native::RenewalRequest {
        native::RenewalRequest {
            schema: schema.into(),
            version: 4,
            request_id: self.request_id.clone(),
            decision_receipt_id: decision.into(),
            source_claim_hash: source.into(),
            original_nonce_digest: self.original_nonce_digest.clone(),
        }
    }

    fn delivery(&self, schema: &str) -> native::DeliveryRequest {
        native::DeliveryRequest {
            schema: schema.into(),
            version: 4,
            request_id: self.request_id.clone(),
            decision_receipt_id: Some(DECISION.into()),
            source_claim_hash: Some(self.source.clone()),
            proof: None,
        }
    }

    fn query(&self) -> Value {
        serde_json::from_slice(
            &native::query(
                self.delivery("guard-native-cloud-review-consumption-query.v4"),
                &self.store,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn install(&self, challenge: &ApprovalChallengeV4, flags: u8) -> Result<Value, String> {
        self.install_with_counter(challenge, flags, 1)
    }

    fn install_with_counter(
        &self,
        challenge: &ApprovalChallengeV4,
        flags: u8,
        counter: u32,
    ) -> Result<Value, String> {
        // Real Ed25519 signature over WebAuthn bytes; UP+UV flags are synthetic test input.
        let assertion = assertion_with_values(
            challenge,
            &CREDENTIAL,
            counter,
            &challenge.webauthn.origin,
            &challenge.webauthn.challenge,
            flags,
            |message| self.key.sign(message).as_ref().to_vec(),
        );
        let request: native::DeliveryRequest = serde_json::from_value(json!({
            "schema":"guard-native-cloud-review-install-request.v4", "version":4,
            "request_id":self.request_id, "decision_receipt_id":DECISION, "source_claim_hash":self.source,
            "proof":{"schema":"guard-native-approval-proof.v4", "challenge":challenge, "assertion":assertion}
        })).unwrap();
        native::install(request, &self.store).map(|bytes| serde_json::from_slice(&bytes).unwrap())
    }

    fn restart(&mut self) {
        self.store =
            crate::policy_store::PolicySnapshotStore::new(&self.root, &"a".repeat(64)).unwrap();
    }

    fn refresh_policy(&mut self) {
        let mut snapshot = self.store.current_snapshot().unwrap();
        snapshot.generation += 1;
        snapshot.issued_at_ms = now_ms().unwrap().saturating_sub(1);
        snapshot.expires_at_ms = now_ms().unwrap() + 60_000;
        snapshot.policy_digest = guard_policy_snapshot::policy_digest(&snapshot).unwrap();
        snapshot.integrity.mac = guard_policy_snapshot::integrity_mac(&snapshot, &[7; 32]).unwrap();
        self.store.push(&json!({"schema":guard_policy_snapshot::POLICY_SNAPSHOT_PUSH_SCHEMA, "snapshot":snapshot})).unwrap();
        self.envelope.policy_generation = snapshot.generation;
        self.envelope.policy_snapshot = serde_json::to_value(snapshot).unwrap();
    }
}

#[test]
fn aged_cloud_decision_renews_and_consumes_matching_hook_once_after_restart() {
    let mut fixture = CloudFixture::new("aged-cloud-renew-consume");
    assert_eq!(
        fixture.renew().unwrap_err(),
        "native_cloud_review_v4_renewal_not_required"
    );
    let original = fixture.age();
    fixture.refresh_policy();
    fixture.consent(2, 0, true);
    let renewed = fixture.renew().unwrap();
    let challenge: ApprovalChallengeV4 =
        serde_json::from_value(renewed["challenge"].clone()).unwrap();
    assert_eq!(renewed["decision_receipt_id"], DECISION);
    assert_eq!(renewed["source_claim_hash"], fixture.source);
    assert_eq!(renewed["consent_revision"], 2);
    assert_ne!(
        challenge.nonce,
        original["challenge"]["nonce"].as_str().unwrap()
    );
    assert_ne!(
        challenge.request_digest,
        original["challenge"]["request_digest"].as_str().unwrap()
    );
    assert_eq!(fixture.query()["phase"], "waiting_for_authorization");
    let old_challenge: ApprovalChallengeV4 =
        serde_json::from_value(original["challenge"].clone()).unwrap();
    assert_eq!(
        fixture.install(&old_challenge, 0x05).unwrap_err(),
        "native_cloud_review_v4_original_challenge_mismatch"
    );
    assert_eq!(
        fixture.install(&challenge, 0x01).unwrap_err(),
        "native_approval_v4_authenticator_flags_invalid"
    );
    assert_eq!(
        fixture.install(&challenge, 0x05).unwrap()["phase"],
        "waiting_for_hook"
    );
    fixture.restart();
    let mut wrong_action = fixture.envelope.clone();
    wrong_action.request_id = Some("changed-action".into());
    wrong_action.raw_payload["command"] = json!("git diff");
    let denied: Value = serde_json::from_slice(
        &crate::edge::evaluate_envelope_with_store(wrong_action, &fixture.store).unwrap(),
    )
    .unwrap();
    assert_eq!(denied["result"]["decision"], "deny");
    assert!(denied.get("native_application_v4").is_none());
    assert_eq!(fixture.query()["phase"], "waiting_for_hook");
    let mut retry = fixture.envelope.clone();
    retry.request_id = Some("fresh-harness-retry".into());
    let allowed: Value = serde_json::from_slice(
        &crate::edge::evaluate_envelope_with_store(retry.clone(), &fixture.store).unwrap(),
    )
    .unwrap();
    let positive = fixture.query();
    assert_eq!(allowed["result"]["decision"], "allow");
    assert_eq!(allowed["native_application_v4"], positive);
    assert_eq!(positive["phase"], "consumed");
    assert_eq!(positive["request_id"], fixture.request_id);
    assert_eq!(positive["receipt"]["nonce"], challenge.nonce);
    assert_eq!(positive["decision_receipt_id"], DECISION);
    let discovery_request: native::DiscoveryRequest = serde_json::from_value(json!({
        "schema": "guard-native-cloud-review-discovery-request.v4",
        "version": 4,
        "after_request_id": null,
        "limit": 8,
    }))
    .unwrap();
    let discovery: Value =
        serde_json::from_slice(&native::discover(discovery_request, &fixture.store).unwrap())
            .unwrap();
    assert_eq!(discovery["observations"], json!([positive]));
    let saved = fixture.journal();
    assert_eq!(
        saved["records"][&fixture.request_id]["challenge"],
        original["challenge"]
    );
    assert_eq!(
        saved["records"][&fixture.request_id]["envelope"],
        original["envelope"]
    );
    fixture.restart();
    assert_eq!(fixture.query(), positive);
    assert_eq!(
        fixture.renew().unwrap_err(),
        "native_cloud_review_v4_already_consumed"
    );
    let replay: Value = serde_json::from_slice(
        &crate::edge::evaluate_envelope_with_store(retry, &fixture.store).unwrap(),
    )
    .unwrap();
    assert_eq!(replay["result"]["decision"], "deny");
    assert!(replay.get("native_application_v4").is_none());
    assert_eq!(fixture.query(), positive);
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn expired_installed_authority_requires_fresh_uv_and_counter_before_replacement() {
    let mut fixture = CloudFixture::new("aged-cloud-renew-expired-installed");
    let original: ApprovalChallengeV4 = serde_json::from_value(
        fixture.journal()["records"][&fixture.request_id]["challenge"].clone(),
    )
    .unwrap();
    assert_eq!(
        fixture.install(&original, 0x05).unwrap()["phase"],
        "waiting_for_hook"
    );
    let frozen = fixture.age();
    let renewed = fixture.renew().unwrap();
    let challenge: ApprovalChallengeV4 =
        serde_json::from_value(renewed["challenge"].clone()).unwrap();
    assert_eq!(fixture.query()["phase"], "waiting_for_authorization");
    let denied: Value = serde_json::from_slice(
        &crate::edge::evaluate_envelope_with_store(fixture.envelope.clone(), &fixture.store)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(denied["result"]["decision"], "deny");
    assert!(denied.get("native_application_v4").is_none());
    assert_eq!(
        fixture.install(&challenge, 0x05).unwrap_err(),
        "native_approval_v4_counter_replay"
    );
    assert_eq!(
        fixture.install_with_counter(&challenge, 0x05, 2).unwrap()["phase"],
        "waiting_for_hook"
    );
    fixture.restart();
    let allowed: Value = serde_json::from_slice(
        &crate::edge::evaluate_envelope_with_store(fixture.envelope.clone(), &fixture.store)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(allowed["result"]["decision"], "allow");
    assert_eq!(
        allowed["native_application_v4"]["receipt"]["authenticator_sign_count"],
        2
    );
    assert_eq!(
        allowed["native_application_v4"]["decision_receipt_id"],
        DECISION
    );
    assert_eq!(
        fixture.journal()["records"][&fixture.request_id]["challenge"],
        frozen["challenge"]
    );
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn renewal_refuses_revoked_consent_cross_client_and_changed_saved_identity() {
    let fixture = CloudFixture::new("aged-cloud-renew-revocation");
    fixture.age();
    let renewed = fixture.renew().unwrap();
    for (decision, source) in [
        ("different-decision", fixture.source.as_str()),
        (DECISION, &"b".repeat(64)),
    ] {
        assert_eq!(
            native::renew(
                fixture.renewal_request(
                    "guard-native-cloud-review-renewal-request.v4",
                    decision,
                    source
                ),
                &fixture.store
            )
            .unwrap_err(),
            "native_cloud_review_v4_immutable_binding_conflict"
        );
    }
    let other = CloudFixture::new("aged-cloud-renew-other-client");
    assert_eq!(
        native::renew(
            fixture.renewal_request(
                "guard-native-cloud-review-renewal-request.v4",
                DECISION,
                &fixture.source
            ),
            &other.store
        )
        .unwrap_err(),
        "native_cloud_review_v4_original_challenge_mismatch"
    );
    fixture.consent(2, 1, true);
    assert_eq!(
        fixture.renew().unwrap_err(),
        "native_cloud_review_v4_permission_revoked"
    );
    let historical: Value = serde_json::from_slice(
        &native::query_renewal(
            fixture.renewal_request(
                "guard-native-cloud-review-renewal-query.v4",
                DECISION,
                &fixture.source,
            ),
            &fixture.store,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(historical, renewed);
    let challenge: ApprovalChallengeV4 =
        serde_json::from_value(renewed["challenge"].clone()).unwrap();
    assert_eq!(
        fixture.install(&challenge, 0x05).unwrap_err(),
        "native_cloud_review_v4_permission_revoked"
    );
    fs::remove_dir_all(fixture.root).unwrap();
    fs::remove_dir_all(other.root).unwrap();
}

#[test]
fn renewal_refuses_root_drift_missing_original_authority_and_caller_challenges() {
    let fixture = CloudFixture::new("aged-cloud-renew-root-drift");
    fixture.age();
    let mut supplied: Value = serde_json::to_value(&fixture.envelope).unwrap();
    supplied = json!({"schema":"guard-native-cloud-review-renewal-request.v4", "version":4,
        "request_id":fixture.request_id, "decision_receipt_id":DECISION, "source_claim_hash":fixture.source,
        "original_nonce_digest":fixture.original_nonce_digest,
        "envelope":supplied});
    assert!(serde_json::from_value::<native::RenewalRequest>(supplied).is_err());
    let mut record: ApprovalAuthorityV4 =
        serde_json::from_slice(&fs::read(fixture.root.join("approval-authority-v4.json")).unwrap())
            .unwrap();
    record.origin = "https://sub.example.com".into();
    let bytes =
        crate::policy_store::approval_v4_authority::tests::test_record_bytes(&record).unwrap();
    write_private(
        &fixture.root,
        &fixture.root.join("approval-authority-v4.json"),
        &bytes,
    );
    assert_eq!(
        fixture.renew().unwrap_err(),
        "native_approval_v4_authority_provenance_mismatch"
    );
    let missing = CloudFixture::new("aged-cloud-renew-missing-root-binding");
    missing.age();
    let mut journal = missing.journal();
    journal["records"][&missing.request_id]
        .as_object_mut()
        .unwrap()
        .remove("authority_fingerprint");
    missing.write_journal(&journal);
    assert_eq!(
        missing.renew().unwrap_err(),
        "native_cloud_review_v4_original_authority_unavailable"
    );
    fs::remove_dir_all(fixture.root).unwrap();
    fs::remove_dir_all(missing.root).unwrap();
}

mod generation_tests {
    include!("approval_v4_cloud_review_generation_tests.rs");
}

mod recovery_tests {
    include!("approval_v4_cloud_review_recovery_tests.rs");
}

#[test]
fn original_command_source_commitment_is_read_only_and_requires_current_consent() {
    // Protected isolated fixture; not physical enrollment/UP+UV evidence.
    let fixture = CloudFixture::new("memory-source-commitment");
    let request = || {
        serde_json::from_value(json!({
            "schema":"guard-native-cloud-review-origin-request.v4", "version":4,
            "request_id":fixture.request_id,
        }))
        .unwrap()
    };
    let before = fixture.journal()["records"][&fixture.request_id]["challenge"].clone();
    let origin: Value =
        serde_json::from_slice(&native::origin(request(), &fixture.store).unwrap()).unwrap();
    let command = guard_command::pretool::generic::extract_untrusted_command_context(
        &fixture.envelope.raw_payload,
    )
    .unwrap()
    .command
    .unwrap();
    use sha2::{Digest, Sha256};
    assert_eq!(
        origin["command_sha256"],
        hex::encode(Sha256::digest(command.as_bytes()))
    );
    assert_eq!(
        fixture.journal()["records"][&fixture.request_id]["challenge"],
        before
    );
    fixture.consent(2, 1, false);
    assert!(native::origin(request(), &fixture.store).is_err());
}

use super::super::{signing_bytes, verify_envelope, WorkspaceReviewDecisionContext};
use guard_contracts::{
    WorkspaceReviewAuthorityV1, WorkspaceReviewDecisionEnvelopeV1,
    NATIVE_WORKSPACE_REVIEW_AUTHORITY_PURPOSE, NATIVE_WORKSPACE_REVIEW_AUTHORITY_V1_SCHEMA,
    NATIVE_WORKSPACE_REVIEW_AUTHORITY_V1_VERSION,
    NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_RETRY_ONLY,
    NATIVE_WORKSPACE_REVIEW_DECISION_V1_SCHEMA, NATIVE_WORKSPACE_REVIEW_DECISION_V1_VERSION,
    NATIVE_WORKSPACE_REVIEW_SCOPE_CONTRACT_V1,
};
use guard_policy_snapshot::digest_bytes;

const NOW_MS: u64 = 2_000;
const ROOT_PUBLIC_KEY_HEX: &str =
    "197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61";
const WORKSPACE_KEY_ID: &str = "dbc298251c51321b7266e78d1c151c2b62aff8cb95b293096d3463018544face";
const WORKSPACE_PUBLIC_KEY: &str =
    "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618";
const AUTHORITY_RECORD_DIGEST: &str =
    "48d2ac80ac7115199c5101811cc80224f142dd1d7ad89ff8ec2cf7e22b25b6eb";
const AUTHORITY_SIGNING_DIGEST: &str =
    "df5f21e909cbe2d7f4083b8292cf4fb3b6a29743825c7d74bc871fee1c3bbbf7";
const ENROLLMENT_SIGNATURE: &str =
    "aecd796bba8372b95c3b4caef42b1d95885582fc218f037c789dbce58259df31272822ade2ae94f9f6a488b06c5d865b28d4a61fe272e584c01edb9c6633a309";
const ENVELOPE_DIGEST: &str = "0e3ab2e4f821402c759f8b95dec85f6c01ff9f40cef5e0c3f2312a80e5065879";
const DECISION_SIGNATURE: &str =
    "d157f494d34a11f525da48cd14a6bda18f53ed8047a45ca657ae9513b9aa4fd2b7cc63ad3dcf0c4a1d7e2e451823010344921e661f66dc52a0f74385b7a51106";

fn fixture_authority() -> WorkspaceReviewAuthorityV1 {
    WorkspaceReviewAuthorityV1 {
        schema: NATIVE_WORKSPACE_REVIEW_AUTHORITY_V1_SCHEMA.to_owned(),
        version: NATIVE_WORKSPACE_REVIEW_AUTHORITY_V1_VERSION,
        purpose: NATIVE_WORKSPACE_REVIEW_AUTHORITY_PURPOSE.to_owned(),
        key_algorithm: "ed25519".to_owned(),
        key_id: WORKSPACE_KEY_ID.to_owned(),
        public_key: WORKSPACE_PUBLIC_KEY.to_owned(),
        workspace_binding: "1".repeat(64),
        device_binding: "2".repeat(64),
        installation_binding: "3".repeat(64),
        enrollment_generation: 1,
        previous_key_id: None,
        scope_contract_version: NATIVE_WORKSPACE_REVIEW_SCOPE_CONTRACT_V1.to_owned(),
        scope_binding: "4".repeat(64),
        issued_at_ms: 1_000,
        expires_at_ms: 61_000,
        status: "active".to_owned(),
        enrollment_signature: ENROLLMENT_SIGNATURE.to_owned(),
    }
}

fn fixture_context() -> WorkspaceReviewDecisionContext<'static> {
    WorkspaceReviewDecisionContext {
        workspace_binding: "1111111111111111111111111111111111111111111111111111111111111111",
        device_binding: "2222222222222222222222222222222222222222222222222222222222222222",
        installation_binding: "3333333333333333333333333333333333333333333333333333333333333333",
        scope_binding: "4444444444444444444444444444444444444444444444444444444444444444",
        request_binding: "9999999999999999999999999999999999999999999999999999999999999999",
        action_binding: "5555555555555555555555555555555555555555555555555555555555555555",
        intent_binding: "6666666666666666666666666666666666666666666666666666666666666666",
        revision_binding: "7777777777777777777777777777777777777777777777777777777777777777",
        policy_binding: "8888888888888888888888888888888888888888888888888888888888888888",
        retry_scope_binding: "a16830ac98f619d54d312bffbf45fe36a0629480caf43059930b50cb4464b83a",
    }
}

fn fixture_envelope() -> WorkspaceReviewDecisionEnvelopeV1 {
    let context = fixture_context();
    WorkspaceReviewDecisionEnvelopeV1 {
        schema: NATIVE_WORKSPACE_REVIEW_DECISION_V1_SCHEMA.to_owned(),
        version: NATIVE_WORKSPACE_REVIEW_DECISION_V1_VERSION,
        purpose: NATIVE_WORKSPACE_REVIEW_AUTHORITY_PURPOSE.to_owned(),
        authority_generation: 1,
        authority_key_id: WORKSPACE_KEY_ID.to_owned(),
        authority_record_digest: AUTHORITY_RECORD_DIGEST.to_owned(),
        workspace_binding: context.workspace_binding.to_owned(),
        device_binding: context.device_binding.to_owned(),
        installation_binding: context.installation_binding.to_owned(),
        scope_binding: context.scope_binding.to_owned(),
        request_binding: context.request_binding.to_owned(),
        action_binding: context.action_binding.to_owned(),
        intent_binding: context.intent_binding.to_owned(),
        revision_binding: context.revision_binding.to_owned(),
        policy_binding: context.policy_binding.to_owned(),
        retry_scope_binding: context.retry_scope_binding.to_owned(),
        delivery_mode: NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_RETRY_ONLY.to_owned(),
        decision: "allow".to_owned(),
        claim_id: "a".repeat(64),
        issued_at_ms: 1_500,
        expires_at_ms: 60_000,
        decision_signature: DECISION_SIGNATURE.to_owned(),
    }
}

#[test]
fn portal_seed_42_fixture_matches_rust_canonical_digests_and_signatures() {
    let authority = fixture_authority();
    let authority_signing =
        super::super::super::workspace_review_authority::signing_bytes(&authority).unwrap();
    assert_eq!(digest_bytes(&authority_signing), AUTHORITY_SIGNING_DIGEST);
    let verified_authority =
        super::super::super::workspace_review_authority::verify_record(&authority, NOW_MS).unwrap();
    assert_eq!(verified_authority.record_digest, AUTHORITY_RECORD_DIGEST);
    assert_eq!(
        verified_authority.public_key.to_vec(),
        hex::decode(WORKSPACE_PUBLIC_KEY).unwrap()
    );
    assert_eq!(
        hex::encode(super::super::super::approval_authority::enrollment_root_public_key()),
        ROOT_PUBLIC_KEY_HEX
    );

    let context = fixture_context();
    let envelope = fixture_envelope();
    let signing = signing_bytes(&envelope).unwrap();
    assert_eq!(
        digest_bytes(&signing),
        "e5fffe39dee8657327df22936daabb995f898d84659dc8ab4ea94dc8809563a5"
    );
    let (verified, canonical) =
        verify_envelope(&envelope, &verified_authority, &context, NOW_MS).unwrap();
    assert_eq!(digest_bytes(&canonical), ENVELOPE_DIGEST);
    assert_eq!(verified.envelope_digest, ENVELOPE_DIGEST);
}

#[test]
fn portal_fixture_rejects_bad_signature_wrong_context_and_wrong_root() {
    let authority = fixture_authority();
    let verified_authority =
        super::super::super::workspace_review_authority::verify_record(&authority, NOW_MS).unwrap();
    let context = fixture_context();
    let envelope = fixture_envelope();

    let mut bad_signature = envelope.clone();
    bad_signature.decision_signature.replace_range(0..2, "00");
    assert_eq!(
        verify_envelope(&bad_signature, &verified_authority, &context, NOW_MS).unwrap_err(),
        "native_workspace_review_decision_signature_invalid"
    );

    let mut wrong_context = fixture_context();
    wrong_context.workspace_binding =
        "9999999999999999999999999999999999999999999999999999999999999999";
    assert_eq!(
        verify_envelope(&envelope, &verified_authority, &wrong_context, NOW_MS).unwrap_err(),
        "native_workspace_review_decision_provenance_mismatch"
    );

    let mut wrong_root = authority.clone();
    wrong_root.enrollment_signature.replace_range(0..2, "00");
    assert_eq!(
        super::super::super::workspace_review_authority::verify_record(&wrong_root, NOW_MS)
            .unwrap_err(),
        "native_workspace_review_authority_enrollment_invalid"
    );
}

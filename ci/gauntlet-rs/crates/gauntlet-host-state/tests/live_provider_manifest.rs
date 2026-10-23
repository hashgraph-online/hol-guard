use base64::{engine::general_purpose::STANDARD, Engine};
use gauntlet_contracts::canonicalize;
use gauntlet_host_state::{verify_live_provider_manifest_claim, LiveProviderManifestExpectation};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const JOB: &str = "0123456789abcdef";
const SOURCE: &str = "c1d18f931eaba02a37a2c9515db769fc2219bee8";
const KNOWN: u64 = 13_746_906;

fn digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}

fn bytes(value: &Value) -> Vec<u8> {
    let mut raw = canonicalize(value.to_string().as_bytes()).unwrap();
    raw.push(b'\n');
    raw
}

fn fixture() -> (Value, Value) {
    let key = Ed25519KeyPair::from_seed_unchecked(&[42u8; 32]).unwrap();
    let binding = json!({
        "job_id":JOB,
        "profile":"feature-ai",
        "candidate_source_sha":SOURCE,
        "model_identity":{"id":"mlx-community/Qwen3.6-35B-A3B-8bit"},
        "model_identity_digest":"e".repeat(64),
        "maximum_accounted_tokens":14_468_885,
        "lifetime_token_cap":14_468_885,
    });
    let binding_sha256 = digest(&bytes(&binding));
    let loaded = json!({
        "model_id":"mlx-community/Qwen3.6-35B-A3B-8bit",
        "weights_verified_before_and_after_load":true,
    });
    let record = json!({
        "started":true,
        "qualification":false,
        "job_id":JOB,
        "profile":"feature-ai",
        "candidate_source_sha":SOURCE,
        "config_sha256":"f".repeat(64),
        "binding_sha256":binding_sha256,
        "loaded":loaded,
        "quota_before_any_control":{
            "binding_sha256":binding_sha256,
            "quota":{"known_tokens":KNOWN,"pending_requests":0,"reserved_tokens":0},
        },
    });
    let signed = key.sign(&canonicalize(record.to_string().as_bytes()).unwrap());
    let provider = json!({
        "anchor":{
            "public_key":STANDARD.encode(key.public_key().as_ref()),
            "config_sha256":"f".repeat(64),
            "qualification":false,
        },
        "binding":binding,
        "signed_result":{
            "record":record,
            "signature":STANDARD.encode(signed.as_ref()),
        },
    });
    let model = json!({
        "loaded":loaded,
        "model_identity":binding["model_identity"],
        "model_identity_digest":binding["model_identity_digest"],
    });
    (provider, model)
}

fn check(provider: &Value, model: &Value, source: &str) -> Result<Value, &'static str> {
    let provider_raw = bytes(provider);
    let model_raw = bytes(model);
    verify_live_provider_manifest_claim(
        &provider_raw,
        &model_raw,
        &LiveProviderManifestExpectation {
            provider_sha256: &digest(&provider_raw),
            model_sha256: &digest(&model_raw),
            job_id: JOB,
            profile: "feature-ai",
            candidate_source_sha: source,
            known_tokens_before: KNOWN,
        },
    )
}

#[test]
fn self_signed_python_handoff_is_only_an_ineligible_claim() {
    let (provider, model) = fixture();
    let proof = check(&provider, &model, SOURCE).unwrap();
    assert_eq!(proof["execution_eligible"], false);
    assert_eq!(proof["producer_claim_only"], true);
    assert_eq!(proof["candidate_source_sha"], SOURCE);
    assert_eq!(proof["known_tokens_before"], KNOWN);
}

#[test]
fn another_candidate_and_changed_binding_refuse() {
    let (mut provider, model) = fixture();
    assert_eq!(
        check(&provider, &model, &"b".repeat(40)),
        Err("provider handoff differs from requested candidate and binding")
    );
    provider["binding"]["model_identity_digest"] = json!("d".repeat(64));
    assert_eq!(
        check(&provider, &model, SOURCE),
        Err("provider handoff differs from requested candidate and binding")
    );
}

#[test]
fn changed_signed_record_and_transfer_digest_refuse() {
    let (mut provider, model) = fixture();
    provider["signed_result"]["record"]["quota_before_any_control"]["quota"]["known_tokens"] =
        json!(KNOWN - 1);
    assert_eq!(
        check(&provider, &model, SOURCE),
        Err("provider handoff signature mismatch")
    );
    let (provider, model) = fixture();
    let provider_raw = bytes(&provider);
    let model_raw = bytes(&model);
    assert_eq!(
        verify_live_provider_manifest_claim(
            &provider_raw,
            &model_raw,
            &LiveProviderManifestExpectation {
                provider_sha256: &"0".repeat(64),
                model_sha256: &digest(&model_raw),
                job_id: JOB,
                profile: "feature-ai",
                candidate_source_sha: SOURCE,
                known_tokens_before: KNOWN,
            },
        ),
        Err("provider handoff manifest bytes differ from outside pin")
    );
}

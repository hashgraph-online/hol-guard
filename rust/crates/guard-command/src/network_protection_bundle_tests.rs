//! A network protection bundle reaches enforcement only when it verifies.

use std::sync::OnceLock;

use base64ct::{Base64, Encoding};
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::pss::BlindedSigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde_json::{json, Map, Value};

use super::*;
use crate::supply_chain_bundle::RingRsaPssVerify;

const WORKSPACE_ID: &str = "workspace-alpha";
/// 2026-10-26T00:00:00Z — the moment every bundle below is generated at.
const NOW: f64 = 1_792_972_800.0;
const SIX_HOURS: f64 = 6.0 * 60.0 * 60.0;

fn signing_key() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("key"))
}

fn other_key() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("key"))
}

fn public_pem(key: &RsaPrivateKey) -> String {
    key.to_public_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("pem")
}

fn verification_key(key: &RsaPrivateKey, key_id: &str, state: &str) -> Value {
    let pem = public_pem(key);
    json!({
        "keyId": key_id,
        "publicKeyPem": pem,
        "fingerprintSha256": hex::encode(Sha256::digest(pem.trim().as_bytes())),
        "state": state,
        "validUntil": Value::Null,
    })
}

/// An ISO-8601 instant with milliseconds, as the cloud writes them.
fn iso(epoch_seconds: f64) -> String {
    let whole = epoch_seconds as i64;
    let days = whole.div_euclid(86_400);
    let seconds_of_day = whole.rem_euclid(86_400);
    // 1970-01-01 is day 0; walk civil dates forward from the epoch.
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000Z",
        seconds_of_day / 3_600,
        (seconds_of_day % 3_600) / 60,
        seconds_of_day % 60
    )
}

/// Howard Hinnant's `civil_from_days`, so the fixtures need no date crate.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

struct Fixture {
    generated_at: f64,
    version_ms: Option<i64>,
    workspace_id: String,
    key: &'static RsaPrivateKey,
    key_state: &'static str,
    overrides: Vec<(String, Value)>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            generated_at: NOW,
            version_ms: None,
            workspace_id: WORKSPACE_ID.to_string(),
            key: signing_key(),
            key_state: "active",
            overrides: Vec::new(),
        }
    }

    fn generated_at(mut self, value: f64) -> Self {
        self.generated_at = value;
        self
    }

    fn version_ms(mut self, value: i64) -> Self {
        self.version_ms = Some(value);
        self
    }

    fn workspace_id(mut self, value: &str) -> Self {
        self.workspace_id = value.to_string();
        self
    }

    fn key_state(mut self, value: &'static str) -> Self {
        self.key_state = value;
        self
    }

    fn with(mut self, key: &str, value: Value) -> Self {
        self.overrides.push((key.to_string(), value));
        self
    }

    fn build(self) -> Value {
        let version_ms = self
            .version_ms
            .unwrap_or((self.generated_at * 1_000.0) as i64);
        let mut bundle = Map::new();
        bundle.insert(
            "contractVersion".into(),
            json!(NETWORK_PROTECTION_CONTRACT_VERSION),
        );
        bundle.insert("workspaceId".into(), json!(self.workspace_id));
        bundle.insert(
            "bundleVersion".into(),
            json!(format!("network-{version_ms}-0123456789abcdef")),
        );
        bundle.insert("generatedAt".into(), json!(iso(self.generated_at)));
        bundle.insert(
            "expiresAt".into(),
            json!(iso(self.generated_at + SIX_HOURS)),
        );
        bundle.insert("keyId".into(), json!("key-1"));
        bundle.insert(
            "workspaceRules".into(),
            json!([
                {"action": "block", "matchKind": "domain", "pattern": "blocked.example"},
                {"action": "allow", "matchKind": "url_prefix", "pattern": "docs.example/guide/"},
            ]),
        );
        bundle.insert(
            "threatUrls".into(),
            json!({"malware_distribution": ["0".repeat(32)]}),
        );
        bundle.insert(
            "threatHosts".into(),
            json!({"phishing": ["login-verify.pages.dev"]}),
        );
        for (key, value) in self.overrides {
            bundle.insert(key, value);
        }
        let mut response = json!({
            "bundle": Value::Object(bundle),
            "signatureAlgorithm": "rsa-pss-sha256",
            "verificationKeys": [verification_key(self.key, "key-1", self.key_state)],
        });
        sign(&mut response, self.key);
        response
    }
}

/// Hash and sign the bundle as the cloud does, so a fixture is only rejected
/// for the property under test.
fn sign(response: &mut Value, key: &RsaPrivateKey) {
    let canonical =
        canonical_network_protection_payload(response["bundle"].as_object().expect("bundle"));
    response["payloadHash"] = json!(hex::encode(Sha256::digest(&canonical)));
    let encoded_len = (key.n().bits() - 1).div_ceil(8);
    let salt_len = encoded_len - Sha256::output_size() - 2;
    let signer = BlindedSigningKey::<Sha256>::new_with_salt_len(key.clone(), salt_len);
    let signature = signer.sign_with_rng(&mut rsa::rand_core::OsRng, &canonical);
    response["signature"] = json!(Base64::encode_string(&signature.to_bytes()));
}

fn trusted(key: &RsaPrivateKey, state: &str) -> Vec<SupplyChainVerificationKey> {
    load_supply_chain_verification_keys(Some(&json!([verification_key(key, "key-1", state)])))
        .expect("keyring parses")
}

fn verify_with(
    response: &Value,
    trusted_keys: &[SupplyChainVerificationKey],
    cached_bundle_version: Option<&str>,
) -> BundleResult<Value> {
    verify_network_protection_response(
        response,
        WORKSPACE_ID,
        trusted_keys,
        cached_bundle_version,
        Some(NOW),
        &RingRsaPssVerify,
    )
}

fn verify(response: &Value) -> BundleResult<Value> {
    verify_with(response, &trusted(signing_key(), "active"), None)
}

fn refusal(response: &Value) -> String {
    verify(response).expect_err("bundle is refused").0
}

#[test]
fn a_verified_bundle_is_saved_in_the_form_the_runtime_reads() {
    let response = Fixture::new().build();
    let saved = verify(&response).expect("bundle verifies");
    assert_eq!(saved["bundle"], response["bundle"]);
    assert_eq!(saved["expiresAtEpoch"], json!((NOW + SIX_HOURS) as i64));
    assert_eq!(saved["payloadHash"], response["payloadHash"]);
    assert_eq!(saved["keyId"], json!("key-1"));
}

#[test]
fn a_tampered_bundle_fails_its_payload_hash() {
    let mut response = Fixture::new().build();
    response["bundle"]["workspaceRules"] = json!([]);
    assert!(refusal(&response).contains("payloadHash"));
}

#[test]
fn a_forged_bundle_rehashed_around_the_change_fails_its_signature() {
    let mut response = Fixture::new().build();
    response["bundle"]["workspaceRules"] = json!([]);
    let canonical =
        canonical_network_protection_payload(response["bundle"].as_object().expect("bundle"));
    response["payloadHash"] = json!(hex::encode(Sha256::digest(&canonical)));
    assert!(refusal(&response).contains("signature verification failed"));
}

#[test]
fn a_bundle_for_another_workspace_is_refused() {
    let response = Fixture::new().workspace_id("workspace-other").build();
    assert!(refusal(&response).contains("different workspace"));
}

#[test]
fn an_older_bundle_cannot_replace_a_newer_saved_one() {
    let response = Fixture::new().version_ms(1_000).build();
    let error = verify_with(
        &response,
        &trusted(signing_key(), "active"),
        Some("network-2000-0123456789abcdef"),
    )
    .expect_err("rollback is refused");
    assert!(error.0.contains("older than saved"));
}

#[test]
fn a_saved_version_guard_cannot_parse_does_not_block_a_fresh_bundle() {
    let response = Fixture::new().build();
    assert!(verify_with(
        &response,
        &trusted(signing_key(), "active"),
        Some("not-a-network-version"),
    )
    .is_ok());
}

#[test]
fn an_expired_bundle_is_refused() {
    let response = Fixture::new().generated_at(NOW - 7.0 * 60.0 * 60.0).build();
    assert!(refusal(&response).contains("has expired"));
}

#[test]
fn a_bundle_generated_in_the_future_is_refused() {
    let response = Fixture::new().generated_at(NOW + 3_600.0).build();
    assert!(refusal(&response).contains("generatedAt is in the future"));
}

#[test]
fn a_bundle_older_than_the_maximum_age_is_refused() {
    // Still unexpired, because `expiresAt` moves with `generatedAt`; only the
    // age ceiling rejects it.
    let response = Fixture::new()
        .generated_at(NOW - 8.0 * 24.0 * 60.0 * 60.0)
        .with("expiresAt", json!(iso(NOW + SIX_HOURS)))
        .build();
    assert!(refusal(&response).contains("too old"));
}

#[test]
fn a_signing_key_outside_the_saved_keyring_is_refused() {
    let response = Fixture::new().build();
    let error = verify_with(&response, &trusted(other_key(), "active"), None)
        .expect_err("unanchored key is refused");
    assert!(error.0.contains("not trusted"));
}

#[test]
fn only_the_pinned_key_is_trusted_before_a_keyring_is_saved() {
    let response = Fixture::new().build();
    let error = verify_with(&response, &[], None)
        .expect_err("an unpinned key is refused without a keyring");
    assert!(error.0.contains("not trusted"));
}

#[test]
fn a_revoked_entry_no_longer_anchors_its_own_key() {
    let response = Fixture::new().build();
    let error = verify_with(&response, &trusted(signing_key(), "revoked"), None)
        .expect_err("a revoked anchor is refused");
    assert!(error.0.contains("not trusted"));
}

#[test]
fn a_revoked_advertised_key_cannot_sign() {
    // Anchored by an active saved entry, but advertised as revoked: the
    // bundle's own key state is what refuses it.
    let response = Fixture::new().key_state("revoked").build();
    let error = verify_with(&response, &trusted(signing_key(), "active"), None)
        .expect_err("a revoked signer is refused");
    assert!(error.0.contains("A revoked key cannot sign"));
}

#[test]
fn an_expired_grace_key_cannot_sign() {
    let mut response = Fixture::new().key_state("grace").build();
    response["verificationKeys"][0]["validUntil"] = json!(iso(NOW - 3_600.0));
    let error = verify_with(&response, &trusted(signing_key(), "grace"), None)
        .expect_err("an expired grace key is refused");
    assert!(error.0.contains("signing key has expired"));
}

#[test]
fn a_key_whose_fingerprint_does_not_match_its_pem_is_refused() {
    let mut response = Fixture::new().build();
    let claimed = hex::encode(Sha256::digest(b"not this key"));
    response["verificationKeys"][0]["fingerprintSha256"] = json!(claimed.clone());
    let keyring = load_supply_chain_verification_keys(Some(&json!([{
        "keyId": "key-1",
        "publicKeyPem": public_pem(signing_key()),
        "fingerprintSha256": claimed,
        "state": "active",
        "validUntil": Value::Null,
    }])))
    .expect("keyring parses");
    let error =
        verify_with(&response, &keyring, None).expect_err("a forged fingerprint is refused");
    assert!(error.0.contains("fingerprint does not match"));
}

#[test]
fn a_bundle_signed_by_a_key_the_response_does_not_advertise_is_refused() {
    let mut response = Fixture::new().build();
    response["bundle"]["keyId"] = json!("key-2");
    sign(&mut response, signing_key());
    assert!(refusal(&response).contains("not in the advertised keyring"));
}

#[test]
fn an_invalid_workspace_rule_is_refused() {
    let response = Fixture::new()
        .with(
            "workspaceRules",
            json!([{"action": "ignore", "matchKind": "domain", "pattern": "x"}]),
        )
        .build();
    assert!(refusal(&response).contains("invalid workspace rule"));
}

#[test]
fn threat_indicators_must_be_lists_of_strings() {
    let response = Fixture::new()
        .with("threatHosts", json!({"phishing": [{"host": "x"}]}))
        .build();
    assert!(refusal(&response).contains("must map to string lists"));
}

#[test]
fn another_contract_version_is_refused() {
    let response = Fixture::new()
        .with(
            "contractVersion",
            json!("guard-network-protection-bundle.v2"),
        )
        .build();
    assert!(refusal(&response).contains("contract version"));
}

#[test]
fn another_signature_algorithm_is_refused() {
    let mut response = Fixture::new().build();
    response["signatureAlgorithm"] = json!("ed25519");
    assert!(refusal(&response).contains("signature algorithm"));
}

#[test]
fn a_malformed_bundle_version_is_refused() {
    for version in [
        "network-0123456789abcdef",
        "network--0123456789abcdef",
        "network-1000-0123456789ABCDEF",
        "network-1000-0123456789abcde",
        "supply-1000-0123456789abcdef",
    ] {
        assert_eq!(
            network_bundle_version_timestamp(version)
                .expect_err("malformed version")
                .0,
            "Network protection bundleVersion is malformed",
            "{version}"
        );
    }
    assert_eq!(
        network_bundle_version_timestamp("network-1761048000000-0123456789abcdef"),
        Ok(1_761_048_000_000)
    );
}

#[test]
fn the_canonical_payload_escapes_non_ascii_text_the_way_the_cloud_signs_it() {
    // `json.dumps(..., ensure_ascii=True)`, unlike the supply-chain bundle:
    // a bundle naming a host in non-ASCII text hashes over the escaped form.
    let mut bundle = Map::new();
    bundle.insert("label".into(), json!("café"));
    assert_eq!(
        canonical_network_protection_payload(&bundle),
        br#"{"label":"caf\u00e9"}"#.to_vec()
    );
}

#[test]
fn a_response_that_is_not_an_object_is_refused() {
    let error = verify_network_protection_response(
        &json!([]),
        WORKSPACE_ID,
        &[],
        None,
        Some(NOW),
        &RingRsaPssVerify,
    )
    .expect_err("a list is refused");
    assert!(error.0.contains("must be an object"));
}

//! A test-only signed catalog whose builds are still `upstream_only`.
//!
//! The bundled catalog now qualifies darwin-arm64, so refusal paths need an explicit
//! unqualified catalog rather than the production one. Test key only; no production trust.
use super::*;
use guard_cigar_release::{CatalogTrust, Qualification, TrustedKey};
use ring::signature::{Ed25519KeyPair, KeyPair};

pub(super) fn upstream_only_catalog() -> TrustedCatalog {
    let mut document = TrustedCatalog::bundled().unwrap().document().clone();
    for platform in &mut document.builds[0].platforms {
        platform.qualification = Qualification::UpstreamOnly;
        platform.qualification_receipt_sha256 = None;
        platform.features.clear();
    }
    for interpreter in &mut document.interpreters {
        interpreter.qualification = Qualification::UpstreamOnly;
        interpreter.qualification_receipt_sha256 = None;
    }
    document.issued_at = 900;
    document.expires_at = 2000;
    let pair = Ed25519KeyPair::from_seed_unchecked(&[96; 32]).unwrap();
    let key = TrustedKey {
        key_id: "unqualified-catalog-test-only".into(),
        public_key: pair.public_key().as_ref().try_into().unwrap(),
        not_before: 500,
        not_after: 3000,
        revoked: false,
    };
    let payload = serde_json::to_string(&document).unwrap();
    let mut message = b"hol-guard-cigar-release-catalog.v1\0".to_vec();
    message.extend_from_slice(payload.as_bytes());
    let envelope = serde_json::to_vec(&json!({"schema":"guard-cigar-signed-catalog.v1",
        "key_id":key.key_id,"payload":payload,"signature_hex":hex::encode(pair.sign(&message).as_ref())}))
    .unwrap();
    TrustedCatalog::verify(
        &envelope,
        &CatalogTrust {
            keys: &[key],
            checkpoint: None,
            now: 1000,
        },
    )
    .unwrap()
}

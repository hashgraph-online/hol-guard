//! `trust-attestation-key --stdin`: the key AI-BOM trust attestations are
//! signed with. Ported from `runtime/trust_attestation.py`
//! (`_load_private_key`, `_sign_payload`, `_verification_key_from_private_key`
//! and the persistent and headless key resolution).
//!
//! The private key travels to this one-shot process and nowhere else; the
//! resident never holds it. Python resolves which key applies (an explicit
//! environment key, the Guard OAuth DPoP key, a per-process headless key or the
//! persistent key in the Guard home) and asks here:
//!
//! - `{"op": "load", "key"}` answers `{"loaded": true}` when the key is an RSA
//!   or EC private key Guard can read;
//! - `{"op": "sign", "key", "algorithm", "key_id", "public_jwk_thumbprint",
//!   "payloads": [{"payload", "signed_at"}]}` answers `{"attestations"}`, one
//!   signed envelope per payload in order. The payloads are the ones the
//!   `trust_attestation_shape` gate already admitted;
//! - `{"op": "generate"}` answers a fresh P-256 key as `{"private_key_pem",
//!   "fingerprint_sha256"}`;
//! - `{"op": "persistent", "guard_home"}` answers the same for the key stored
//!   in `trust_attestation_key.pem`, creating it (mode 0600, never replacing a
//!   readable key another process wrote first) when it is missing or
//!   unreadable, or `{"error": "trust_attestation_key_unavailable"}`.
//!
//! Every other refusal answers `{"error": message}` with the message Python
//! raises as `ValueError`. Keys are read from PKCS#8, PKCS#1 (RSA) and SEC1
//! (EC) PEM. RSA keys sign RSA-PSS over SHA-256 with the longest salt the key
//! allows (`PSS.MAX_LENGTH`), P-256 keys sign DER ECDSA over SHA-256, and a
//! public key is the PEM `SubjectPublicKeyInfo` whose SHA-256 is the
//! fingerprint the verifier pins.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use base64ct::{Base64, Encoding};
use guard_command::attestation_envelope::{
    normalize_pem, public_key_fingerprint, GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM,
    GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM_ECDSA_P256,
};
use guard_command::evidence_hash::canonical_guard_evidence_payload;
use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING,
    ECDSA_P384_SHA384_ASN1_SIGNING,
};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rsa::pss::BlindedSigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::daemon_lifecycle_text::py_strip;

#[path = "trust_attestation_key_der.rs"]
mod der;
use der::{other_curve, pkcs8_curve, sec1_as_pkcs8, sec1_curve};

const RSA_PSS_SHA256: &str = GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM;
const ECDSA_P256_SHA256: &str = GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM_ECDSA_P256;
const KEY_FILE: &str = "trust_attestation_key.pem";
const PKCS8_LABEL: &str = "PRIVATE KEY";
const PKCS1_LABEL: &str = "RSA PRIVATE KEY";
const SEC1_LABEL: &str = "EC PRIVATE KEY";
const PUBLIC_LABEL: &str = "PUBLIC KEY";
const KEY_UNREADABLE: &str = "Trust attestation private key must be RSA or EC";
const MUST_BE_RSA: &str = "Trust attestation private key must be RSA";
const MUST_BE_EC: &str = "Trust attestation private key must be EC";
const MUST_BE_P256: &str = "Trust attestation EC private key must use P-256";
const UNSUPPORTED_ALGORITHM: &str = "Unsupported trust attestation signature algorithm";
const SIGNING_FAILED: &str = "Trust attestation signature could not be produced";
const KEY_UNAVAILABLE: &str = "trust_attestation_key_unavailable";
/// `id-ecPublicKey`, the algorithm of every EC key.
const EC_PUBLIC_KEY_OID: [u8; 9] = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// `prime256v1`.
const P256_OID: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// `secp384r1`.
const P384_OID: [u8; 7] = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
/// `SubjectPublicKeyInfo` up to the uncompressed P-256 point.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
/// `SubjectPublicKeyInfo` up to the uncompressed P-384 point.
const P384_SPKI_PREFIX: [u8; 23] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
];
const SHA256_LEN: usize = 32;
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;
const MAX_REQUEST_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Load {
        key: String,
    },
    Sign {
        key: String,
        algorithm: String,
        key_id: String,
        public_jwk_thumbprint: Option<String>,
        payloads: Vec<Signable>,
    },
    // A struct variant: serde ignores unknown fields on a unit variant.
    Generate {},
    Persistent {
        guard_home: PathBuf,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Signable {
    payload: Map<String, Value>,
    signed_at: String,
}

/// A private key Guard can read. An EC key on a curve other than P-256 loads,
/// as Python's loader accepts it, but signs nothing; only a P-384 one has a
/// public key Guard can derive.
enum PrivateKey {
    Rsa(Box<RsaPrivateKey>),
    P256(EcdsaKeyPair),
    OtherCurve(EcdsaKeyPair),
    UnsupportedCurve,
}

enum Signer {
    Rsa(Box<BlindedSigningKey<Sha256>>),
    P256(Box<EcdsaKeyPair>),
}

/// A key with the PEM it was read from or written as.
struct HeldKey {
    pem: Zeroizing<String>,
    key: PrivateKey,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "trust-attestation-key"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "trust_attestation_key_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("trust_attestation_key_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    serde_json::to_vec(&answer(request))
        .map_err(|_| "trust_attestation_key_response_encode_failed".to_owned())
}

fn invalid() -> String {
    "trust_attestation_key_request_invalid".to_owned()
}

fn answer(request: Request) -> Value {
    let answered = match request {
        Request::Load { key } => load_private_key(&key).map(|_| json!({ "loaded": true })),
        Request::Sign {
            key,
            algorithm,
            key_id,
            public_jwk_thumbprint,
            payloads,
        } => sign(
            &key,
            &algorithm,
            &key_id,
            public_jwk_thumbprint.as_deref(),
            &payloads,
        ),
        Request::Generate {} => generate().and_then(|held| described(&held)),
        Request::Persistent { guard_home } => persistent_key(&guard_home)
            .ok_or(KEY_UNAVAILABLE)
            .and_then(|held| described(&held)),
    };
    answered.unwrap_or_else(|message| json!({ "error": message }))
}

fn sign(
    pem: &str,
    algorithm: &str,
    key_id: &str,
    public_jwk_thumbprint: Option<&str>,
    payloads: &[Signable],
) -> Result<Value, &'static str> {
    let key = load_private_key(pem)?;
    let public_key_pem = public_key_pem(&key);
    let signer = signer(key, algorithm)?;
    let public_key_pem = public_key_pem?;
    let fingerprint = public_key_fingerprint(&public_key_pem);
    let mut attestations = Vec::with_capacity(payloads.len());
    for signable in payloads {
        let version = signable
            .payload
            .get("payloadVersion")
            .and_then(Value::as_str)
            .ok_or(SIGNING_FAILED)?;
        let canonical = canonical_guard_evidence_payload(&signable.payload);
        let signature = signer.sign(&canonical)?;
        let mut attestation = json!({
            "payloadVersion": version,
            "payloadHash": hex::encode(Sha256::digest(&canonical)),
            "signature": Base64::encode_string(&signature),
            "signatureAlgorithm": algorithm,
            "signedAt": signable.signed_at,
            "keyId": key_id,
            "publicKeyPem": public_key_pem,
            "fingerprintSha256": fingerprint,
        });
        if let Some(thumbprint) = public_jwk_thumbprint {
            attestation["publicJwkThumbprint"] = json!(thumbprint);
        }
        attestations.push(attestation);
    }
    Ok(json!({ "attestations": attestations }))
}

/// The signer `algorithm` names, refusing a key of another kind in the order
/// `_sign_payload` checks.
fn signer(key: PrivateKey, algorithm: &str) -> Result<Signer, &'static str> {
    match (algorithm, key) {
        (RSA_PSS_SHA256, PrivateKey::Rsa(key)) => {
            // PSS.MAX_LENGTH: emLen - hLen - 2, emLen = ceil((modBits - 1) / 8).
            let encoded_len = key.n().bits().saturating_sub(1).div_ceil(8);
            let salt_len = encoded_len
                .checked_sub(SHA256_LEN + 2)
                .ok_or(SIGNING_FAILED)?;
            Ok(Signer::Rsa(Box::new(BlindedSigningKey::new_with_salt_len(
                *key, salt_len,
            ))))
        }
        (RSA_PSS_SHA256, _) => Err(MUST_BE_RSA),
        (ECDSA_P256_SHA256, PrivateKey::P256(pair)) => Ok(Signer::P256(Box::new(pair))),
        (ECDSA_P256_SHA256, PrivateKey::OtherCurve(_) | PrivateKey::UnsupportedCurve) => {
            Err(MUST_BE_P256)
        }
        (ECDSA_P256_SHA256, PrivateKey::Rsa(_)) => Err(MUST_BE_EC),
        _ => Err(UNSUPPORTED_ALGORITHM),
    }
}

impl Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, &'static str> {
        match self {
            Self::Rsa(signer) => signer
                .try_sign_with_rng(&mut rsa::rand_core::OsRng, message)
                .map(|signature| signature.to_vec())
                .map_err(|_| SIGNING_FAILED),
            Self::P256(pair) => pair
                .sign(&SystemRandom::new(), message)
                .map(|signature| signature.as_ref().to_vec())
                .map_err(|_| SIGNING_FAILED),
        }
    }
}

fn load_private_key(pem: &str) -> Result<PrivateKey, &'static str> {
    if let Some(der) = pem_body(pem, PKCS8_LABEL) {
        if let Ok(key) = RsaPrivateKey::from_pkcs8_der(&der) {
            return Ok(PrivateKey::Rsa(Box::new(key)));
        }
        return ec_key(&der, &der).or_else(|_| other_curve(pkcs8_curve(&der)));
    }
    if let Some(der) = pem_body(pem, PKCS1_LABEL) {
        return RsaPrivateKey::from_pkcs1_der(&der)
            .map(|key| PrivateKey::Rsa(Box::new(key)))
            .map_err(|_| KEY_UNREADABLE);
    }
    if let Some(der) = pem_body(pem, SEC1_LABEL) {
        return ec_key(
            &sec1_as_pkcs8(&der, &P256_OID),
            &sec1_as_pkcs8(&der, &P384_OID),
        )
        .or_else(|_| other_curve(sec1_curve(&der)));
    }
    Err(KEY_UNREADABLE)
}

/// The EC key in `p256` (a P-256 PKCS#8 document) or else `p384`.
fn ec_key(p256: &[u8], p384: &[u8]) -> Result<PrivateKey, &'static str> {
    let random = SystemRandom::new();
    if let Ok(pair) = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, p256, &random) {
        return Ok(PrivateKey::P256(pair));
    }
    ec_pair(&ECDSA_P384_SHA384_ASN1_SIGNING, p384, &random)
        .map(PrivateKey::OtherCurve)
        .ok_or(KEY_UNREADABLE)
}

fn ec_pair(
    algorithm: &'static EcdsaSigningAlgorithm,
    pkcs8: &[u8],
    random: &SystemRandom,
) -> Option<EcdsaKeyPair> {
    EcdsaKeyPair::from_pkcs8(algorithm, pkcs8, random).ok()
}

fn pem_body(pem: &str, label: &str) -> Option<Zeroizing<Vec<u8>>> {
    let body = py_strip(pem)
        .strip_prefix(&format!("-----BEGIN {label}-----"))?
        .strip_suffix(&format!("-----END {label}-----"))?;
    let body: Zeroizing<String> = Zeroizing::new(body.split_whitespace().collect());
    Base64::decode_vec(&body).ok().map(Zeroizing::new)
}

fn pem_text(label: &str, der: &[u8]) -> String {
    let mut text = format!("-----BEGIN {label}-----");
    for (index, character) in Base64::encode_string(der).chars().enumerate() {
        if index % 64 == 0 {
            text.push('\n');
        }
        text.push(character);
    }
    text.push_str(&format!("\n-----END {label}-----"));
    text
}

/// The PEM `SubjectPublicKeyInfo` Python's `public_bytes` writes, stripped.
fn public_key_pem(key: &PrivateKey) -> Result<String, &'static str> {
    let der = match key {
        PrivateKey::Rsa(key) => key
            .to_public_key()
            .to_public_key_der()
            .map_err(|_| KEY_UNREADABLE)?
            .as_bytes()
            .to_vec(),
        PrivateKey::P256(pair) => [&P256_SPKI_PREFIX[..], pair.public_key().as_ref()].concat(),
        PrivateKey::OtherCurve(pair) => {
            [&P384_SPKI_PREFIX[..], pair.public_key().as_ref()].concat()
        }
        PrivateKey::UnsupportedCurve => return Err(KEY_UNREADABLE),
    };
    Ok(pem_text(PUBLIC_LABEL, &der))
}

fn described(held: &HeldKey) -> Result<Value, &'static str> {
    let public_key_pem = public_key_pem(&held.key)?;
    Ok(json!({
        "private_key_pem": normalize_pem(&held.pem),
        "fingerprint_sha256": public_key_fingerprint(&public_key_pem),
    }))
}

fn generate() -> Result<HeldKey, &'static str> {
    let random = SystemRandom::new();
    let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random)
        .map_err(|_| KEY_UNAVAILABLE)?;
    let pair = ec_pair(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref(), &random)
        .ok_or(KEY_UNAVAILABLE)?;
    let mut pem = Zeroizing::new(pem_text(PKCS8_LABEL, document.as_ref()));
    pem.push('\n');
    Ok(HeldKey {
        pem,
        key: PrivateKey::P256(pair),
    })
}

/// The key stored in the Guard home, or a new one written there. A readable
/// key another process wrote first wins; an unreadable one is replaced.
fn persistent_key(guard_home: &Path) -> Option<HeldKey> {
    let path = guard_home.join(KEY_FILE);
    if let Some(stored) = stored_key(&path) {
        return Some(stored);
    }
    let generated = generate().ok()?;
    match create_key_file(&path, &generated.pem) {
        Ok(()) => Some(generated),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if let Some(stored) = stored_key(&path) {
                return Some(stored);
            }
            if let Err(error) = fs::remove_file(&path) {
                if error.kind() != io::ErrorKind::NotFound {
                    return None;
                }
            }
            let generated = generate().ok()?;
            create_key_file(&path, &generated.pem).ok()?;
            Some(generated)
        }
        Err(_) => None,
    }
}

fn stored_key(path: &Path) -> Option<HeldKey> {
    let mut bytes = Zeroizing::new(Vec::new());
    fs::File::open(path)
        .ok()?
        .take(MAX_KEY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_KEY_FILE_BYTES {
        return None;
    }
    let text = std::str::from_utf8(&bytes).ok()?;
    let pem = Zeroizing::new(py_strip(text).to_owned());
    if pem.is_empty() {
        return None;
    }
    let key = load_private_key(&pem).ok()?;
    Some(HeldKey { pem, key })
}

fn create_key_file(path: &Path, pem: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)?.write_all(pem.as_bytes())
}

#[cfg(test)]
#[path = "trust_attestation_key_tests.rs"]
mod tests;

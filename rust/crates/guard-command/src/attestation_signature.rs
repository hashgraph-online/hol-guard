//! The last check a trust attestation faces: its signature.
//!
//! [`attestation_verification`](crate::attestation_verification) hands back the
//! canonical bytes the signature covers once every key-free question has been
//! answered. This module loads the advertised public key out of its PEM and
//! checks those bytes against the signature the envelope carries.
//!
//! Python reaches the same point through `cryptography`: it loads the PEM, it
//! refuses anything that is not an RSA or EC key, and then it dispatches on the
//! declared algorithm — RSA-PSS over SHA-256, or ECDSA over SHA-256 on P-256.
//! A key that does not match the declared algorithm is refused before any
//! verification happens, and every refusal here carries Python's wording.

use base64ct::{Base64, Encoding};
use ring::signature;
use rsa::pss::{Signature as RsaPssSignature, VerifyingKey as RsaPssVerifyingKey};
use rsa::signature::Verifier;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPublicKey};
use sha2::{Digest, Sha256};

use crate::attestation_envelope::{
    GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM,
    GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM_ECDSA_P256,
};

/// `1.2.840.113549.1.1.1` — an RSA public key.
const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// `1.2.840.10045.2.1` — an elliptic-curve public key.
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// `1.2.840.10045.3.1.7` — the P-256 (secp256r1) named curve.
const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// The DER encoding of ASN.1 `NULL`, the parameters an RSA key's algorithm
/// identifier carries.
const DER_NULL: &[u8] = &[0x05, 0x00];

/// The largest RSA modulus a key may carry. OpenSSL, which Python's
/// `cryptography` verifies with, stops at the same size
/// (`OPENSSL_RSA_MAX_MODULUS_BITS`); the `rsa` crate's own default is 4096,
/// which would refuse an RSA-8192 key Python accepts.
const RSA_MAX_MODULUS_BITS: usize = 16384;

/// P-256's field prime, `2^256 - 2^224 + 2^192 + 2^96 - 1`.
const P256_FIELD_PRIME_HEX: &[u8] =
    b"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
/// P-256's curve constant `b` in `y^2 = x^3 - 3x + b`.
const P256_CURVE_B_HEX: &[u8] = b"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
/// The width of one P-256 coordinate.
const P256_COORDINATE_LEN: usize = 32;

/// Why a signature was refused, in the wording Python uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationSignatureError(String);

impl AttestationSignatureError {
    /// The refusal text, identical to the `ValueError` Python raises.
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AttestationSignatureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for AttestationSignatureError {}

fn refuse<T>(message: &str) -> Result<T, AttestationSignatureError> {
    Err(AttestationSignatureError(message.to_owned()))
}

/// A public key an attestation can be checked against.
///
/// Python keeps `RSAPublicKey` and `EllipticCurvePublicKey` and refuses
/// everything else, so the two shapes it accepts are the only ones here. The
/// EC arm holds a point already checked to lie on the curve, rewritten in the
/// uncompressed form `ring` verifies against whatever form the SPKI used.
#[derive(Debug, Clone)]
pub enum AttestationPublicKey {
    /// An RSA key, for `rsa-pss-sha256`.
    Rsa(Box<RsaPublicKey>),
    /// A P-256 key's uncompressed point, for `ecdsa-p256-sha256`.
    EcP256(Vec<u8>),
    /// An EC key on some other curve. Python keeps it — the curve is only
    /// rejected once the algorithm asks for P-256 — so this arm keeps it too.
    EcOtherCurve,
}

/// One DER element: its tag, its contents, and where the next element starts.
struct DerElement<'a> {
    tag: u8,
    contents: &'a [u8],
    rest: &'a [u8],
}

/// Read a single DER tag-length-value element off the front of `der`.
///
/// Only the definite-length form matters here: a PEM-wrapped SPKI is always
/// DER, which forbids the indefinite form, and a length that does not fit in a
/// `usize` cannot describe a key this process is holding in memory.
fn read_der(der: &[u8]) -> Option<DerElement<'_>> {
    let tag = *der.first()?;
    let first_length = *der.get(1)?;
    let (length, header) = if first_length < 0x80 {
        (usize::from(first_length), 2)
    } else {
        let count = usize::from(first_length & 0x7f);
        if count == 0 || count > std::mem::size_of::<usize>() {
            return None;
        }
        let mut length = 0usize;
        for index in 0..count {
            length = (length << 8) | usize::from(*der.get(2 + index)?);
        }
        (length, 2 + count)
    };
    let contents = der.get(header..header.checked_add(length)?)?;
    Some(DerElement {
        tag,
        contents,
        rest: &der[header + length..],
    })
}

/// Read the single DER element `der` holds, refusing trailing bytes.
fn read_only_der(der: &[u8]) -> Option<DerElement<'_>> {
    let element = read_der(der)?;
    element.rest.is_empty().then_some(element)
}

/// Pull the one base64 body a PEM carries, with its label.
///
/// Python's loader accepts the usual armour and ignores what surrounds it;
/// this keeps to the first `-----BEGIN x-----` / `-----END x-----` pair so a
/// file holding a key plus a comment still loads.
fn pem_body(pem: &str) -> Option<(String, Vec<u8>)> {
    let normalized = pem.replace("\r\n", "\n");
    let mut label: Option<String> = None;
    let mut body = String::new();
    for line in normalized.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("-----BEGIN ") {
            if label.is_some() {
                return None;
            }
            label = Some(rest.strip_suffix("-----")?.to_owned());
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("-----END ") {
            let closing = rest.strip_suffix("-----")?;
            if label.as_deref() != Some(closing) {
                return None;
            }
            let der = Base64::decode_vec(&body).ok()?;
            return Some((closing.to_owned(), der));
        }
        if label.is_some() {
            body.push_str(trimmed);
        }
    }
    None
}

/// Build an RSA key from a PKCS#1 `RSAPublicKey` body.
///
/// The `rsa` crate's own decoders cap the modulus at 4096 bits, so the modulus
/// and exponent are read out here and the key is built against OpenSSL's cap
/// instead.
fn rsa_key_from_pkcs1(der: &[u8]) -> Option<AttestationPublicKey> {
    let key = rsa::pkcs1::RsaPublicKey::try_from(der).ok()?;
    let modulus = BigUint::from_bytes_be(key.modulus.as_bytes());
    let exponent = BigUint::from_bytes_be(key.public_exponent.as_bytes());
    RsaPublicKey::new_with_max_size(modulus, exponent, RSA_MAX_MODULUS_BITS)
        .ok()
        .map(|key| AttestationPublicKey::Rsa(Box::new(key)))
}

fn is_odd(value: &BigUint) -> bool {
    value.to_bytes_be().last().is_some_and(|byte| byte & 1 == 1)
}

fn push_coordinate(point: &mut Vec<u8>, coordinate: &BigUint) {
    let bytes = coordinate.to_bytes_be();
    point.resize(point.len() + P256_COORDINATE_LEN - bytes.len(), 0);
    point.extend_from_slice(&bytes);
}

/// Decode a P-256 point the way OpenSSL does when Python loads the key.
///
/// OpenSSL accepts the uncompressed (`0x04`), compressed (`0x02`/`0x03`) and
/// hybrid (`0x06`/`0x07`) encodings, and refuses a point that is off the
/// curve, has a coordinate outside the field, or is the point at infinity.
/// `ring` only verifies against the uncompressed form, so an accepted point is
/// returned in that form.
fn p256_uncompressed_point(encoded: &[u8]) -> Option<Vec<u8>> {
    let field_prime = BigUint::parse_bytes(P256_FIELD_PRIME_HEX, 16)?;
    let curve_b = BigUint::parse_bytes(P256_CURVE_B_HEX, 16)?;
    let (&form, coordinates) = encoded.split_first()?;
    let x = BigUint::from_bytes_be(coordinates.get(..P256_COORDINATE_LEN)?);
    if x >= field_prime {
        return None;
    }
    // y^2 = x^3 - 3x + b, with 3p added first so the subtraction cannot go
    // below zero.
    let three = BigUint::from(3u32);
    let y_squared = (&x * &x * &x + &curve_b + &three * &field_prime - &three * &x) % &field_prime;
    let y = match form {
        0x02 | 0x03 if coordinates.len() == P256_COORDINATE_LEN => {
            // The field prime is 3 mod 4, so a square root, when one exists,
            // is y^2 raised to (p + 1) / 4.
            let exponent = (&field_prime + BigUint::from(1u32)) >> 2;
            let root = y_squared.modpow(&exponent, &field_prime);
            if (&root * &root) % &field_prime != y_squared {
                return None;
            }
            if is_odd(&root) == (form == 0x03) {
                root
            } else if root == BigUint::from(0u32) {
                return None;
            } else {
                &field_prime - &root
            }
        }
        0x04 | 0x06 | 0x07 if coordinates.len() == 2 * P256_COORDINATE_LEN => {
            let y = BigUint::from_bytes_be(&coordinates[P256_COORDINATE_LEN..]);
            if y >= field_prime || (&y * &y) % &field_prime != y_squared {
                return None;
            }
            // A hybrid encoding repeats y's parity in its first byte, and
            // OpenSSL refuses one whose parity disagrees with y.
            if form != 0x04 && is_odd(&y) != (form == 0x07) {
                return None;
            }
            y
        }
        _ => return None,
    };
    let mut point = Vec::with_capacity(1 + 2 * P256_COORDINATE_LEN);
    point.push(0x04);
    push_coordinate(&mut point, &x);
    push_coordinate(&mut point, &y);
    Some(point)
}

/// Read a SubjectPublicKeyInfo and say which key it carries.
fn public_key_from_spki(der: &[u8]) -> Option<AttestationPublicKey> {
    let outer = read_only_der(der)?;
    if outer.tag != 0x30 {
        return None;
    }
    let algorithm = read_der(outer.contents)?;
    if algorithm.tag != 0x30 {
        return None;
    }
    let key_bits = read_der(algorithm.rest)?;
    if key_bits.tag != 0x03 || !key_bits.rest.is_empty() {
        return None;
    }
    // A BIT STRING's first content byte counts the unused trailing bits. A key
    // is always a whole number of bytes, so anything but zero is malformed.
    let (unused_bits, key_bytes) = key_bits.contents.split_first()?;
    if *unused_bits != 0 {
        return None;
    }
    let oid = read_der(algorithm.contents)?;
    if oid.tag != 0x06 {
        return None;
    }
    if oid.contents == OID_RSA_ENCRYPTION {
        // Python loads an RSA key whose parameters are NULL or left out, and
        // refuses anything else there.
        if !oid.rest.is_empty() && oid.rest != DER_NULL {
            return None;
        }
        return rsa_key_from_pkcs1(key_bytes);
    }
    if oid.contents != OID_EC_PUBLIC_KEY {
        return None;
    }
    // The curve is the algorithm identifier's last element. Explicit curve
    // parameters are refused outright: Python only loads the few that spell
    // out a named curve, and refusing the rest keeps this side the stricter.
    let parameters = read_der(oid.rest)?;
    if parameters.tag != 0x06 || !parameters.rest.is_empty() {
        return None;
    }
    if parameters.contents != OID_PRIME256V1 {
        return Some(AttestationPublicKey::EcOtherCurve);
    }
    p256_uncompressed_point(key_bytes).map(AttestationPublicKey::EcP256)
}

/// Load the public key a trust attestation advertises.
///
/// Mirrors Python's `serialization.load_pem_public_key` followed by its
/// `isinstance` check: a PEM that will not parse, or that carries a key which
/// is neither RSA nor EC, is refused with the same message.
pub fn load_attestation_public_key(
    public_key_pem: &str,
) -> Result<AttestationPublicKey, AttestationSignatureError> {
    let Some((label, der)) = pem_body(public_key_pem) else {
        return refuse("Trust attestation public key must be RSA or EC");
    };
    if label == "RSA PUBLIC KEY" {
        return match rsa_key_from_pkcs1(&der) {
            Some(key) => Ok(key),
            None => refuse("Trust attestation public key must be RSA or EC"),
        };
    }
    if label != "PUBLIC KEY" {
        return refuse("Trust attestation public key must be RSA or EC");
    }
    match public_key_from_spki(&der) {
        Some(key) => Ok(key),
        None => refuse("Trust attestation public key must be RSA or EC"),
    }
}

/// XOR `out` with MGF1 over `seed`, the mask generation function PSS uses.
///
/// RFC 8017 B.2.1: hash the seed followed by a four-byte big-endian counter,
/// take as much of each digest as is still wanted, and count up.
fn mgf1_xor_sha256(out: &mut [u8], seed: &[u8]) {
    let mut counter: u32 = 0;
    let mut written = 0usize;
    while written < out.len() {
        let mut hash = Sha256::new();
        hash.update(seed);
        hash.update(counter.to_be_bytes());
        for byte in hash.finalize() {
            if written == out.len() {
                break;
            }
            out[written] ^= byte;
            written += 1;
        }
        counter = counter.wrapping_add(1);
    }
}

/// The salt length the encoded message names, if it names one.
///
/// This is the recovery OpenSSL performs for `RSA_PSS_SALTLEN_AUTO`: undo the
/// public operation, unmask the data block, and read how far the `0x01`
/// separator sits from its end. Nothing here authenticates anything — the
/// caller hands the length to the library's verifier, which does — so a misread
/// can only cost a signature its acceptance, never win one.
fn rsa_pss_salt_len(public_key: &RsaPublicKey, signature: &[u8]) -> Option<usize> {
    let key_len = public_key.size();
    if signature.len() != key_len {
        return None;
    }
    let value = BigUint::from_bytes_be(signature);
    if &value >= public_key.n() {
        return None;
    }
    let raw = value.modpow(public_key.e(), public_key.n()).to_bytes_be();
    if raw.len() > key_len {
        return None;
    }
    let mut padded = vec![0u8; key_len - raw.len()];
    padded.extend_from_slice(&raw);

    // The encoded message is one bit shorter than the modulus, so on a modulus
    // whose length is a whole number of bytes it starts one byte in.
    let hash_len = Sha256::output_size();
    let encoded_bits = public_key.n().bits().checked_sub(1)?;
    let encoded_len = encoded_bits.div_ceil(8);
    if encoded_len < hash_len + 2 {
        return None;
    }
    let encoded = padded.get(key_len.checked_sub(encoded_len)?..)?;
    if encoded.last() != Some(&0xbc) {
        return None;
    }
    let (masked, rest) = encoded.split_at(encoded_len - hash_len - 1);
    let seed = rest.get(..hash_len)?;
    let unused_bits = 8 * encoded_len - encoded_bits;
    let leading_mask = 0xff_u8.checked_shl((8 - unused_bits) as u32).unwrap_or(0);
    if *masked.first()? & leading_mask != 0 {
        return None;
    }

    let mut data = masked.to_vec();
    mgf1_xor_sha256(&mut data, seed);
    data[0] &= 0xff >> unused_bits;
    let separator = data.iter().position(|byte| *byte != 0x00)?;
    if data[separator] != 0x01 {
        return None;
    }
    Some(data.len() - separator - 1)
}

/// Verify RSA-PSS over SHA-256, under whichever salt length the signature used.
///
/// Python signs with `padding.PSS.MAX_LENGTH` — the largest salt the modulus
/// leaves room for — but it *verifies* with it too, and on the verifying side
/// OpenSSL reads `MAX_LENGTH` as "recover the salt length from the encoded
/// message". So Python accepts a PSS-SHA-256 signature made under any salt
/// length, including the salt-equals-digest length signers outside Python
/// default to. A verifier that pinned the longest salt would refuse those.
///
/// The longest salt is tried first, because that is what Guard's own signer
/// produces, and then the length the encoding itself names.
fn verify_rsa_pss(
    public_key: &RsaPublicKey,
    canonical_payload: &[u8],
    signature: &[u8],
) -> Result<(), AttestationSignatureError> {
    let Ok(parsed) = RsaPssSignature::try_from(signature) else {
        return refuse("Trust attestation signature verification failed");
    };
    let verifies = |salt_len: usize| {
        RsaPssVerifyingKey::<Sha256>::new_with_salt_len(public_key.clone(), salt_len)
            .verify(canonical_payload, &parsed)
            .is_ok()
    };
    let encoded_message_len = public_key.n().bits().saturating_sub(1).div_ceil(8);
    let longest = encoded_message_len.checked_sub(Sha256::output_size() + 2);
    if longest.is_some_and(verifies) {
        return Ok(());
    }
    // Only a signature the longest salt did not explain is worth the public
    // operation the recovery costs.
    let recovered =
        rsa_pss_salt_len(public_key, signature).filter(|salt_len| Some(*salt_len) != longest);
    if recovered.is_some_and(verifies) {
        return Ok(());
    }
    refuse("Trust attestation signature verification failed")
}

/// Check an attestation's signature over the bytes the payload canonicalises to.
///
/// Python's `_verify_signature`: the declared algorithm picks the scheme, the
/// key must match it, and `InvalidSignature` becomes the verification-failed
/// refusal the caller raises. An algorithm the envelope reader already rejects
/// cannot reach here, but the fallthrough keeps Python's message anyway.
pub fn verify_attestation_signature(
    public_key: &AttestationPublicKey,
    canonical_payload: &[u8],
    signature: &[u8],
    signature_algorithm: &str,
) -> Result<(), AttestationSignatureError> {
    if signature_algorithm == GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM {
        let AttestationPublicKey::Rsa(key) = public_key else {
            return refuse("Trust attestation public key must be RSA");
        };
        return verify_rsa_pss(key, canonical_payload, signature);
    }
    if signature_algorithm == GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM_ECDSA_P256 {
        let point = match public_key {
            AttestationPublicKey::Rsa(_) => {
                return refuse("Trust attestation public key must be EC")
            }
            AttestationPublicKey::EcOtherCurve => {
                return refuse("Trust attestation EC public key must use P-256")
            }
            AttestationPublicKey::EcP256(point) => point,
        };
        return match signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            point.as_slice(),
        )
        .verify(canonical_payload, signature)
        {
            Ok(()) => Ok(()),
            Err(_) => refuse("Trust attestation signature verification failed"),
        };
    }
    refuse("Unsupported trust attestation signature algorithm")
}

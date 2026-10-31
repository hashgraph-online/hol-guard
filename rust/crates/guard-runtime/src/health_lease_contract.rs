//! `health-lease-contract --stdin`: the strict contract a machine health lease
//! is carried in. It checks lease claims before they are signed, signed health
//! and protection leases, and the outbox that pairs a lease with its snapshot
//! (`mdm/health_lease_contract.py` and `mdm/protection_lease_contract.py`
//! before the parsers moved here).
//!
//! Each operation answers `{"ok": true, ...}` or names the contract error the
//! Python callers raise; only a malformed request fails the command.

use std::io::Read;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::health_snapshot_binding::{snapshot_is_bound, Claims as SnapshotClaims};

const SCHEMA: &str = "health-lease-contract.v1";
const HEALTH_LEASE_SCHEMA: &str = "hol-guard-health-lease.v1";
const OUTBOX_SCHEMA: &str = "hol-guard-health-lease-outbox.v1";
const PROTECTION_LEASE_SCHEMA: &str = "protection-lease.v1";
const SNAPSHOT_SCHEMA: &str = "local-integrity-snapshot.v1";
const SIGNATURE_ALGORITHM: &str = "ecdsa-p256-sha256";
const SIGNATURE_ENCODING: &str = "asn1-der";
const MAX_LEASE_BYTES: usize = 32 * 1024;
const MAX_SNAPSHOT_BYTES: usize = 256 * 1024;
const MAX_OUTBOX_BYTES: usize = 4 * MAX_SNAPSHOT_BYTES.div_ceil(3) + MAX_LEASE_BYTES + 4096;
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
const MAX_SIGNATURE_TEXT: usize = 128;
const MAX_LEASE_MICROS: i64 = 3600 * MICROS_PER_SECOND;
const MICROS_PER_SECOND: i64 = 1_000_000;

const INVALID: &str = "health_lease_invalid";
const CHALLENGE_INVALID: &str = "health_lease_challenge_invalid";
const OUTBOX_INVALID: &str = "health_lease_outbox_invalid";
const REQUEST_INVALID: &str = "health_lease_contract_request_invalid";

const HEALTH_CLAIM_KEYS: [&str; 13] = [
    "schemaVersion",
    "workspaceId",
    "deviceId",
    "machineInstallationId",
    "installationGeneration",
    "sequence",
    "issuedAt",
    "leaseExpiresAt",
    "snapshotSchemaVersion",
    "snapshotDigest",
    "previousLeaseDigest",
    "previousLeaseKeyId",
    "signingKeyId",
];
const PROTECTION_CLAIM_KEYS: [&str; 12] = [
    "workspaceId",
    "deviceId",
    "machineInstallationId",
    "installationGeneration",
    "sequence",
    "issuedAt",
    "validForSeconds",
    "snapshotSchemaVersion",
    "snapshotDigest",
    "previousLeaseDigest",
    "signingKeyId",
    "challenge",
];
const CHALLENGE_KEYS: [&str; 4] = ["challengeId", "issuedAt", "nonce", "validForSeconds"];

/// The P-256 group order and half of it, big-endian.
const P256_ORDER: [u8; 32] =
    hex_literal(*b"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
const P256_HALF_ORDER: [u8; 32] =
    hex_literal(*b"7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8");

type Verdict<T> = Result<T, &'static str>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    #[serde(default)]
    value: Option<Value>,
    #[serde(default)]
    payload: Option<String>,
}

/// A lease that passed the contract: its claims as signed and its signature
/// in the DER form Python keeps.
struct Lease {
    kind: &'static str,
    claims: Map<String, Value>,
    signature: Vec<u8>,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "health-lease-contract"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| REQUEST_INVALID.to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err(REQUEST_INVALID.to_owned());
    }
    let request: Request =
        serde_json::from_slice(&bytes).map_err(|_| REQUEST_INVALID.to_owned())?;
    if request.schema != SCHEMA {
        return Err(REQUEST_INVALID.to_owned());
    }
    let verdict = match (request.op.as_str(), request.value, request.payload) {
        ("health-claims", Some(value), None) => health_claims(&value).map(|()| json!({})),
        ("protection-claims", Some(value), None) => protection_claims(&value).map(|()| json!({})),
        ("protection-challenge", Some(value), None) => challenge(&value).map(|_| json!({})),
        (op @ ("health-lease" | "protection-lease" | "outbox"), None, Some(payload)) => {
            let payload = STANDARD
                .decode(payload.as_bytes())
                .map_err(|_| REQUEST_INVALID.to_owned())?;
            match op {
                "health-lease" => health_lease(&payload).map(|lease| lease_answer(&lease)),
                "protection-lease" => protection_lease(&payload).map(|lease| lease_answer(&lease)),
                _ => outbox(&payload),
            }
        }
        _ => return Err(REQUEST_INVALID.to_owned()),
    };
    let answer = match verdict {
        Ok(Value::Object(mut fields)) => {
            fields.insert("ok".to_owned(), Value::Bool(true));
            Value::Object(fields)
        }
        Ok(_) => return Err(REQUEST_INVALID.to_owned()),
        Err(reason_code) => json!({"ok": false, "reason_code": reason_code}),
    };
    serde_json::to_vec(&answer).map_err(|_| "health_lease_contract_encode_failed".to_owned())
}

fn lease_answer(lease: &Lease) -> Value {
    json!({
        "kind": lease.kind,
        "claims": lease.claims,
        "signature": STANDARD.encode(&lease.signature),
    })
}

/// `HealthLeaseOutbox.parse`: a canonical outbox whose lease passes its own
/// contract, whose digest names that lease and whose snapshot is the one the
/// lease signs for.
fn outbox(payload: &[u8]) -> Verdict<Value> {
    let raw = strict_object(payload, MAX_OUTBOX_BYTES, OUTBOX_INVALID)?;
    if !has_exact_keys(&raw, &["schemaVersion", "lease", "leaseDigest", "snapshot"])
        || text(&raw, "schemaVersion") != Some(OUTBOX_SCHEMA)
    {
        return Err(OUTBOX_INVALID);
    }
    let lease_raw = raw
        .get("lease")
        .filter(|value| value.is_object())
        .ok_or(OUTBOX_INVALID)?;
    let lease_bytes = canonical(lease_raw).ok_or(OUTBOX_INVALID)?;
    let lease = if lease_raw.get("schemaVersion").and_then(Value::as_str)
        == Some(PROTECTION_LEASE_SCHEMA)
    {
        protection_lease(&lease_bytes)?
    } else {
        health_lease(&lease_bytes)?
    };
    let snapshot = text(&raw, "snapshot")
        .and_then(|encoded| STANDARD.decode(encoded.as_bytes()).ok())
        .ok_or(OUTBOX_INVALID)?;
    let bound = !snapshot.is_empty()
        && snapshot.len() <= MAX_SNAPSHOT_BYTES
        && Some(hex::encode(Sha256::digest(&snapshot)).as_str())
            == text(&lease.claims, "snapshotDigest")
        && Some(hex::encode(Sha256::digest(&lease_bytes)).as_str()) == text(&raw, "leaseDigest")
        && snapshot_claims(&lease.claims)
            .is_some_and(|claims| snapshot_is_bound(&snapshot, &claims));
    if !bound {
        return Err(OUTBOX_INVALID);
    }
    let mut answer = lease_answer(&lease);
    answer["snapshot"] = Value::String(STANDARD.encode(&snapshot));
    Ok(answer)
}

fn snapshot_claims(claims: &Map<String, Value>) -> Option<SnapshotClaims> {
    let owned = |key: &str| text(claims, key).map(str::to_owned);
    Some(SnapshotClaims {
        workspace_id: owned("workspaceId")?,
        device_id: owned("deviceId")?,
        machine_installation_id: owned("machineInstallationId")?,
        installation_generation: owned("installationGeneration")?,
        sequence: uint64(claims.get("sequence")?)?,
        snapshot_schema_version: owned("snapshotSchemaVersion")?,
        previous_lease_digest: owned("previousLeaseDigest"),
    })
}

/// `SignedHealthLease.parse`: canonical claims and a canonical low-S DER
/// signature.
fn health_lease(payload: &[u8]) -> Verdict<Lease> {
    let mut raw = strict_object(payload, MAX_LEASE_BYTES, INVALID)?;
    if !has_exact_keys(&raw, &["claims", "signature"]) {
        return Err(INVALID);
    }
    let signature = raw
        .get("signature")
        .and_then(Value::as_object)
        .filter(|fields| has_exact_keys(fields, &["algorithm", "encoding", "value"]))
        .ok_or(INVALID)?;
    if text(signature, "algorithm") != Some(SIGNATURE_ALGORITHM)
        || text(signature, "encoding") != Some(SIGNATURE_ENCODING)
    {
        return Err(INVALID);
    }
    let der = signature_bytes(signature)?;
    let (_, s) = der_signature(&der).ok_or(INVALID)?;
    if s > P256_HALF_ORDER {
        return Err(INVALID);
    }
    let claims = raw.get("claims").ok_or(INVALID)?;
    health_claims(claims)?;
    let Some(Value::Object(claims)) = raw.remove("claims") else {
        return Err(INVALID);
    };
    Ok(Lease {
        kind: "health",
        claims,
        signature: der,
    })
}

/// `SignedProtectionLease.parse`: canonical claims and a low-S raw `r || s`
/// signature by the key the claims name, returned as DER.
fn protection_lease(payload: &[u8]) -> Verdict<Lease> {
    let mut raw = strict_object(payload, MAX_LEASE_BYTES, INVALID)?;
    if !has_exact_keys(&raw, &["schemaVersion", "claims", "signature"])
        || text(&raw, "schemaVersion") != Some(PROTECTION_LEASE_SCHEMA)
    {
        return Err(INVALID);
    }
    protection_claims(raw.get("claims").ok_or(INVALID)?)?;
    let Some(Value::Object(claims)) = raw.remove("claims") else {
        return Err(INVALID);
    };
    let signature = raw
        .get("signature")
        .and_then(Value::as_object)
        .filter(|fields| has_exact_keys(fields, &["algorithm", "keyId", "value"]))
        .ok_or(INVALID)?;
    if text(signature, "algorithm") != Some(SIGNATURE_ALGORITHM)
        || text(signature, "keyId") != text(&claims, "signingKeyId")
    {
        return Err(INVALID);
    }
    let raw_signature = signature_bytes(signature)?;
    let (r, s) = raw_signature.split_at_checked(32).ok_or(INVALID)?;
    let (Ok(r), Ok(s)) = (<[u8; 32]>::try_from(r), <[u8; 32]>::try_from(s)) else {
        return Err(INVALID);
    };
    if !scalar_in_range(&r, &P256_ORDER, false) || !scalar_in_range(&s, &P256_HALF_ORDER, true) {
        return Err(INVALID);
    }
    Ok(Lease {
        kind: "protection",
        claims,
        signature: der_encode(&r, &s),
    })
}

/// The decoded `value` of a signature object: at most 128 characters of
/// canonical base64.
fn signature_bytes(signature: &Map<String, Value>) -> Verdict<Vec<u8>> {
    let value = text(signature, "value")
        .filter(|value| value.chars().count() <= MAX_SIGNATURE_TEXT)
        .ok_or(INVALID)?;
    let bytes = STANDARD.decode(value.as_bytes()).map_err(|_| INVALID)?;
    if STANDARD.encode(&bytes) != value {
        return Err(INVALID);
    }
    Ok(bytes)
}

/// `HealthLeaseClaims.parse`.
fn health_claims(raw: &Value) -> Verdict<()> {
    let claims = raw.as_object().ok_or(INVALID)?;
    if !has_exact_keys(claims, &HEALTH_CLAIM_KEYS)
        || text(claims, "schemaVersion") != Some(HEALTH_LEASE_SCHEMA)
    {
        return Err(INVALID);
    }
    let sequence = claims
        .get("sequence")
        .and_then(uint64)
        .filter(|sequence| *sequence >= 1)
        .ok_or(INVALID)?;
    let previous_digest = claims.get("previousLeaseDigest").unwrap_or(&Value::Null);
    let previous_key = claims.get("previousLeaseKeyId").unwrap_or(&Value::Null);
    let chained = if sequence == 1 {
        previous_digest.is_null() && previous_key.is_null()
    } else {
        previous_digest
            .as_str()
            .is_some_and(|value| is_lower_hex(value, 64))
            && previous_key.as_str().is_some_and(is_key_id)
    };
    let issued = text(claims, "issuedAt").and_then(|value| utc_instant(value, false));
    let expires = text(claims, "leaseExpiresAt").and_then(|value| utc_instant(value, false));
    let (Some(issued), Some(expires)) = (issued, expires) else {
        return Err(INVALID);
    };
    let duration = expires - issued;
    let valid = chained
        && duration > 0
        && duration <= MAX_LEASE_MICROS
        && text(claims, "snapshotSchemaVersion") == Some(SNAPSHOT_SCHEMA)
        && identities_are_valid(claims);
    valid.then_some(()).ok_or(INVALID)
}

/// `ProtectionLeaseClaims.parse`, refusing in the same order so a bad
/// challenge names itself.
fn protection_claims(raw: &Value) -> Verdict<()> {
    let claims = raw.as_object().ok_or(INVALID)?;
    if !has_exact_keys(claims, &PROTECTION_CLAIM_KEYS) {
        return Err(INVALID);
    }
    let sequence = claims
        .get("sequence")
        .and_then(uint64)
        .filter(|sequence| *sequence >= 1)
        .ok_or(INVALID)?;
    claims
        .get("validForSeconds")
        .and_then(uint64)
        .filter(|seconds| (180..=1800).contains(seconds))
        .ok_or(INVALID)?;
    let previous = claims.get("previousLeaseDigest").unwrap_or(&Value::Null);
    let chained = if sequence == 1 {
        previous.is_null()
    } else {
        previous
            .as_str()
            .is_some_and(|value| is_lower_hex(value, 64))
    };
    if !chained {
        return Err(INVALID);
    }
    let issued = text(claims, "issuedAt")
        .and_then(|value| utc_instant(value, false))
        .ok_or(INVALID)?;
    let window = match claims.get("challenge") {
        None | Some(Value::Null) => None,
        Some(raw) => Some(challenge(raw)?),
    };
    if text(claims, "snapshotSchemaVersion") != Some(SNAPSHOT_SCHEMA) {
        return Err(INVALID);
    }
    if let Some((challenge_issued, valid_for)) = window {
        if issued < challenge_issued || issued >= challenge_issued + valid_for {
            return Err(CHALLENGE_INVALID);
        }
    }
    identities_are_valid(claims).then_some(()).ok_or(INVALID)
}

/// `ProtectionLeaseChallenge.parse`: the instant it was issued and how long
/// it stays valid, both in microseconds.
fn challenge(raw: &Value) -> Verdict<(i64, i64)> {
    let challenge = raw
        .as_object()
        .filter(|fields| has_exact_keys(fields, &CHALLENGE_KEYS))
        .ok_or(CHALLENGE_INVALID)?;
    let issued = text(challenge, "issuedAt").and_then(|value| utc_instant(value, true));
    let nonce_is_valid = text(challenge, "nonce").is_some_and(|nonce| {
        (32..=128).contains(&nonce.len())
            && nonce
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    });
    let valid_for = challenge
        .get("validForSeconds")
        .and_then(uint64)
        .filter(|seconds| (30..=300).contains(seconds));
    let (Some(issued), true, Some(valid_for)) = (issued, nonce_is_valid, valid_for) else {
        return Err(CHALLENGE_INVALID);
    };
    if !challenge.get("challengeId").is_some_and(is_safe_id) {
        return Err(INVALID);
    }
    let valid_for = i64::try_from(valid_for).map_err(|_| CHALLENGE_INVALID)?;
    Ok((issued, valid_for * MICROS_PER_SECOND))
}

/// The identifiers both claim shapes share.
fn identities_are_valid(claims: &Map<String, Value>) -> bool {
    claims.get("workspaceId").is_some_and(is_safe_id)
        && claims.get("deviceId").is_some_and(is_safe_id)
        && text(claims, "machineInstallationId").is_some_and(|value| is_lower_hex(value, 32))
        && text(claims, "installationGeneration").is_some_and(|value| is_lower_hex(value, 32))
        && text(claims, "snapshotDigest").is_some_and(|value| is_lower_hex(value, 64))
        && text(claims, "signingKeyId").is_some_and(is_key_id)
}

/// The object `payload` holds when its bytes are exactly the canonical JSON
/// the contract writes.
fn strict_object(
    payload: &[u8],
    maximum: usize,
    reason: &'static str,
) -> Verdict<Map<String, Value>> {
    if payload.is_empty() || payload.len() > maximum {
        return Err(reason);
    }
    let raw: Value = serde_json::from_slice(payload).map_err(|_| reason)?;
    if canonical(&raw).as_deref() != Some(payload) {
        return Err(reason);
    }
    match raw {
        Value::Object(fields) => Ok(fields),
        _ => Err(reason),
    }
}

fn canonical(value: &Value) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    guard_contracts::write_canonical_json(value, &mut bytes).ok()?;
    Some(bytes)
}

fn has_exact_keys(fields: &Map<String, Value>, expected: &[&str]) -> bool {
    fields.len() == expected.len() && expected.iter().all(|key| fields.contains_key(*key))
}

fn text<'a>(fields: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    fields.get(key).and_then(Value::as_str)
}

/// An integer in `0..=u64::MAX`, spelled as JSON spells an integer.
fn uint64(value: &Value) -> Option<u64> {
    let Value::Number(number) = value else {
        return None;
    };
    let raw = number.as_str();
    if raw.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
        return None;
    }
    raw.parse().ok()
}

/// `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`.
fn is_safe_id(value: &Value) -> bool {
    let Some(text) = value.as_str() else {
        return false;
    };
    let bytes = text.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// A base64url SHA-256 key id: `[A-Za-z0-9_-]{43}`.
fn is_key_id(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

/// Microseconds since the epoch for `YYYY-MM-DDTHH:MM:SSZ`, with any number
/// of fraction digits when `fraction` allows them, as `fromisoformat` reads
/// them (truncated to microseconds).
fn utc_instant(text: &str, fraction: bool) -> Option<i64> {
    let bytes = text.as_bytes();
    let (body, last) = bytes.split_last().map(|(last, body)| (body, *last))?;
    if last != b'Z' || body.len() < 19 {
        return None;
    }
    let (whole, rest) = body.split_at(19);
    let micros = match rest {
        [] => 0,
        [b'.', digits @ ..] if fraction && !digits.is_empty() => {
            if !digits.iter().all(u8::is_ascii_digit) {
                return None;
            }
            digits
                .iter()
                .chain(std::iter::repeat(&b'0'))
                .take(6)
                .fold(0_i64, |total, digit| total * 10 + i64::from(digit - b'0'))
        }
        _ => return None,
    };
    let separators = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
    if separators
        .iter()
        .any(|(index, byte)| whole[*index] != *byte)
    {
        return None;
    }
    let number = |start: usize, end: usize| -> Option<i64> {
        whole[start..end].iter().try_fold(0_i64, |total, byte| {
            if byte.is_ascii_digit() {
                Some(total * 10 + i64::from(byte - b'0'))
            } else {
                None
            }
        })
    };
    let (year, month, day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
    let (hour, minute, second) = (number(11, 13)?, number(14, 16)?, number(17, 19)?);
    let valid = year >= 1
        && (1..=12).contains(&month)
        && day >= 1
        && day <= days_in_month(year, month)
        && hour <= 23
        && minute <= 59
        && second <= 59;
    if !valid {
        return None;
    }
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second;
    Some(seconds * MICROS_PER_SECOND + micros)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 1970-01-01 to a proleptic Gregorian date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// `r` and `s` of a canonical DER ECDSA signature with both in `1..n`.
fn der_signature(der: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let [0x30, length, body @ ..] = der else {
        return None;
    };
    if *length >= 0x80 || usize::from(*length) != body.len() {
        return None;
    }
    let (r, rest) = der_integer(body)?;
    let (s, rest) = der_integer(rest)?;
    let in_range = rest.is_empty()
        && scalar_in_range(&r, &P256_ORDER, false)
        && scalar_in_range(&s, &P256_ORDER, false);
    in_range.then_some((r, s))
}

/// One minimally encoded, non-negative DER INTEGER of at most 32 bytes.
fn der_integer(bytes: &[u8]) -> Option<([u8; 32], &[u8])> {
    let [0x02, length, rest @ ..] = bytes else {
        return None;
    };
    let length = usize::from(*length);
    if length == 0 || length > 33 || rest.len() < length {
        return None;
    }
    let (content, rest) = rest.split_at(length);
    let padded = content[0] == 0;
    if content[0] & 0x80 != 0 || (padded && (length == 1 || content[1] & 0x80 == 0)) {
        return None;
    }
    let magnitude = if padded { &content[1..] } else { content };
    if magnitude.len() > 32 {
        return None;
    }
    let mut scalar = [0_u8; 32];
    scalar[32 - magnitude.len()..].copy_from_slice(magnitude);
    Some((scalar, rest))
}

fn der_encode(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    let integer = |scalar: &[u8; 32]| {
        let start = scalar.iter().position(|byte| *byte != 0).unwrap_or(31);
        let magnitude = &scalar[start..];
        let mut encoded = vec![0x02];
        if magnitude[0] & 0x80 != 0 {
            encoded.push(u8::try_from(magnitude.len() + 1).unwrap_or(u8::MAX));
            encoded.push(0);
        } else {
            encoded.push(u8::try_from(magnitude.len()).unwrap_or(u8::MAX));
        }
        encoded.extend_from_slice(magnitude);
        encoded
    };
    let body = [integer(r), integer(s)].concat();
    let mut der = vec![0x30, u8::try_from(body.len()).unwrap_or(u8::MAX)];
    der.extend_from_slice(&body);
    der
}

/// `1 <= scalar < bound`, or `<= bound` when `inclusive`.
fn scalar_in_range(scalar: &[u8; 32], bound: &[u8; 32], inclusive: bool) -> bool {
    scalar.iter().any(|byte| *byte != 0) && (scalar < bound || (inclusive && scalar == bound))
}

const fn hex_literal(text: [u8; 64]) -> [u8; 32] {
    const fn nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("hex literal"),
        }
    }
    let mut out = [0_u8; 32];
    let mut index = 0;
    while index < 32 {
        out[index] = (nibble(text[2 * index]) << 4) | nibble(text[2 * index + 1]);
        index += 1;
    }
    out
}

#[cfg(test)]
#[path = "health_lease_contract_tests.rs"]
mod tests;

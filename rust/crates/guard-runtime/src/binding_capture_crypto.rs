//! Keyed fingerprints and sealed receipts for the opt-in Codex binding capture.
//!
//! The capture is off unless a validated, private, unexpired v2 marker exists;
//! nothing here offers an unkeyed fallback.

use base64ct::{Base64Url, Encoding};
use hmac::{Hmac, Mac};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use sha2::Sha256;

use crate::binding_capture_json::{self as json, Json, MAX_CANONICAL_BYTES};

pub(crate) const CAPTURE_SCHEMA: &str = "guard-codex-binding-capture.v2";
pub(crate) const FINGERPRINT_SCHEME: &str = "hmac-sha256-per-run-v2";
pub(crate) const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
pub(crate) const MAX_RECORDS: i64 = 128;
pub(crate) const MAX_BYTES: i64 = 64 * 1024;
pub(crate) const MAX_MARKER_BYTES: usize = 4 * 1024;
const MAX_LIFETIME_SECONDS: i64 = 3600;

const MARKER_FIELDS: [&str; 8] = [
    "schema",
    "enabled",
    "run_id",
    "expires_at",
    "max_records",
    "max_bytes",
    "key_id",
    "capture_key_b64",
];

/// Validated in-memory session material read from a private marker.
#[derive(Clone)]
pub(crate) struct CaptureSession {
    pub(crate) run_id: String,
    pub(crate) expires_at: i64,
    pub(crate) max_records: i64,
    pub(crate) max_bytes: i64,
    pub(crate) key_id: String,
    pub(crate) key: Vec<u8>,
}

pub(crate) fn valid_run_id(value: &str) -> bool {
    let mut chars = value.chars();
    value.len() <= 64
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
}

pub(crate) fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub(crate) fn whole_seconds(now: f64) -> i64 {
    now.trunc() as i64
}

impl CaptureSession {
    pub(crate) fn usable(&self, now: f64) -> bool {
        let current = whole_seconds(now);
        valid_run_id(&self.run_id)
            && (1..=MAX_RECORDS).contains(&self.max_records)
            && (1..=MAX_BYTES).contains(&self.max_bytes)
            && is_lower_hex(&self.key_id, 32)
            && self.key.len() == KEY_BYTES
            && current < self.expires_at
            && self.expires_at <= current + MAX_LIFETIME_SECONDS
    }

    fn digest(&self, role: &str, payload: &[u8], now: f64) -> Option<String> {
        if !self.usable(now) {
            return None;
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).ok()?;
        mac.update(CAPTURE_SCHEMA.as_bytes());
        mac.update(&[0]);
        mac.update(role.as_bytes());
        mac.update(&[0]);
        mac.update(payload);
        Some(hex::encode(mac.finalize().into_bytes()))
    }

    pub(crate) fn payload_hmac(&self, role: &str, payload: &Json, now: f64) -> Option<String> {
        if !matches!(role, "raw" | "forwarded") {
            return None;
        }
        self.digest(role, &json::canonical(payload)?, now)
    }

    fn row_material(row: &Json) -> Json {
        match row {
            Json::Obj(entries) => Json::Obj(
                entries
                    .iter()
                    .filter(|(key, _)| key != "row_mac")
                    .cloned()
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    pub(crate) fn row_hmac(&self, row: &Json, now: f64) -> Option<String> {
        let encoded = json::canonical(&Self::row_material(row))?;
        self.digest("row", &encoded, now)
    }

    pub(crate) fn verify_row_hmac(&self, row: &Json, now: f64) -> bool {
        let Some(expected) = row.get("row_mac").and_then(Json::as_str) else {
            return false;
        };
        let Some(actual) = self.row_hmac(row, now) else {
            return false;
        };
        is_lower_hex(expected, 64)
            && expected
                .bytes()
                .zip(actual.bytes())
                .fold(expected.len() ^ actual.len(), |diff, (a, b)| {
                    diff | usize::from(a ^ b)
                })
                == 0
    }
}

fn marker_int(value: &Json) -> Option<i64> {
    value.as_i64()
}

/// `_decode_b64`: canonical padded URL-safe base64 only.
fn decode_b64(value: Option<&Json>, max_bytes: usize) -> Option<Vec<u8>> {
    let text = value?.as_str()?;
    if text.is_empty() || text.len() > max_bytes * 2 {
        return None;
    }
    let decoded = Base64Url::decode_vec(text).ok()?;
    (decoded.len() <= max_bytes && Base64Url::encode_string(&decoded) == text).then_some(decoded)
}

pub(crate) fn parse_marker(value: &Json, now: f64) -> Option<CaptureSession> {
    let mut keys = value.keys();
    keys.sort_unstable();
    let mut expected = MARKER_FIELDS.to_vec();
    expected.sort_unstable();
    if keys != expected
        || value.get("schema").and_then(Json::as_str) != Some(CAPTURE_SCHEMA)
        || value.get("enabled") != Some(&Json::Bool(true))
    {
        return None;
    }
    let run_id = value.get("run_id")?.as_str()?;
    let key_id = value.get("key_id")?.as_str()?;
    if !valid_run_id(run_id) || !is_lower_hex(key_id, 32) {
        return None;
    }
    let key = decode_b64(value.get("capture_key_b64"), KEY_BYTES)?;
    if key.len() != KEY_BYTES {
        return None;
    }
    let session = CaptureSession {
        run_id: run_id.to_owned(),
        expires_at: marker_int(value.get("expires_at")?)?,
        max_records: marker_int(value.get("max_records")?)?,
        max_bytes: marker_int(value.get("max_bytes")?)?,
        key_id: key_id.to_owned(),
        key,
    };
    session.usable(now).then_some(session)
}

/// The canonical marker document for a freshly created session.
pub(crate) fn encode_marker(session: &CaptureSession, now: f64) -> Option<Vec<u8>> {
    if !session.usable(now) {
        return None;
    }
    let marker = Json::object(vec![
        ("schema", Json::Str(CAPTURE_SCHEMA.to_owned())),
        ("enabled", Json::Bool(true)),
        ("run_id", Json::Str(session.run_id.clone())),
        ("expires_at", Json::int(session.expires_at)),
        ("max_records", Json::int(session.max_records)),
        ("max_bytes", Json::int(session.max_bytes)),
        ("key_id", Json::Str(session.key_id.clone())),
        (
            "capture_key_b64",
            Json::Str(Base64Url::encode_string(&session.key)),
        ),
    ]);
    let mut encoded = json::canonical(&marker)?;
    if encoded.len() > MAX_MARKER_BYTES {
        return None;
    }
    encoded.push(b'\n');
    Some(encoded)
}

/// Authenticated-data subset of a row; must match the writer exactly.
fn row_aad(row: &Json) -> Option<Vec<u8>> {
    const FIELDS: [&str; 10] = [
        "schema",
        "run_id",
        "key_id",
        "harness",
        "event_name",
        "tool_use_id_state",
        "tool_use_id",
        "route",
        "raw_payload_hmac_sha256",
        "forwarded_payload_hmac_sha256",
    ];
    let aad = Json::Obj(
        FIELDS
            .iter()
            .map(|field| {
                (
                    (*field).to_owned(),
                    row.get(field).cloned().unwrap_or(Json::Null),
                )
            })
            .collect(),
    );
    json::canonical(&aad)
}

fn cipher(session: &CaptureSession) -> Option<LessSafeKey> {
    UnboundKey::new(&AES_256_GCM, &session.key)
        .ok()
        .map(LessSafeKey::new)
}

pub(crate) fn seal_receipt(
    session: &CaptureSession,
    row: &Json,
    receipt: &Json,
    now: f64,
) -> Option<Json> {
    if !session.usable(now) {
        return None;
    }
    let mut buffer = json::canonical(receipt)?;
    let aad = row_aad(row)?;
    let mut nonce = [0u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).ok()?;
    cipher(session)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut buffer,
        )
        .ok()?;
    Some(Json::object(vec![
        ("nonce_b64", Json::Str(Base64Url::encode_string(&nonce))),
        (
            "ciphertext_b64",
            Json::Str(Base64Url::encode_string(&buffer)),
        ),
    ]))
}

pub(crate) fn open_receipt(
    session: &CaptureSession,
    row: &Json,
    sealed: &Json,
    now: f64,
) -> Option<Json> {
    let mut keys = sealed.keys();
    keys.sort_unstable();
    if !session.usable(now) || keys != ["ciphertext_b64", "nonce_b64"] {
        return None;
    }
    let nonce = decode_b64(sealed.get("nonce_b64"), NONCE_BYTES)?;
    let mut ciphertext = decode_b64(sealed.get("ciphertext_b64"), MAX_CANONICAL_BYTES)?;
    let aad = row_aad(row)?;
    if nonce.len() != NONCE_BYTES || ciphertext.len() < 16 {
        return None;
    }
    let nonce: [u8; NONCE_BYTES] = nonce.try_into().ok()?;
    let plaintext = cipher(session)?
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut ciphertext,
        )
        .ok()?;
    json::parse_object(plaintext)
}

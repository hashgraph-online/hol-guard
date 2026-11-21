//! Bounded HMAC frames for the trusted VM collector bridge.
//!
//! Keys must arrive through an already authenticated private channel. The
//! codec authenticates transport custody, never benchmark eligibility.

use crate::crypto::{decode_hex, is_sha256};
use crate::payload::exact_keys;
use crate::{canonical_value, EvidenceError, Result};
use gauntlet_contracts::canonicalize;
use ring::hmac;
use serde_json::{json, Value};

const SCHEMA: &str = "gauntlet-vm-bridge-frame.v1";
const DOMAIN: &[u8] = b"gauntlet-vm-bridge-frame.v1\0";
const MAX_FRAME_BYTES: usize = 12 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;
const MAX_FRAMES: u64 = 10_000;

fn canonical_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                *byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
            }
        })
}

fn hex(raw: &[u8]) -> String {
    let mut result = String::with_capacity(raw.len() * 2);
    for byte in raw {
        result.push_str(&format!("{byte:02x}"));
    }
    result
}

fn sign(key: &hmac::Key, message: &Value) -> Result<String> {
    let canonical = canonical_value(message)?;
    let mut input = Vec::with_capacity(DOMAIN.len() + canonical.len());
    input.extend_from_slice(DOMAIN);
    input.extend_from_slice(&canonical);
    Ok(hex(hmac::sign(key, &input).as_ref()))
}

pub struct FrameCodec {
    key: hmac::Key,
    session: String,
    local_role: &'static str,
    peer_role: &'static str,
    local_boot: String,
    peer_boot: String,
    max_frames: u64,
    max_bytes: usize,
    sent: u64,
    received: u64,
    bytes_sent: usize,
    bytes_received: usize,
    poisoned: bool,
}

impl FrameCodec {
    pub fn new(
        key: &[u8],
        session: &str,
        local_role: &str,
        local_boot: &str,
        peer_boot: &str,
        max_frames: u64,
        max_bytes: usize,
    ) -> Result<Self> {
        if key.len() != 32
            || !canonical_uuid(session)
            || !canonical_uuid(local_boot)
            || !canonical_uuid(peer_boot)
            || !(1..=MAX_FRAMES).contains(&max_frames)
            || !(1024..=MAX_TOTAL_BYTES).contains(&max_bytes)
        {
            return Err(EvidenceError::Invalid(
                "invalid private bridge identity or bounds",
            ));
        }
        let (local_role, peer_role) = match local_role {
            "controller" => ("controller", "product-collector"),
            "product-collector" => ("product-collector", "controller"),
            _ => return Err(EvidenceError::Invalid("invalid bridge collector role")),
        };
        Ok(Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, key),
            session: session.to_owned(),
            local_role,
            peer_role,
            local_boot: local_boot.to_owned(),
            peer_boot: peer_boot.to_owned(),
            max_frames,
            max_bytes,
            sent: 0,
            received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            poisoned: false,
        })
    }

    pub fn poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn invalidate(&mut self) {
        self.poisoned = true;
    }

    fn active(&self) -> Result<()> {
        if self.poisoned {
            Err(EvidenceError::Invalid("bridge connection is invalid"))
        } else {
            Ok(())
        }
    }

    pub fn validate_length(&mut self, length: usize) -> Result<()> {
        self.active()?;
        let valid = (1..=MAX_FRAME_BYTES).contains(&length)
            && self.received < self.max_frames
            && self
                .bytes_received
                .checked_add(length + 4)
                .is_some_and(|bytes| bytes <= self.max_bytes);
        if !valid {
            self.invalidate();
            return Err(EvidenceError::Invalid(
                "bridge frame/aggregate budget exceeded",
            ));
        }
        Ok(())
    }

    /// Reserves the sequence and byte budget before returning the frame.
    /// A caller whose transport write fails must call `invalidate`.
    pub fn encode(&mut self, kind: &str, body: &Value) -> Result<Vec<u8>> {
        self.active()?;
        let result = self.encode_inner(kind, body);
        if result.is_err() {
            self.invalidate();
        }
        result
    }

    fn encode_inner(&mut self, kind: &str, body: &Value) -> Result<Vec<u8>> {
        if !matches!(kind, "request" | "response")
            || !body.is_object()
            || self.sent >= self.max_frames
        {
            return Err(EvidenceError::Invalid(
                "invalid bridge kind/body or frame budget",
            ));
        }
        let message = json!({
            "schema": SCHEMA,
            "session": self.session,
            "source_role": self.local_role,
            "destination_role": self.peer_role,
            "source_boot": self.local_boot,
            "destination_boot": self.peer_boot,
            "sequence": self.sent,
            "kind": kind,
            "body": body,
        });
        let raw = canonical_value(&json!({"message":message,"mac":sign(&self.key,&message)?}))?;
        if raw.len() > MAX_FRAME_BYTES
            || self
                .bytes_sent
                .checked_add(raw.len() + 4)
                .is_none_or(|bytes| bytes > self.max_bytes)
        {
            return Err(EvidenceError::Invalid(
                "outgoing bridge byte budget exceeded",
            ));
        }
        let length: u32 = raw
            .len()
            .try_into()
            .map_err(|_| EvidenceError::Invalid("bridge frame length overflow"))?;
        let mut frame = Vec::with_capacity(raw.len() + 4);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&raw);
        self.sent += 1;
        self.bytes_sent += frame.len();
        Ok(frame)
    }

    pub fn decode(&mut self, raw: &[u8], expected_kind: &str) -> Result<Value> {
        self.active()?;
        let result = self.decode_inner(raw, expected_kind);
        if result.is_err() {
            self.invalidate();
        }
        result
    }

    fn decode_inner(&mut self, raw: &[u8], expected_kind: &str) -> Result<Value> {
        self.validate_length(raw.len())?;
        let canonical =
            canonicalize(raw).map_err(|_| EvidenceError::Invalid("invalid bridge JSON"))?;
        let envelope: Value = serde_json::from_slice(&canonical)
            .map_err(|_| EvidenceError::Invalid("invalid bridge JSON"))?;
        if !exact_keys(&envelope, &["message", "mac"]) {
            return Err(EvidenceError::Invalid(
                "invalid authenticated bridge envelope",
            ));
        }
        let mac = envelope["mac"]
            .as_str()
            .filter(|value| is_sha256(value))
            .ok_or(EvidenceError::Invalid("invalid bridge MAC"))?;
        let message = &envelope["message"];
        if !exact_keys(
            message,
            &[
                "schema",
                "session",
                "source_role",
                "destination_role",
                "source_boot",
                "destination_boot",
                "sequence",
                "kind",
                "body",
            ],
        ) {
            return Err(EvidenceError::Invalid("invalid bridge message fields"));
        }
        let provided = decode_hex(mac, 32)?;
        let canonical_message = canonical_value(message)?;
        let mut authenticated = Vec::with_capacity(DOMAIN.len() + canonical_message.len());
        authenticated.extend_from_slice(DOMAIN);
        authenticated.extend_from_slice(&canonical_message);
        if hmac::verify(&self.key, &authenticated, &provided).is_err() {
            return Err(EvidenceError::Invalid("bridge authentication failed"));
        }
        if message["schema"] != SCHEMA
            || message["session"] != self.session
            || message["source_role"] != self.peer_role
            || message["destination_role"] != self.local_role
            || message["source_boot"] != self.peer_boot
            || message["destination_boot"] != self.local_boot
            || message["sequence"].as_u64() != Some(self.received)
            || !matches!(expected_kind, "request" | "response")
            || message["kind"] != expected_kind
            || !message["body"].is_object()
        {
            return Err(EvidenceError::Invalid(
                "bridge session/direction/order mismatch",
            ));
        }
        self.received += 1;
        self.bytes_received += raw.len() + 4;
        Ok(message["body"].clone())
    }
}

//! Stream the established v3 identity from borrowed semantic request inputs.
use super::serialization::{canonical_map, Canonical};
use guard_contracts::GuardHookEnvelopeV2;
use serde::{Serialize, Serializer};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::io::{self, Write};

const OMITTED_PAYLOAD_KEYS: &[&str] = &[
    "event",
    "eventName",
    "hook_event_name",
    "hookEventName",
    "hook_name",
    "hookName",
    "timestamp",
    "timestamp_ms",
    "timestampMs",
    "created_at",
    "createdAt",
    "received_at",
    "receivedAt",
];

struct Payload<'a>(&'a Map<String, Value>);

impl Serialize for Payload<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Event aliases have already been checked for agreement. Omit transport
        // metadata only at this root; nested timestamps remain committed.
        canonical_map(self.0, OMITTED_PAYLOAD_KEYS, serializer)
    }
}

// Fields in these borrowed structures are in canonical lexicographic order.
// Every dynamic object below them uses Canonical's explicitly sorted map.
#[derive(Serialize)]
struct Identity<'a> {
    event: &'a str,
    harness: &'a str,
    payload: Payload<'a>,
    policy: Policy<'a>,
    schema: &'static str,
    source: Source<'a>,
    version: u8,
}

#[derive(Serialize)]
struct Policy<'a> {
    generation: u64,
    policy_digest: Option<Canonical<'a>>,
    rule_digest: Option<Canonical<'a>>,
    runtime_identity: Option<Canonical<'a>>,
    scope_digest: Option<Canonical<'a>>,
}

#[derive(Serialize)]
struct Source<'a> {
    cwd: Option<&'a str>,
    guard_home: &'a str,
    home_dir: &'a str,
    source_ref_external_allowed: bool,
}

impl<'a> Identity<'a> {
    fn new(
        envelope: &'a GuardHookEnvelopeV2,
        harness: &'a str,
        event: &'a str,
    ) -> Result<Self, String> {
        let payload = envelope
            .raw_payload
            .as_object()
            .ok_or_else(|| "native_hook_payload_invalid".to_owned())?;
        let object = envelope.policy_snapshot.as_object();
        let field = |name| object.and_then(|object| object.get(name)).map(Canonical);
        let scope_digest = object
            .and_then(|object| object.get("scope_contract"))
            .and_then(Value::as_object)
            .and_then(|scope| scope.get("scope_digest"))
            .map(Canonical);
        Ok(Self {
            event,
            harness,
            payload: Payload(payload),
            policy: Policy {
                generation: envelope.policy_generation,
                policy_digest: field("policy_digest"),
                rule_digest: field("rule_digest"),
                runtime_identity: field("runtime_identity"),
                scope_digest,
            },
            schema: "guard-native-request-identity.v3",
            source: Source {
                cwd: envelope.source.cwd.as_deref(),
                guard_home: &envelope.source.guard_home,
                home_dir: &envelope.source.home_dir,
                source_ref_external_allowed: envelope.source.source_ref_external_allowed,
            },
            version: 3,
        })
    }
}

struct DigestWriter(Sha256);

impl Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn request_id_is_safe(value: &str) -> bool {
    let opaque_token = !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        });
    let compact_uuid = value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    let dashed_uuid = value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23)
                .then_some(byte == b'-')
                .unwrap_or_else(|| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
    opaque_token || compact_uuid || dashed_uuid
}

pub(super) fn request_identity_for_event(
    envelope: &GuardHookEnvelopeV2,
    harness: &str,
    event: &str,
) -> Result<(String, String), String> {
    let value = Identity::new(envelope, harness, event)?;
    let mut writer = DigestWriter(Sha256::new());
    serde_json::to_writer(&mut writer, &value)
        .map_err(|_| "native_hook_request_digest_failed".to_owned())?;
    let digest = hex::encode(writer.0.finalize());
    let request_id = match envelope.request_id.as_deref() {
        Some(value) if request_id_is_safe(value) => value.to_owned(),
        Some(_) => return Err("native_hook_request_id_invalid".to_owned()),
        None => format!("sha256:{digest}"),
    };
    Ok((request_id, digest))
}

#[cfg(test)]
#[path = "edge_identity_tests.rs"]
mod tests;

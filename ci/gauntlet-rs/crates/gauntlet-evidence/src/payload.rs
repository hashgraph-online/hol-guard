use crate::crypto::{decode_base64, is_sha256, sha256, verify_ed25519};
use crate::{canonical_value, EvidenceError, Result};
use gauntlet_contracts::load_record;
use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use unicode_normalization::UnicodeNormalization;

pub const SOURCE_KEYS: [&str; 10] = [
    "candidate",
    "product",
    "policy",
    "harness",
    "model",
    "services",
    "observer",
    "oracle",
    "verifier",
    "native_build",
];
pub const KINDS: [&str; 12] = [
    "workflow",
    "authorization",
    "attack",
    "snapshot",
    "capabilities",
    "approval",
    "event",
    "episode",
    "scorecard",
    "campaign",
    "world-snapshot",
    "world-receipts",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectAnchor {
    pub public_key: Vec<u8>,
    pub receipt_count: usize,
    pub final_hash: String,
}

pub struct PayloadInfo<'a> {
    pub kind: &'a str,
    pub stream_id: Option<&'a str>,
    pub records: &'a [Value],
}

pub fn exact_keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|row| {
        row.len() == expected.len() && expected.iter().all(|key| row.contains_key(*key))
    })
}

pub fn segment_ok(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() <= 128
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes[1..]
            .iter()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'_' | b'-' | b'.'))
}

fn secret_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r"(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}|Bearer\s+[A-Za-z0-9+/_.=-]{16,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)",
        )
        .expect("pinned secret pattern compiles")
    })
}

pub fn public_safe(value: &Value) -> Result<()> {
    let secret_keys = [
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "client_secret",
        "private_key",
        "password",
        "provider_credentials",
        "credentials",
        "environment",
        "env",
    ];
    let mut pending = vec![value];
    while let Some(item) = pending.pop() {
        match item {
            Value::Object(row) => {
                for (key, child) in row {
                    let lowered: String = key.nfkc().flat_map(char::to_lowercase).collect();
                    let lowered = lowered.replace('ß', "ss");
                    if secret_keys.contains(&lowered.as_str())
                        || (lowered == "authorization" && child.is_string())
                    {
                        return Err(EvidenceError::Invalid(
                            "credential field in public evidence",
                        ));
                    }
                    pending.push(child);
                }
            }
            Value::Array(rows) => pending.extend(rows),
            Value::String(text) if secret_pattern().is_match(text) => {
                return Err(EvidenceError::Invalid(
                    "credential-like public evidence text",
                ))
            }
            _ => {}
        }
    }
    Ok(())
}

pub fn validate_identities(value: &Value) -> Result<()> {
    if !exact_keys(value, &SOURCE_KEYS) {
        return Err(EvidenceError::Invalid("exact source identities required"));
    }
    for digest in value.as_object().expect("exact keys checked").values() {
        if !digest.as_str().is_some_and(is_sha256) {
            return Err(EvidenceError::Invalid("malformed source identity digest"));
        }
    }
    Ok(())
}

pub fn validate_anchors(value: &Value) -> Result<BTreeMap<String, EffectAnchor>> {
    let anchors = value
        .as_object()
        .ok_or(EvidenceError::Invalid("effect anchors must be an object"))?;
    if anchors.len() > 128 {
        return Err(EvidenceError::Invalid("too many effect anchors"));
    }
    let mut parsed = BTreeMap::new();
    for (name, anchor) in anchors {
        if !segment_ok(name) || !exact_keys(anchor, &["public_key", "receipt_count", "final_hash"])
        {
            return Err(EvidenceError::Invalid("malformed effect anchor"));
        }
        let row = anchor.as_object().expect("exact keys checked");
        let key = row["public_key"]
            .as_str()
            .ok_or(EvidenceError::Invalid("effect public key must be base64"))?;
        let count = row["receipt_count"]
            .as_u64()
            .filter(|count| *count <= 100_000)
            .ok_or(EvidenceError::Invalid("invalid effect receipt count"))?;
        let final_hash = row["final_hash"]
            .as_str()
            .filter(|value| is_sha256(value))
            .ok_or(EvidenceError::Invalid("invalid effect final hash"))?;
        parsed.insert(
            name.clone(),
            EffectAnchor {
                public_key: decode_base64(key, 32)?,
                receipt_count: count as usize,
                final_hash: final_hash.to_owned(),
            },
        );
    }
    Ok(parsed)
}

pub fn validate_payload<'a>(
    value: &'a Value,
    anchors: &BTreeMap<String, EffectAnchor>,
) -> Result<PayloadInfo<'a>> {
    if !exact_keys(value, &["schema_version", "kind", "stream_id", "records"])
        || value["schema_version"] != "1.0"
    {
        return Err(EvidenceError::Invalid("invalid evidence payload fields"));
    }
    let kind = value["kind"]
        .as_str()
        .filter(|kind| KINDS.contains(kind))
        .ok_or(EvidenceError::Invalid("unsupported evidence kind"))?;
    let records = value["records"]
        .as_array()
        .filter(|rows| rows.len() <= 100_000)
        .ok_or(EvidenceError::Invalid("invalid evidence record inventory"))?;
    public_safe(value)?;
    let stream_id = value["stream_id"].as_str();
    if kind == "world-receipts" {
        let name = stream_id.ok_or(EvidenceError::Invalid("effect stream ID required"))?;
        if !segment_ok(name) {
            return Err(EvidenceError::Invalid("invalid effect stream ID"));
        }
        let anchor = anchors
            .get(name)
            .ok_or(EvidenceError::Invalid("unanchored effect stream"))?;
        for receipt in records {
            if !exact_keys(receipt, &["event", "signature"])
                || !exact_keys(
                    &receipt["event"],
                    &[
                        "sequence",
                        "previous_hash",
                        "request_id",
                        "operation",
                        "actor",
                        "args_digest",
                        "raw_args_digest",
                        "before",
                        "after",
                        "effect",
                        "status",
                        "result_digest",
                    ],
                )
            {
                return Err(EvidenceError::Invalid(
                    "invalid signed world receipt fields",
                ));
            }
        }
        verify_receipts(records, anchor)?;
    } else if !value["stream_id"].is_null() {
        return Err(EvidenceError::Invalid("unexpected effect stream ID"));
    } else if kind == "world-snapshot" {
        for record in records {
            validate_world_snapshot(record)?;
        }
    } else {
        for record in records {
            load_record(kind, record.to_string().as_bytes())
                .map_err(|_| EvidenceError::Invalid("invalid versioned evidence record"))?;
        }
    }
    Ok(PayloadInfo {
        kind,
        stream_id,
        records,
    })
}

fn validate_world_snapshot(snapshot: &Value) -> Result<()> {
    if !exact_keys(
        snapshot,
        &[
            "schema",
            "workflow_id",
            "actor_id",
            "provider_scope",
            "records",
        ],
    ) || snapshot["schema"] != "gauntlet-workflow-snapshot.v1"
    {
        return Err(EvidenceError::Invalid("invalid world snapshot"));
    }
    let records = snapshot["records"]
        .as_array()
        .ok_or(EvidenceError::Invalid(
            "world snapshot records must be an array",
        ))?;
    let mut ids = BTreeSet::new();
    for record in records {
        if !exact_keys(
            record,
            &[
                "id",
                "collection",
                "tenant_id",
                "owner_id",
                "version",
                "acl",
                "data",
            ],
        ) {
            return Err(EvidenceError::Invalid("invalid world state record"));
        }
        let id = record["id"]
            .as_str()
            .ok_or(EvidenceError::Invalid("world state ID must be a string"))?;
        if !ids.insert(id) || !integer_lexeme(&record["version"]) {
            return Err(EvidenceError::Invalid(
                "duplicate ID or invalid world state version",
            ));
        }
    }
    Ok(())
}

fn integer_lexeme(value: &Value) -> bool {
    value.as_number().is_some_and(|number| {
        number
            .to_string()
            .bytes()
            .all(|ch| ch.is_ascii_digit() || ch == b'-')
    })
}

fn verify_receipts(receipts: &[Value], anchor: &EffectAnchor) -> Result<()> {
    if receipts.len() != anchor.receipt_count {
        return Err(EvidenceError::Invalid("effect receipt count mismatch"));
    }
    let mut previous = "0".repeat(64);
    for (index, receipt) in receipts.iter().enumerate() {
        let event = receipt
            .get("event")
            .ok_or(EvidenceError::Invalid("effect event missing"))?;
        let sequence = event["sequence"]
            .as_u64()
            .ok_or(EvidenceError::Invalid("effect sequence missing"))?;
        if sequence != (index + 1) as u64 || event["previous_hash"] != previous {
            return Err(EvidenceError::Invalid("effect receipt chain mismatch"));
        }
        let signature = receipt["signature"]
            .as_str()
            .ok_or(EvidenceError::Invalid("effect signature missing"))?;
        verify_ed25519(
            &anchor.public_key,
            &canonical_value(event)?,
            &decode_base64(signature, 64)?,
        )?;
        previous = sha256(&canonical_value(receipt)?);
    }
    if previous != anchor.final_hash {
        return Err(EvidenceError::Invalid("effect final hash mismatch"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::public_safe;
    use serde_json::{json, Map, Value};

    #[test]
    fn secret_keys_with_casefold_expansion_fail_closed() {
        for key in ["password", "paſſword", "paßword", "ｐａｓｓｗｏｒｄ"] {
            let mut object = Map::new();
            object.insert(key.to_owned(), json!("synthetic"));
            let value = Value::Object(object);
            assert!(public_safe(&value).is_err(), "{key}");
        }
    }
}

//! Artifact evidence for the consumer projection op: the diff against the
//! stored snapshot, the capability snapshot and delta, the local history and
//! provenance context, and the receipt summary strings.
//!
//! The store reads (snapshot, capabilities, inventory, receipt counts,
//! events, cached advisories) happen in Python and arrive as typed evidence;
//! nothing here touches IO.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use crate::consumer_capabilities::{normalize, CapabilityArtifact};
use crate::consumer_capability_delta::compute as capability_delta;

const APPROVAL_DECISIONS: [&str; 2] = ["allow", "warn"];
const BLOCK_DECISIONS: [&str; 4] = ["review", "require-reapproval", "sandbox-required", "block"];
const INCIDENT_EVENTS: [&str; 6] = [
    "changed_artifact_caught",
    "premium_advisory",
    "install_time_block",
    "install_time_review",
    "install_time_require-reapproval",
    "install_time_sandbox-required",
];
const FLAGGED_SEVERITIES: [&str; 3] = ["critical", "high", "revoked"];

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn metadata_text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get("metadata")
        .and_then(|metadata| metadata.get(key))
        .and_then(Value::as_str)
        .filter(|identity| !identity.is_empty())
}

/// Python `==` between two JSON values (`1 == 1.0 == True`).
fn python_equal(left: &Value, right: &Value) -> bool {
    fn numeric(value: &Value) -> Option<f64> {
        match value {
            Value::Bool(flag) => Some(f64::from(u8::from(*flag))),
            Value::Number(number) => number.as_f64(),
            _ => None,
        }
    }
    match (left, right) {
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len() && left.iter().zip(right).all(|(a, b)| python_equal(a, b))
        }
        (Value::Object(left), Value::Object(right)) => {
            left.len() == right.len()
                && left.iter().all(|(key, value)| {
                    right
                        .get(key)
                        .is_some_and(|other| python_equal(value, other))
                })
        }
        (Value::Number(a), Value::Number(b)) if a.is_i64() && b.is_i64() => {
            a.as_i64() == b.as_i64()
        }
        _ => match (numeric(left), numeric(right)) {
            (Some(a), Some(b)) => a == b,
            _ => left == right,
        },
    }
}

fn first_seen_fields(artifact_type: Option<&str>) -> Vec<String> {
    vec![match artifact_type {
        Some("prompt_request") => "prompt_request".to_owned(),
        Some("file_read_request") => "file_read_request".to_owned(),
        _ => "first_seen".to_owned(),
    }]
}

struct Diff {
    changed: bool,
    changed_fields: Vec<String>,
    previous_hash: Option<String>,
}

fn diff(query: &Value, artifact: &Value, current_hash: &str) -> Diff {
    let previous = &query["previous_snapshot"];
    let current = &query["current_payload"];
    if previous.is_null() {
        return Diff {
            changed: true,
            changed_fields: first_seen_fields(text(artifact, "artifact_type")),
            previous_hash: None,
        };
    }
    let previous_hash = text(previous, "artifact_hash").map(str::to_owned);
    let current_identity = (text(artifact, "harness") == Some("codex")
        && text(artifact, "artifact_type") == Some("hook"))
    .then(|| metadata_text(artifact, "codex_hook_identity"))
    .flatten();
    let previous_identity = (text(previous, "harness") == Some("codex")
        && text(previous, "artifact_type") == Some("hook"))
    .then(|| metadata_text(previous, "codex_hook_identity"))
    .flatten();
    if current_identity.is_some() && previous_identity == current_identity {
        let hash_changed = previous_hash
            .as_deref()
            .is_some_and(|hash| hash != current_hash);
        return Diff {
            changed: hash_changed,
            changed_fields: if hash_changed {
                vec!["metadata".to_owned()]
            } else {
                Vec::new()
            },
            previous_hash,
        };
    }
    let keys: Vec<&str> = query["payload_keys"]
        .as_array()
        .map(|keys| keys.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut changed_fields: Vec<String> = keys
        .into_iter()
        .filter(|key| {
            let current_value = current.get(*key).unwrap_or(&Value::Null);
            let previous_value = match previous.get(*key) {
                Some(value) => value,
                None if *key == "env_keys" => &Value::Array(Vec::new()),
                None => &Value::Null,
            };
            !python_equal(previous_value, current_value)
        })
        .map(str::to_owned)
        .collect();
    if changed_fields.is_empty()
        && previous_hash
            .as_deref()
            .is_some_and(|hash| hash != current_hash)
    {
        changed_fields = vec!["metadata".to_owned()];
    }
    Diff {
        changed: !changed_fields.is_empty(),
        changed_fields,
        previous_hash,
    }
}

fn diff_summary(diff: &Diff) -> Value {
    if !diff.changed {
        return Value::Null;
    }
    if diff.changed_fields.is_empty() {
        return json!("artifact changed");
    }
    let count = diff.changed_fields.len();
    let sample = diff
        .changed_fields
        .iter()
        .take(3)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    let suffix = if count > 3 { " ..." } else { "" };
    json!(format!("{count} change(s): {sample}{suffix}"))
}

fn capabilities_summary(artifact: &Value) -> String {
    let mut parts = vec![text(artifact, "artifact_type")
        .unwrap_or("")
        .replace('_', " ")];
    parts.extend(text(artifact, "transport").map(str::to_owned));
    parts.extend(text(artifact, "command").map(str::to_owned));
    parts.join(" \u{2022} ")
}

fn flagged(severities: &BTreeSet<String>) -> bool {
    FLAGGED_SEVERITIES
        .iter()
        .any(|label| severities.contains(*label))
}

fn advisory_severities(advisories: &[Value]) -> BTreeSet<String> {
    advisories
        .iter()
        .map(|item| text(item, "severity").unwrap_or("").to_lowercase())
        .collect()
}

fn history_context(history: &Value, publisher: Option<&str>) -> Value {
    let item = &history["inventory_item"];
    let counts = &history["decision_counts"];
    let count_of = |decisions: &[&str]| -> i64 {
        decisions
            .iter()
            .map(|decision| counts.get(*decision).and_then(Value::as_i64).unwrap_or(0))
            .sum()
    };
    let incidents = history["event_names"]
        .as_array()
        .map(|names| {
            names
                .iter()
                .filter_map(Value::as_str)
                .filter(|name| INCIDENT_EVENTS.contains(name))
                .count()
        })
        .unwrap_or(0);
    let advisories = history["advisories"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let trust = if publisher.is_some_and(|name| !name.is_empty()) && !advisories.is_empty() {
        if flagged(&advisory_severities(&advisories)) {
            "flagged"
        } else {
            "known-good"
        }
    } else {
        "unknown"
    };
    json!({
        "first_seen_at": text(item, "first_seen_at"),
        "last_seen_at": text(item, "last_seen_at"),
        "prior_approvals": count_of(&APPROVAL_DECISIONS),
        "prior_incidents": incidents,
        "prior_blocks": count_of(&BLOCK_DECISIONS),
        "publisher_trust": trust,
    })
}

/// `ProvenanceBundle` for a publisher (`null` means no publisher at all).
pub(crate) fn provenance_bundle(publisher: Option<&str>, advisories: &[Value]) -> Value {
    let Some(publisher) = publisher else {
        return json!({
            "source_kind": "none",
            "publisher_trust": "unknown",
            "signature_verified": false,
            "attestation_verified": false,
            "evidence_refs": [],
        });
    };
    if advisories.is_empty() {
        return json!({
            "source_kind": "self-declared",
            "publisher_trust": "unknown",
            "signature_verified": false,
            "attestation_verified": false,
            "evidence_refs": [format!("publisher:{publisher}")],
        });
    }
    let any_true = |key: &str| {
        advisories
            .iter()
            .any(|item| item.get(key) == Some(&Value::Bool(true)))
    };
    let references: BTreeSet<&str> = advisories
        .iter()
        .filter_map(|item| text(item, "advisory_id"))
        .filter(|id| !id.is_empty())
        .collect();
    let refs: Vec<String> = if references.is_empty() {
        vec![format!("publisher:{publisher}")]
    } else {
        references.into_iter().map(str::to_owned).collect()
    };
    json!({
        "source_kind": "curated",
        "publisher_trust": if flagged(&advisory_severities(advisories)) { "flagged" } else { "known-good" },
        "signature_verified": any_true("signature_verified"),
        "attestation_verified": any_true("attestation_verified"),
        "evidence_refs": refs,
    })
}

/// Evidence payload for one detected artifact.
pub(crate) fn artifact_evidence(query: &Value) -> Result<Value, &'static str> {
    let artifact = &query["artifact"];
    let current_hash =
        text(query, "current_hash").ok_or("native_consumer_artifact_project_request_invalid")?;
    let capabilities = normalize(&CapabilityArtifact::from_value(artifact)?);
    let deltas = capability_delta(&query["previous_capabilities"], &capabilities);
    let diff = diff(query, artifact, current_hash);
    let publisher = text(artifact, "publisher");
    let history = &query["history"];
    let advisories = history["advisories"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let provenance = provenance_bundle(publisher, &advisories);
    let history_context = history_context(history, publisher);
    let changed_capabilities: Vec<Value> = if deltas.is_empty() {
        diff.changed_fields
            .iter()
            .map(|field| json!(field))
            .collect()
    } else {
        deltas
            .iter()
            .map(|delta| delta["delta_type"].clone())
            .collect()
    };
    let scoring_deltas: Vec<Value> = deltas
        .iter()
        .map(|delta| {
            json!({
                "delta_type": delta["delta_type"],
                "severity": delta["severity"],
                "explanation": delta["explanation"],
            })
        })
        .collect();
    let mut payload = Map::new();
    payload.insert("changed".to_owned(), json!(diff.changed));
    payload.insert(
        "first_seen".to_owned(),
        json!(diff.changed_fields == ["first_seen"]),
    );
    payload.insert("diff_summary".to_owned(), diff_summary(&diff));
    payload.insert("changed_fields".to_owned(), json!(diff.changed_fields));
    payload.insert("previous_hash".to_owned(), json!(diff.previous_hash));
    payload.insert("current_hash".to_owned(), json!(current_hash));
    payload.insert(
        "capabilities_summary".to_owned(),
        json!(capabilities_summary(artifact)),
    );
    payload.insert(
        "changed_capabilities".to_owned(),
        json!(changed_capabilities),
    );
    payload.insert(
        "provenance_summary".to_owned(),
        json!(format!(
            "{} artifact defined at {} (provenance: {})",
            text(artifact, "source_scope").unwrap_or("None"),
            text(artifact, "config_path").unwrap_or("None"),
            provenance["source_kind"].as_str().unwrap_or("none"),
        )),
    );
    payload.insert(
        "scoring".to_owned(),
        json!({
            "deltas": scoring_deltas,
            "provenance_source_kind": provenance["source_kind"],
            "publisher_trust": provenance["publisher_trust"],
            "prior_approvals": history_context["prior_approvals"],
            "prior_incidents": history_context["prior_incidents"],
        }),
    );
    payload.insert("capability_snapshot".to_owned(), capabilities);
    payload.insert("capability_delta".to_owned(), Value::Array(deltas));
    payload.insert("history_context".to_owned(), history_context);
    payload.insert("provenance".to_owned(), provenance);
    Ok(Value::Object(payload))
}

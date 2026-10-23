//! Pure audit of already-retained Python v1 controller invocation bytes.
//!
//! The caller must independently establish private file custody and the
//! frozen campaign/ledger. This reducer does not read a live controller,
//! attest provider bytes or grant benchmark eligibility.

use crate::crypto::{is_sha256, sha256};
use crate::payload::exact_keys;
use crate::provider_status::verify_provider_status;
use crate::{EvidenceError, Result};
use gauntlet_contracts::{canonicalize, MAX_RECORD_BYTES};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

const FILES: [&str; 4] = [
    "preflight.json",
    "provider-before.json",
    "provider-after.json",
    "controller-result.json",
];

fn invalid(message: &'static str) -> EvidenceError {
    EvidenceError::Invalid(message)
}

fn parse(raw: &[u8]) -> Result<Value> {
    if raw.len() > MAX_RECORD_BYTES {
        return Err(invalid("controller invocation file exceeds byte bound"));
    }
    let canonical = canonicalize(raw).map_err(|_| invalid("invalid controller invocation JSON"))?;
    serde_json::from_slice(&canonical).map_err(|_| invalid("invalid controller invocation JSON"))
}

fn required<'a>(files: &'a BTreeMap<String, Vec<u8>>, name: &str) -> Result<&'a [u8]> {
    files.get(name).map(Vec::as_slice).ok_or(invalid(
        if matches!(name, "result.json" | "preflight.json") {
            "public input must be a bounded ordinary file"
        } else {
            "pinned file must be ordinary, not a symlink"
        },
    ))
}

fn whole_nonnegative(value: &Value) -> Option<u64> {
    value.as_u64()
}

/// A frozen invocation directory represented as independently read raw bytes.
/// The record name is diagnostic only and never supplies paths or trust pins.
#[derive(Debug)]
pub struct ControllerInvocationBytes {
    pub name: String,
    pub files: BTreeMap<String, Vec<u8>>,
}

/// Match Python `audit_invocations` accounting over immutable input bytes.
/// `None` means the entire `controller-attempts` directory was absent.
pub fn audit_controller_invocations(
    records: Option<&[ControllerInvocationBytes]>,
    expected_config_digest: &str,
    expected_manifest_digest: &str,
    provider_pins: &Value,
    shard_count: usize,
    charged_tokens: u64,
) -> Result<Value> {
    if !is_sha256(expected_config_digest)
        || !is_sha256(expected_manifest_digest)
        || shard_count == 0
        || shard_count > 10_000
    {
        return Err(invalid("outside controller invocation pins required"));
    }
    let Some(records) = records else {
        return Ok(json!({
            "errors": if charged_tokens == 0 { Vec::<&str>::new() } else { vec!["provider-witnesses-missing"] },
            "provider_tokens_delta":0,
            "qualification_eligible":false,
        }));
    };
    if records.len() > 10_000 {
        return Err(invalid("controller invocation count exceeds bound"));
    }
    let mut total = 0_u64;
    let mut errors = Vec::new();
    let mut names = BTreeSet::new();
    for record in records {
        if record.name.is_empty()
            || record.name.len() > 128
            || record.files.len() > 16
            || !names.insert(&record.name)
        {
            return Err(invalid("invalid controller invocation inventory"));
        }
        let row = parse(required(&record.files, "result.json")?)?;
        let diagnosis = parse(required(&record.files, "preflight.json")?)?;
        if diagnosis["config_digest"] != expected_config_digest {
            return Err(invalid(
                "invocation preflight belongs to another runner configuration",
            ));
        }
        if row["status"] == "preflight-failed" {
            if diagnosis["passed"] != false {
                return Err(invalid("failed invocation changed its preflight outcome"));
            }
            errors.push("retained-controller-preflight-failure");
            continue;
        }
        let file_pins = &row["files"];
        if row["runner_config_digest"] != expected_config_digest
            || row["manifest_digest"] != expected_manifest_digest
            || diagnosis["passed"] != true
            || row["shard"]
                .as_u64()
                .is_none_or(|index| index >= shard_count as u64)
            || !exact_keys(file_pins, &FILES)
        {
            return Err(invalid(
                "invocation inputs or retained provider evidence changed",
            ));
        }
        for name in FILES {
            let raw = required(&record.files, name)?;
            let actual = sha256(raw);
            if file_pins[name].as_str() != Some(actual.as_str()) {
                return Err(invalid(
                    "invocation inputs or retained provider evidence changed",
                ));
            }
        }
        let before = parse(required(&record.files, "provider-before.json")?)?;
        let after = parse(required(&record.files, "provider-after.json")?)?;
        let before = verify_provider_status(&before["status"], provider_pins)?;
        let after = verify_provider_status(&after["status"], provider_pins)?;
        let before_known = before["known_tokens"]
            .as_u64()
            .expect("verified quota integer");
        let after_known = after["known_tokens"]
            .as_u64()
            .expect("verified quota integer");
        let observed = after_known.checked_sub(before_known).ok_or(invalid(
            "invocation provider counter and ledger charges differ",
        ))?;
        let old = whole_nonnegative(&row["ledger_charge_before"]);
        let new = whole_nonnegative(&row["ledger_charge_after"]);
        if row["provider_tokens_delta"].as_u64() != Some(observed)
            || old.is_none()
            || new.and_then(|value| value.checked_sub(old.expect("checked old charge")))
                != Some(observed)
        {
            return Err(invalid(
                "invocation provider counter and ledger charges differ",
            ));
        }
        total = total
            .checked_add(observed)
            .ok_or(invalid("aggregate provider delta exceeds integer bound"))?;
    }
    if total != charged_tokens {
        errors.push("aggregate-provider-and-ledger-cost-mismatch");
    }
    Ok(json!({
        "errors":errors,
        "provider_tokens_delta":total,
        "qualification_eligible":false,
    }))
}

#[cfg(test)]
#[path = "controller_invocations_tests.rs"]
mod tests;

//! Data-only relations in Python's deterministic `cancel` branch. Product,
//! private-cell, Native review and kernel observations remain separate.

use crate::control_opening::verify_control_session_opening;
use crate::{EvidenceError, Result};
use gauntlet_contracts::canonicalize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const INVALID: EvidenceError = EvidenceError::Invalid("invalid cancellation record");
const SETUP: EvidenceError = EvidenceError::Invalid("cancel setup failed");
const CAPTURE: EvidenceError = EvidenceError::Invalid("one real interrupted capture required");
const SAMPLES: EvidenceError =
    EvidenceError::Invalid("interrupted sink requires bounded nonempty outside samples");
const DUPLICATE: EvidenceError =
    EvidenceError::Invalid("interrupted sink repeats outside process samples");
const COMMAND: EvidenceError = EvidenceError::Invalid(
    "interrupted capture must be the actual installed Native contained sink",
);
const COMMAND_SAMPLE: EvidenceError =
    EvidenceError::Invalid("interrupted sink lacks outside command sampling");
const POST: EvidenceError =
    EvidenceError::Invalid("cancelled sink became complete or lost missing Post");
const PARTIAL: EvidenceError =
    EvidenceError::Invalid("active cancellation/descendant/partial evidence incomplete");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelReportedRelation {
    pub sample_count: usize,
    /// Reported relations are never independently authenticated effects.
    pub execution_eligible: bool,
}

fn exact_true(record: &Value, name: &str) -> bool {
    record.get(name) == Some(&Value::Bool(true))
}

fn exact_false(record: &Value, name: &str) -> bool {
    record.get(name) == Some(&Value::Bool(false))
}

/// Match Python `_cancel`'s non-I/O relations after the signed control/session
/// opening. `outside_review_summary` must eventually come from independently
/// recomputed transport observations, never the builtin producer field. This
/// function does not call the product/private-cell/kernel validators that the
/// Python branch invokes and cannot grant a deterministic pass.
pub fn verify_cancel_reported_relation(
    raw_control: &[u8],
    outside_public_key: &[u8],
    outside_expected: &Value,
    outside_review_summary: &Value,
) -> Result<CancelReportedRelation> {
    let session = verify_control_session_opening(
        raw_control,
        "cancel",
        outside_public_key,
        outside_expected,
    )?;
    let canonical = canonicalize(raw_control).map_err(|_| INVALID)?;
    let control: Value = serde_json::from_slice(&canonical).map_err(|_| INVALID)?;
    let runtime = &session.signed.runtime;
    let builtin = &session.signed.builtin;
    let plane = &session.signed.plane;

    if runtime["errors"]
        .as_array()
        .is_none_or(|errors| !errors.is_empty())
        || !exact_true(runtime, "prompt_allowed")
    {
        return Err(SETUP);
    }
    let observations = plane["observations"].as_array().ok_or(CAPTURE)?;
    let failures: Vec<&Value> = observations
        .iter()
        .filter(|row| row["kind"] == "actual-native-capture-failure")
        .collect();
    if failures.len() != 1 || failures[0]["exception_type"] != "InterruptedError" {
        return Err(CAPTURE);
    }
    let failure = failures[0];
    let samples = failure["kernel_process_samples"]
        .as_array()
        .ok_or(SAMPLES)?;
    if samples.is_empty() || samples.len() > 1000 {
        return Err(SAMPLES);
    }
    let mut identities = BTreeSet::new();
    for sample in samples {
        let pid = sample["pid"].as_u64().ok_or(DUPLICATE)?;
        let start = sample["identity"]["start_time"].as_str().ok_or(DUPLICATE)?;
        let command_sha = sample["command_sha256"].as_str().ok_or(DUPLICATE)?;
        identities.insert((pid, start.to_owned(), command_sha.to_owned()));
    }
    if identities.len() != samples.len() {
        return Err(DUPLICATE);
    }
    let command = failure["command"].as_array().ok_or(COMMAND)?;
    let prefix = plane["runtime_prefix"].as_str().ok_or(COMMAND)?;
    let expected = [
        format!("{prefix}/bin/python"),
        "-I".to_owned(),
        "-B".to_owned(),
        "-m".to_owned(),
        "codex_plugin_scanner.cli".to_owned(),
        "guard".to_owned(),
        "execute-contained-test".to_owned(),
    ];
    if command.len() < expected.len()
        || !command
            .iter()
            .take(expected.len())
            .zip(&expected)
            .all(|(actual, expected)| actual.as_str() == Some(expected))
    {
        return Err(COMMAND);
    }
    let mut hash = Sha256::new();
    for argument in command {
        hash.update(argument.as_str().ok_or(COMMAND)?.as_bytes());
        hash.update([0]);
    }
    let command_hash = format!("{:x}", hash.finalize());
    if !samples
        .iter()
        .any(|row| row["command_sha256"] == command_hash)
    {
        return Err(COMMAND_SAMPLE);
    }
    if builtin["review_summary"] != *outside_review_summary
        || outside_review_summary["missing_required_post_call_ids"]
            != serde_json::json!(["sdk-contained-control"])
        || plane["executions"]
            .as_array()
            .is_none_or(|rows| !rows.is_empty())
    {
        return Err(POST);
    }
    if !exact_true(failure, "cell_closed")
        || !exact_true(&control, "cell_closed_before_explicit_teardown")
        || !exact_false(&control, "detached_child_alive_before_cell_teardown")
        || !exact_false(&control, "late_effect_present")
        || control["detached_child_samples"]
            .as_array()
            .is_none_or(|rows| rows.is_empty())
    {
        return Err(PARTIAL);
    }
    Ok(CancelReportedRelation {
        sample_count: samples.len(),
        execution_eligible: false,
    })
}

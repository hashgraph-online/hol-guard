//! Inert consistency reader for the pinned Python VM worker's terminal JSON.
//!
//! The caller must separately establish Root-owned file custody, source pins
//! and report provenance. A consistent producer report is not a gate verdict.

use crate::crypto::{is_sha256, sha256};
use crate::payload::exact_keys;
use crate::{EvidenceError, Result};
use gauntlet_contracts::{canonicalize, is_git_sha};
use serde_json::Value;

const MAX_RECEIPT_BYTES: usize = 1024 * 1024;
const MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonWorkerTerminal {
    pub source_sha: String,
    pub job_id: String,
    pub deployment_digest: String,
    pub status: String,
    pub exit_code: i32,
    pub report_sha256: Option<String>,
    pub report_consistent: bool,
    pub execution_eligible: bool,
}

fn lowercase_hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn bounded_json(raw: &[u8], limit: usize) -> Result<Value> {
    if raw.len() > limit {
        return Err(EvidenceError::Invalid("worker record exceeds byte limit"));
    }
    let canonical =
        canonicalize(raw).map_err(|_| EvidenceError::Invalid("invalid worker record JSON"))?;
    serde_json::from_slice(&canonical)
        .map_err(|_| EvidenceError::Invalid("invalid worker record JSON"))
}

/// Compare a Python `vm_worker.py` terminal receipt and optional report bytes
/// with independent source/job/deployment/config pins. This does not read the
/// VM filesystem, authenticate the worker or recompute the six control gates.
pub fn verify_python_worker_terminal(
    receipt_raw: &[u8],
    report_raw: Option<&[u8]>,
    expected_source_sha: &str,
    expected_job_id: &str,
    expected_deployment_digest: &str,
    expected_config_digest: &str,
) -> Result<PythonWorkerTerminal> {
    if !is_git_sha(expected_source_sha)
        || !lowercase_hex(expected_job_id, 16)
        || !is_sha256(expected_deployment_digest)
        || !is_sha256(expected_config_digest)
    {
        return Err(EvidenceError::Invalid("invalid independent worker pins"));
    }
    let receipt = bounded_json(receipt_raw, MAX_RECEIPT_BYTES)?;
    let base = [
        "source_sha",
        "job_id",
        "deployment_digest",
        "exit_code",
        "report_path",
        "status",
        "model_tokens",
    ];
    let with_report = [
        "source_sha",
        "job_id",
        "deployment_digest",
        "exit_code",
        "report_path",
        "status",
        "model_tokens",
        "cells",
        "elapsed_seconds",
        "report_sha256",
    ];
    if !exact_keys(
        &receipt,
        if report_raw.is_some() {
            &with_report
        } else {
            &base
        },
    ) {
        return Err(EvidenceError::Invalid("invalid terminal receipt fields"));
    }
    let expected_report_path = format!("/var/lib/hol-gauntlet/outputs/{expected_job_id}/report");
    if receipt["source_sha"] != expected_source_sha
        || receipt["job_id"] != expected_job_id
        || receipt["deployment_digest"] != expected_deployment_digest
        || receipt["report_path"] != expected_report_path
        || receipt["model_tokens"].as_u64() != Some(0)
    {
        return Err(EvidenceError::Invalid(
            "worker terminal identity differs from pins",
        ));
    }
    let exit_code = receipt["exit_code"]
        .as_i64()
        .and_then(|code| i32::try_from(code).ok())
        .filter(|code| (-128..=255).contains(code))
        .ok_or(EvidenceError::Invalid("invalid worker exit code"))?;
    let status = receipt["status"]
        .as_str()
        .filter(|status| matches!(*status, "passed" | "failed" | "invalid-evidence"))
        .ok_or(EvidenceError::Invalid("invalid worker terminal status"))?;
    if status == "passed" && exit_code != 0 {
        return Err(EvidenceError::Invalid(
            "successful worker status disagrees with exit",
        ));
    }
    let report_sha256 = if let Some(raw) = report_raw {
        let digest = receipt["report_sha256"]
            .as_str()
            .filter(|digest| is_sha256(digest))
            .ok_or(EvidenceError::Invalid("missing terminal report digest"))?;
        if sha256(raw) != digest {
            return Err(EvidenceError::Invalid(
                "terminal report bytes differ from receipt",
            ));
        }
        let report = bounded_json(raw, MAX_REPORT_BYTES)?;
        if report["schema"] != "gauntlet-ci-check.v1"
            || report["expected_guard_source_sha"] != expected_source_sha
            || report["guard_source_sha"] != expected_source_sha
            || report["runner_config_digest"] != expected_config_digest
            || report["exit_code"] != exit_code
            || report["profile"] != "deterministic"
            || report["model_tokens"].as_u64() != Some(0)
            || report["model_usage_known"] != true
            || report["status"] != status
            || receipt["cells"]
                != report
                    .get("cells")
                    .cloned()
                    .unwrap_or_else(|| Value::Array(vec![]))
            || receipt["elapsed_seconds"]
                != report
                    .get("elapsed_seconds")
                    .cloned()
                    .unwrap_or(Value::Null)
        {
            return Err(EvidenceError::Invalid(
                "terminal report disagrees with worker receipt",
            ));
        }
        Some(digest.to_owned())
    } else {
        if status != "invalid-evidence" {
            return Err(EvidenceError::Invalid(
                "terminal report missing for claimed outcome",
            ));
        }
        None
    };
    Ok(PythonWorkerTerminal {
        source_sha: expected_source_sha.to_owned(),
        job_id: expected_job_id.to_owned(),
        deployment_digest: expected_deployment_digest.to_owned(),
        status: status.to_owned(),
        exit_code,
        report_sha256,
        report_consistent: report_raw.is_some(),
        execution_eligible: false,
    })
}

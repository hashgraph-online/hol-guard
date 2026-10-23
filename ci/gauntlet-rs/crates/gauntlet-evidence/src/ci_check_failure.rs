//! The fixed pre-execution failure shape of Python `ci check`.
//!
//! This is a source-pinned projection only. It does not load a runner config,
//! execute a cell, audit a receipt or grant eligibility.

use crate::{EvidenceError, Result};
use serde_json::{json, Value};

const DETERMINISTIC: [&str; 6] = [
    "success",
    "input-binding",
    "injection",
    "boundary",
    "timeout",
    "cancel",
];

const BETA_E2E: [&str; 12] = [
    "episode-4a5e622e82731975dfe5a24aab0b68c7",
    "episode-ef5c7100cd4b03e7ab77006dbf2882f6",
    "episode-268cfea4db77a374ad61adf61c6eade8",
    "episode-588b50bb8c55ad5dc15e966a126ed1b7",
    "episode-f0e95df4f66d7712513960603baf4cc9",
    "episode-44ddf70edd007ea09a0f3f545f443476",
    "episode-4f9d1c2da05d460a1e0dbbf73d9b9a01",
    "episode-b8f701fd1468561bbd8699b9cc582fc2",
    "episode-a82f7a2e89415f8391c11557c6bebd06",
    "episode-55f480945fb89f2700071a2a1ee0f87e",
    "episode-5e746ec9a4e4d6dc7f25d6b810740122",
    "episode-f8b65231c455a4b4675bf6388e037f6c",
];

const FEATURE_AI: [&str; 2] = [
    "episode-a9344653386e0c30b3bd63437f283047",
    "episode-406531b0394f2bfaba126c5ec3ddfadb",
];

#[derive(Debug)]
pub struct CiCheckFailureProjection {
    python_result: Value,
}

impl CiCheckFailureProjection {
    pub fn python_result(&self) -> &Value {
        &self.python_result
    }

    pub const fn execution_eligible(&self) -> bool {
        false
    }
}

/// Reproduce Python's `failed(profile, reason, code)` for its two actual
/// pre-execution failure codes, with the fixed declared case IDs. The result
/// is only a failure-report projection; it never proves execution.
pub fn project_ci_check_failure_ineligible(
    profile: &str,
    reason: &str,
    code: i32,
) -> Result<CiCheckFailureProjection> {
    if reason.is_empty() || reason.len() > 4096 {
        return Err(EvidenceError::Invalid("invalid CI check failure reason"));
    }
    if !matches!(code, 2 | 130) {
        return Err(EvidenceError::Invalid("unsupported CI check failure exit"));
    }
    let ids: &[&str] = match profile {
        "deterministic" => &DETERMINISTIC,
        "beta-e2e" => &BETA_E2E,
        "feature-ai" | "feature-ai-protocol" => &FEATURE_AI,
        _ => return Err(EvidenceError::Invalid("unsupported CI check profile")),
    };
    let cells: Vec<Value> = ids
        .iter()
        .map(|id| json!({"episode_id": id, "status": "failed", "reasons": [reason]}))
        .collect();
    Ok(CiCheckFailureProjection {
        python_result: json!({
            "status": if code == 130 { "interrupted" } else { "invalid-evidence" },
            "exit_code": code,
            "selected_cases": ids.len(),
            "cells": cells,
            "errors": [reason],
        }),
    })
}

//! Caller-pinned gate policy bindings over an already verified selection.

use crate::{load_record, Record, RecordError};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[derive(Debug)]
pub enum GatePolicyError {
    Record(RecordError),
    DuplicateEpisode,
    InexactCoverage,
    UnsafeOutcome,
    UnsupportedSurface,
}

impl fmt::Display for GatePolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Record(error) => return write!(f, "{error}"),
            Self::DuplicateEpisode => "duplicate policy or selected episode ID",
            Self::InexactCoverage => "policy must cover exactly the frozen selected cells",
            Self::UnsafeOutcome => "policy outcome does not match its frozen cell condition",
            Self::UnsupportedSurface => "unprotected cells cannot claim native surfaces",
        };
        f.write_str(message)
    }
}

impl std::error::Error for GatePolicyError {}

impl From<RecordError> for GatePolicyError {
    fn from(error: RecordError) -> Self {
        Self::Record(error)
    }
}

/// Validate Python `validate_policy` and `_policy_bindings` on inert records.
/// The caller must separately authenticate the policy bytes, campaign, and
/// selected inventory; this function does not turn a policy into authority.
pub fn bind_gate_policy(raw: &[u8], selected: &[Value]) -> Result<Record, GatePolicyError> {
    let policy = load_record("ci-gate-policy", raw)?;
    let rows = policy.value()["cells"]
        .as_array()
        .expect("pinned policy schema requires cells");
    let mut rules = BTreeMap::new();
    for row in rows {
        let id = row["episode_id"]
            .as_str()
            .expect("pinned policy schema requires episode ID");
        if rules.insert(id, row).is_some() {
            return Err(GatePolicyError::DuplicateEpisode);
        }
    }
    let mut ids = BTreeSet::new();
    for cell in selected {
        let id = cell["id"]
            .as_str()
            .ok_or(GatePolicyError::InexactCoverage)?;
        if !ids.insert(id) {
            return Err(GatePolicyError::DuplicateEpisode);
        }
    }
    if ids != rules.keys().copied().collect() {
        return Err(GatePolicyError::InexactCoverage);
    }
    for cell in selected {
        let id = cell["id"].as_str().expect("selection IDs checked");
        let rule = rules[id];
        let protected = cell["protected"]
            .as_bool()
            .ok_or(GatePolicyError::UnsafeOutcome)?;
        let group = cell["group"]
            .as_str()
            .ok_or(GatePolicyError::UnsafeOutcome)?;
        let condition = cell["condition"]
            .as_str()
            .ok_or(GatePolicyError::UnsafeOutcome)?;
        match rule["outcome"].as_str().expect("policy schema checked") {
            "attacked-baseline-measurement" if protected || condition != "attacked-unprotected" => {
                return Err(GatePolicyError::UnsafeOutcome)
            }
            "authorized-approval" if group != "approval" => {
                return Err(GatePolicyError::UnsafeOutcome)
            }
            "secure-completion" if group == "approval" => {
                return Err(GatePolicyError::UnsafeOutcome)
            }
            _ => {}
        }
        if !protected
            && !rule["required_surfaces"]
                .as_array()
                .expect("policy schema checked")
                .is_empty()
        {
            return Err(GatePolicyError::UnsupportedSurface);
        }
    }
    Ok(policy)
}

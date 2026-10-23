//! Data-only parity with the pinned Python local-model startup admission.
//! Hashes, quota snapshot and port observation require independent custody.

use serde_json::{json, Value};
use std::fmt;

pub(crate) const TEMPLATE_SHA: &str =
    "f95dde32317bb5a2c09a2295c51524126c8c81ee4c16618a1b2a27ccfa8c8244";
pub(crate) const ALLOWANCE_SHA: &str =
    "269508fcb01074d6bb07ef20505e90bc863fc85fca65a3a930ab93a8c23e2b28";
pub(crate) const CANDIDATE_SOURCE: &str = "c1d18f931eaba02a37a2c9515db769fc2219bee8";
const ALLOWANCE_START: u64 = 9_468_885;
const CEILING: u64 = 14_468_885;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveProviderPreflightError {
    JobIdentity,
    CandidateSource,
    Profile,
    Template,
    AllowanceDigest,
    AllowanceRecord,
    Quota,
    PortBusy,
}

impl fmt::Display for LiveProviderPreflightError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::JobIdentity => "fixed live job identity required",
            Self::CandidateSource => "candidate source identity differs from local model allowance",
            Self::Profile => "reviewed live profile required",
            Self::Template => "reviewed provider template changed",
            Self::AllowanceDigest => "local model allowance authorization changed",
            Self::AllowanceRecord => {
                "local model allowance authorization differs from this candidate"
            }
            Self::Quota => "complete selected matrix reservation does not fit settled quota",
            Self::PortBusy => "port 8002 already has a service",
        })
    }
}

impl std::error::Error for LiveProviderPreflightError {}

fn number(value: &Value, name: &str) -> Option<u64> {
    value.get(name).and_then(Value::as_u64)
}

/// Mirror Python's branch before it creates a provider directory. This does
/// not inspect files, open the quota lock, test the actual port or launch MLX.
pub fn evaluate_live_provider_preflight(
    input: &Value,
) -> Result<Value, LiveProviderPreflightError> {
    let job_id = input
        .get("job_id")
        .and_then(Value::as_str)
        .ok_or(LiveProviderPreflightError::JobIdentity)?;
    if job_id.len() != 16
        || !job_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(LiveProviderPreflightError::JobIdentity);
    }
    if input
        .get("requested_candidate_source_sha")
        .and_then(Value::as_str)
        != Some(CANDIDATE_SOURCE)
    {
        return Err(LiveProviderPreflightError::CandidateSource);
    }
    let reservation = match input.get("profile").and_then(Value::as_str) {
        Some("beta-e2e") => 1_200_000_u64,
        Some("feature-ai" | "feature-ai-protocol") => 200_000_u64,
        _ => return Err(LiveProviderPreflightError::Profile),
    };
    if input.get("template_sha").and_then(Value::as_str) != Some(TEMPLATE_SHA) {
        return Err(LiveProviderPreflightError::Template);
    }
    if input.get("allowance_sha").and_then(Value::as_str) != Some(ALLOWANCE_SHA) {
        return Err(LiveProviderPreflightError::AllowanceDigest);
    }
    let allowance = input.get("allowance").unwrap_or(&Value::Null);
    if allowance.get("schema").and_then(Value::as_str)
        != Some("gauntlet-local-allowance-authorization.v1")
        || number(allowance, "previous_charged_tokens") != Some(ALLOWANCE_START)
        || number(allowance, "additional_tokens") != Some(5_000_000)
        || number(allowance, "total_tokens") != Some(CEILING)
        || allowance
            .get("candidate_source_sha")
            .and_then(Value::as_str)
            != Some(CANDIDATE_SOURCE)
    {
        return Err(LiveProviderPreflightError::AllowanceRecord);
    }
    let quota = input.get("quota").unwrap_or(&Value::Null);
    let known = number(quota, "known_tokens").ok_or(LiveProviderPreflightError::Quota)?;
    let charged = number(quota, "charged_tokens").ok_or(LiveProviderPreflightError::Quota)?;
    let settled = known == charged
        && quota.get("halted").and_then(Value::as_bool) == Some(false)
        && number(quota, "pending_requests") == Some(0)
        && number(quota, "reserved_tokens") == Some(0)
        && number(quota, "token_cap") == Some(CEILING)
        && known
            .checked_add(reservation)
            .is_some_and(|sum| sum <= CEILING)
        && known >= ALLOWANCE_START;
    if !settled {
        return Err(LiveProviderPreflightError::Quota);
    }
    match input.get("port_busy").and_then(Value::as_bool) {
        Some(false) => {}
        _ => return Err(LiveProviderPreflightError::PortBusy),
    }
    Ok(json!({"reservation":reservation,"known_tokens_before":known}))
}

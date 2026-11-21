//! Inert source claims checked against caller-owned candidate and base pins.

use serde_json::Value;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    InvalidPin,
    DirtyOrUnrecorded,
    SourceMismatch,
    InvalidTestMerge,
    StaleBase,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidPin => "caller source pin must be a full lowercase Git SHA",
            Self::DirtyOrUnrecorded => "tested source tree is dirty or dirtiness is unrecorded",
            Self::SourceMismatch => "source, installed build and candidate binding disagree",
            Self::InvalidTestMerge => "tested source is not an exact candidate test merge",
            Self::StaleBase => "test-merge base is stale or inconsistent",
        };
        f.write_str(message)
    }
}

impl std::error::Error for IdentityError {}

pub fn is_git_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Validate an untrusted source report against independent caller pins.
///
/// This matches `ci/gauntlet/source_identity.py::validate_identity` at the
/// pinned Gauntlet revision. The caller must obtain `expected_sha` and the
/// optional base from a trusted channel; the report cannot pin itself.
pub fn validate_source_identity(
    report: &Value,
    expected_sha: &str,
    expected_base_sha: Option<&str>,
) -> Result<(), IdentityError> {
    if !is_git_sha(expected_sha) || expected_base_sha.is_some_and(|sha| !is_git_sha(sha)) {
        return Err(IdentityError::InvalidPin);
    }
    if report.get("source_dirty") != Some(&Value::Bool(false)) {
        return Err(IdentityError::DirtyOrUnrecorded);
    }
    let source = report
        .get("tested_source_sha")
        .and_then(Value::as_str)
        .filter(|sha| is_git_sha(sha))
        .ok_or(IdentityError::SourceMismatch)?;
    let candidate = report
        .get("candidate_sha")
        .and_then(Value::as_str)
        .ok_or(IdentityError::SourceMismatch)?;
    let parents = report
        .get("source_parents")
        .and_then(Value::as_array)
        .ok_or(IdentityError::SourceMismatch)?;
    if candidate != expected_sha
        || report.get("installed_source_sha").and_then(Value::as_str) != Some(source)
        || parents
            .iter()
            .any(|parent| parent.as_str().is_none_or(|sha| !is_git_sha(sha)))
    {
        return Err(IdentityError::SourceMismatch);
    }
    if source != candidate {
        if parents.len() != 2 || !parents.iter().any(|parent| parent == candidate) {
            return Err(IdentityError::InvalidTestMerge);
        }
        let base = parents
            .iter()
            .find_map(|parent| parent.as_str().filter(|sha| *sha != candidate))
            .ok_or(IdentityError::StaleBase)?;
        if report.get("tested_base_sha").and_then(Value::as_str) != Some(base)
            || expected_base_sha.is_some_and(|sha| sha != base)
        {
            return Err(IdentityError::StaleBase);
        }
    } else if report
        .get("tested_base_sha")
        .is_some_and(|base| !base.is_null())
    {
        return Err(IdentityError::StaleBase);
    }
    Ok(())
}

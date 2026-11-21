//! `runtime/command_activity_lifecycle.build_policy_only_pre_hook_evidence`
//! and the evidence writer's [`CorrelationApi`] seam.
//!
//! The writer records a final hook action without inventing rule evaluation:
//! a policy-only activity names the action Guard took, carries no matches and
//! claims no parse confidence. Everything the contract rejects in Python —
//! an unknown harness, a non-canonical action, an accepted approval reuse
//! that also claims a prompt, a receipt link that disagrees with its receipt —
//! is rejected here, before the row reaches the store.
//!
//! The seam lives in `guard-runtime` because its harness membership check
//! needs the resident's registry and its correlation methods need the keyed
//! derivation in [`crate::hook_evidence_correlation`]; the display text it
//! delegates to `guard-command`, which owns the redaction passes.

use std::io;
use std::path::PathBuf;

use guard_command::hook_evidence_writer::{
    build_invocation_preview_from_payload, CorrelationApi, CorrelationHandle,
    InstallationCorrelationKey,
};
use guard_contracts::GuardAction;
use serde_json::{Map, Value};

use crate::guard_config_harness::canonical_harness_id;
use crate::guard_config_iso::is_valid_iso_datetime;
use crate::hook_evidence_correlation::{
    derive_proven_request_correlation, load_or_create_correlation_key,
};

/// `COMMAND_ACTIVITY_SCHEMA_VERSION` (`command_activity_contract.py:18`).
const SCHEMA_VERSION: &str = "1.0.0";
/// `ActivityApprovalReuseStatus` values.
const APPROVAL_REUSE_STATUSES: [&str; 3] = ["accepted", "rejected", "not-applicable"];
const NOT_APPLICABLE: &str = "not-applicable";
/// `ReceiptLinkStatus.NOT_APPLICABLE` — spelled with an underscore, unlike the
/// approval-reuse value above. The wire reader rebuilds the enum from this
/// string, so the two cannot share one constant.
const RECEIPT_NOT_APPLICABLE: &str = "not_applicable";

/// The writer's correlation seam, bound to one installation's Guard home.
pub(crate) struct NativeCorrelation {
    guard_home: PathBuf,
}

impl NativeCorrelation {
    pub(crate) fn new(guard_home: PathBuf) -> Self {
        Self { guard_home }
    }
}

impl CorrelationApi for NativeCorrelation {
    fn load_or_create_installation_correlation_key(
        &self,
    ) -> Result<Option<InstallationCorrelationKey>, io::Error> {
        load_or_create_correlation_key(&self.guard_home).map(Some)
    }

    fn derive_proven_request_correlation(
        &self,
        harness: &str,
        event: &str,
        payload: &Map<String, Value>,
        key: &InstallationCorrelationKey,
    ) -> Result<Option<CorrelationHandle>, io::Error> {
        derive_proven_request_correlation(harness, event, payload, key)
    }

    fn build_invocation_preview_from_payload(
        &self,
        payload: &Map<String, Value>,
    ) -> Result<Option<String>, io::Error> {
        Ok(build_invocation_preview_from_payload(payload, None))
    }

    fn build_policy_only_pre_hook_evidence(
        &self,
        activity_id: &str,
        occurred_at: &str,
        harness: &str,
        policy_action: &str,
        request_correlation: Option<&CorrelationHandle>,
        receipt_id: Option<&str>,
        prompted: bool,
        approval_reuse_status: &str,
    ) -> Result<Map<String, Value>, io::Error> {
        policy_only_pre_hook_evidence(
            activity_id,
            occurred_at,
            harness,
            policy_action,
            request_correlation,
            receipt_id,
            prompted,
            approval_reuse_status,
        )
    }

    fn build_unpaired_post_evidence(
        &self,
        activity_id: &str,
        occurred_at: &str,
        harness: &str,
        succeeded: bool,
    ) -> Result<Map<String, Value>, io::Error> {
        unpaired_post_evidence(activity_id, occurred_at, harness, succeeded)
    }

    fn build_correlated_post_activity(
        &self,
        previous: &Map<String, Value>,
        request_correlation: &CorrelationHandle,
        succeeded: bool,
    ) -> Result<Map<String, Value>, io::Error> {
        correlated_post_activity(previous, request_correlation, succeeded)
    }
}

/// `build_policy_only_pre_hook_evidence` (`command_activity_lifecycle.py:88`)
/// serialized through `store_command_activity_wire.evidence_wire`.
///
/// The seam never claims a workflow authorization, so the reason code is
/// always `policy` and the parse confidence always absent — the two facts the
/// contract reads when it decides a match-free, receipt-free activity is
/// legitimate.
#[allow(clippy::too_many_arguments)]
pub(crate) fn policy_only_pre_hook_evidence(
    activity_id: &str,
    occurred_at: &str,
    harness: &str,
    policy_action: &str,
    request_correlation: Option<&CorrelationHandle>,
    receipt_id: Option<&str>,
    prompted: bool,
    approval_reuse_status: &str,
) -> Result<Map<String, Value>, io::Error> {
    require_opaque_id(activity_id, "activity_id")?;
    let occurred_at = require_utc_datetime(occurred_at)?;
    require_harness(harness)?;
    let severity = guard_action_severity(policy_action)?;
    if !APPROVAL_REUSE_STATUSES.contains(&approval_reuse_status) {
        return Err(invalid(
            "approval_reuse_status must be an exact ActivityApprovalReuseStatus value",
        ));
    }
    if prompted && approval_reuse_status == "accepted" {
        return Err(invalid("accepted approval reuse cannot claim a prompt"));
    }
    if let Some(receipt_id) = receipt_id {
        require_opaque_id(receipt_id, "receipt_id")?;
    }
    let request_correlation = match request_correlation {
        Some(handle) => Some(require_request_correlation(handle, harness)?),
        None => None,
    };

    let mut activity = Map::new();
    activity.insert("activity_id".into(), activity_id.into());
    activity.insert("occurred_at".into(), occurred_at.into());
    activity.insert("harness".into(), harness.into());
    activity.insert("hook_phase".into(), "pre".into());
    activity.insert(
        "execution_status".into(),
        if severity >= GuardAction::Review.severity() {
            "prevented".into()
        } else {
            "allowed_unconfirmed".into()
        },
    );
    activity.insert("proof_level".into(), "pre_hook".into());
    activity.insert("policy_action".into(), policy_action.into());
    activity.insert("decision_reason_code".into(), "policy".into());
    activity.insert("controlling_rule_id".into(), Value::Null);
    activity.insert("parse_confidence".into(), Value::Null);
    activity.insert("uncertainty_class".into(), Value::Null);
    activity.insert("match_count".into(), 0.into());
    activity.insert("prompted".into(), i32::from(prompted).into());
    activity.insert("approval_reuse_status".into(), approval_reuse_status.into());
    activity.insert(
        "receipt_link_status".into(),
        if receipt_id.is_some() {
            "linked".into()
        } else {
            RECEIPT_NOT_APPLICABLE.into()
        },
    );
    activity.insert(
        "receipt_id".into(),
        receipt_id.map_or(Value::Null, Value::from),
    );
    activity.insert("evaluation_latency_bucket".into(), "not_measured".into());
    activity.insert("persistence_latency_bucket".into(), "not_measured".into());
    activity.insert("schema_version".into(), SCHEMA_VERSION.into());
    activity.insert(
        "request_correlation".into(),
        request_correlation.unwrap_or(Value::Null),
    );
    activity.insert("session_correlation".into(), Value::Null);

    let mut evidence = Map::new();
    evidence.insert("activity".into(), Value::Object(activity));
    evidence.insert("matches".into(), Value::Array(Vec::new()));
    Ok(evidence)
}

/// `build_unpaired_post_evidence` (`command_activity_lifecycle.py:207`)
/// serialized through `store_command_activity_wire.evidence_wire`.
///
/// A post event that found no stored pre-hook row describes the outcome and
/// nothing else: no policy action, no rule, no correlation, no receipt. The
/// contract reads that emptiness as the proof level `unpaired_post`, so the
/// row can never be mistaken for a decision Guard made.
pub(crate) fn unpaired_post_evidence(
    activity_id: &str,
    occurred_at: &str,
    harness: &str,
    succeeded: bool,
) -> Result<Map<String, Value>, io::Error> {
    require_opaque_id(activity_id, "activity_id")?;
    let occurred_at = require_utc_datetime(occurred_at)?;
    require_harness(harness)?;

    let mut activity = Map::new();
    activity.insert("activity_id".into(), activity_id.into());
    activity.insert("occurred_at".into(), occurred_at.into());
    activity.insert("harness".into(), harness.into());
    activity.insert("hook_phase".into(), post_hook_phase(succeeded).into());
    activity.insert("execution_status".into(), "unpaired_post".into());
    activity.insert("proof_level".into(), "unpaired_post".into());
    activity.insert("policy_action".into(), Value::Null);
    activity.insert("decision_reason_code".into(), Value::Null);
    activity.insert("controlling_rule_id".into(), Value::Null);
    activity.insert("parse_confidence".into(), Value::Null);
    activity.insert("uncertainty_class".into(), Value::Null);
    activity.insert("match_count".into(), 0.into());
    activity.insert("prompted".into(), 0.into());
    activity.insert("approval_reuse_status".into(), NOT_APPLICABLE.into());
    activity.insert("receipt_link_status".into(), RECEIPT_NOT_APPLICABLE.into());
    activity.insert("receipt_id".into(), Value::Null);
    activity.insert("evaluation_latency_bucket".into(), "not_measured".into());
    activity.insert("persistence_latency_bucket".into(), "not_measured".into());
    activity.insert("schema_version".into(), SCHEMA_VERSION.into());
    activity.insert("request_correlation".into(), Value::Null);
    activity.insert("session_correlation".into(), Value::Null);

    let mut evidence = Map::new();
    evidence.insert("activity".into(), Value::Object(activity));
    evidence.insert("matches".into(), Value::Array(Vec::new()));
    Ok(evidence)
}

/// `build_correlated_post_activity` (`command_activity_lifecycle.py:183`)
/// over the `activity_wire` map the resident already exchanges.
///
/// Python promotes a frozen dataclass and compares two `CorrelationHandle`s
/// for equality, so every field of the handle has to agree with the stored
/// row's. The serialized handle carries those same four keys, which is why
/// the comparison here is a whole-value one rather than a digest check.
pub(crate) fn correlated_post_activity(
    previous: &Map<String, Value>,
    request_correlation: &CorrelationHandle,
    succeeded: bool,
) -> Result<Map<String, Value>, io::Error> {
    if previous.get("execution_status").and_then(Value::as_str) != Some("allowed_unconfirmed") {
        return Err(invalid(
            "only allowed-unconfirmed activity can receive post-hook proof",
        ));
    }
    let harness = previous
        .get("harness")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let expected = require_request_correlation(request_correlation, harness)?;
    if previous.get("request_correlation") != Some(&expected) {
        return Err(invalid(
            "post-hook proof requires the exact pre-hook request correlation",
        ));
    }

    let mut current = previous.clone();
    current.insert("hook_phase".into(), post_hook_phase(succeeded).into());
    current.insert(
        "execution_status".into(),
        if succeeded {
            "confirmed_success".into()
        } else {
            "confirmed_failure".into()
        },
    );
    current.insert("proof_level".into(), "post_hook".into());
    current.insert("persistence_latency_bucket".into(), "not_measured".into());
    Ok(current)
}

/// `CommandHookPhase.POST_SUCCESS if succeeded else POST_FAILURE`.
fn post_hook_phase(succeeded: bool) -> &'static str {
    if succeeded {
        "post_success"
    } else {
        "post_failure"
    }
}

/// `handle_wire` plus `_require_optional_correlation(…, REQUEST, harness)`.
fn require_request_correlation(
    handle: &CorrelationHandle,
    harness: &str,
) -> Result<Value, io::Error> {
    if handle.kind != "request" || handle.harness != harness {
        return Err(invalid(
            "correlation kind and harness must match the activity",
        ));
    }
    require_stable_id(&handle.key_id, "key_id")?;
    if handle.digest.len() != 64
        || !handle
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(invalid(
            "digest must be a 256-bit lowercase hexadecimal HMAC",
        ));
    }
    let mut wire = Map::new();
    wire.insert("kind".into(), handle.kind.as_str().into());
    wire.insert("harness".into(), handle.harness.as_str().into());
    wire.insert("key_id".into(), handle.key_id.as_str().into());
    wire.insert("digest".into(), handle.digest.as_str().into());
    Ok(Value::Object(wire))
}

/// `is_guard_action` plus `guard_action_severity` over the canonical lattice.
fn guard_action_severity(value: &str) -> Result<i32, io::Error> {
    GuardAction::LATTICE
        .iter()
        .find(|action| action.as_str() == value)
        .map(|action| action.severity())
        .ok_or_else(|| invalid("policy_action must be a canonical GuardAction"))
}

/// `_require_utc_datetime` over the serialized form the resident exchanges:
/// `datetime.isoformat()` of a UTC-aware value, so a `Z` designator
/// normalizes to the `+00:00` offset Python writes.
fn require_utc_datetime(value: &str) -> Result<String, io::Error> {
    let normalized = match value.strip_suffix('Z') {
        Some(head) => format!("{head}+00:00"),
        None => value.to_owned(),
    };
    if !normalized.ends_with("+00:00") || !is_valid_iso_datetime(&normalized) {
        return Err(invalid("occurred_at must be a timezone-aware UTC datetime"));
    }
    Ok(normalized)
}

/// `_require_stable_id(value, "harness")` — the registry membership half.
fn require_harness(value: &str) -> Result<(), io::Error> {
    require_stable_id(value, "harness")?;
    if canonical_harness_id(value) != Some(value) {
        return Err(invalid("harness must be a stable lowercase identifier"));
    }
    Ok(())
}

/// `_OPAQUE_ID` (`[A-Za-z0-9][A-Za-z0-9._:-]{0,255}`).
fn require_opaque_id(value: &str, label: &str) -> Result<(), io::Error> {
    let mut characters = value.chars();
    let valid = characters
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric())
        && value.chars().count() <= 256
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-')
        });
    if !valid {
        return Err(invalid(&format!(
            "{label} must be a bounded opaque identifier"
        )));
    }
    Ok(())
}

/// `_STABLE_ID` (`[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*`), bounded at 128.
fn require_stable_id(value: &str, label: &str) -> Result<(), io::Error> {
    let invalid_id = || invalid(&format!("{label} must be a stable lowercase identifier"));
    if value.len() > 128 || !value.starts_with(|first: char| first.is_ascii_lowercase()) {
        return Err(invalid_id());
    }
    let mut separated = false;
    for character in value.chars().skip(1) {
        match character {
            'a'..='z' | '0'..='9' => separated = false,
            '.' | '_' | '-' if !separated => separated = true,
            _ => return Err(invalid_id()),
        }
    }
    if separated {
        return Err(invalid_id());
    }
    Ok(())
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.to_owned())
}

#[cfg(test)]
#[path = "hook_evidence_activity_tests.rs"]
mod tests;

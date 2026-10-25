//! Native port of `runtime/protection_health.py` — the truthful protection state.
//!
//! The report answers "am I protected?" without inferring proof that was never
//! produced: a check with no signal is `unknown`, never a pass, and an unknown
//! check keeps the report out of `protected`. The only checks allowed to fail
//! without degrading the state are the four that a platform may not support at
//! all, and only when they fail for exactly that reason.
//!
//! `TruthfulState`, `ProtectionHealth` and `derive_protection_state` mirror
//! `runtime/effect_contract.py`, whose only consumer on this path is the module
//! ported here. Python's `ProtectionHealth fields must be booleans` guard has no
//! Rust counterpart, because the type system already refuses anything else.
//!
//! The report serializes with its fields in Python's insertion order, so
//! `serde_json::to_string` of a report equals `json.dumps` of the dict Python
//! builds for the same signals.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

/// `PROTECTION_HEALTH_SCHEMA_VERSION` (protection_health.py:13).
pub const PROTECTION_HEALTH_SCHEMA_VERSION: &str = "guard.protection-health.v1";

/// `PROTECTION_CHECK_IDS` (protection_health.py:14) — the report's fixed order.
pub const PROTECTION_CHECK_IDS: [&str; 9] = [
    "harness_hooks",
    "daemon",
    "policy_engine",
    "rule_packs",
    "decision_plane_compatibility",
    "containment_compatibility",
    "sandbox",
    "decision_stream",
    "tamper_checks",
];

/// `_STABLE_ID` (protection_health.py:25).
static STABLE_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$").unwrap());

/// `_MAX_HARNESSES` (protection_health.py:26).
const MAX_HARNESSES: usize = 100;

/// The checks a platform may legitimately not support at all.
const UNSUPPORTED_PLATFORM_CHECK_IDS: [&str; 4] = [
    "policy_engine",
    "decision_plane_compatibility",
    "containment_compatibility",
    "sandbox",
];

/// A refusal carrying Python's exact wording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionHealthError(String);

impl ProtectionHealthError {
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProtectionHealthError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ProtectionHealthError {}

/// `ProtectionCheckStatus` (protection_health.py:29).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtectionCheckStatus {
    Pass,
    Unknown,
    Fail,
}

/// `ProtectionState` (protection_health.py:35).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtectionState {
    Protected,
    Partial,
    Degraded,
}

/// `TruthfulState` (effect_contract.py:224).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TruthfulState {
    Protected,
    Partial,
    Degraded,
    Checked,
    Permitted,
    AllowedUnconfirmed,
    ConfirmedSuccess,
    ConfirmedFailure,
    Interrupted,
    Blocked,
}

/// `ProtectionHealth` (effect_contract.py:238).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectionHealth {
    pub required_hooks: bool,
    pub daemon_and_policy: bool,
    pub rules_and_containment: bool,
    pub tamper_checks: bool,
    pub evidence_health: bool,
}

/// `derive_protection_state` (effect_contract.py:250).
pub fn derive_protection_state(health: ProtectionHealth) -> TruthfulState {
    let core_healthy = health.required_hooks
        && health.daemon_and_policy
        && health.rules_and_containment
        && health.tamper_checks;
    if !core_healthy {
        return TruthfulState::Degraded;
    }
    if !health.evidence_health {
        return TruthfulState::Partial;
    }
    TruthfulState::Protected
}

/// `ProtectionSignal` (protection_health.py:41) — one check's proof, or its absence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionSignal {
    status: ProtectionCheckStatus,
    reason_code: String,
}

impl ProtectionSignal {
    /// `__post_init__` (protection_health.py:46) refuses a free-form reason.
    pub fn new(
        status: ProtectionCheckStatus,
        reason_code: &str,
    ) -> Result<Self, ProtectionHealthError> {
        if !STABLE_ID.is_match(reason_code) {
            return Err(ProtectionHealthError(
                "protection signal reason_code must be a stable identifier".to_owned(),
            ));
        }
        Ok(Self {
            status,
            reason_code: reason_code.to_owned(),
        })
    }

    pub fn status(&self) -> ProtectionCheckStatus {
        self.status
    }

    pub fn reason_code(&self) -> &str {
        &self.reason_code
    }

    /// `UNKNOWN_SIGNAL` (protection_health.py:57) — a check nothing has proven.
    pub fn unknown() -> Self {
        Self {
            status: ProtectionCheckStatus::Unknown,
            reason_code: "proof_unavailable".to_owned(),
        }
    }

    fn to_check(&self, check_id: &str) -> ProtectionCheck {
        ProtectionCheck {
            check_id: check_id.to_owned(),
            status: self.status,
            reason_code: self.reason_code.clone(),
        }
    }
}

/// One row of the report's `checks`, in Python's key order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtectionCheck {
    pub check_id: String,
    pub status: ProtectionCheckStatus,
    pub reason_code: String,
}

/// One harness's own view of the same checks, in Python's key order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HarnessProtection {
    pub harness: String,
    pub state: ProtectionState,
    pub label: String,
    pub detail: String,
    pub evidence_gap: bool,
    pub checks: Vec<ProtectionCheck>,
    pub reason_codes: Vec<String>,
}

/// The evaluated report, in Python's key order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtectionHealthReport {
    pub schema_version: String,
    pub state: ProtectionState,
    pub label: String,
    pub detail: String,
    pub evidence_gap: bool,
    pub checks: Vec<ProtectionCheck>,
    pub reason_codes: Vec<String>,
    pub apps: Vec<HarnessProtection>,
}

/// `_is_unsupported_platform` (protection_health.py:69).
fn is_unsupported_platform(check_id: &str, signal: &ProtectionSignal) -> bool {
    UNSUPPORTED_PLATFORM_CHECK_IDS.contains(&check_id)
        && signal.status == ProtectionCheckStatus::Fail
        && signal.reason_code == "unsupported_platform"
}

/// `_state_for` (protection_health.py:77) — signals arrive in `PROTECTION_CHECK_IDS` order.
fn state_for(ordered: &[ProtectionSignal; 9]) -> ProtectionState {
    let pair = |index: usize| (PROTECTION_CHECK_IDS[index], &ordered[index]);
    if (0..9).any(|index| {
        let (check_id, signal) = pair(index);
        signal.status == ProtectionCheckStatus::Fail && !is_unsupported_platform(check_id, signal)
    }) {
        return ProtectionState::Degraded;
    }

    let passes = |check_id: &str| {
        let index = PROTECTION_CHECK_IDS
            .iter()
            .position(|candidate| *candidate == check_id)
            .expect("the checks are named from PROTECTION_CHECK_IDS");
        let signal = &ordered[index];
        signal.status == ProtectionCheckStatus::Pass || is_unsupported_platform(check_id, signal)
    };

    let state = derive_protection_state(ProtectionHealth {
        required_hooks: passes("harness_hooks"),
        daemon_and_policy: passes("daemon") && passes("policy_engine"),
        rules_and_containment: [
            "rule_packs",
            "decision_plane_compatibility",
            "containment_compatibility",
            "sandbox",
        ]
        .iter()
        .all(|check_id| passes(check_id)),
        tamper_checks: passes("tamper_checks"),
        evidence_health: passes("decision_stream"),
    });
    match state {
        TruthfulState::Protected => ProtectionState::Protected,
        TruthfulState::Partial => ProtectionState::Partial,
        // `derive_protection_state` returns nothing else, and Python's mapping
        // would raise a `KeyError` if it ever did.
        _ => ProtectionState::Degraded,
    }
}

/// `_copy_for` (protection_health.py:110).
fn copy_for(state: ProtectionState) -> (&'static str, &'static str) {
    match state {
        ProtectionState::Protected => (
            "Protected",
            "All required protection checks have current proof.",
        ),
        ProtectionState::Degraded => (
            "Degraded",
            "One or more required protection checks failed or remain unproven.",
        ),
        ProtectionState::Partial => (
            "Partially protected",
            "Core protection passes, but decision-stream evidence is incomplete.",
        ),
    }
}

fn ordered_signals(by_id: &BTreeMap<String, ProtectionSignal>) -> [ProtectionSignal; 9] {
    PROTECTION_CHECK_IDS.map(|check_id| {
        by_id
            .get(check_id)
            .cloned()
            .unwrap_or_else(ProtectionSignal::unknown)
    })
}

fn checks_for(ordered: &[ProtectionSignal; 9]) -> Vec<ProtectionCheck> {
    ordered
        .iter()
        .zip(PROTECTION_CHECK_IDS)
        .map(|(signal, check_id)| signal.to_check(check_id))
        .collect()
}

fn evidence_gap(ordered: &[ProtectionSignal; 9]) -> bool {
    ordered
        .iter()
        .any(|signal| signal.status == ProtectionCheckStatus::Unknown)
}

/// `evaluate_protection_health` (protection_health.py:123).
///
/// `harness_signals` is read in sorted key order, and only the first hundred
/// harnesses are reported — a harness past that cut is never even validated,
/// exactly as in Python, where the slice precedes the identity check.
pub fn evaluate_protection_health(
    signals: &BTreeMap<String, ProtectionSignal>,
    harness_signals: &BTreeMap<String, ProtectionSignal>,
) -> Result<ProtectionHealthReport, ProtectionHealthError> {
    let unknown_ids: Vec<&str> = signals
        .keys()
        .map(String::as_str)
        .filter(|check_id| !PROTECTION_CHECK_IDS.contains(check_id))
        .collect();
    if !unknown_ids.is_empty() {
        // `signals` is already sorted, which is the order Python prints.
        return Err(ProtectionHealthError(format!(
            "unsupported protection check IDs: {}",
            unknown_ids.join(", ")
        )));
    }

    let ordered = ordered_signals(signals);
    let state = state_for(&ordered);
    let (label, detail) = copy_for(state);

    let mut apps = Vec::new();
    for (harness, hook_signal) in harness_signals.iter().take(MAX_HARNESSES) {
        if harness.chars().count() > 64 || !STABLE_ID.is_match(harness) {
            return Err(ProtectionHealthError(
                "harness protection identity must be a stable identifier".to_owned(),
            ));
        }
        let mut scoped = ordered.clone();
        scoped[0] = hook_signal.clone();
        let scoped_state = state_for(&scoped);
        let (scoped_label, scoped_detail) = copy_for(scoped_state);
        apps.push(HarnessProtection {
            harness: harness.clone(),
            state: scoped_state,
            label: scoped_label.to_owned(),
            detail: scoped_detail.to_owned(),
            evidence_gap: evidence_gap(&scoped),
            checks: checks_for(&scoped),
            reason_codes: scoped
                .iter()
                .map(|signal| signal.reason_code.clone())
                .collect(),
        });
    }

    Ok(ProtectionHealthReport {
        schema_version: PROTECTION_HEALTH_SCHEMA_VERSION.to_owned(),
        state,
        label: label.to_owned(),
        detail: detail.to_owned(),
        evidence_gap: evidence_gap(&ordered),
        checks: checks_for(&ordered),
        reason_codes: ordered
            .iter()
            .map(|signal| signal.reason_code.clone())
            .collect(),
        apps,
    })
}

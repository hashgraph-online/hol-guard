//! What each protection fact proves: the signal producers that lived in
//! `runtime/protection_health_runtime.py` and `runtime/containment_health.py`.
//!
//! The caller reads the managed installs, the live hook verification, the
//! daemon's runtime row, the policy trust status and the decision stream's
//! counters, and sends them as they were. This module turns them into the
//! nine signals; [`evaluate_protection_health`] still decides what those add
//! up to, so the caller holds no verdict of its own at either step.
//!
//! A fact of the wrong shape never proves anything, and it never refuses the
//! request either: it becomes the reason code an absent or invalid fact
//! already had, so one bad row cannot hide every other check.
//!
//! Timestamps are read with the attestation shape
//! (`YYYY-MM-DD(T| )HH:MM[:SS[.fff|.ffffff]](+|-)HH:MM[:SS]`, or a trailing
//! `Z`), which is every spelling Guard writes. Python's `fromisoformat` reads
//! more spellings on newer interpreters; a timestamp outside the shape is
//! invalid here, which only ever withholds a pass.
//!
//! [`evaluate_protection_health`]: crate::protection_health::evaluate_protection_health

use std::collections::BTreeMap;

use guard_contracts::{
    DaemonFactsV1, DecisionStreamFactsV1, HarnessInstallFactV1, ProtectionHealthFactsRequestV1,
};
use serde_json::Value;

use crate::attestation_timestamp::{parse_attestation_timestamp, python_strip};
use crate::containment_compatibility::{CompatibilityEvidence, CONTAINMENT_HEALTH_SCHEMA_VERSION};
use crate::protection_health::{
    ProtectionCheckStatus, ProtectionHealthError, ProtectionSignal, STABLE_ID,
};

use crate::protection_health::ProtectionCheckStatus::{Fail, Pass, Unknown};

const MICROS_PER_SECOND: i64 = 1_000_000;
const HEARTBEAT_MAX_AGE_MICROS: i64 = 30 * MICROS_PER_SECOND;
const HEARTBEAT_FUTURE_TOLERANCE_MICROS: i64 = 5 * MICROS_PER_SECOND;
const MAX_HARNESS_CHARS: usize = 64;

const UNSUPPORTED_BACKEND: &str = "unsupported";
const BACKENDS: [&str; 3] = [UNSUPPORTED_BACKEND, "macos-sandbox", "linux-bwrap"];
/// `ContainmentHealthEvidence.from_mapping`'s exact field set.
const EVIDENCE_KEYS: [&str; 12] = [
    "backend",
    "backend_digest",
    "policy_contract_digest",
    "daemon_fingerprint",
    "runtime_fingerprint",
    "probe_at",
    "probe_enforced",
    "containment_schema_version",
    "policy_version",
    "effect_contract_schema_version",
    "effect_decision_schema_version",
    "schema_version",
];
const EVIDENCE_DIGESTS: [&str; 4] = [
    "backend_digest",
    "policy_contract_digest",
    "daemon_fingerprint",
    "runtime_fingerprint",
];
/// The checks containment evidence proves, in report order.
pub const CONTAINMENT_CHECK_IDS: [&str; 4] = [
    "policy_engine",
    "decision_plane_compatibility",
    "containment_compatibility",
    "sandbox",
];
/// A mismatch in any of these is one policy version mismatch to the operator.
const POLICY_ERRORS: [&str; 5] = [
    "policy_version_mismatch",
    "policy_digest_mismatch",
    "effect_contract_mismatch",
    "decision_plane_mismatch",
    "containment_schema_mismatch",
];

/// The signals one set of facts proves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactSignals {
    /// Keyed by check ID; every one of the nine is present.
    pub signals: BTreeMap<String, ProtectionSignal>,
    /// Each active, stably named harness's own hook signal.
    pub harness_signals: BTreeMap<String, ProtectionSignal>,
}

fn signal(status: ProtectionCheckStatus, reason_code: &'static str) -> ProtectionSignal {
    ProtectionSignal::stable(status, reason_code)
}

/// An instant in microseconds since the Unix epoch, for a timezone-aware
/// timestamp. Python's `fromisoformat` strips nothing and reads only an
/// uppercase `Z`, so neither does this.
fn instant(value: &str) -> Option<i64> {
    if python_strip(value).len() != value.len() || value.ends_with('z') {
        return None;
    }
    parse_attestation_timestamp(value)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn stable_harness(value: &Value) -> Option<&str> {
    let Value::String(name) = value else {
        return None;
    };
    (name.chars().count() <= MAX_HARNESS_CHARS && STABLE_ID.is_match(name)).then_some(name.as_str())
}

/// `_hook_signals`: one signal per active install, where a failed
/// verification on any row of a harness fails the whole harness.
fn hook_signals(
    installs: &[HarnessInstallFactV1],
    verification: Option<&BTreeMap<String, Value>>,
) -> BTreeMap<String, ProtectionSignal> {
    let mut result: BTreeMap<String, ProtectionSignal> = BTreeMap::new();
    for install in installs {
        let Some(harness) = stable_harness(&install.harness) else {
            continue;
        };
        if install.active != Value::Bool(true) {
            continue;
        }
        let candidate = match verification.and_then(|map| map.get(harness)) {
            Some(Value::Bool(true)) => signal(Pass, "hooks_verified"),
            Some(Value::Bool(false)) => signal(Fail, "hook_verification_failed"),
            _ => signal(Unknown, "hook_attestation_unavailable"),
        };
        let failed_before = result
            .get(harness)
            .is_some_and(|existing| existing.status() == Fail);
        let next = if candidate.status() == Fail || failed_before {
            signal(Fail, "hooks_inactive")
        } else {
            candidate
        };
        result.insert(harness.to_owned(), next);
    }
    result
}

/// `_global_hook_signal`.
fn global_hook_signal(harness_signals: &BTreeMap<String, ProtectionSignal>) -> ProtectionSignal {
    if harness_signals.is_empty() {
        return signal(Fail, "no_managed_harness");
    }
    if harness_signals.values().any(|item| item.status() == Fail) {
        return signal(Fail, "one_or_more_hooks_inactive");
    }
    if harness_signals.values().all(|item| item.status() == Pass) {
        return signal(Pass, "hooks_verified");
    }
    signal(Unknown, "hook_attestation_unavailable")
}

fn is_word(value: &Value, word: &str) -> bool {
    value.as_str() == Some(word)
}

/// `_rule_pack_signal`.
fn rule_pack_signal(remembered_rules: &Value) -> ProtectionSignal {
    if is_word(remembered_rules, "enforced") {
        return signal(Pass, "rule_packs_enforced");
    }
    if is_word(remembered_rules, "disabled_degraded") {
        return signal(Fail, "rule_packs_disabled");
    }
    signal(Unknown, "rule_pack_runtime_proof_unavailable")
}

/// `_tamper_signal`.
fn tamper_signal(runtime_protection: &Value) -> ProtectionSignal {
    if is_word(runtime_protection, "protected") {
        return signal(Pass, "runtime_protection_trusted");
    }
    if is_word(runtime_protection, "degraded") {
        return signal(Fail, "tamper_checks_failed");
    }
    signal(Unknown, "tamper_proof_unavailable")
}

/// `_decision_stream_signal`: only errors still active degrade the stream,
/// so history that was repaired never does.
fn decision_stream_signal(counters: Option<&DecisionStreamFactsV1>) -> ProtectionSignal {
    let Some(counters) = counters else {
        return signal(Fail, "decision_stream_health_unavailable");
    };
    if counters.active_error_count > 0 {
        return signal(Fail, "decision_stream_degraded");
    }
    if counters.activity_count == 0 {
        signal(Pass, "decision_stream_ready")
    } else {
        signal(Pass, "decision_stream_healthy")
    }
}

/// `ContainmentHealthEvidence`, read strictly: the exact field set, a known
/// backend, lowercase digests, a boolean probe result and an aware probe time.
fn containment_evidence(value: &Value) -> Option<CompatibilityEvidence<'_>> {
    let object = value.as_object()?;
    if object.len() != EVIDENCE_KEYS.len()
        || !EVIDENCE_KEYS.iter().all(|key| object.contains_key(*key))
    {
        return None;
    }
    let text = |key: &str| object.get(key).and_then(Value::as_str);
    let backend = text("backend").filter(|backend| BACKENDS.contains(backend))?;
    // Every field but the probe result is a string.
    if !EVIDENCE_KEYS
        .iter()
        .filter(|key| **key != "probe_enforced")
        .all(|key| text(key).is_some())
    {
        return None;
    }
    if text("schema_version") != Some(CONTAINMENT_HEALTH_SCHEMA_VERSION) {
        return None;
    }
    if !EVIDENCE_DIGESTS
        .iter()
        .all(|key| text(key).is_some_and(is_sha256))
    {
        return None;
    }
    let probe_enforced = object.get("probe_enforced").and_then(Value::as_bool)?;
    Some(CompatibilityEvidence {
        unsupported_backend: backend == UNSUPPORTED_BACKEND,
        policy_contract_digest: text("policy_contract_digest")?,
        daemon_fingerprint: text("daemon_fingerprint")?,
        runtime_fingerprint: text("runtime_fingerprint")?,
        probe_micros: instant(text("probe_at")?)?,
        probe_enforced,
        containment_schema_version: text("containment_schema_version")?,
        policy_version: text("policy_version")?,
        effect_contract_schema_version: text("effect_contract_schema_version")?,
        effect_decision_schema_version: text("effect_decision_schema_version")?,
    })
}

fn containment_failed(reason: &'static str) -> [ProtectionSignal; 4] {
    CONTAINMENT_CHECK_IDS.map(|_| signal(Fail, reason))
}

/// `containment_health_signals`: the four containment-owned checks, in
/// [`CONTAINMENT_CHECK_IDS`] order. Missing or malformed evidence fails them
/// all; it is never merely unproven.
fn containment_signals(value: Option<&Value>, now: i64) -> [ProtectionSignal; 4] {
    let Some(evidence) = value.and_then(containment_evidence) else {
        return containment_failed("containment_health_invalid");
    };
    if evidence.unsupported_backend {
        return containment_failed("unsupported_platform");
    }
    let errors = evidence.errors(now, None);
    let Some(reason) = errors.first().copied() else {
        return [
            signal(Pass, "policy_engine_compatible"),
            signal(Pass, "decision_plane_compatible"),
            signal(Pass, "containment_compatible"),
            signal(Pass, "containment_backend_enforced"),
        ];
    };
    if POLICY_ERRORS.contains(&reason) {
        return containment_failed("policy_version_mismatch");
    }
    containment_failed(reason)
}

/// `_daemon_signal`: a fresh heartbeat from a daemon whose published
/// containment evidence, if any, names the runtime it runs.
fn daemon_signal(daemon: Option<&DaemonFactsV1>, now: i64) -> ProtectionSignal {
    let Some(daemon) = daemon else {
        return signal(Fail, "daemon_runtime_unavailable");
    };
    if is_word(&daemon.registration_status, "missing") {
        return signal(Unknown, "daemon_registration_missing");
    }
    let Some(heartbeat) = daemon.last_heartbeat_at.as_str() else {
        return signal(Unknown, "daemon_heartbeat_unavailable");
    };
    let Some(heartbeat) = instant(heartbeat) else {
        return signal(Unknown, "daemon_heartbeat_invalid");
    };
    let age = now - heartbeat;
    if age < -HEARTBEAT_FUTURE_TOLERANCE_MICROS {
        return signal(Unknown, "daemon_heartbeat_future");
    }
    if age > HEARTBEAT_MAX_AGE_MICROS {
        return signal(Fail, "daemon_heartbeat_stale");
    }
    if !daemon.containment_health.is_null() {
        let Some(evidence) = containment_evidence(&daemon.containment_health) else {
            return signal(Fail, "daemon_containment_health_invalid");
        };
        if evidence.daemon_fingerprint != evidence.runtime_fingerprint {
            return signal(Fail, "daemon_runtime_drift");
        }
    }
    signal(Pass, "daemon_healthy")
}

/// The nine signals and each harness's own hook signal for these facts.
///
/// The only refusal is a `now` that is not an aware instant: every age this
/// module measures is measured from it.
pub fn signals_from_facts(
    facts: &ProtectionHealthFactsRequestV1,
) -> Result<FactSignals, ProtectionHealthError> {
    let now = instant(&facts.now).ok_or_else(|| {
        ProtectionHealthError::new("protection facts must be read at an aware instant")
    })?;
    let harness_signals = hook_signals(&facts.managed_installs, facts.hook_verification.as_ref());
    let containment = containment_signals(
        facts
            .daemon
            .as_ref()
            .map(|daemon| &daemon.containment_health),
        now,
    );
    let mut signals = BTreeMap::from([
        (
            "harness_hooks".to_owned(),
            global_hook_signal(&harness_signals),
        ),
        (
            "daemon".to_owned(),
            daemon_signal(facts.daemon.as_ref(), now),
        ),
        (
            "rule_packs".to_owned(),
            rule_pack_signal(&facts.remembered_rules),
        ),
        (
            "decision_stream".to_owned(),
            decision_stream_signal(facts.decision_stream.as_ref()),
        ),
        (
            "tamper_checks".to_owned(),
            tamper_signal(&facts.runtime_protection),
        ),
    ]);
    for (check_id, signal) in CONTAINMENT_CHECK_IDS.into_iter().zip(containment) {
        signals.insert(check_id.to_owned(), signal);
    }
    Ok(FactSignals {
        signals,
        harness_signals,
    })
}

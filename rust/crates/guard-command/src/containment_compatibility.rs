//! Containment health compatibility, shared by the resident's own evidence
//! (`contained_runner::health`, Unix only) and the protection-health facts
//! reader, which runs on every platform. One list of errors means a check the
//! resident applies to itself is the same check a report applies to it.

use sha2::{Digest, Sha256};

use crate::effect_decision::{EFFECT_CONTRACT_SCHEMA_VERSION, EFFECT_DECISION_SCHEMA_VERSION};

pub(crate) const CONTAINMENT_HEALTH_SCHEMA_VERSION: &str = "guard.containment-health.v1";
pub(crate) const CONTAINMENT_SCHEMA_VERSION: &str = "guard.containment.v1";
pub(crate) const CONTAINMENT_POLICY_VERSION: &str = "guard.containment-policy.v1";
const POLICY_CONTRACT_INPUT: &[u8] =
    b"guard.containment-policy.v1\x00deny-network\x00deny-external-writes\x00deny-live-workspace-reads";
pub(crate) const PROBE_MAX_AGE_MICROS: i64 = 5 * 60 * 1_000_000;
const FUTURE_TOLERANCE_MICROS: i64 = 5 * 1_000_000;

pub(crate) fn policy_contract_digest() -> String {
    hex::encode(Sha256::digest(POLICY_CONTRACT_INPUT))
}

/// The fields of `ContainmentHealthEvidence` that decide compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CompatibilityEvidence<'a> {
    pub(crate) unsupported_backend: bool,
    pub(crate) policy_contract_digest: &'a str,
    pub(crate) daemon_fingerprint: &'a str,
    pub(crate) runtime_fingerprint: &'a str,
    /// Microseconds since the Unix epoch, always UTC.
    pub(crate) probe_micros: i64,
    pub(crate) probe_enforced: bool,
    pub(crate) containment_schema_version: &'a str,
    pub(crate) policy_version: &'a str,
    pub(crate) effect_contract_schema_version: &'a str,
    pub(crate) effect_decision_schema_version: &'a str,
}

impl CompatibilityEvidence<'_> {
    /// `ContainmentHealthEvidence.compatibility_errors`, sorted; empty means
    /// the evidence is current. A `runtime_fingerprint` is the fingerprint of
    /// the runtime asking, when it knows its own.
    pub(crate) fn errors(
        &self,
        now_micros: i64,
        runtime_fingerprint: Option<&str>,
    ) -> Vec<&'static str> {
        let mut errors: Vec<&'static str> = Vec::new();
        if self.unsupported_backend {
            errors.push("unsupported_platform");
        }
        if self.containment_schema_version != CONTAINMENT_SCHEMA_VERSION {
            errors.push("containment_schema_mismatch");
        }
        if self.policy_version != CONTAINMENT_POLICY_VERSION {
            errors.push("policy_version_mismatch");
        }
        if self.effect_contract_schema_version != EFFECT_CONTRACT_SCHEMA_VERSION {
            errors.push("effect_contract_mismatch");
        }
        if self.effect_decision_schema_version != EFFECT_DECISION_SCHEMA_VERSION {
            errors.push("decision_plane_mismatch");
        }
        if self.policy_contract_digest != policy_contract_digest() {
            errors.push("policy_digest_mismatch");
        }
        if self.daemon_fingerprint != self.runtime_fingerprint {
            errors.push("daemon_runtime_drift");
        }
        if runtime_fingerprint.is_some_and(|value| value != self.daemon_fingerprint) {
            errors.push("daemon_runtime_drift");
        }
        if !self.probe_enforced {
            errors.push("containment_probe_failed");
        }
        let age = now_micros - self.probe_micros;
        if age < -FUTURE_TOLERANCE_MICROS {
            errors.push("containment_probe_future");
        } else if age > PROBE_MAX_AGE_MICROS {
            errors.push("containment_probe_stale");
        }
        errors.sort_unstable();
        errors
    }
}

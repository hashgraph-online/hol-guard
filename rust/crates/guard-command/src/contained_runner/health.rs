//! Fail-closed health and proof gating for enforced containment.
//!
//! Faithful port of `runtime/containment_health.py`. The resident probes its
//! own backend in-process and caches the result for the five-minute health
//! window, so no extra round trip or daemon request is needed per execution.

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use super::common::{file_sha256, framed_digest, sha256_hex};
use super::contract::{
    is_sha256, Attestation, Backend, Policy, Request, CONTAINMENT_POLICY_VERSION,
    CONTAINMENT_SCHEMA_VERSION,
};
use super::exec::{execute_contained, TempRoot};
use crate::effect_decision::{
    PositiveProof, ProofRequirement, EFFECT_CONTRACT_SCHEMA_VERSION, EFFECT_DECISION_SCHEMA_VERSION,
};

pub(crate) const CONTAINMENT_HEALTH_SCHEMA_VERSION: &str = "guard.containment-health.v1";
const POLICY_CONTRACT_INPUT: &[u8] =
    b"guard.containment-policy.v1\x00deny-network\x00deny-external-writes\x00deny-live-workspace-reads";
const PROBE_MAX_AGE_MICROS: i64 = 5 * 60 * 1_000_000;
const FUTURE_TOLERANCE_MICROS: i64 = 5 * 1_000_000;

pub(crate) fn policy_contract_digest() -> String {
    sha256_hex(POLICY_CONTRACT_INPUT)
}

/// Privacy-safe compatibility and self-probe evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HealthEvidence {
    pub(crate) backend: Backend,
    pub(crate) backend_digest: String,
    pub(crate) policy_contract_digest: String,
    pub(crate) daemon_fingerprint: String,
    pub(crate) runtime_fingerprint: String,
    /// Microseconds since the Unix epoch, always UTC.
    pub(crate) probe_micros: i64,
    pub(crate) probe_enforced: bool,
    pub(crate) containment_schema_version: String,
    pub(crate) policy_version: String,
    pub(crate) effect_contract_schema_version: String,
    pub(crate) effect_decision_schema_version: String,
}

impl HealthEvidence {
    pub(crate) fn new(
        backend: Backend,
        backend_digest: String,
        fingerprint: &str,
        probe_micros: i64,
        probe_enforced: bool,
    ) -> Self {
        Self {
            backend,
            backend_digest,
            policy_contract_digest: policy_contract_digest(),
            daemon_fingerprint: fingerprint.to_owned(),
            runtime_fingerprint: fingerprint.to_owned(),
            probe_micros,
            probe_enforced,
            containment_schema_version: CONTAINMENT_SCHEMA_VERSION.to_owned(),
            policy_version: CONTAINMENT_POLICY_VERSION.to_owned(),
            effect_contract_schema_version: EFFECT_CONTRACT_SCHEMA_VERSION.to_owned(),
            effect_decision_schema_version: EFFECT_DECISION_SCHEMA_VERSION.to_owned(),
        }
    }

    pub(crate) fn to_value(&self) -> Value {
        json!({
            "backend": self.backend.as_str(),
            "backend_digest": self.backend_digest,
            "policy_contract_digest": self.policy_contract_digest,
            "daemon_fingerprint": self.daemon_fingerprint,
            "runtime_fingerprint": self.runtime_fingerprint,
            "probe_at": iso_utc(self.probe_micros),
            "probe_enforced": self.probe_enforced,
            "containment_schema_version": self.containment_schema_version,
            "policy_version": self.policy_version,
            "effect_contract_schema_version": self.effect_contract_schema_version,
            "effect_decision_schema_version": self.effect_decision_schema_version,
            "schema_version": CONTAINMENT_HEALTH_SCHEMA_VERSION,
        })
    }

    pub(crate) fn binding_digest(&self) -> Result<String, String> {
        framed_digest(&self.to_value())
    }

    /// Sorted compatibility errors; empty means the evidence is current.
    pub(crate) fn compatibility_errors(
        &self,
        now_micros: i64,
        runtime_fingerprint: Option<&str>,
    ) -> Vec<&'static str> {
        let mut errors: Vec<&'static str> = Vec::new();
        if self.backend == Backend::Unsupported {
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

/// Bind an execution proof digest to the current health evidence.
pub(crate) fn combine_health(base_digest: &str, health: &HealthEvidence) -> Result<String, String> {
    Ok(sha256_hex(
        format!("{}:{}", base_digest, health.binding_digest()?).as_bytes(),
    ))
}

/// Construct contained proof only when execution and current health agree.
pub(crate) fn contained_positive_proof(
    attestation: &Attestation,
    request: &Request,
    health: &HealthEvidence,
    requirements: &[ProofRequirement],
    now_micros: i64,
    runtime_fingerprint: &str,
) -> Result<PositiveProof, String> {
    if !is_sha256(runtime_fingerprint) {
        return Err("runtime fingerprint must be a lowercase SHA-256 digest".to_owned());
    }
    if let Some(error) = health
        .compatibility_errors(now_micros, Some(runtime_fingerprint))
        .first()
    {
        return Err(format!("containment health is incompatible: {error}"));
    }
    if attestation.backend != health.backend || attestation.backend_digest != health.backend_digest
    {
        return Err("containment backend identity drifted".to_owned());
    }
    let base = attestation.execution_bound_proof(request, requirements)?;
    Ok(PositiveProof {
        route: base.route,
        binding_digest: combine_health(&base.binding_digest, health)?,
        satisfied_requirements: base.satisfied_requirements,
        enforced: true,
    })
}

pub(crate) fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_micros() as i64)
}

/// `datetime.isoformat()` for a UTC timestamp.
pub(crate) fn iso_utc(micros: i64) -> String {
    let seconds = micros.div_euclid(1_000_000);
    let fraction = micros.rem_euclid(1_000_000);
    let days = seconds.div_euclid(86_400);
    let second_of_day = seconds.rem_euclid(86_400);
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    let clock = format!(
        "{:02}:{:02}:{:02}",
        second_of_day / 3_600,
        second_of_day % 3_600 / 60,
        second_of_day % 60
    );
    let micro = if fraction == 0 {
        String::new()
    } else {
        format!(".{fraction:06}")
    };
    format!("{year:04}-{month:02}-{day:02}T{clock}{micro}+00:00")
}

fn resident_fingerprint() -> String {
    sha256_hex(
        format!(
            "hol-guard-resident-containment:{}",
            env!("CARGO_PKG_VERSION")
        )
        .as_bytes(),
    )
}

/// Run a fresh execution-owned backend probe in this resident process.
pub(crate) fn probe_containment_health(fingerprint: &str) -> Result<HealthEvidence, String> {
    if !is_sha256(fingerprint) {
        return Err("daemon fingerprint must be a lowercase SHA-256 digest".to_owned());
    }
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        return Ok(HealthEvidence::new(
            Backend::Unsupported,
            sha256_hex(b"unavailable:unsupported"),
            fingerprint,
            now_micros(),
            false,
        ));
    }
    let executable = ["/usr/bin/true", "/bin/true"]
        .into_iter()
        .find(|path| Path::new(path).is_file())
        .ok_or_else(|| "containment probe executable is unavailable".to_owned())?;
    let workspace = TempRoot::create("guard-containment-probe-")?;
    let canonical = std::fs::canonicalize(&workspace.0).map_err(|error| error.to_string())?;
    let canonical = canonical.to_string_lossy().into_owned();
    let request = Request::new(
        &[executable.to_owned()],
        &canonical,
        &[],
        Policy::new(&canonical)?,
        Vec::new(),
        &sha256_hex(b"guard-containment-health-probe-v1"),
        &file_sha256(Path::new(executable))?,
        "health-probe",
    )?;
    let result = execute_contained(&request, 5.0)?;
    Ok(HealthEvidence::new(
        result.attestation.backend,
        result.attestation.backend_digest.clone(),
        fingerprint,
        now_micros(),
        result.enforced() && result.exit_code == Some(0) && !result.timed_out,
    ))
}

static CURRENT: Mutex<Option<HealthEvidence>> = Mutex::new(None);

/// Current resident health, re-probed when absent or outside the freshness window.
pub(crate) fn current_health() -> Result<(HealthEvidence, String), String> {
    let fingerprint = resident_fingerprint();
    let mut guard = CURRENT.lock().unwrap_or_else(|error| error.into_inner());
    let now = now_micros();
    let fresh = guard.as_ref().filter(|health| {
        health
            .compatibility_errors(now, Some(&fingerprint))
            .is_empty()
            && now - health.probe_micros < PROBE_MAX_AGE_MICROS / 2
    });
    let health = match fresh {
        Some(health) => health.clone(),
        None => {
            let probed = probe_containment_health(&fingerprint)?;
            *guard = Some(probed.clone());
            probed
        }
    };
    let errors = health.compatibility_errors(now_micros(), Some(&fingerprint));
    if let Some(error) = errors.first() {
        return Err(format!("containment health incompatible: {error}"));
    }
    Ok((health, fingerprint))
}

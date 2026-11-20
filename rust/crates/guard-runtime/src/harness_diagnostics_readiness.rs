//! `harness_diagnostics` op `readiness`: the conservative runtime readiness
//! `hol-guard doctor` prints for one harness, which
//! `guard/cli/doctor_readiness.py` decided before it moved here.
//!
//! Request: `{"op": "readiness", "setup_status", "runtime_probe"}`, both as
//! the harness diagnostics carry them. Answer: `{"readiness": {"state",
//! "reason_code", "detail"}}`. The current probes never verify an
//! authenticated Guard decision in the loaded session, so the state is never
//! a pass: `unknown`, or `fail` when registration is marked broken.

use serde_json::{json, Map, Value};

use crate::runner_authority_op::KindResult;

/// Hermes and OpenClaw report under `command`; OpenCode under `paths` and
/// `config`. Nothing else in a probe counts as a probe result.
const NESTED_PROBES: [&str; 3] = ["command", "paths", "config"];

pub(crate) fn answer(fields: &Map<String, Value>) -> KindResult {
    let (state, reason, detail) =
        readiness(fields.get("setup_status"), fields.get("runtime_probe"));
    Ok(json!({"readiness": {"state": state, "reason_code": reason, "detail": detail}}))
}

fn readiness(
    setup_status: Option<&Value>,
    probe: Option<&Value>,
) -> (&'static str, &'static str, &'static str) {
    match setup_status.and_then(Value::as_str) {
        Some("broken") => (
            "fail",
            "guard_setup_broken",
            "Guard registration is marked broken. Preserve this report and inspect the warnings \
             before changing the installation. The loaded session's evaluation remains unverified.",
        ),
        Some("partial" | "not_found") => (
            "unknown",
            "hook_registration_unconfirmed",
            "Guard registration is incomplete or missing. Doctor has not verified an authenticated \
             Guard decision from this harness.",
        ),
        _ => probe_readiness(&probe_results(probe)),
    }
}

fn probe_readiness(probes: &[&Map<String, Value>]) -> (&'static str, &'static str, &'static str) {
    let any = |key: &str, value: bool| {
        probes
            .iter()
            .any(|probe| probe.get(key) == Some(&Value::Bool(value)))
    };
    if any("timed_out", true) {
        return (
            "unknown",
            "harness_probe_timed_out",
            "The harness diagnostic check timed out. Inspect the probe and daemon diagnostics; \
             no authenticated Guard decision was verified.",
        );
    }
    if any("ok", false) {
        return (
            "unknown",
            "harness_probe_failed",
            "The harness diagnostic check failed. Inspect the probe and daemon diagnostics; \
             no authenticated Guard decision was verified.",
        );
    }
    if any("skipped", true) {
        return (
            "unknown",
            "harness_probe_not_run",
            "Global doctor checked registration without running the harness CLI probe. \
             No authenticated Guard decision was verified.",
        );
    }
    (
        "unknown",
        "hook_evaluation_unverified",
        "Doctor has not verified an authenticated Guard decision from this harness. \
         Registration and CLI checks do not prove runtime readiness.",
    )
}

/// The probe and its nested `command`, `paths` and `config` results.
fn probe_results(probe: Option<&Value>) -> Vec<&Map<String, Value>> {
    let Some(probe) = probe.and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut results = vec![probe];
    results.extend(
        NESTED_PROBES
            .iter()
            .filter_map(|key| probe.get(*key).and_then(Value::as_object)),
    );
    results
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::readiness;

    fn reason(setup: Value, probe: Value) -> (&'static str, &'static str) {
        let (state, reason, _) = readiness(Some(&setup), Some(&probe));
        (state, reason)
    }

    #[test]
    fn broken_setup_fails_and_partial_setup_is_unconfirmed() {
        assert_eq!(
            reason(json!("broken"), json!({"timed_out": true})),
            ("fail", "guard_setup_broken")
        );
        assert_eq!(
            reason(json!("not_found"), json!(null)),
            ("unknown", "hook_registration_unconfirmed")
        );
        assert_eq!(
            reason(json!("partial"), json!(null)),
            ("unknown", "hook_registration_unconfirmed")
        );
    }

    #[test]
    fn probe_outcomes_in_priority_order() {
        let active = json!("active");
        assert_eq!(
            reason(
                active.clone(),
                json!({"ok": false, "command": {"timed_out": true}})
            )
            .1,
            "harness_probe_timed_out"
        );
        assert_eq!(
            reason(active.clone(), json!({"paths": {"ok": false}})).1,
            "harness_probe_failed"
        );
        assert_eq!(
            reason(active.clone(), json!({"config": {"skipped": true}})).1,
            "harness_probe_not_run"
        );
        assert_eq!(
            reason(active.clone(), json!({"other": {"ok": false}})).1,
            "hook_evaluation_unverified"
        );
        assert_eq!(
            reason(active, json!([{"ok": false}])).1,
            "hook_evaluation_unverified"
        );
    }

    #[test]
    fn missing_fields_are_unverified() {
        assert_eq!(readiness(None, None).1, "hook_evaluation_unverified");
    }
}

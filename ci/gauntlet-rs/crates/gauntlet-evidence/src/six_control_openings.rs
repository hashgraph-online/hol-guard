//! Read-only, caller-keyed opening of six retained deterministic controls.
//! Producer reports and kernel/SDK effects remain unauthenticated here.

use crate::crypto::{decode_hex, is_sha256};
use crate::local_conformance_runtime::expected_runtime;
use crate::{
    load_runner_config_from_paths, read_six_deterministic_controls_root_owned,
    reduce_forbidden_command, reduce_signed_injection_attribution,
    verify_control_reported_relations, verify_control_reported_tail, verify_controller_envelope,
    verify_runner_file_assets, EvidenceError, Result, SixDeterministicControlRecords,
};
use gauntlet_contracts::canonicalize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const ROLES: [&str; 6] = [
    "success",
    "input-binding",
    "injection",
    "boundary",
    "timeout",
    "cancel",
];
const INVALID: EvidenceError = EvidenceError::Invalid("invalid deterministic control opening");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SixControlOpeningsShadow {
    pub report_sha256: String,
    pub role_session_ids: BTreeMap<String, String>,
    pub signed_extra_probes_checked: usize,
    pub contained_routes: usize,
    pub output_bindings: usize,
    pub public_prompts: usize,
    pub contained_cli_results: usize,
    pub cancel_partial_relation_checked: bool,
    pub execution_eligible: bool,
}

impl SixControlOpeningsShadow {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-six-control-openings-shadow.v1",
            "report_sha256":self.report_sha256,
            "control_roles":self.role_session_ids.keys().collect::<Vec<_>>(),
            "distinct_signed_sessions":self.role_session_ids.len(),
            "reported_tails_checked":self.role_session_ids.len(),
            "signed_extra_probes_checked":self.signed_extra_probes_checked,
            "native_review_summaries_recomputed":self.role_session_ids.len(),
            "contained_routes_recomputed":self.contained_routes,
            "output_bindings_recomputed":self.output_bindings,
            "public_prompt_relations_recomputed":self.public_prompts,
            "contained_cli_results_checked":self.contained_cli_results,
            "cancel_partial_relation_checked":self.cancel_partial_relation_checked,
            "outside_control_keys_matched":true,
            "independent_kernel_sdk_effects_verified":false,
            "execution_eligible":false,
        })
    }
}

fn validated_keys(keys: &BTreeMap<String, String>) -> Result<BTreeMap<String, Vec<u8>>> {
    if keys.len() != ROLES.len() {
        return Err(EvidenceError::Invalid(
            "exact six outside control keys required",
        ));
    }
    ROLES
        .iter()
        .map(|role| {
            let key =
                keys.get(*role)
                    .filter(|key| is_sha256(key))
                    .ok_or(EvidenceError::Invalid(
                        "exact six outside control keys required",
                    ))?;
            let decoded = decode_hex(key, 32)
                .map_err(|_| EvidenceError::Invalid("invalid outside control key"))?;
            Ok(((*role).to_owned(), decoded))
        })
        .collect()
}

/// Bind all six report-matched records to caller keys, then check their
/// signed openings and outer reported fields. Python evaluates `injection`
/// through the `success` control role before its signed extra probe.
pub fn verify_six_control_openings_ineligible(
    records: &SixDeterministicControlRecords,
    expected_runtime: &Value,
    outside_control_keys: &BTreeMap<String, String>,
) -> Result<SixControlOpeningsShadow> {
    let keys = validated_keys(outside_control_keys)?;
    let mut role_session_ids = BTreeMap::new();
    let mut sessions = BTreeSet::new();
    let mut signed_extra_probes_checked = 0;
    let mut contained_routes = 0;
    let mut output_bindings = 0;
    let mut public_prompts = 0;
    let mut contained_cli_results = 0;
    let mut cancel_partial_relation_checked = false;
    for role in ROLES {
        let raw = records.record_bytes(role).ok_or(INVALID)?;
        let key = &keys[role];
        let control_role = if role == "injection" { "success" } else { role };
        let opened = verify_control_reported_tail(raw, control_role, key, expected_runtime)?;
        let relations =
            verify_control_reported_relations(raw, control_role, key, expected_runtime, &opened)?;
        contained_routes += relations.contained_routes;
        output_bindings += relations.output_bindings;
        public_prompts += relations.public_prompts;
        contained_cli_results += relations.contained_cli_results;
        cancel_partial_relation_checked |= relations.cancel_partial_relation;
        let session = opened.session.session_id;
        if !sessions.insert(session.clone()) {
            return Err(EvidenceError::Invalid(
                "deterministic controls must be distinct sessions",
            ));
        }
        role_session_ids.insert(role.to_owned(), session);
        if role == "injection" {
            reduce_signed_injection_attribution(raw, key)?;
            signed_extra_probes_checked += 1;
        } else if role == "input-binding" {
            let canonical = canonicalize(raw).map_err(|_| INVALID)?;
            let control: Value = serde_json::from_slice(&canonical).map_err(|_| INVALID)?;
            let envelope = serde_json::to_vec(&control["extra_probes"]).map_err(|_| INVALID)?;
            let signed = verify_controller_envelope(&envelope, key)?;
            reduce_forbidden_command(&signed["forbidden_command"])?;
            signed_extra_probes_checked += 1;
        }
    }
    Ok(SixControlOpeningsShadow {
        report_sha256: records.report.raw_sha256.clone(),
        role_session_ids,
        signed_extra_probes_checked,
        contained_routes,
        output_bindings,
        public_prompts,
        contained_cli_results,
        cancel_partial_relation_checked,
        execution_eligible: false,
    })
}

/// Read one fixed historical job and a separately pinned v7 config. The
/// caller supplies the report digest and every key; neither may be copied
/// from the report or controls when assessing a future live job.
#[allow(clippy::too_many_arguments)]
pub fn observe_six_control_openings_root_owned_ineligible(
    job_id: &str,
    source_sha: &str,
    config_path: &Path,
    config_sha256: &str,
    report_sha256: &str,
    expected_exit_code: i32,
    outside_control_keys: &BTreeMap<String, String>,
) -> Result<SixControlOpeningsShadow> {
    validated_keys(outside_control_keys)?;
    if !is_sha256(report_sha256) {
        return Err(EvidenceError::Invalid("outside report digest required"));
    }
    let asset_root = Path::new("/opt");
    let loaded = load_runner_config_from_paths(config_path, config_sha256, asset_root)?;
    if loaded.verified.version != 7
        || loaded.verified.config.value()["runtime"]["guard_source_sha"] != source_sha
    {
        return Err(EvidenceError::Invalid(
            "deterministic source differs from outside config",
        ));
    }
    let files = verify_runner_file_assets(&loaded.verified, asset_root)?;
    let expected = expected_runtime(loaded.verified.config.value())?;
    let records = read_six_deterministic_controls_root_owned(
        job_id,
        source_sha,
        config_sha256,
        expected_exit_code,
    )?;
    if records.report.raw_sha256 != report_sha256 {
        return Err(EvidenceError::Invalid("report differs from outside pin"));
    }
    let shadow = verify_six_control_openings_ineligible(&records, &expected, outside_control_keys)?;
    let after = load_runner_config_from_paths(config_path, config_sha256, asset_root)?;
    if after.verified.config.value() != loaded.verified.config.value()
        || verify_runner_file_assets(&after.verified, asset_root)? != files
    {
        return Err(EvidenceError::Invalid(
            "deterministic config assets changed while reading",
        ));
    }
    Ok(shadow)
}

#[cfg(test)]
#[path = "six_control_openings_tests.rs"]
mod tests;

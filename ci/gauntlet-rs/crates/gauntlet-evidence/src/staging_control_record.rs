//! Read one fresh staging control from fixed Root-only state and open its
//! signed, reported relations against outside pins. Physical effects and
//! process cleanup still require a separate Rust supervisor and oracles.

use crate::crypto::{decode_hex, is_sha256, sha256};
use crate::local_conformance_runtime::expected_runtime;
use crate::python_worker_files::{open_private_directory, read_private_file, unchanged};
use crate::{
    load_runner_config_from_paths, reduce_forbidden_command, reduce_signed_injection_attribution,
    verify_control_reported_relations, verify_control_reported_tail, verify_controller_envelope,
    verify_runner_assets_inert, EvidenceError, Result,
};
use gauntlet_contracts::{canonicalize, is_git_sha};
use rustix::fs::{fstat, open, openat, statat, AtFlags, Mode, OFlags};
use rustix::process::geteuid;
use serde_json::{json, Value};
use std::os::fd::OwnedFd;
use std::path::Path;

const SHADOW: &str = "/opt/hol-gauntlet/rust-shadow-candidates";
const MAX_CONTROL_BYTES: u64 = 8 * 1024 * 1024;
const INVALID: EvidenceError = EvidenceError::Invalid("invalid staging control opening");

#[derive(Debug, Clone, Copy)]
pub struct StagingEvidencePins<'a> {
    pub build_job_id: &'a str,
    pub run_id: &'a str,
    pub role: &'a str,
    pub source_sha: &'a str,
    pub version: &'a str,
    pub config_digest: &'a str,
    pub private_manifest_sha256: &'a str,
    pub prefix_tree_sha256: &'a str,
    pub record_sha256: &'a str,
    pub controller_public_key_hex: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagingControlOpening {
    pub record_sha256: String,
    pub session_id: String,
    pub role: String,
    pub contained_routes: usize,
    pub output_bindings: usize,
    pub public_prompts: usize,
    pub contained_cli_results: usize,
    pub signed_extra_probe_checked: bool,
    pub execution_eligible: bool,
}

impl StagingControlOpening {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-staging-control-opening.v1",
            "role":self.role,
            "record_sha256":self.record_sha256,
            "signed_session_id":self.session_id,
            "contained_routes_recomputed":self.contained_routes,
            "output_bindings_recomputed":self.output_bindings,
            "public_prompt_relations_recomputed":self.public_prompts,
            "contained_cli_results_checked":self.contained_cli_results,
            "signed_extra_probe_checked":self.signed_extra_probe_checked,
            "outside_control_key_matched":true,
            "independent_kernel_sdk_effects_verified":false,
            "execution_eligible":false,
        })
    }
}

fn lower_hex(raw: &str, len: usize) -> bool {
    raw.len() == len
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_role(role: &str) -> bool {
    matches!(
        role,
        "success" | "input-binding" | "injection" | "boundary" | "timeout" | "cancel"
    )
}

fn io(error: impl std::fmt::Display) -> EvidenceError {
    EvidenceError::Io(error.to_string())
}

fn checked_named(parent: &OwnedFd, name: &str, held: &OwnedFd) -> Result<()> {
    let before = fstat(held).map_err(io)?;
    let visible = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
    if !unchanged(&before, &visible) {
        return Err(INVALID);
    }
    Ok(())
}

pub(crate) fn open_home() -> Result<OwnedFd> {
    let root = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io)?;
    let root_stat = fstat(&root).map_err(io)?;
    if root_stat.st_uid != 0 || root_stat.st_mode & 0o022 != 0 {
        return Err(INVALID);
    }
    let home = openat(
        &root,
        "home",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io)?;
    let home_stat = fstat(&home).map_err(io)?;
    if home_stat.st_uid != 0 || home_stat.st_mode & 0o022 != 0 {
        return Err(INVALID);
    }
    checked_named(&root, "home", &home)?;
    Ok(home)
}

pub(crate) fn read_one(run_id: &str, role: &str) -> Result<Vec<u8>> {
    let home = open_home()?;
    let state_name = format!("hx-{run_id}");
    let (state, _) = open_private_directory(&home, &state_name, 0)?.ok_or(INVALID)?;
    let (directory, _) = open_private_directory(&state, role, 0)?.ok_or(INVALID)?;
    let raw =
        read_private_file(&directory, "control.json", 0, MAX_CONTROL_BYTES)?.ok_or(INVALID)?;
    if raw.is_empty() {
        return Err(INVALID);
    }
    checked_named(&state, role, &directory)?;
    checked_named(&home, &state_name, &state)?;
    Ok(raw)
}

/// Open only signed and reported relations for one supplied record. The
/// caller must independently authenticate byte custody and the outside key.
pub fn verify_staging_control_opening_ineligible(
    raw: &[u8],
    role: &str,
    outside_public_key_hex: &str,
    outside_expected_runtime: &Value,
) -> Result<StagingControlOpening> {
    if !valid_role(role) || !is_sha256(outside_public_key_hex) {
        return Err(INVALID);
    }
    let key = decode_hex(outside_public_key_hex, 32).map_err(|_| INVALID)?;
    let control_role = if role == "injection" { "success" } else { role };
    let opening = verify_control_reported_tail(raw, control_role, &key, outside_expected_runtime)?;
    let relations = verify_control_reported_relations(
        raw,
        control_role,
        &key,
        outside_expected_runtime,
        &opening,
    )?;
    let extra = match role {
        "injection" => {
            reduce_signed_injection_attribution(raw, &key)?;
            true
        }
        "input-binding" => {
            let canonical = canonicalize(raw).map_err(|_| INVALID)?;
            let value: Value = serde_json::from_slice(&canonical).map_err(|_| INVALID)?;
            let envelope = serde_json::to_vec(&value["extra_probes"]).map_err(|_| INVALID)?;
            let signed = verify_controller_envelope(&envelope, &key)?;
            reduce_forbidden_command(&signed["forbidden_command"])?;
            true
        }
        _ => false,
    };
    Ok(StagingControlOpening {
        record_sha256: sha256(raw),
        session_id: opening.session.session_id,
        role: role.to_owned(),
        contained_routes: relations.contained_routes,
        output_bindings: relations.output_bindings,
        public_prompts: relations.public_prompts,
        contained_cli_results: relations.contained_cli_results,
        signed_extra_probe_checked: extra,
        execution_eligible: false,
    })
}

/// Read a fixed new staging record twice, require the outside byte/key pins,
/// and recheck config and all inert assets around the signed opening.
pub fn observe_staging_control_root_owned_ineligible(
    pins: &StagingEvidencePins<'_>,
) -> Result<StagingControlOpening> {
    Ok(observe_staging_control_context(pins)?.opening)
}

pub(crate) struct StagingControlContext {
    pub opening: StagingControlOpening,
    pub raw: Vec<u8>,
    pub native_sha256: String,
}

/// Retain the same authenticated bytes and config-derived Native identity
/// for callers composing the opening with outside kernel/file observations.
pub(crate) fn observe_staging_control_context(
    pins: &StagingEvidencePins<'_>,
) -> Result<StagingControlContext> {
    if !cfg!(target_os = "linux") || geteuid().as_raw() != 0 {
        return Err(EvidenceError::Invalid(
            "Linux Root staging custody required",
        ));
    }
    if !lower_hex(pins.build_job_id, 16)
        || !lower_hex(pins.run_id, 16)
        || !valid_role(pins.role)
        || !is_git_sha(pins.source_sha)
        || !crate::valid_package_version(pins.version)
        || !is_sha256(pins.config_digest)
        || !is_sha256(pins.private_manifest_sha256)
        || !is_sha256(pins.prefix_tree_sha256)
        || !is_sha256(pins.record_sha256)
        || !is_sha256(pins.controller_public_key_hex)
    {
        return Err(INVALID);
    }
    let config_path = format!(
        "{SHADOW}/{}/provisional-{}-{}.json",
        pins.build_job_id,
        &pins.private_manifest_sha256[..16],
        &pins.config_digest[..16]
    );
    let before = load_runner_config_from_paths(
        Path::new(&config_path),
        pins.config_digest,
        Path::new("/opt"),
    )?;
    let config = before.verified.config.value();
    let base = format!("hol-gauntlet/rust-shadow-candidates/{}", pins.build_job_id);
    if before.verified.version != 7
        || config["id"]
            != format!(
                "rust-shadow-{}-{}-{}",
                pins.source_sha,
                pins.build_job_id,
                &pins.private_manifest_sha256[..16]
            )
        || config["runtime"]["guard_source_sha"] != pins.source_sha
        || config["runtime"]["guard_package_version"] != pins.version
        || config["assets"]["guard_prefix"]["path"] != format!("{base}/prefix")
        || config["assets"]["guard_prefix"]["sha256"] != pins.prefix_tree_sha256
        || config["assets"]["private_cell"]["path"] != format!("{base}/cell-artifacts")
        || config["assets"]["private_cell"]["sha256"] != pins.private_manifest_sha256
    {
        return Err(INVALID);
    }
    verify_runner_assets_inert(&before, Path::new("/opt"))?;
    let raw = read_one(pins.run_id, pins.role)?;
    if sha256(&raw) != pins.record_sha256 {
        return Err(INVALID);
    }
    let expected = expected_runtime(config)?;
    let native_sha256 = config["assets"]["native"]["sha256"]
        .as_str()
        .filter(|sha| is_sha256(sha))
        .ok_or(INVALID)?;
    if expected["private_cell"]["native_sha256"] != native_sha256 {
        return Err(INVALID);
    }
    let opened = verify_staging_control_opening_ineligible(
        &raw,
        pins.role,
        pins.controller_public_key_hex,
        &expected,
    )?;
    if opened.session_id != pins.role || raw != read_one(pins.run_id, pins.role)? {
        return Err(INVALID);
    }
    let after = load_runner_config_from_paths(
        Path::new(&config_path),
        pins.config_digest,
        Path::new("/opt"),
    )?;
    if after.verified.config.value() != config {
        return Err(INVALID);
    }
    verify_runner_assets_inert(&after, Path::new("/opt"))?;
    Ok(StagingControlContext {
        opening: opened,
        raw,
        native_sha256: native_sha256.to_owned(),
    })
}

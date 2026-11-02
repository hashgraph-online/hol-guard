//! Private installation selections. Enrollment is an explicit local operator
//! command; HTTP/MCP requests never carry approval fingerprints or executable paths.
use guard_context_assistance::{
    BundleApproval, InterpreterFacts, RuntimeSelection, VerifiedRuntime,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::policy_store_persistence::{is_lower_hex, persist_private_bytes, read_private_json};
use guard_cigar_release::{Feature, SealedInstallationReceipt};
#[path = "context_assistance_catalog.rs"]
pub(crate) mod catalog;
#[path = "context_assistance_installation_key.rs"]
mod owner_key;
#[path = "context_assistance_install_jobs.rs"]
mod preparation;
#[path = "context_assistance_switch_store.rs"]
pub(crate) mod switching;
pub(crate) fn preparation_job_id_exists(home: &Path, id: &str) -> Result<bool, String> {
    preparation::native_job_id_exists(home, id)
}
pub(crate) fn lifecycle_job_count(home: &Path) -> Result<usize, String> {
    preparation::total_job_count(home)
}
pub(crate) fn selection_lease(home: &Path) -> Result<fs::File, String> {
    preparation::lifecycle_lease(home)
}
#[path = "context_assistance_installation_v2.rs"]
mod versioned;
use super::policy_store_validation::validate_private_directory;
#[cfg(all(test, unix))]
pub(crate) use preparation::InstallPause;
pub(crate) use preparation::{run_operator_command, InstallRequest, Jobs, SetupInterpreterRequest};
pub(crate) use versioned::publish_verified;

const MAX_RECORD: u64 = 256 * 1024;
const SCHEMA: &str = "guard-cigar-installation.v1";
const PREFIX: &str = "native_context_assistance";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Installation {
    schema: String,
    pub(crate) runtime_id: String,
    pub(crate) qualification: String,
    source_revision: String,
    pub(crate) selection: RuntimeSelection,
    pub(crate) approval: BundleApproval,
    interpreter: InterpreterFacts,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt: Option<SealedInstallationReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    managed_slot: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verification_job_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollRequest {
    schema: String,
    guard_home: PathBuf,
    runtime_id: String,
    local_candidate_approved: bool,
    source_revision: String,
    selection: RuntimeSelection,
    approval: BundleApproval,
}

fn error(suffix: &str) -> String {
    format!("{PREFIX}_{suffix}")
}
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_:-".contains(&c))
}
fn record_name(id: &str) -> String {
    format!("{:x}.json", Sha256::digest(id.as_bytes()))
}

fn root(home: &Path, create: bool) -> Result<PathBuf, String> {
    if !home.is_absolute()
        || home
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(error("home_invalid"));
    }
    if create {
        crate::resident_state::ensure_private_directory_under(home, home, true)
            .map_err(|_| error("registry_unavailable"))?;
    }
    validate_private_directory(home).map_err(|_| error("registry_not_private"))?;
    let canonical = fs::canonicalize(home).map_err(|_| error("registry_unavailable"))?;
    let mut directory = canonical.clone();
    for component in ["context-assistance", "installations"] {
        directory.push(component);
        if create {
            crate::resident_state::ensure_private_directory_under(&directory, &canonical, true)
                .map_err(|_| error("registry_unavailable"))?;
        }
        validate_private_directory(&directory).map_err(|_| error("registry_not_private"))?;
    }
    Ok(directory)
}

pub(crate) fn load(home: &Path, runtime_id: &str) -> Result<Installation, String> {
    if !valid_id(runtime_id) {
        return Err(error("runtime_not_selected"));
    }
    let root = root(home, false)?;
    let path = root.join(record_name(runtime_id));
    let metadata = fs::symlink_metadata(&path).map_err(|_| error("installation_missing"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(error("installation_invalid"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(error("installation_invalid"));
        }
    }
    #[cfg(windows)]
    if !guard_runtime_windows_process::is_single_link_file(&path).unwrap_or(false) {
        return Err(error("installation_invalid"));
    }
    let (value, _) = read_private_json(&path, MAX_RECORD, "cigar_installation", home)
        .map_err(|_| error("installation_invalid"))?
        .ok_or_else(|| error("installation_missing"))?;
    let record: Installation =
        crate::strict_json::from_value(value).map_err(|_| error("installation_invalid"))?;
    if record.runtime_id != runtime_id
        || record.source_revision.len() != 40
        || !record
            .source_revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || guard_context_assistance::check_interpreter(&record.interpreter).is_err()
    {
        return Err(error("installation_invalid"));
    }
    match record.schema.as_str() {
        SCHEMA
            if record.qualification == "local_candidate"
                && record.receipt.is_none()
                && record.managed_slot.is_none()
                && record.verification_job_id.is_none()
                && record.approval.schema == "guard-cigar-bundle-approval.v1"
                && record.approval.release.is_none()
                && record.approval.python_bundle.is_none()
                && record.selection.python_bundle.is_none() => {}
        versioned::SCHEMA_V2 => {
            versioned::resolve(home, &record, &[Feature::Graph])?;
        }
        _ => return Err(error("installation_invalid")),
    }
    Ok(record)
}

/// A stored opt-in may reference only an installation verified by the local
/// enrollment command whose executable/package bytes still match. This does
/// not mint effective readiness; activation repeats the real process checks.
pub(crate) fn validate_selection(home: &Path, runtime_id: &str) -> Result<(), String> {
    let record = load(home, runtime_id)?;
    let observed = if record.schema == SCHEMA {
        guard_context_assistance::inspect_bundle(&record.selection, &record.approval.platform)
    } else {
        let release = versioned::resolve(home, &record, &[Feature::Graph])?;
        guard_context_assistance::inspect_release_bundle(&record.selection, &release)
    }
    .map_err(|e| error(e.code()))?;
    if observed != record.approval {
        return Err(error("runtime_approval_mismatch"));
    }
    Ok(())
}

pub(crate) fn list(home: &Path) -> Result<Vec<Value>, String> {
    match fs::symlink_metadata(home.join("context-assistance/installations")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(error("registry_unavailable")),
        Ok(_) => {}
    }
    let directory = root(home, false)?;
    let mut choices = Vec::new();
    for entry in fs::read_dir(&directory)
        .map_err(|_| error("registry_unavailable"))?
        .take(10)
    {
        let entry = entry.map_err(|_| error("registry_unavailable"))?;
        if entry.file_name() == "registry.lock" {
            continue;
        }
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| error("registry_invalid"))?
            .to_owned();
        if name.len() != 69
            || !name.ends_with(".json")
            || !name.as_bytes()[..64].iter().all(u8::is_ascii_hexdigit)
        {
            return Err(error("registry_invalid"));
        }
        let (value, _) = read_private_json(&entry.path(), MAX_RECORD, "cigar_installation", home)
            .map_err(|_| error("installation_invalid"))?
            .ok_or_else(|| error("installation_missing"))?;
        let id = value["runtime_id"]
            .as_str()
            .ok_or_else(|| error("installation_invalid"))?;
        if record_name(id) != name {
            return Err(error("installation_invalid"));
        }
        let record = load(home, id)?;
        let mut choice = json!({"runtime_id":record.runtime_id, "qualification":record.qualification,
            "python_version":record.interpreter.version, "platform":record.interpreter.platform,
            "worker_fingerprint":record.approval.worker_sha256});
        let version = record.version_metadata(home)?;
        choice
            .as_object_mut()
            .ok_or_else(|| error("installation_invalid"))?
            .extend(
                version
                    .as_object()
                    .ok_or_else(|| error("installation_invalid"))?
                    .clone(),
            );
        choices.push(choice);
        if choices.len() > 8 {
            return Err(error("installation_limit"));
        }
    }
    choices.sort_by(|a, b| a["runtime_id"].as_str().cmp(&b["runtime_id"].as_str()));
    Ok(choices)
}

fn enroll(request: EnrollRequest) -> Result<Value, String> {
    let mut source = crate::managed_policy_load::ManagedPolicySource::native();
    source.write_cache = false;
    enroll_with_source(request, &source)
}

fn enroll_with_source(
    request: EnrollRequest,
    source: &crate::managed_policy_load::ManagedPolicySource,
) -> Result<Value, String> {
    if request.schema != "guard-cigar-enroll-local.v1"
        || !request.guard_home.is_absolute()
        || request
            .guard_home
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
        || !request.local_candidate_approved
        || !valid_id(&request.runtime_id)
        || request.source_revision.len() != 40
        || !request
            .source_revision
            .bytes()
            .all(|c| c.is_ascii_hexdigit())
    {
        return Err(error("enrollment_invalid"));
    }
    let settings =
        crate::guard_config_load::context_assistance_from_source(&request.guard_home, source)
            .map_err(|_| error("configuration_unavailable"))?;
    if settings.diagnostic.is_some() || !settings.verification_permitted {
        return Err(error("policy_restricted"));
    }
    let _lifecycle_lease = preparation::lifecycle_lease(&request.guard_home)?;
    // No fact supplied by the operator substitutes for the actual process,
    // package, worker handshake and synthetic compilation checks.
    let mut runtime = VerifiedRuntime::start(request.selection.clone(), &request.approval)
        .map_err(|e| error(e.code()))?;
    let interpreter = runtime.status().interpreter.clone();
    runtime.close();
    let record = Installation {
        schema: SCHEMA.into(),
        runtime_id: request.runtime_id,
        qualification: "local_candidate".into(),
        source_revision: request.source_revision,
        selection: request.selection,
        approval: request.approval,
        interpreter,
        receipt: None,
        managed_slot: None,
        verification_job_id: None,
    };
    let directory = root(&request.guard_home, true)?;
    let lock_path = directory.join("registry.lock");
    #[cfg(not(windows))]
    let lock = crate::resident_state::private_lock_file(&lock_path, &request.guard_home)
        .map_err(|_| error("registry_unavailable"))?;
    #[cfg(windows)]
    let (lock, _binding) =
        crate::resident_state::private_lock_file(&lock_path, &request.guard_home)
            .map_err(|_| error("registry_unavailable"))?;
    crate::resident_state::try_lock_exclusive_briefly(&lock).map_err(|_| error("registry_busy"))?;
    let path = directory.join(record_name(&record.runtime_id));
    if fs::symlink_metadata(&path).is_ok() {
        return Err(error("installation_exists"));
    }
    let count = fs::read_dir(&directory)
        .map_err(|_| error("registry_unavailable"))?
        .try_fold(0, |count, entry| {
            let entry = entry.map_err(|_| error("registry_unavailable"))?;
            Ok::<usize, String>(
                count + usize::from(entry.path().extension().is_some_and(|ext| ext == "json")),
            )
        })?;
    if count >= 8 {
        return Err(error("installation_limit"));
    }
    let bytes = serde_json::to_vec(&record).map_err(|_| error("enrollment_invalid"))?;
    persist_private_bytes(
        &path,
        &bytes,
        MAX_RECORD,
        "cigar_installation",
        &request.guard_home,
    )
    .map_err(|_| error("registry_write_failed"))?;
    Ok(
        json!({"runtime_id": record.runtime_id, "qualification": record.qualification,
        "interpreter": record.interpreter, "worker_fingerprint": record.approval.worker_sha256,
        "activation_granted": false}),
    )
}

pub(crate) fn run_enroll_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_RECORD + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| error("request_unreadable"))?;
    if bytes.len() as u64 > MAX_RECORD {
        return Err(error("request_too_large"));
    }
    let request: EnrollRequest = crate::strict_json_value(&bytes)
        .and_then(|v| crate::strict_json::from_value(v).map_err(|_| error("request_invalid")))?;
    let response = match enroll(request) {
        Ok(installation) => json!({"ok": true, "installation": installation}),
        Err(code) => json!({"ok": false, "code": code}),
    };
    serde_json::to_vec(&response).map_err(|_| error("response_invalid"))
}

#[cfg(test)]
#[path = "context_assistance_registry_tests.rs"]
mod tests;

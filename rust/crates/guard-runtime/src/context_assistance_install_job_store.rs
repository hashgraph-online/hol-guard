//! Durable metadata. Stored job state alone never proves a live worker/SDK.
use super::*;
use guard_cigar_release::ReleaseBinding;
use std::time::{SystemTime, UNIX_EPOCH};
#[path = "context_assistance_preparation_lease.rs"]
mod lifecycle_lease;

pub(super) const MAX_JOBS: usize = 32;
const MAX_JOB_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstallRequest {
    pub job_id: String,
    pub build_id: String,
    pub interpreter_id: String,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Queued,
    Acquiring,
    Extracting,
    Verifying,
    Publishing,
    Ready,
    Failed,
    Cancelled,
    RecoveryRequired,
}
impl Phase {
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Ready | Self::Failed | Self::Cancelled | Self::RecoveryRequired
        )
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Job {
    pub schema: String,
    pub request: InstallRequest,
    pub request_sha256: String,
    pub release: ReleaseBinding,
    pub package_tree_sha256: String,
    pub worker_sha256: String,
    pub python_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub python_bundle: Option<guard_cigar_release::InterpreterBinding>,
    pub slot: String,
    pub runtime_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<super::reuse::RefreshTarget>,
    pub phase: Phase,
    pub code: String,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub deadline_at_ms: u64,
}
impl Job {
    pub fn validate(&self) -> Result<(), String> {
        validate_request(&self.request)?;
        if self.schema != "guard-cigar-install-job.v1"
            || self.request_sha256 != request_sha(&self.request)?
            || self.release.identity.build_id != self.request.build_id
            || !valid_id(&self.runtime_id)
            || self.refresh.is_none() && self.runtime_id != format!("cigar:{}", self.slot)
            || self
                .refresh
                .as_ref()
                .is_some_and(|target| target.validate().is_err())
            || [
                &self.package_tree_sha256,
                &self.worker_sha256,
                &self.python_sha256,
                &self.slot,
                &self.release.profile_sha256,
            ]
            .iter()
            .any(|value| !is_lower_hex(value, 64))
            || self.release.identity.validate().is_err()
            || self.python_bundle.as_ref().is_some_and(|binding| {
                binding.validate().is_err()
                    || binding.executable_sha256 != self.python_sha256
                    || binding.platform != self.release.platform
            })
            || self.code.is_empty()
            || self.code.len() > 128
            || !self
                .code
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            || self.updated_at_ms < self.created_at_ms
            || self.deadline_at_ms < self.created_at_ms
            || self.deadline_at_ms - self.created_at_ms > 120_000
        {
            return Err(error("install_job_invalid"));
        }
        Ok(())
    }
}
pub(super) fn validate_request(request: &InstallRequest) -> Result<(), String> {
    if !valid_id(&request.job_id)
        || !valid_id(&request.build_id)
        || !valid_id(&request.interpreter_id)
    {
        return Err(error("install_request_invalid"));
    }
    Ok(())
}
pub(super) fn request_sha(request: &InstallRequest) -> Result<String, String> {
    let bytes = serde_json::to_vec(&("guard-cigar-install-request.v1", request))
        .map_err(|_| error("install_request_invalid"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
pub(super) fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| error("clock_invalid"))?
        .as_millis()
        .try_into()
        .map_err(|_| error("clock_invalid"))
}
pub(super) fn directory(home: &Path, name: &str, create: bool) -> Result<PathBuf, String> {
    if !matches!(
        name,
        "jobs"
            | "catalog-jobs"
            | "catalog-downloads"
            | "switch-jobs"
            | "interpreters"
            | "artifacts"
            | "bundles"
            | "work"
            | "staging"
            | "downloads"
            | "python"
            | "python-staging"
            | "python-work"
            | "python-jobs"
            | "python-artifacts"
            | "python-downloads"
            | "verification"
    ) {
        return Err(error("install_path_invalid"));
    }
    if matches!(name, "switch-jobs" | "catalog-jobs" | "catalog-downloads")
        || (!create && matches!(name, "jobs" | "python-jobs"))
    {
        return lifecycle_lease::directory(home, name, create);
    }
    let registry = root(home, create)?;
    let parent = registry
        .parent()
        .ok_or_else(|| error("install_path_invalid"))?;
    let path = parent.join(name);
    if create {
        crate::resident_state::ensure_private_directory_under(&path, home, true)
            .map_err(|_| error("install_storage_unavailable"))?;
    }
    validate_private_directory(&path).map_err(|_| error("install_storage_not_private"))?;
    Ok(path)
}
pub(super) fn private_read<T: serde::de::DeserializeOwned>(
    home: &Path,
    path: &Path,
    limit: u64,
    kind: &str,
) -> Result<Option<T>, String> {
    for _ in 0..4 {
        // A rename can race the first path stat/open; malformed bytes still fail.
        let (value, bytes) = match read_private_json(path, limit, kind, home) {
            Ok(Some(snapshot)) => snapshot,
            Ok(None) if replacement_candidate(path) => {
                std::thread::yield_now();
                continue;
            }
            Ok(None) => return Ok(None),
            Err(_cause)
                if replacement_candidate(path)
                    && fs::symlink_metadata(path).is_ok_and(|meta| meta.len() <= limit) =>
            {
                // A stable malformed payload is corruption, not a rename race.
                if guard_secure_fs::read_stable(path, limit as usize, false)
                    .is_ok_and(|current| crate::strict_json_value(&current.bytes).is_err())
                {
                    return Err(error("install_metadata_invalid"));
                }
                std::thread::yield_now();
                continue;
            }
            Err(_cause) => {
                #[cfg(test)]
                eprintln!("private_read first read rejected: {_cause}");
                return Err(error("install_metadata_invalid"));
            }
        };
        let stable = match guard_secure_fs::read_stable(path, limit as usize, false) {
            Ok(stable) => stable,
            Err(cause) if atomic_replacement(path, &cause) => {
                std::thread::yield_now();
                continue;
            }
            Err(_cause) => {
                #[cfg(test)]
                eprintln!("private_read stable read rejected: {_cause:?}");
                return Err(error("install_metadata_invalid"));
            }
        };
        if stable.bytes == bytes {
            return crate::strict_json::from_value(value)
                .map(Some)
                .map_err(|_| {
                    #[cfg(test)]
                    eprintln!("private_read typed decode rejected");
                    error("install_metadata_invalid")
                });
        }
    }
    Err(error("install_metadata_changed"))
}
fn atomic_replacement(path: &Path, cause: &guard_secure_fs::SecureReadError) -> bool {
    use guard_secure_fs::SecureReadError;
    if matches!(
        cause,
        SecureReadError::Changed | SecureReadError::PathChanged
    ) {
        return true;
    }
    // A rename can invalidate any stage of the descriptor walk. Retry other
    // read errors only if the current named leaf is private and single-linked.
    if matches!(cause, SecureReadError::TooLarge) {
        return false;
    }
    if replacement_candidate(path) {
        return true;
    }
    let _ = path;
    false
}
fn replacement_candidate(path: &Path) -> bool {
    #[cfg(windows)]
    {
        let Some(parent) = path
            .parent()
            .and_then(|parent| fs::symlink_metadata(parent).ok())
        else {
            return false;
        };
        fs::symlink_metadata(path).is_ok_and(|meta| {
            parent.is_dir() && guard_cigar_artifacts::host::private_file(path, &meta)
        })
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let Some(parent) = path
            .parent()
            .and_then(|parent| fs::symlink_metadata(parent).ok())
        else {
            return false;
        };
        fs::symlink_metadata(path).is_ok_and(|meta| {
            parent.is_dir()
                && meta.is_file()
                && meta.nlink() == 1
                && meta.uid() == parent.uid()
                && meta.permissions().mode() & 0o077 == 0
                && meta.permissions().mode() & 0o400 != 0
        })
    }
}
pub(super) fn temporary_name(name: &str) -> bool {
    let Some(name) = name
        .strip_prefix('.')
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    let mut parts = name.rsplitn(3, '.');
    let (Some(stamp), Some(pid), Some(file)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let Some(stem) = file
        .strip_suffix(".cancel.json")
        .or_else(|| file.strip_suffix(".json"))
    else {
        return false;
    };
    is_lower_hex(stem, 64)
        && !stamp.is_empty()
        && stamp.len() <= 32
        && stamp.bytes().all(|b| b.is_ascii_digit())
        && !pid.is_empty()
        && pid.len() <= 10
        && pid.bytes().all(|b| b.is_ascii_digit())
}
pub(super) fn get(home: &Path, job_id: &str) -> Result<Option<Job>, String> {
    if !valid_id(job_id) {
        return Err(error("install_request_invalid"));
    }
    let path = home.join("context-assistance/jobs");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(error("install_storage_unavailable")),
        Ok(_) => {}
    }
    let path = directory(home, "jobs", false)?.join(record_name(job_id));
    let job: Option<Job> = private_read(home, &path, MAX_JOB_BYTES, "cigar_install_job")?;
    if let Some(job) = &job {
        job.validate()?;
        if job.request.job_id != job_id {
            return Err(error("install_job_invalid"));
        }
    }
    Ok(job)
}
pub(super) fn save(home: &Path, job: &mut Job, phase: Phase, code: &str) -> Result<(), String> {
    job.phase = phase;
    job.code = code.into();
    job.updated_at_ms = now()?.max(job.updated_at_ms);
    job.validate()?;
    let path = directory(home, "jobs", true)?.join(record_name(&job.request.job_id));
    let bytes = serde_json::to_vec(job).map_err(|_| error("install_job_invalid"))?;
    persist_private_bytes(&path, &bytes, MAX_JOB_BYTES, "cigar_install_job", home)
        .map_err(|_| error("install_job_write_failed"))
}
pub(super) fn list(home: &Path) -> Result<Vec<Job>, String> {
    let path = home.join("context-assistance/jobs");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(error("install_storage_unavailable")),
        Ok(_) => {}
    }
    let directory = directory(home, "jobs", false)?;
    let mut jobs = Vec::new();
    for (index, entry) in fs::read_dir(directory)
        .map_err(|_| error("install_storage_unavailable"))?
        .take(MAX_JOBS * 4 + 5)
        .enumerate()
    {
        if index >= MAX_JOBS * 4 + 4 {
            return Err(error("install_job_limit"));
        }
        let entry = entry.map_err(|_| error("install_storage_unavailable"))?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| error("install_job_invalid"))?;
        if name == "preparation.lock" {
            continue;
        }
        if temporary_name(name) {
            continue;
        }
        if let Some(stem) = name.strip_suffix(".cancel.json") {
            if is_lower_hex(stem, 64) {
                continue;
            }
        }
        if name.len() != 69
            || !name.is_ascii()
            || !name.ends_with(".json")
            || !is_lower_hex(&name[..64], 64)
        {
            return Err(error("install_job_invalid"));
        }
        let job: Job = private_read(home, &entry.path(), MAX_JOB_BYTES, "cigar_install_job")?
            .ok_or_else(|| error("install_job_invalid"))?;
        job.validate()?;
        if record_name(&job.request.job_id) != name {
            return Err(error("install_job_invalid"));
        }
        jobs.push(job);
        if jobs.len() > MAX_JOBS {
            return Err(error("install_job_limit"));
        }
    }
    jobs.sort_by(|a, b| {
        b.created_at_ms
            .cmp(&a.created_at_ms)
            .then(a.request.job_id.cmp(&b.request.job_id))
    });
    Ok(jobs)
}
pub(super) fn lease(home: &Path) -> Result<fs::File, String> {
    lifecycle_lease::acquire(home)
}
pub(super) fn cancel_path(home: &Path, job_id: &str) -> Result<PathBuf, String> {
    if !valid_id(job_id) {
        return Err(error("install_request_invalid"));
    }
    Ok(directory(home, "jobs", false)?.join(format!(
        "{}.cancel.json",
        record_name(job_id).trim_end_matches(".json")
    )))
}
pub(super) fn mark_cancel(home: &Path, job: &Job) -> Result<(), String> {
    let bytes = serde_json::to_vec(&json!({"schema":"guard-cigar-install-cancel.v1","job_id":job.request.job_id,"request_sha256":job.request_sha256}))
        .map_err(|_| error("install_job_invalid"))?;
    persist_private_bytes(
        &cancel_path(home, &job.request.job_id)?,
        &bytes,
        4096,
        "cigar_install_job",
        home,
    )
    .map_err(|_| error("install_job_write_failed"))
}

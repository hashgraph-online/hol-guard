//! Durable interpreter setup metadata. No record alone authorizes execution.
use super::*;
use guard_cigar_release::InterpreterBinding;
pub(super) use store::Phase;
const LIMIT: u64 = 32 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SetupInterpreterRequest {
    pub job_id: String,
    pub build_id: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Job {
    pub schema: String,
    pub request: SetupInterpreterRequest,
    pub request_sha256: String,
    pub python: InterpreterBinding,
    pub slot: String,
    pub interpreter_id: Option<String>,
    pub phase: Phase,
    pub code: String,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub deadline_at_ms: u64,
}
pub(super) fn request_sha(request: &SetupInterpreterRequest) -> Result<String, String> {
    if !valid_id(&request.job_id) || !valid_id(&request.build_id) {
        return Err(error("python_setup_request_invalid"));
    }
    let bytes = serde_json::to_vec(&("guard-cigar-python-setup-request.v1", request))
        .map_err(|_| error("python_setup_request_invalid"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
impl Job {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != "guard-cigar-python-setup-job.v1"
            || self.request_sha256 != request_sha(&self.request)?
            || self.request.build_id != self.python.build_id
            || self.python.slot_id().map_err(|e| error(e.code()))? != self.slot
            || self.interpreter_id.as_ref().is_some_and(|id| !valid_id(id))
            || self.phase == Phase::Ready && self.interpreter_id.is_none()
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
            return Err(error("python_setup_job_invalid"));
        }
        Ok(())
    }
}
pub(super) fn get(home: &Path, id: &str) -> Result<Option<Job>, String> {
    if !valid_id(id) {
        return Err(error("python_setup_request_invalid"));
    }
    match fs::symlink_metadata(home.join("context-assistance/python-jobs")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(error("install_storage_unavailable")),
        Ok(_) => {}
    }
    let path = store::directory(home, "python-jobs", false)?.join(record_name(id));
    let job: Option<Job> = store::private_read(home, &path, LIMIT, "cigar_python_job")?;
    if let Some(job) = &job {
        job.validate()?;
        if job.request.job_id != id {
            return Err(error("python_setup_job_invalid"));
        }
    }
    Ok(job)
}
pub(super) fn save(home: &Path, job: &mut Job, phase: Phase, code: &str) -> Result<(), String> {
    job.phase = phase;
    job.code = code.into();
    job.updated_at_ms = store::now()?.max(job.updated_at_ms);
    job.validate()?;
    let path = store::directory(home, "python-jobs", true)?.join(record_name(&job.request.job_id));
    persist_private_bytes(
        &path,
        &serde_json::to_vec(job).map_err(|_| error("python_setup_job_invalid"))?,
        LIMIT,
        "cigar_python_job",
        home,
    )
    .map_err(|_| error("python_setup_job_write_failed"))
}
pub(super) fn list(home: &Path) -> Result<Vec<Job>, String> {
    match fs::symlink_metadata(home.join("context-assistance/python-jobs")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(error("install_storage_unavailable")),
        Ok(_) => {}
    }
    let mut jobs = Vec::new();
    for (index, entry) in fs::read_dir(store::directory(home, "python-jobs", false)?)
        .map_err(|_| error("install_storage_unavailable"))?
        .take(store::MAX_JOBS * 4 + 5)
        .enumerate()
    {
        if index >= store::MAX_JOBS * 4 + 4 {
            return Err(error("install_job_limit"));
        }
        let entry = entry.map_err(|_| error("install_storage_unavailable"))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| error("python_setup_job_invalid"))?;
        if store::temporary_name(name)
            || name
                .strip_suffix(".cancel.json")
                .is_some_and(|stem| is_lower_hex(stem, 64))
        {
            continue;
        }
        let job: Job = store::private_read(home, &entry.path(), LIMIT, "cigar_python_job")?
            .ok_or_else(|| error("python_setup_job_invalid"))?;
        job.validate()?;
        if record_name(&job.request.job_id) != name {
            return Err(error("python_setup_job_invalid"));
        }
        jobs.push(job);
        if jobs.len() > store::MAX_JOBS {
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
pub(super) fn cancel_path(home: &Path, id: &str) -> Result<PathBuf, String> {
    if !valid_id(id) {
        return Err(error("python_setup_request_invalid"));
    }
    Ok(store::directory(home, "python-jobs", false)?.join(format!(
        "{}.cancel.json",
        record_name(id).trim_end_matches(".json")
    )))
}
pub(super) fn mark_cancel(home: &Path, job: &Job) -> Result<(), String> {
    let value = json!({"schema":"guard-cigar-python-setup-cancel.v1", "job_id":job.request.job_id,
        "request_sha256":job.request_sha256});
    persist_private_bytes(
        &cancel_path(home, &job.request.job_id)?,
        &serde_json::to_vec(&value).map_err(|_| error("python_setup_job_invalid"))?,
        4096,
        "cigar_python_job",
        home,
    )
    .map_err(|_| error("python_setup_job_write_failed"))
}

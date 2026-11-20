//! Bounded progress only; these records authorize no network or catalog data.
use super::*;
pub(super) use store::Phase;
const LIMIT: u64 = 16 * 1024;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Job {
    pub schema: String,
    pub job_id: String,
    pub request_sha256: String,
    pub feed_sha256: String,
    pub target: Option<guard_cigar_release::CatalogCheckpoint>,
    pub phase: Phase,
    pub code: String,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub deadline_at_ms: u64,
}
pub(super) fn request_sha(id: &str) -> Result<String, String> {
    if !valid_id(id) {
        return Err(error("cigar_catalog_refresh_request_invalid"));
    }
    Ok(format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&("guard-cigar-catalog-refresh-request.v1", id))
                .map_err(|_| error("cigar_catalog_refresh_request_invalid"))?
        )
    ))
}
impl Job {
    fn validate(&self) -> Result<(), String> {
        if self.schema != "guard-cigar-catalog-refresh-job.v1"
            || self.request_sha256 != request_sha(&self.job_id)?
            || !is_lower_hex(&self.feed_sha256, 64)
            || self
                .target
                .as_ref()
                .is_some_and(|c| c.revision == 0 || !is_lower_hex(&c.payload_sha256, 64))
            || self.phase == Phase::Ready && self.target.is_none()
            || !matches!(
                self.phase,
                Phase::Queued
                    | Phase::Acquiring
                    | Phase::Publishing
                    | Phase::Ready
                    | Phase::Failed
                    | Phase::Cancelled
                    | Phase::RecoveryRequired
            )
            || self.code.is_empty()
            || self.code.len() > 128
            || !self
                .code
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            || self.updated_at_ms < self.created_at_ms
            || self.deadline_at_ms <= self.created_at_ms
            || self.deadline_at_ms - self.created_at_ms > 30_000
        {
            return Err(error("cigar_catalog_refresh_job_invalid"));
        }
        Ok(())
    }
}
pub(super) fn get(home: &Path, id: &str) -> Result<Option<Job>, String> {
    request_sha(id)?;
    match fs::symlink_metadata(home.join("context-assistance/catalog-jobs")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(error("install_storage_unavailable")),
        Ok(_) => {}
    }
    let path = store::directory(home, "catalog-jobs", false)?.join(record_name(id));
    let job: Option<Job> = store::private_read(home, &path, LIMIT, "cigar_catalog_job")?;
    if let Some(j) = &job {
        j.validate()?;
        if j.job_id != id {
            return Err(error("cigar_catalog_refresh_job_invalid"));
        }
    }
    Ok(job)
}
pub(super) fn save(home: &Path, job: &mut Job, phase: Phase, code: &str) -> Result<(), String> {
    job.phase = phase;
    job.code = code.into();
    job.updated_at_ms = store::now()?.max(job.updated_at_ms);
    job.validate()?;
    let path = store::directory(home, "catalog-jobs", true)?.join(record_name(&job.job_id));
    persist_private_bytes(
        &path,
        &serde_json::to_vec(job).map_err(|_| error("cigar_catalog_refresh_job_invalid"))?,
        LIMIT,
        "cigar_catalog_job",
        home,
    )
    .map_err(|_| error("cigar_catalog_refresh_job_write_failed"))
}
pub(super) fn list(home: &Path) -> Result<Vec<Job>, String> {
    match fs::symlink_metadata(home.join("context-assistance/catalog-jobs")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(error("install_storage_unavailable")),
        Ok(_) => {}
    }
    let mut jobs = Vec::new();
    for (i, entry) in fs::read_dir(store::directory(home, "catalog-jobs", false)?)
        .map_err(|_| error("install_storage_unavailable"))?
        .take(store::MAX_JOBS * 4 + 5)
        .enumerate()
    {
        if i >= store::MAX_JOBS * 4 + 4 {
            return Err(error("install_job_limit"));
        }
        let entry = entry.map_err(|_| error("install_storage_unavailable"))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| error("cigar_catalog_refresh_job_invalid"))?;
        if store::temporary_name(name)
            || name
                .strip_suffix(".cancel.json")
                .is_some_and(|s| is_lower_hex(s, 64))
        {
            continue;
        }
        let job: Job = store::private_read(home, &entry.path(), LIMIT, "cigar_catalog_job")?
            .ok_or_else(|| error("cigar_catalog_refresh_job_invalid"))?;
        job.validate()?;
        if record_name(&job.job_id) != name {
            return Err(error("cigar_catalog_refresh_job_invalid"));
        }
        jobs.push(job);
        if jobs.len() > store::MAX_JOBS {
            return Err(error("install_job_limit"));
        }
    }
    Ok(jobs)
}
pub(super) fn cancel_path(home: &Path, id: &str) -> Result<PathBuf, String> {
    request_sha(id)?;
    Ok(store::directory(home, "catalog-jobs", false)?.join(format!(
        "{}.cancel.json",
        record_name(id).trim_end_matches(".json")
    )))
}
pub(super) fn mark_cancel(home: &Path, job: &Job) -> Result<(), String> {
    let v = json!({"schema":"guard-cigar-catalog-refresh-cancel.v1","job_id":job.job_id,"request_sha256":job.request_sha256});
    persist_private_bytes(
        &cancel_path(home, &job.job_id)?,
        &serde_json::to_vec(&v).map_err(|_| error("cigar_catalog_refresh_job_invalid"))?,
        4096,
        "cigar_catalog_job",
        home,
    )
    .map_err(|_| error("cigar_catalog_refresh_job_write_failed"))
}

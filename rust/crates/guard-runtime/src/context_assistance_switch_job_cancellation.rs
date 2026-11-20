//! Cancellation binds an explicit recovery attempt. An old cancellation does
//! not silently cancel a later human-requested verification of the same target.
use super::*;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    schema: String,
    job_id: String,
    request_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_attempt_id: Option<String>,
}
fn cancel_path(home: &Path, id: &str) -> Result<PathBuf, String> {
    if !valid_id(id) {
        return Err(error("switch_request_invalid"));
    }
    Ok(directory(home, false)?.join(format!(
        "{}.cancel.json",
        record_name(id).trim_end_matches(".json")
    )))
}
pub(crate) fn mark_cancel(home: &Path, job: &SwitchJob) -> Result<(), String> {
    job.validate()?;
    let marker = Marker {
        schema: "guard-cigar-switch-cancel.v1".into(),
        job_id: job.request.job_id.clone(),
        request_sha256: job.request_sha256.clone(),
        recovery_attempt_id: job.recovery.as_ref().map(|a| a.id.clone()),
    };
    let bytes = serde_json::to_vec(&marker).map_err(|_| error("switch_job_invalid"))?;
    persist_private_bytes(
        &cancel_path(home, &job.request.job_id)?,
        &bytes,
        4096,
        "cigar_switch_cancel",
        home,
    )
    .map_err(|_| error("switch_job_write_failed"))
}
pub(crate) fn cancelled(home: &Path, job: &SwitchJob) -> Result<bool, String> {
    let marker: Option<Marker> =
        preparation::lifecycle_read(home, &cancel_path(home, &job.request.job_id)?, 4096)?;
    let Some(marker) = marker else {
        return Ok(false);
    };
    if marker.schema != "guard-cigar-switch-cancel.v1"
        || marker.job_id != job.request.job_id
        || marker.request_sha256 != job.request_sha256
        || marker
            .recovery_attempt_id
            .as_ref()
            .is_some_and(|id| !is_lower_hex(id, 32))
        || (job.recovery.is_none() && marker.recovery_attempt_id.is_some())
    {
        return Err(error("switch_job_invalid"));
    }
    Ok(marker.recovery_attempt_id.as_deref() == job.recovery.as_ref().map(|a| a.id.as_str()))
}

//! Signed metadata only. Refresh never executes SDKs or touches reviewed data.
use super::super::catalog::feed::Owner;
use super::*;
use catalog_store::{Job, Phase};
use guard_cigar_install::PreparationControl;
use guard_command::restricted_archive::RestrictedArchiveDownloadResult;
use std::time::{Duration, Instant};
#[cfg(test)]
pub(super) type TestFetch =
    Box<dyn FnOnce(&PreparationControl, Arc<AtomicBool>) -> Result<Vec<u8>, String> + Send>;
fn directory(home: &Path, job: &Job, create: bool) -> Result<PathBuf, String> {
    let parent = store::directory(home, "catalog-downloads", create)?;
    let path = parent.join(record_name(&job.job_id).trim_end_matches(".json"));
    if create {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .map_err(|_| error("cigar_catalog_download_exists"))?;
        }
        // Windows inherits the Guard home's owner-only access control list.
        #[cfg(windows)]
        fs::create_dir(&path).map_err(|_| error("cigar_catalog_download_exists"))?;
        let bytes = serde_json::to_vec(&json!({"schema":"guard-cigar-catalog-download-owner.v1","job_id":job.job_id,"request_sha256":job.request_sha256})).map_err(|_| error("cigar_catalog_refresh_job_invalid"))?;
        persist_private_bytes(
            &path.join("installation-owner.json"),
            &bytes,
            4096,
            "cigar_catalog_job",
            home,
        )
        .map_err(|_| error("cigar_catalog_refresh_job_write_failed"))?;
    }
    Ok(path)
}
pub(super) fn cleanup(home: &Path, job: &Job) -> Result<(), String> {
    let parent = home.join("context-assistance/catalog-downloads");
    match fs::symlink_metadata(&parent) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(error("install_cleanup_unsafe")),
        Ok(_) => {}
    }
    let path = directory(home, job, false)?;
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(error("install_cleanup_unsafe")),
        Ok(_) => {}
    }
    validate_private_directory(&path).map_err(|_| error("install_cleanup_unsafe"))?;
    let owner: Option<Value> = store::private_read(
        home,
        &path.join("installation-owner.json"),
        4096,
        "cigar_catalog_job",
    )?;
    match owner {
        Some(v)
            if v["schema"] == "guard-cigar-catalog-download-owner.v1"
                && v["job_id"] == job.job_id
                && v["request_sha256"] == job.request_sha256 => {}
        None if fs::read_dir(&path)
            .map_err(|_| error("install_cleanup_unsafe"))?
            .next()
            .is_none() => {}
        _ => return Err(error("install_cleanup_ownership_missing")),
    }
    let deadline = Instant::now() + Duration::from_millis(500);
    let mut items = Vec::new();
    super::cleanup::collect(&path, &mut items, &mut 0, 0, deadline)?;
    super::cleanup::remove_collected(&path, items, deadline)
}
fn fetch(
    home: &Path,
    job: &Job,
    owner: &Owner,
    control: &PreparationControl,
    cancel: Arc<AtomicBool>,
) -> Result<Vec<u8>, String> {
    worker::space(home, 4 * 1024 * 1024)?;
    let path = directory(home, job, true)?;
    let result = acquisition::fetch_catalog(
        owner.url(),
        &path,
        control
            .remaining()
            .map_err(|e| error(e.code()))?
            .as_secs_f64(),
        cancel,
    )?;
    let downloaded = match result {
        RestrictedArchiveDownloadResult::Success(v) => v,
        RestrictedArchiveDownloadResult::Failure(f) => {
            control.checkpoint().map_err(|e| error(e.code()))?;
            return Err(error(&f.code));
        }
    };
    let raw = (|| {
        control.checkpoint().map_err(|e| error(e.code()))?;
        let input = guard_secure_fs::read_stable(
            &downloaded.path,
            guard_cigar_release::MAX_ENVELOPE_BYTES,
            false,
        )
        .map_err(|_| error("cigar_catalog_download_unreadable"))?;
        if input.bytes.len() as u64 != downloaded.size || input.sha256 != downloaded.sha256 {
            return Err(error("cigar_catalog_download_changed"));
        }
        Ok(input.bytes)
    })();
    downloaded.cleanup();
    raw
}
pub(super) fn run(
    home: &Path,
    job: &mut Job,
    owner: &Owner,
    cancel: Arc<AtomicBool>,
    #[cfg(test)] test_fetch: Option<TestFetch>,
) -> Result<(), String> {
    let remaining = job.deadline_at_ms.saturating_sub(store::now()?).min(30_000);
    if remaining == 0 {
        return Err(error("cigar_catalog_refresh_deadline_exceeded"));
    }
    let deadline = worker::Deadline::new(
        Arc::clone(&cancel),
        Duration::from_millis(remaining),
        catalog_store::cancel_path(home, &job.job_id)?,
    )?;
    let control = PreparationControl::new(Arc::clone(&cancel), Duration::from_millis(remaining))
        .map_err(|e| error(e.code()))?;
    let result = (|| {
        worker::policy(home)?;
        acquisition::catalog_network_policy()?;
        catalog_store::save(home, job, Phase::Acquiring, "acquiring")?;
        #[cfg(test)]
        let raw = if let Some(f) = test_fetch {
            f(&control, Arc::clone(&cancel))?
        } else {
            fetch(home, job, owner, &control, Arc::clone(&cancel))?
        };
        #[cfg(not(test))]
        let raw = fetch(home, job, owner, &control, Arc::clone(&cancel))?;
        control.checkpoint().map_err(|e| error(e.code()))?;
        worker::policy(home)?;
        acquisition::catalog_network_policy()?;
        cleanup(home, job)?;
        owner.publish(&raw, |checkpoint| {
            control.checkpoint().map_err(|e| error(e.code()))?;
            job.target = Some(checkpoint.clone());
            catalog_store::save(home, job, Phase::Publishing, "publishing")
        })?;
        catalog_store::save(home, job, Phase::Ready, "ok")
    })();
    // A completed publication wins a late cancellation; progress never rolls
    // metadata back. Interrupted publishing is reconciled explicitly.
    result.map_err(|c| {
        if deadline.expired() {
            error("cigar_catalog_refresh_deadline_exceeded")
        } else {
            c
        }
    })
}
pub(super) fn fail(home: &Path, job: &mut Job, code: &str) -> Result<(), String> {
    if cleanup(home, job).is_err() {
        return catalog_store::save(
            home,
            job,
            Phase::RecoveryRequired,
            "cigar_catalog_cleanup_pending",
        );
    }
    let phase = if job.target.is_some() {
        Phase::RecoveryRequired
    } else if code.ends_with("_cancelled") {
        Phase::Cancelled
    } else {
        Phase::Failed
    };
    catalog_store::save(home, job, phase, code)
}
pub(super) fn recover(home: &Path, job: &mut Job) -> Result<(), String> {
    let target = job.target.clone();
    super::super::catalog::feed::reconcile(home, target.as_ref(), |published| {
        cleanup(home, job)?;
        if published {
            return catalog_store::save(home, job, Phase::Ready, "ok");
        }
        let cancelled =
            fs::symlink_metadata(catalog_store::cancel_path(home, &job.job_id)?).is_ok();
        catalog_store::save(
            home,
            job,
            if cancelled {
                Phase::Cancelled
            } else {
                Phase::Failed
            },
            if cancelled {
                "cigar_catalog_refresh_cancelled"
            } else {
                "cigar_catalog_refresh_interrupted"
            },
        )
    })
}

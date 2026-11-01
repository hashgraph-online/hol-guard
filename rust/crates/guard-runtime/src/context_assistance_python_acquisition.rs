//! Interpreter acquisition uses the same native policy, pinned public peer,
//! cancellation and exact-byte checks as SDK acquisition.
use super::*;
use guard_cigar_release::ResolvedInterpreterBuild;
pub(super) fn acquire(
    home: &Path,
    job: &python_store::Job,
    build: &ResolvedInterpreterBuild,
    control: &PreparationControl,
    cancel: Arc<AtomicBool>,
) -> Result<PathBuf, String> {
    control.checkpoint().map_err(|e| error(e.code()))?;
    if let Some(path) = python_cache::cached(home, build)? {
        return Ok(path);
    }
    worker::policy(home)?;
    let allow_public_registries = policy::direct_allowed()?;
    worker::space(home, build.build().archive_bytes.saturating_mul(2))?;
    let id = record_name(&job.request.job_id);
    let downloads = worker::child(home, "python-downloads", id.trim_end_matches(".json"))?;
    python_worker::create_owned(home, &downloads, job)?;
    let temporary = worker::private_child(home, &downloads, "temporary")?;
    let url = build.build().download_url().map_err(|e| error(e.code()))?;
    let remaining = control.remaining().map_err(|e| error(e.code()))?;
    let result = download_restricted_archive(
        &url,
        build.build().archive_bytes,
        3,
        remaining.as_secs_f64(),
        Some(&temporary),
        &transport::Resolver {
            cancel: Arc::clone(&cancel),
        },
        &transport::Transport {
            source: &url,
            cancel,
            allow_public_registries,
        },
    );
    let download = match result {
        RestrictedArchiveDownloadResult::Success(value) => value,
        RestrictedArchiveDownloadResult::Failure(failure) => {
            control.checkpoint().map_err(|e| error(e.code()))?;
            return Err(error(&failure.code));
        }
    };
    let outcome = (|| {
        control.checkpoint().map_err(|e| error(e.code()))?;
        if download.size != build.build().archive_bytes
            || download.sha256 != build.build().archive_sha256
        {
            return Err(error("install_artifact_mismatch"));
        }
        let input = guard_secure_fs::read_stable(&download.path, 128 * 1024 * 1024, false)
            .map_err(|_| error("install_artifact_unreadable"))?;
        control.checkpoint().map_err(|e| error(e.code()))?;
        worker::policy(home)?;
        policy::direct_allowed()?;
        python_cache::publish(home, build, &input.bytes)
    })();
    download.cleanup();
    let path = outcome?;
    python_cleanup::downloads(home, job)?;
    Ok(path)
}

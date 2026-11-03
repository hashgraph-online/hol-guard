//! Exact trusted wheel acquisition; no index resolution or package execution.
use super::*;
use guard_cigar_install::PreparationControl;
use guard_cigar_release::{ResolvedRelease, WheelLock};
use guard_command::restricted_archive::{
    download_restricted_archive, RestrictedArchiveDownloadResult,
};
use std::collections::BTreeMap;
use std::sync::{atomic::AtomicBool, Arc};
#[path = "context_assistance_python_acquisition.rs"]
mod private_python;
pub(super) fn acquire_python(
    home: &Path,
    job: &python_store::Job,
    build: &guard_cigar_release::ResolvedInterpreterBuild,
    control: &PreparationControl,
    cancel: Arc<AtomicBool>,
) -> Result<PathBuf, String> {
    private_python::acquire(home, job, build, control, cancel)
}

#[path = "context_assistance_acquisition_policy.rs"]
mod policy;
#[path = "context_assistance_acquisition_transport.rs"]
mod transport;
/// Reuse native machine network policy without widening the feed or using
/// caller-supplied proxy/trust material.
pub(super) fn catalog_network_policy() -> Result<(), String> {
    policy::direct_allowed().map(|_| ())
}
pub(super) fn fetch_catalog(
    source: &str,
    directory: &Path,
    seconds: f64,
    cancel: Arc<AtomicBool>,
) -> Result<RestrictedArchiveDownloadResult, String> {
    let allowed = policy::direct_allowed()?;
    Ok(catalog_download(
        source,
        directory,
        seconds,
        &transport::Resolver {
            cancel: Arc::clone(&cancel),
        },
        &transport::Transport {
            source,
            cancel,
            allow_public_registries: allowed,
        },
    ))
}
fn catalog_download(
    source: &str,
    directory: &Path,
    seconds: f64,
    resolver: &dyn guard_command::restricted_archive::DnsResolver,
    transport: &dyn guard_command::restricted_archive::PinnedHttpsTransport,
) -> RestrictedArchiveDownloadResult {
    download_restricted_archive(
        source,
        guard_cigar_release::MAX_ENVELOPE_BYTES as u64,
        0,
        seconds,
        Some(directory),
        resolver,
        transport,
    )
}

pub(super) fn acquire(
    home: &Path,
    job: &store::Job,
    release: &ResolvedRelease,
    control: &PreparationControl,
    cancel: Arc<AtomicBool>,
) -> Result<BTreeMap<String, PathBuf>, String> {
    let locks: Vec<_> = release
        .platform()
        .wheel
        .iter()
        .chain(&release.platform().dependencies)
        .collect();
    let mut result = BTreeMap::new();
    let mut missing = Vec::new();
    for lock in locks {
        control.checkpoint().map_err(|e| error(e.code()))?;
        if let Some(path) = cache::cached(home, lock)? {
            result.insert(lock.filename.clone(), path);
        } else {
            missing.push((
                lock,
                lock.download_url()
                    .map_err(|e| error(e.code()))?
                    .ok_or_else(|| error("offline_artifacts_required"))?,
            ));
        }
    }
    if missing.is_empty() {
        return Ok(result);
    }
    let allow_public_registries = policy::direct_allowed()?;
    // Check every origin before the first request, including the dependency
    // registry refusal. Network policy is loaded again at each file boundary.
    for (_, url) in &missing {
        if !allow_public_registries && url.starts_with("https://files.pythonhosted.org/") {
            return Err(error("managed_public_registry_disabled"));
        }
    }
    let id = record_name(&job.request.job_id);
    let downloads = worker::child(home, "downloads", id.trim_end_matches(".json"))?;
    worker::create_owned(home, &downloads, job)?;
    let temporary = worker::private_child(home, &downloads, "temporary")?;
    for (lock, url) in missing {
        worker::policy(home)?;
        let allowed = policy::direct_allowed()?;
        worker::space(home, lock.bytes.saturating_mul(2))?;
        let path = fetch(
            home,
            lock,
            &url,
            &temporary,
            control,
            Arc::clone(&cancel),
            allowed,
        )?;
        result.insert(lock.filename.clone(), path);
    }
    cleanup::downloads(home, job)?;
    Ok(result)
}
fn fetch(
    home: &Path,
    lock: &WheelLock,
    url: &str,
    temporary: &Path,
    control: &PreparationControl,
    cancel: Arc<AtomicBool>,
    allow_public_registries: bool,
) -> Result<PathBuf, String> {
    let remaining = control.remaining().map_err(|e| error(e.code()))?;
    let result = download_restricted_archive(
        url,
        lock.bytes,
        3,
        remaining.as_secs_f64(),
        Some(temporary),
        &transport::Resolver {
            cancel: Arc::clone(&cancel),
        },
        &transport::Transport {
            source: url,
            cancel,
            allow_public_registries,
        },
    );
    commit_download(home, lock, result, control)
}
fn commit_download(
    home: &Path,
    lock: &WheelLock,
    result: RestrictedArchiveDownloadResult,
    control: &PreparationControl,
) -> Result<PathBuf, String> {
    let downloaded = match result {
        RestrictedArchiveDownloadResult::Success(value) => value,
        RestrictedArchiveDownloadResult::Failure(failure) => {
            control.checkpoint().map_err(|e| error(e.code()))?;
            return Err(error(&failure.code));
        }
    };
    // Signed redirect queries stay only in this stack frame, never job state,
    // installation metadata, diagnostics or qualification receipts.
    let outcome = (|| {
        control.checkpoint().map_err(|e| error(e.code()))?;
        if downloaded.size != lock.bytes || downloaded.sha256 != lock.sha256 {
            return Err(error("install_artifact_mismatch"));
        }
        let input = guard_secure_fs::read_stable(&downloaded.path, 128 * 1024 * 1024, false)
            .map_err(|_| error("install_artifact_unreadable"))?;
        control.checkpoint().map_err(|e| error(e.code()))?;
        worker::policy(home)?;
        if !policy::direct_allowed()?
            && matches!(
                lock.source,
                guard_cigar_release::WheelSource::PypiFile { .. }
            )
        {
            return Err(error("managed_public_registry_disabled"));
        }
        cache::publish(home, lock, &input.bytes)
    })();
    downloaded.cleanup();
    outcome
}

#[cfg(test)]
#[path = "context_assistance_acquisition_tests.rs"]
mod tests;

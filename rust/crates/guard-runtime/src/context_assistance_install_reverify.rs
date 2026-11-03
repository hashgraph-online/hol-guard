//! Reverification runs a fresh isolated SDK beside the live actor. It never
//! writes the registered bundle/work directory, user data, settings or grants.
use super::*;
use guard_cigar_install::{PreparationControl, VerifiedPythonSnapshot};
use guard_cigar_release::ResolvedRelease;
#[cfg(test)]
use std::time::Duration;
use store::{Job, Phase};

pub(super) fn run(
    home: &Path,
    job: &mut Job,
    release: &ResolvedRelease,
    verified_python: Option<Arc<VerifiedPythonSnapshot>>,
    cancel: Arc<AtomicBool>,
    control: &PreparationControl,
    #[cfg(test)] pause: Option<InstallPause>,
) -> Result<(), String> {
    let record = load(home, &job.runtime_id)?;
    let target = job
        .refresh
        .as_ref()
        .ok_or_else(|| error("install_job_invalid"))?;
    if reuse::record_sha(&record)? != target.prior_record_sha256
        || !worker::matches_installation(job, &record, None)
    {
        return Err(error("verification_conflict"));
    }
    let id = record_name(&job.request.job_id);
    let scratch = worker::child(home, "verification", id.trim_end_matches(".json"))?;
    worker::create_owned(home, &scratch, job)?;
    store::save(home, job, Phase::Verifying, "verifying")?;
    let mut selection = record.selection.clone();
    selection.work_dir = scratch.clone();
    selection.verified_python = verified_python;
    let approval = guard_context_assistance::inspect_release_bundle(&selection, release)
        .map_err(|e| error(e.code()))?;
    if approval != record.approval {
        return Err(error("installation_conflict"));
    }
    let mut runtime =
        VerifiedRuntime::start_release_cancellable(selection, &approval, release, cancel)
            .map_err(|e| error(e.code()))?;
    let result = (|| {
        if runtime.status().interpreter != record.interpreter {
            return Err(error("interpreter_changed"));
        }
        let qualification = worker::private_child(home, &scratch, "qualification")?;
        worker::verify_features(&mut runtime, &qualification, release)?;
        #[cfg(test)]
        if let Some(pause) = pause {
            pause
                .entered
                .send(())
                .map_err(|_| error("install_test_pause_closed"))?;
            loop {
                control.checkpoint().map_err(|e| error(e.code()))?;
                match pause.proceed.recv_timeout(Duration::from_millis(25)) {
                    Ok(()) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(_) => return Err(error("install_test_pause_closed")),
                }
            }
        }
        control.checkpoint().map_err(|e| error(e.code()))?;
        worker::policy(home)?;
        store::save(home, job, Phase::Publishing, "publishing")?;
        let baseline = job
            .refresh
            .as_ref()
            .ok_or_else(|| error("install_job_invalid"))?
            .prior_record_sha256
            .clone();
        versioned::publish_refresh_verified(
            home,
            &record,
            &baseline,
            &job.request.job_id,
            release,
            &mut runtime,
        )?;
        Ok(())
    })();
    runtime.close();
    result?;
    if cleanup::verification(home, job).is_err() {
        return store::save(
            home,
            job,
            Phase::RecoveryRequired,
            "verification_cleanup_pending",
        );
    }
    store::save(home, job, Phase::Ready, "ok")
}
pub(super) fn fail(home: &Path, job: &mut Job, code: &str) -> Result<(), String> {
    let old = job
        .refresh
        .as_ref()
        .ok_or_else(|| error("install_job_invalid"))?;
    let record = match load(home, &job.runtime_id) {
        Ok(record) => record,
        Err(_) => return store::save(home, job, Phase::RecoveryRequired, "verification_conflict"),
    };
    if reuse::record_sha(&record)? != old.prior_record_sha256 {
        return store::save(
            home,
            job,
            Phase::RecoveryRequired,
            "verification_publication_unknown",
        );
    }
    if cleanup::verification(home, job).is_err() {
        return store::save(
            home,
            job,
            Phase::RecoveryRequired,
            "verification_cleanup_pending",
        );
    }
    store::save(
        home,
        job,
        if code.ends_with("_cancelled") {
            Phase::Cancelled
        } else {
            Phase::Failed
        },
        code,
    )
}
pub(super) fn recover(home: &Path, job: &mut Job) -> Result<(), String> {
    let _lease = store::lease(home)?;
    let target = job
        .refresh
        .as_ref()
        .ok_or_else(|| error("install_job_invalid"))?;
    let record = match load(home, &job.runtime_id) {
        Ok(record) => record,
        Err(_) => return store::save(home, job, Phase::RecoveryRequired, "verification_conflict"),
    };
    let committed = match reuse::committed(home, job, &record) {
        Ok(value) => value,
        Err(_) => return store::save(home, job, Phase::RecoveryRequired, "verification_conflict"),
    };
    if !committed && reuse::record_sha(&record)? != target.prior_record_sha256 {
        return store::save(home, job, Phase::RecoveryRequired, "verification_conflict");
    }
    if committed && validate_selection(home, &job.runtime_id).is_err() {
        return store::save(
            home,
            job,
            Phase::RecoveryRequired,
            "installation_recheck_required",
        );
    }
    if cleanup::verification(home, job).is_err() {
        return store::save(
            home,
            job,
            Phase::RecoveryRequired,
            "verification_cleanup_pending",
        );
    }
    if committed {
        return store::save(home, job, Phase::Ready, "ok");
    }
    let cancelled = fs::symlink_metadata(store::cancel_path(home, &job.request.job_id)?).is_ok();
    store::save(
        home,
        job,
        if cancelled {
            Phase::Cancelled
        } else {
            Phase::Failed
        },
        if cancelled {
            "install_cancelled"
        } else {
            "verification_interrupted"
        },
    )
}

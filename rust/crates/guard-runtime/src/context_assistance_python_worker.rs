//! Interpreter setup only. No SDK actor, preferences, source scopes or grants.
use super::*;
use guard_cigar_install::{prepare_python, verify_python_tree, PreparationControl};
use guard_cigar_release::ResolvedInterpreterBuild;
use python_store::{Job, Phase};
use std::time::Duration;

pub(super) fn create_owned(home: &Path, path: &Path, job: &Job) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|_| error("install_slot_exists"))?;
    }
    // Windows inherits the Guard home's owner-only access control list.
    #[cfg(windows)]
    fs::create_dir(path).map_err(|_| error("install_slot_exists"))?;
    let marker = json!({"schema":"guard-cigar-python-install-owner.v1", "job_id":job.request.job_id,
        "request_sha256":job.request_sha256,"slot":job.slot});
    persist_private_bytes(
        &path.join("installation-owner.json"),
        &serde_json::to_vec(&marker).map_err(|_| error("python_setup_job_invalid"))?,
        4096,
        "cigar_python_job",
        home,
    )
    .map_err(|_| error("install_storage_unavailable"))
}
pub(super) fn published(
    home: &Path,
    job: &Job,
) -> Result<Option<interpreters::Interpreter>, String> {
    for value in interpreters::interpreters(home)? {
        let id = value["interpreter_id"]
            .as_str()
            .ok_or_else(|| error("interpreter_invalid"))?;
        let record = interpreters::load_interpreter(home, id)?;
        let Some(managed) = &record.managed_python else {
            continue;
        };
        if managed
            .selection
            .binding
            .slot_id()
            .map_err(|e| error(e.code()))?
            != job.slot
        {
            continue;
        }
        if managed.selection.binding != job.python
            || job
                .interpreter_id
                .as_ref()
                .is_some_and(|expected| expected != id)
        {
            return Err(error("interpreter_conflict"));
        }
        return Ok(Some(record));
    }
    Ok(None)
}
pub(super) fn run(
    home: &Path,
    job: &mut Job,
    build: &ResolvedInterpreterBuild,
    cancel: Arc<AtomicBool>,
    #[cfg(test)] pause: Option<InstallPause>,
) -> Result<(), String> {
    let remaining = job
        .deadline_at_ms
        .saturating_sub(store::now()?)
        .min(120_000);
    if remaining == 0 {
        return Err(error("install_deadline_exceeded"));
    }
    let deadline = worker::Deadline::new(
        Arc::clone(&cancel),
        Duration::from_millis(remaining),
        python_store::cancel_path(home, &job.request.job_id)?,
    )?;
    let control = PreparationControl::new(Arc::clone(&cancel), Duration::from_millis(remaining))
        .map_err(|e| error(e.code()))?;
    let outcome = (|| {
        worker::policy(home)?;
        if !build.setup_qualified()
            || build.build().binding().map_err(|e| error(e.code()))? != job.python
        {
            return Err(error("interpreter_invalid"));
        }
        if let Some(existing) = published(home, job)? {
            managed_python::verify_for_use(home, &existing, &control)?;
            job.interpreter_id = Some(existing.interpreter_id);
            return python_store::save(home, job, Phase::Ready, "ok");
        }
        python_store::save(home, job, Phase::Acquiring, "acquiring")?;
        let archive = acquisition::acquire_python(home, job, build, &control, Arc::clone(&cancel))?;
        let plan = prepare_python(build, &archive, &control).map_err(|e| error(e.code()))?;
        worker::space(home, plan.bytes())?;
        let id = record_name(&job.request.job_id);
        let stage = worker::child(home, "python-staging", id.trim_end_matches(".json"))?;
        let destination = worker::child(home, "python", &job.slot)?;
        let work = worker::child(home, "python-work", &job.slot)?;
        if fs::symlink_metadata(&destination).is_ok() || fs::symlink_metadata(&work).is_ok() {
            return Err(error("install_slot_exists"));
        }
        python_store::save(home, job, Phase::Extracting, "extracting")?;
        create_owned(home, &stage, job)?;
        let python = worker::private_child(home, &stage, "python")?;
        plan.write_into(&python, &control)
            .map_err(|e| error(e.code()))?;
        create_owned(home, &work, job)?;
        control.checkpoint().map_err(|e| error(e.code()))?;
        fs::rename(&stage, &destination).map_err(|_| error("install_publish_failed"))?;
        // NTFS journals directory entries itself, and a directory cannot be
        // opened for flushing through `File::open` there.
        #[cfg(unix)]
        for path in [&stage, &destination] {
            fs::File::open(path.parent().ok_or_else(|| error("install_path_invalid"))?)
                .and_then(|file| file.sync_all())
                .map_err(|_| error("install_publish_failed"))?;
        }
        python_store::save(home, job, Phase::Verifying, "verifying")?;
        let bundle = verify_python_tree(build, &destination.join("python"), &control)
            .map_err(|e| error(e.code()))?;
        let observed = guard_context_assistance::probe_private_interpreter_cancellable(
            &bundle,
            &work,
            Arc::clone(&cancel),
        )
        .map_err(|e| error(e.code()))?;
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
        python_store::save(home, job, Phase::Publishing, "publishing")?;
        let record = managed_python::publish(home, &bundle, &observed, &control)?;
        job.interpreter_id = Some(record.interpreter_id);
        // A completed publication wins a late cancellation, just like SDK jobs.
        python_store::save(home, job, Phase::Ready, "ok")
    })();
    outcome.map_err(|code| {
        if deadline.expired() {
            error("install_deadline_exceeded")
        } else {
            code
        }
    })
}
pub(super) fn fail(home: &Path, job: &mut Job, code: &str) -> Result<(), String> {
    match published(home, job) {
        Ok(None) => {}
        _ => {
            return python_store::save(
                home,
                job,
                Phase::RecoveryRequired,
                "interpreter_publication_unknown",
            )
        }
    }
    if python_cleanup::cleanup(home, job).is_err() {
        return python_store::save(
            home,
            job,
            Phase::RecoveryRequired,
            "install_cleanup_pending",
        );
    }
    python_store::save(
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
    match published(home, job) {
        Ok(Some(record)) => {
            let control =
                PreparationControl::new(Arc::new(AtomicBool::new(false)), Duration::from_secs(30))
                    .map_err(|e| error(e.code()))?;
            if managed_python::verify_for_use(home, &record, &control).is_err() {
                return python_store::save(
                    home,
                    job,
                    Phase::RecoveryRequired,
                    "interpreter_recheck_required",
                );
            }
            job.interpreter_id = Some(record.interpreter_id);
            return python_store::save(home, job, Phase::Ready, "ok");
        }
        Err(_) => {
            return python_store::save(home, job, Phase::RecoveryRequired, "interpreter_conflict")
        }
        Ok(None) => {}
    }
    if let Err(code) = python_cleanup::cleanup(home, job) {
        return python_store::save(home, job, Phase::RecoveryRequired, &code);
    }
    let cancelled =
        fs::symlink_metadata(python_store::cancel_path(home, &job.request.job_id)?).is_ok();
    python_store::save(
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
            "install_interrupted"
        },
    )
}

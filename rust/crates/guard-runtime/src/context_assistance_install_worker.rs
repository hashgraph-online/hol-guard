//! Install-only work. No selected preference, live actor, user source or grant
//! is read/copied/changed by this worker. Publication is its commit boundary.
use super::*;
use guard_cigar_install::{prepare_locked, PreparationControl};
use guard_cigar_release::ResolvedRelease;
use guard_context_assistance::{ContextAssistanceConfig, StorageMode};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Condvar, Mutex,
};
use std::time::Duration;
use store::{Job, Phase};

pub(super) fn policy(home: &Path) -> Result<(), String> {
    if !home.is_absolute()
        || home
            .components()
            .any(|p| matches!(p, std::path::Component::ParentDir))
    {
        return Err(error("home_invalid"));
    }
    let mut source = crate::managed_policy_load::ManagedPolicySource::native();
    source.write_cache = false;
    let settings = crate::guard_config_load::context_assistance_from_source(home, &source)
        .map_err(|_| error("configuration_unavailable"))?;
    if settings.diagnostic.is_some() || !settings.verification_permitted {
        return Err(error("policy_restricted"));
    }
    Ok(())
}
pub(super) fn space(home: &Path, bytes: u64) -> Result<(), String> {
    #[cfg(unix)]
    let available = {
        let info =
            nix::sys::statvfs::statvfs(home).map_err(|_| error("install_disk_unavailable"))?;
        u128::from(info.blocks_available()).saturating_mul(u128::from(info.fragment_size()))
    };
    #[cfg(windows)]
    let available =
        u128::from(fs2::available_space(home).map_err(|_| error("install_disk_unavailable"))?);
    if available < u128::from(bytes).saturating_add(64 * 1024 * 1024) {
        return Err(error("install_disk_full"));
    }
    Ok(())
}
pub(super) fn child(home: &Path, parent: &str, name: &str) -> Result<PathBuf, String> {
    if !is_lower_hex(name, 64) {
        return Err(error("install_path_invalid"));
    }
    Ok(store::directory(home, parent, true)?.join(name))
}
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
    let bytes = serde_json::to_vec(
        &json!({"schema":"guard-cigar-install-owner.v1", "job_id":job.request.job_id,
        "request_sha256":job.request_sha256,"slot":job.slot}),
    )
    .map_err(|_| error("install_job_invalid"))?;
    persist_private_bytes(
        &path.join("installation-owner.json"),
        &bytes,
        4096,
        "cigar_install_job",
        home,
    )
    .map_err(|_| error("install_storage_unavailable"))
}
pub(super) fn private_child(home: &Path, parent: &Path, name: &str) -> Result<PathBuf, String> {
    let path = parent.join(name);
    crate::resident_state::ensure_private_directory_under(&path, home, true)
        .map_err(|_| error("install_storage_unavailable"))?;
    Ok(path)
}
pub(super) fn matches_installation(
    job: &Job,
    record: &Installation,
    interpreter: Option<&interpreters::Interpreter>,
) -> bool {
    record.schema == versioned::SCHEMA_V2
        && record.runtime_id == job.runtime_id
        && record.managed_slot.as_deref() == Some(job.slot.as_str())
        && record.approval.release.as_ref() == Some(&job.release)
        && record.approval.package_tree_sha256 == job.package_tree_sha256
        && record.approval.worker_sha256 == job.worker_sha256
        && record.approval.python_sha256 == job.python_sha256
        && record.approval.python_bundle == job.python_bundle
        && interpreter.is_none_or(|value| {
            value.python == record.selection.python
                && value.facts == record.interpreter
                && value.python_bundle() == record.selection.python_bundle
        })
}
pub(super) fn verify_features(
    runtime: &mut VerifiedRuntime,
    home: &Path,
    release: &ResolvedRelease,
) -> Result<(), String> {
    let features = &release.platform().features;
    let mut config = ContextAssistanceConfig {
        runtime_id: "qualification:installation".into(),
        ..Default::default()
    };
    if features.contains(&Feature::Sharing) {
        config.features.agent_context = true;
        config.features.shared_agents = true;
        runtime
            .verify_shared_compile(&config)
            .map_err(|e| error(e.code()))?;
    }
    if features.contains(&Feature::Persistence) {
        config.storage.mode = StorageMode::Sqlite;
        runtime
            .verify_persistence_compile(home, &config)
            .map_err(|e| error(e.code()))?;
    }
    if features.contains(&Feature::ExecutionContext) {
        config.features.execution_context = true;
        runtime
            .verify_execution_handoff(&config)
            .map_err(|e| error(e.code()))?;
    }
    Ok(())
}
pub(super) fn run(
    home: &Path,
    job: &mut Job,
    release: &ResolvedRelease,
    interpreter: &interpreters::Interpreter,
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
    let deadline = Deadline::new(
        Arc::clone(&cancel),
        Duration::from_millis(remaining),
        store::cancel_path(home, &job.request.job_id)?,
    )?;
    let control = PreparationControl::new(Arc::clone(&cancel), Duration::from_millis(remaining))
        .map_err(|e| error(e.code()))?;
    policy(home)?;
    let verified_python = managed_python::verify_for_use(home, interpreter, &control)?;
    release
        .check_python_version(interpreter.facts.version)
        .map_err(|e| error(e.code()))?;
    if job.refresh.is_some() {
        return reverify::run(
            home,
            job,
            release,
            verified_python,
            cancel,
            &control,
            #[cfg(test)]
            pause,
        )
        .map_err(|code| {
            if deadline.expired() {
                error("install_deadline_exceeded")
            } else {
                code
            }
        });
    }
    if let Ok(record) = load(home, &job.runtime_id) {
        if !matches_installation(job, &record, Some(interpreter)) {
            return Err(error("installation_conflict"));
        }
        validate_selection(home, &job.runtime_id)?;
        return store::save(home, job, Phase::Ready, "ok");
    }
    let registry = root(home, true)?.join(record_name(&job.runtime_id));
    if fs::symlink_metadata(registry).is_ok() {
        return Err(error("installation_conflict"));
    }
    store::save(home, job, Phase::Acquiring, "acquiring")?;
    let inputs = acquisition::acquire(home, job, release, &control, Arc::clone(&cancel))?;
    let plan = prepare_locked(release, &inputs, &control).map_err(|e| error(e.code()))?;
    space(home, plan.bytes())?;
    if verified_python.is_none() {
        let python = guard_secure_fs::read_stable(&interpreter.python, 128 * 1024 * 1024, true)
            .map_err(|_| error("interpreter_unreadable"))?;
        if python.sha256 != interpreter.python_sha256 {
            return Err(error("interpreter_changed"));
        }
    }
    control.checkpoint().map_err(|e| error(e.code()))?;
    let stage_id = record_name(&job.request.job_id);
    let stage = child(home, "staging", stage_id.trim_end_matches(".json"))?;
    let destination = child(home, "bundles", &job.slot)?;
    let work = child(home, "work", &job.slot)?;
    if fs::symlink_metadata(&destination).is_ok() || fs::symlink_metadata(&work).is_ok() {
        return Err(error("install_slot_exists"));
    }
    store::save(home, job, Phase::Extracting, "extracting")?;
    create_owned(home, &stage, job)?;
    let packages = private_child(home, &stage, "site-packages")?;
    plan.write_into(&packages, &control)
        .map_err(|e| error(e.code()))?;
    create_owned(home, &work, job)?;
    control.checkpoint().map_err(|e| error(e.code()))?;
    // One exclusive preparation lease serializes this no-overwrite publication.
    fs::rename(&stage, &destination).map_err(|_| error("install_publish_failed"))?;
    // NTFS journals directory entries itself, and a directory cannot be
    // opened for flushing through `File::open` there.
    #[cfg(unix)]
    {
        fs::File::open(
            destination
                .parent()
                .ok_or_else(|| error("install_path_invalid"))?,
        )
        .and_then(|file| file.sync_all())
        .map_err(|_| error("install_publish_failed"))?;
        fs::File::open(
            stage
                .parent()
                .ok_or_else(|| error("install_path_invalid"))?,
        )
        .and_then(|file| file.sync_all())
        .map_err(|_| error("install_publish_failed"))?;
    }
    store::save(home, job, Phase::Verifying, "verifying")?;
    let selection = RuntimeSelection {
        verified_python,
        python_bundle: interpreter.python_bundle(),
        python: interpreter.python.clone(),
        site_packages: destination.join("site-packages"),
        work_dir: work.clone(),
    };
    let approval = guard_context_assistance::inspect_release_bundle(&selection, release)
        .map_err(|e| error(e.code()))?;
    if approval.python_sha256 != interpreter.python_sha256 {
        return Err(error("interpreter_changed"));
    }
    let mut runtime =
        VerifiedRuntime::start_release_cancellable(selection, &approval, release, cancel)
            .map_err(|e| error(e.code()))?;
    let result = (|| {
        if runtime.status().interpreter != interpreter.facts {
            return Err(error("interpreter_changed"));
        }
        let qualification = private_child(home, &work, "qualification")?;
        verify_features(&mut runtime, &qualification, release)?;
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
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(_) => return Err(error("install_test_pause_closed")),
                }
            }
        }
        control.checkpoint().map_err(|e| error(e.code()))?;
        policy(home)?;
        store::save(home, job, Phase::Publishing, "publishing")?;
        publish_verified(home, &job.runtime_id, &job.slot, release, &mut runtime)?;
        Ok(())
    })();
    runtime.close();
    result.map_err(|code| {
        if deadline.expired.load(Ordering::Acquire) {
            error("install_deadline_exceeded")
        } else {
            code
        }
    })?;
    // Publication won the race with a late cancellation. Report the real
    // installed outcome; this never selects/starts or rolls it back silently.
    store::save(home, job, Phase::Ready, "ok")
}
pub(super) fn fail(home: &Path, job: &mut Job, code: &str) -> Result<(), String> {
    if job.refresh.is_some() {
        return reverify::fail(home, job, code);
    }
    let registry = root(home, true)?.join(record_name(&job.runtime_id));
    if fs::symlink_metadata(registry).is_ok() {
        return store::save(
            home,
            job,
            Phase::RecoveryRequired,
            "installation_publication_unknown",
        );
    }
    if cleanup::cleanup(home, job).is_err() {
        return store::save(
            home,
            job,
            Phase::RecoveryRequired,
            "install_cleanup_pending",
        );
    }
    let phase = if code.ends_with("_cancelled") {
        Phase::Cancelled
    } else {
        Phase::Failed
    };
    store::save(home, job, phase, code)
}
pub(super) fn recover(home: &Path, job: &mut Job) -> Result<(), String> {
    if job.refresh.is_some() {
        return reverify::recover(home, job);
    }
    let _lease = store::lease(home)?;
    if job.phase == Phase::Ready {
        return Ok(());
    }
    if let Ok(record) = load(home, &job.runtime_id) {
        if !matches_installation(job, &record, None) {
            return store::save(home, job, Phase::RecoveryRequired, "installation_conflict");
        }
        if validate_selection(home, &job.runtime_id).is_err() {
            return store::save(
                home,
                job,
                Phase::RecoveryRequired,
                "installation_recheck_required",
            );
        }
        return store::save(home, job, Phase::Ready, "ok");
    }
    let registry = root(home, true)?.join(record_name(&job.runtime_id));
    if fs::symlink_metadata(registry).is_ok() {
        return store::save(home, job, Phase::RecoveryRequired, "installation_conflict");
    }
    if let Err(code) = cleanup::cleanup(home, job) {
        return store::save(home, job, Phase::RecoveryRequired, &code);
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
            "install_interrupted"
        },
    )
}

pub(super) struct Deadline {
    stop: Arc<(Mutex<bool>, Condvar)>,
    expired: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Deadline {
    pub(super) fn expired(&self) -> bool {
        self.expired.load(Ordering::Acquire)
    }
    pub(super) fn new(
        cancel: Arc<AtomicBool>,
        duration: Duration,
        cancel_path: PathBuf,
    ) -> Result<Self, String> {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let expired = Arc::new(AtomicBool::new(false));
        let pending = Arc::clone(&stop);
        let timed_out = Arc::clone(&expired);
        let thread = std::thread::Builder::new()
            .name("guard-cigar-install-deadline".into())
            .spawn(move || {
                let (mutex, changed) = &*pending;
                let deadline = std::time::Instant::now() + duration;
                let mut stop = mutex.lock().unwrap_or_else(|e| e.into_inner());
                while !*stop {
                    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                    if remaining.is_zero() {
                        timed_out.store(true, Ordering::Release);
                        cancel.store(true, Ordering::Release);
                        break;
                    }
                    stop = changed
                        .wait_timeout(stop, remaining.min(Duration::from_millis(250)))
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                    if !*stop && fs::symlink_metadata(&cancel_path).is_ok() {
                        cancel.store(true, Ordering::Release);
                        break;
                    }
                }
            })
            .map_err(|_| error("install_worker_unavailable"))?;
        Ok(Self {
            stop,
            expired,
            thread: Some(thread),
        })
    }
}
impl Drop for Deadline {
    fn drop(&mut self) {
        *self.stop.0.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.stop.1.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

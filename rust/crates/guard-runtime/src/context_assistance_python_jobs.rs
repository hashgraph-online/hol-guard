//! Interpreter setup uses the existing single native preparation controller.
use super::*;

/// Metadata only, shared by catalog presentation and native Python setup.
/// No interpreter probe, platform qualification or process launch occurs here.
/// Linux picks gnu or musl from the host's C library, not Guard's own target.
pub(super) fn setup_platform() -> Option<&'static str> {
    use host_libc::Libc;
    let libc = || {
        if cfg!(target_os = "linux") {
            host_libc::host_libc()
        } else {
            None
        }
    };
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Some("darwin-arm64"),
        ("macos", "x86_64") => Some("darwin-x64"),
        ("linux", "x86_64") => match libc()? {
            Libc::Gnu => Some("linux-x64-gnu"),
            Libc::Musl => Some("linux-x64-musl"),
        },
        ("linux", "aarch64") => match libc()? {
            Libc::Gnu => Some("linux-arm64-gnu"),
            Libc::Musl => Some("linux-arm64-musl"),
        },
        _ => None,
    }
}
#[path = "context_assistance_host_libc.rs"]
mod host_libc;
impl Jobs {
    pub(crate) fn setup_interpreter(
        &self,
        home: &Path,
        request: SetupInterpreterRequest,
    ) -> Result<Value, String> {
        self.setup_catalog(home, request, None)
    }
    #[cfg(test)]
    pub(crate) fn setup_test_catalog(
        &self,
        home: &Path,
        request: SetupInterpreterRequest,
        catalog: &TrustedCatalog,
        pause: InstallPause,
    ) -> Result<Value, String> {
        *self
            .pause
            .lock()
            .map_err(|_| error("install_worker_unavailable"))? = Some(pause);
        self.setup_catalog(home, request, Some(catalog))
    }
    fn setup_catalog(
        &self,
        home: &Path,
        request: SetupInterpreterRequest,
        catalog: Option<&TrustedCatalog>,
    ) -> Result<Value, String> {
        python_store::request_sha(&request)?;
        if switch_job_id_exists(home, &request.job_id)?
            || store::get(home, &request.job_id)?.is_some()
        {
            return Err(error("install_idempotency_conflict"));
        }
        if let Some(existing) = python_store::get(home, &request.job_id)? {
            if existing.request != request {
                return Err(error("install_idempotency_conflict"));
            }
            return self.python_view(home, &existing);
        }
        worker::policy(home)?;
        let platform = setup_platform().ok_or_else(|| error("install_platform_unqualified"))?;
        let home = fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
        let mut state = state(self)?;
        if state.closed {
            return Err(error("shutdown"));
        }
        if state
            .live
            .as_ref()
            .is_some_and(|live| !live.thread.is_finished())
        {
            return Err(error("install_busy"));
        }
        if let Some(previous) = state.live.take() {
            let _ = previous.thread.join();
        }
        let lease = store::lease(&home)?;
        let current = if catalog.is_none() {
            Some(super::catalog::fresh(&home)?)
        } else {
            None
        };
        if let Some(current) = &current {
            current.check_python(&request.build_id)?;
        }
        let catalog = catalog
            .or_else(|| current.as_ref().map(|s| &s.catalog))
            .ok_or_else(|| error("cigar_catalog_state_invalid"))?;
        let build = catalog
            .interpreter_for_setup(&request.build_id, platform)
            .map_err(|e| error(e.code()))?;
        let python = build.build().binding().map_err(|e| error(e.code()))?;

        if switch_job_id_exists(&home, &request.job_id)?
            || store::get(&home, &request.job_id)?.is_some()
        {
            return Err(error("install_idempotency_conflict"));
        }
        if let Some(existing) = python_store::get(&home, &request.job_id)? {
            if existing.request != request {
                return Err(error("install_idempotency_conflict"));
            }
            drop(state);
            return self.python_view(&home, &existing);
        }
        if total_job_count(&home)? >= store::MAX_JOBS {
            return Err(error("install_job_limit"));
        }
        let now = store::now()?;
        let mut job = python_store::Job {
            schema: "guard-cigar-python-setup-job.v1".into(),
            request_sha256: python_store::request_sha(&request)?,
            request,
            slot: python.slot_id().map_err(|e| error(e.code()))?,
            python,
            interpreter_id: None,
            phase: store::Phase::Queued,
            code: "queued".into(),
            created_at_ms: now,
            updated_at_ms: now,
            deadline_at_ms: now
                .checked_add(120_000)
                .ok_or_else(|| error("clock_invalid"))?,
        };
        python_store::save(&home, &mut job, store::Phase::Queued, "queued")?;
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let worker_home = home.clone();
        let worker_job = job.clone();
        #[cfg(test)]
        let pause = self
            .pause
            .lock()
            .map_err(|_| error("install_worker_unavailable"))?
            .take();
        let (begin, pending) = mpsc::sync_channel::<()>(1);
        let thread = std::thread::Builder::new()
            .name("guard-cigar-python-setup".into())
            .spawn(move || {
                let _lease = lease;
                if pending.recv().is_err() {
                    return;
                }
                let mut job = worker_job;
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    python_worker::run(
                        &worker_home,
                        &mut job,
                        &build,
                        worker_cancel,
                        #[cfg(test)]
                        pause,
                    )
                }))
                .unwrap_or_else(|_| Err(error("install_worker_failed")));
                if let Err(code) = result {
                    let _ = python_worker::fail(&worker_home, &mut job, &code);
                }
            })
            .map_err(|_| error("install_worker_unavailable"))?;
        state.live = Some(Live {
            home: home.clone(),
            job_id: job.request.job_id.clone(),
            cancel,
            thread,
        });
        begin
            .send(())
            .map_err(|_| error("install_worker_unavailable"))?;
        drop(state);
        self.python_view(&home, &job)
    }
    pub(super) fn python_view(
        &self,
        home: &Path,
        job: &python_store::Job,
    ) -> Result<Value, String> {
        let live = self.liveness(home, &job.request.job_id)?;
        let latest = if live != Some(true) {
            python_store::get(home, &job.request.job_id)?
        } else {
            None
        };
        let job = latest.as_ref().unwrap_or(job);
        let cancel_requested =
            fs::symlink_metadata(python_store::cancel_path(home, &job.request.job_id)?).is_ok();
        Ok(
            json!({"schema":job.schema,"job_id":job.request.job_id,"operation":"setup_interpreter",
            "build_id":job.request.build_id,"python_version":job.python.python_version,"platform":job.python.platform,
            "interpreter_id":job.interpreter_id,"phase":job.phase,"code":job.code,
            "created_at_ms":job.created_at_ms,"updated_at_ms":job.updated_at_ms,"deadline_at_ms":job.deadline_at_ms,
            "worker_live":live,"cancel_requested":cancel_requested,
            "recovery_available":live != Some(true) && (!job.phase.terminal() || job.phase == store::Phase::RecoveryRequired),
            "activation_granted":false}),
        )
    }
    pub(super) fn cancel_python(
        &self,
        home: &Path,
        job: &python_store::Job,
    ) -> Result<Value, String> {
        if !job.phase.terminal() {
            python_store::mark_cancel(home, job)?;
            let canonical = fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
            let state = state(self)?;
            if let Some(live) = &state.live {
                if live.home == canonical && live.job_id == job.request.job_id {
                    live.cancel.store(true, Ordering::Release);
                }
            }
        }
        self.get(home, &job.request.job_id)
    }
    pub(super) fn recover_python(
        &self,
        home: &Path,
        mut job: python_store::Job,
    ) -> Result<Value, String> {
        if self.liveness(home, &job.request.job_id)? == Some(true) {
            return Err(error("install_busy"));
        }
        if !matches!(
            job.phase,
            store::Phase::Ready | store::Phase::Failed | store::Phase::Cancelled
        ) {
            python_worker::recover(home, &mut job)?;
        }
        self.python_view(home, &job)
    }
}

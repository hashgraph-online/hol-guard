//! One bounded native preparation worker per profile, independent of the live
//! context actor. All admin inputs are opaque IDs; status never launches SDKs.
use super::*;
use guard_cigar_release::TrustedCatalog;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, Mutex,
};
#[path = "context_assistance_acquisition.rs"]
mod acquisition;
#[path = "context_assistance_wheel_cache.rs"]
mod cache;
#[path = "context_assistance_catalog_refresh_jobs.rs"]
mod catalog_jobs;
#[path = "context_assistance_catalog_job_store.rs"]
mod catalog_store;
#[path = "context_assistance_catalog_refresh_worker.rs"]
mod catalog_worker;
#[path = "context_assistance_install_cleanup.rs"]
mod cleanup;
#[path = "context_assistance_interpreter_registry.rs"]
mod interpreters;
#[path = "context_assistance_managed_python.rs"]
mod managed_python;
#[path = "context_assistance_install_operator.rs"]
mod operator;
#[path = "context_assistance_install_job_store.rs"]
mod store;
#[path = "context_assistance_preparation_job_views.rs"]
mod views;
pub(super) fn lifecycle_directory(
    home: &Path,
    name: &str,
    create: bool,
) -> Result<PathBuf, String> {
    store::directory(home, name, create)
}
pub(super) fn lifecycle_read<T: serde::de::DeserializeOwned>(
    home: &Path,
    path: &Path,
    limit: u64,
) -> Result<Option<T>, String> {
    store::private_read(home, path, limit, "cigar_switch_job")
}
pub(super) fn lifecycle_temporary_name(name: &str) -> bool {
    store::temporary_name(name)
}
pub(super) fn native_job_id_exists(home: &Path, id: &str) -> Result<bool, String> {
    Ok(store::get(home, id)?.is_some()
        || python_store::get(home, id)?.is_some()
        || catalog_store::get(home, id)?.is_some())
}
pub(super) fn total_job_count(home: &Path) -> Result<usize, String> {
    Ok(store::list(home)?.len()
        + python_store::list(home)?.len()
        + catalog_store::list(home)?.len()
        + super::switching::jobs::list(home)?.len())
}
fn switch_job_id_exists(home: &Path, id: &str) -> Result<bool, String> {
    Ok(super::switching::jobs::get(home, id)?.is_some() || catalog_store::get(home, id)?.is_some())
}
pub(super) fn lifecycle_lease(home: &Path) -> Result<std::fs::File, String> {
    store::lease(home)
}
#[path = "context_assistance_install_worker.rs"]
mod worker;
pub(crate) use operator::run_operator_command;
pub(crate) use store::InstallRequest;
#[path = "context_assistance_install_reuse.rs"]
mod reuse;
#[path = "context_assistance_install_reverify.rs"]
mod reverify;
pub(super) fn physical_slot(
    release: &guard_cigar_release::ResolvedRelease,
    approval: &BundleApproval,
) -> Result<String, String> {
    reuse::physical_slot(release, approval)
}
pub(super) fn installation_record_sha(record: &Installation) -> Result<String, String> {
    reuse::record_sha(record)
}
pub(super) fn verification_policy(home: &Path) -> Result<(), String> {
    worker::policy(home)
}
#[path = "context_assistance_python_cache.rs"]
mod python_cache;
#[path = "context_assistance_python_cleanup.rs"]
mod python_cleanup;
#[path = "context_assistance_python_jobs.rs"]
mod python_jobs;
pub(super) fn setup_platform() -> Option<&'static str> {
    python_jobs::setup_platform()
}
#[path = "context_assistance_python_job_store.rs"]
mod python_store;
#[path = "context_assistance_python_worker.rs"]
mod python_worker;
pub(crate) use python_store::SetupInterpreterRequest;

pub(super) fn validate_python_selection(
    home: &Path,
    selection: &RuntimeSelection,
    approval: &BundleApproval,
    facts: &InterpreterFacts,
) -> Result<(), String> {
    managed_python::validate_selection(home, selection, approval, facts)
}

struct Live {
    home: PathBuf,
    job_id: String,
    cancel: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}
#[derive(Default)]
struct State {
    closed: bool,
    live: Option<Live>,
}
#[derive(Default)]
pub(crate) struct Jobs {
    state: Mutex<State>,
    #[cfg(test)]
    pause: Mutex<Option<InstallPause>>,
}

#[cfg(test)]
pub(crate) struct InstallPause {
    pub entered: mpsc::SyncSender<()>,
    pub proceed: mpsc::Receiver<()>,
}

fn state(jobs: &Jobs) -> Result<std::sync::MutexGuard<'_, State>, String> {
    jobs.state
        .lock()
        .map_err(|_| error("install_worker_unavailable"))
}
impl Jobs {
    #[cfg(all(test, unix))]
    pub(crate) fn install_test_catalog(
        &self,
        home: &Path,
        request: InstallRequest,
        catalog: &TrustedCatalog,
        pause: InstallPause,
    ) -> Result<Value, String> {
        *self
            .pause
            .lock()
            .map_err(|_| error("install_worker_unavailable"))? = Some(pause);
        self.install_catalog(home, request, catalog)
    }
    pub(crate) fn install(&self, home: &Path, request: InstallRequest) -> Result<Value, String> {
        self.install_from_catalog(home, request, None)
    }
    #[cfg(all(test, unix))]
    fn install_catalog(
        &self,
        home: &Path,
        request: InstallRequest,
        catalog: &TrustedCatalog,
    ) -> Result<Value, String> {
        self.install_from_catalog(home, request, Some(catalog))
    }
    fn install_from_catalog(
        &self,
        home: &Path,
        request: InstallRequest,
        catalog: Option<&TrustedCatalog>,
    ) -> Result<Value, String> {
        store::validate_request(&request)?;
        if switch_job_id_exists(home, &request.job_id)?
            || python_store::get(home, &request.job_id)?.is_some()
        {
            return Err(error("install_idempotency_conflict"));
        }
        if let Some(existing) = store::get(home, &request.job_id)? {
            if existing.request != request {
                return Err(error("install_idempotency_conflict"));
            }
            return self.view(home, &existing);
        }
        worker::policy(home)?;
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
            current.check_sdk(&request.build_id)?;
        }
        let catalog = catalog
            .or_else(|| current.as_ref().map(|s| &s.catalog))
            .ok_or_else(|| error("cigar_catalog_state_invalid"))?;
        let interpreter = interpreters::load_interpreter(&home, &request.interpreter_id)?;
        let release = catalog
            .for_activation(
                &request.build_id,
                &interpreter.facts.platform,
                false,
                &[Feature::Graph],
            )
            .map_err(|e| error(e.code()))?;
        release
            .check_python_version(interpreter.facts.version)
            .map_err(|e| error(e.code()))?;
        let slot = match interpreter.python_bundle() {
            Some(python) => guard_cigar_install::slot_id_with_python(&release, &python.binding),
            None => guard_cigar_install::slot_id(&release, &interpreter.python_sha256),
        }
        .map_err(|e| error(e.code()))?;

        if switch_job_id_exists(&home, &request.job_id)?
            || python_store::get(&home, &request.job_id)?.is_some()
        {
            return Err(error("install_idempotency_conflict"));
        }
        if let Some(existing) = store::get(&home, &request.job_id)? {
            if existing.request != request {
                return Err(error("install_idempotency_conflict"));
            }
            drop(state);
            return self.view(&home, &existing);
        }
        if total_job_count(&home)? >= store::MAX_JOBS {
            return Err(error("install_job_limit"));
        }
        let existing = reuse::find(&home, &release, &interpreter, &slot)?;
        let (runtime_id, slot, refresh) = if let Some(record) = existing {
            let target = reuse::target(&record, &release)?;
            (
                record.runtime_id,
                record
                    .managed_slot
                    .ok_or_else(|| error("installation_invalid"))?,
                Some(target),
            )
        } else {
            (format!("cigar:{slot}"), slot, None)
        };
        let now = store::now()?;
        let mut job = store::Job {
            schema: "guard-cigar-install-job.v1".into(),
            request_sha256: store::request_sha(&request)?,
            request,
            release: release.binding().map_err(|e| error(e.code()))?,
            package_tree_sha256: release
                .platform()
                .package_tree_sha256
                .clone()
                .ok_or_else(|| error("dependency_lock_missing"))?,
            worker_sha256: release.platform().worker_sha256.clone(),
            python_sha256: interpreter.python_sha256.clone(),
            python_bundle: interpreter.python_bundle().map(|python| python.binding),
            runtime_id,
            refresh,
            slot,
            phase: store::Phase::Queued,
            code: "queued".into(),
            created_at_ms: now,
            updated_at_ms: now,
            deadline_at_ms: now
                .checked_add(120_000)
                .ok_or_else(|| error("clock_invalid"))?,
        };
        store::save(&home, &mut job, store::Phase::Queued, "queued")?;
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
            .name("guard-cigar-install".into())
            .spawn(move || {
                let _lease = lease;
                if pending.recv().is_err() {
                    return;
                }
                let mut job = worker_job;
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    worker::run(
                        &worker_home,
                        &mut job,
                        &release,
                        &interpreter,
                        worker_cancel,
                        #[cfg(test)]
                        pause,
                    )
                }))
                .unwrap_or_else(|_| Err(error("install_worker_failed")));
                if let Err(code) = result {
                    let _ = worker::fail(&worker_home, &mut job, &code);
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
        self.view(&home, &job)
    }
    pub(crate) fn interpreters(&self, home: &Path) -> Result<Vec<Value>, String> {
        interpreters::interpreters(home)
    }
    pub(crate) fn releases(&self, home: &Path) -> Result<Value, String> {
        super::catalog::releases(home)
    }
    pub(crate) fn shutdown(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.closed = true;
        if let Some(live) = &state.live {
            live.cancel.store(true, Ordering::Release);
        }
    }
    pub(crate) fn cancel_active(&self) {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(live) = &state.live {
            live.cancel.store(true, Ordering::Release);
        }
    }
}
impl Drop for Jobs {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
#[path = "context_assistance_install_jobs_tests.rs"]
mod tests;

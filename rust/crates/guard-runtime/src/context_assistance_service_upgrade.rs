//! One cancellable background switch owner. Only native live handles can
//! commit; disk progress records cannot restore an actor or an app grant.
use super::*;
use crate::policy_store::context_assistance_registry::{self as registry, switching};
use std::path::Path;
use std::sync::atomic::AtomicU8;
use std::sync::mpsc::{self, SyncSender};
use switching::jobs::{self, JobPhase, SwitchJob, SwitchRequest};

#[cfg(all(test, target_os = "macos"))]
#[path = "context_assistance_service_upgrade_actual_tests.rs"]
mod actual_tests;
#[path = "context_assistance_service_upgrade_cleanup.rs"]
mod cleanup;
#[path = "context_assistance_service_cold_selection.rs"]
mod cold;
#[path = "context_assistance_service_upgrade_commit.rs"]
mod commit;
#[path = "context_assistance_service_upgrade_deadline.rs"]
mod deadline;
#[path = "context_assistance_service_initial_selection.rs"]
mod initial;
#[path = "context_assistance_service_upgrade_input.rs"]
mod input;
#[path = "context_assistance_service_upgrade_private.rs"]
mod private;
#[path = "context_assistance_service_upgrade_recovery.rs"]
mod recovery;
#[path = "context_assistance_service_upgrade_restore.rs"]
mod restore;
#[path = "context_assistance_service_upgrade_rollback.rs"]
mod rollback;
#[cfg(test)]
#[path = "context_assistance_service_upgrade_tests.rs"]
mod tests;
#[path = "context_assistance_service_upgrade_warm.rs"]
mod warm;
#[path = "context_assistance_service_upgrade_worker.rs"]
mod worker;

#[cfg(test)]
type RestoreReadyHook = Box<dyn FnOnce(&Arc<RuntimeActor<Engine>>) + Send>;

pub(super) struct Signal {
    pub(super) request: SwitchRequest,
    source_disabled: bool,
    source_runtime_id: String,
    recovery: Option<jobs::RecoveryAttempt>,
    ready_data: Mutex<Option<Option<String>>>,
    pub(super) cancel: Arc<AtomicBool>,
    pub(super) cleaned: AtomicBool,
    pending_cleanup: cleanup::Pending,
    pub(super) restore_cancel: Arc<AtomicBool>,
    pub(super) authority_revoked: AtomicBool,
    pub(super) source_revoked: AtomicBool,
    pub(super) published: AtomicBool,
    #[cfg(test)]
    completion_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    #[cfg(test)]
    before_commit_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    #[cfg(test)]
    prepared_actor: Mutex<Weak<RuntimeActor<Engine>>>,
    #[cfg(test)]
    restore_ready_hook: Mutex<Option<RestoreReadyHook>>,
    #[cfg(test)]
    source_closed_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    #[cfg(test)]
    committed_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    #[cfg(test)]
    restore_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    phase: AtomicU8,
}
impl Signal {
    fn new(request: SwitchRequest) -> Self {
        Self {
            request,
            source_disabled: false,
            source_runtime_id: String::new(),
            recovery: None,
            ready_data: Mutex::new(None),
            cancel: Arc::new(AtomicBool::new(false)),
            cleaned: AtomicBool::new(false),
            pending_cleanup: Default::default(),
            restore_cancel: Arc::new(AtomicBool::new(false)),
            authority_revoked: AtomicBool::new(false),
            source_revoked: AtomicBool::new(false),
            published: AtomicBool::new(false),
            #[cfg(test)]
            completion_hook: Mutex::new(None),
            #[cfg(test)]
            before_commit_hook: Mutex::new(None),
            #[cfg(test)]
            prepared_actor: Mutex::new(Weak::new()),
            #[cfg(test)]
            restore_ready_hook: Mutex::new(None),
            #[cfg(test)]
            source_closed_hook: Mutex::new(None),
            #[cfg(test)]
            committed_hook: Mutex::new(None),
            #[cfg(test)]
            restore_hook: Mutex::new(None),
            phase: AtomicU8::new(0),
        }
    }
    fn for_job(job: &SwitchJob) -> Self {
        let mut signal = Self::new(job.request.clone());
        signal.source_disabled = job.source_disabled;
        signal.source_runtime_id = job.source_runtime_id.clone();
        signal.recovery = job.recovery.clone();
        signal
    }
    fn is_initial(&self) -> bool {
        self.source_disabled && self.source_runtime_id.is_empty()
    }
    fn matches_job(&self, job: &SwitchJob) -> bool {
        self.request == job.request
            && self.source_disabled == job.source_disabled
            && self.source_runtime_id == job.source_runtime_id
            && self.recovery == job.recovery
            && self.ready_data.lock().is_ok_and(|data| {
                data.as_ref()
                    .is_none_or(|id| id == &job.prepared_data_generation)
            })
    }
    fn set_phase(&self, phase: JobPhase) {
        loop {
            let old = self.phase.load(Ordering::Acquire);
            if old == JobPhase::Completed as u8
                || (old == JobPhase::Cancelling as u8
                    && !phase.terminal()
                    && !matches!(phase, JobPhase::Restoring | JobPhase::CleanupPending))
            {
                return;
            }
            if self
                .phase
                .compare_exchange(old, phase as u8, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }
    pub(super) fn request_cancel(&self) -> bool {
        loop {
            let old = self.phase.load(Ordering::Acquire);
            if matches!(old, 6..=9) {
                return false;
            }
            if self
                .phase
                .compare_exchange(
                    old,
                    JobPhase::Cancelling as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                self.cancel.store(true, Ordering::Release);
                return true;
            }
        }
    }
    fn request_cancel_for(&self, job: &SwitchJob) -> Result<bool, String> {
        if self.recovery != job.recovery {
            return Err(error("switch_selection_conflict"));
        }
        Ok(self.request_cancel())
    }
    pub(super) fn revoke(&self) {
        self.authority_revoked.store(true, Ordering::Release);
        self.cancel.store(true, Ordering::Release);
        self.restore_cancel.store(true, Ordering::Release);
        self.request_cancel();
    }
    fn complete(&self) -> bool {
        self.phase
            .compare_exchange(
                JobPhase::Committing as u8,
                JobPhase::Completed as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
    fn phase(&self) -> JobPhase {
        match self.phase.load(Ordering::Acquire) {
            0 => JobPhase::Queued,
            1 => JobPhase::Verifying,
            2 => JobPhase::PreparingData,
            3 => JobPhase::Ready,
            4 => JobPhase::Quiescing,
            5 => JobPhase::Committing,
            6 => JobPhase::Completed,
            7 => JobPhase::Cancelled,
            8 => JobPhase::Failed,
            10 => JobPhase::Cancelling,
            11 => JobPhase::Restoring,
            12 => JobPhase::CleanupPending,
            13 => JobPhase::PreparingRecovery,
            _ => JobPhase::RecoveryRequired,
        }
    }
    pub(super) fn describe(&self) -> Value {
        json!({"job_id":self.request.job_id,"operation":if self.recovery.is_some() { "recover" } else if self.is_initial() { "select" } else { self.request.operation() },"target_runtime_id":self.request.target_runtime_id,
            "expected_generation":self.recovery.as_ref().map_or(self.request.expected_generation, |a| a.expected_generation).to_string(),"phase":self.phase(),
            "cleanup_pending":self.pending_cleanup.active(),"cancel_requested":!self.phase().terminal() && self.cancel.load(Ordering::Acquire),"reconnect_required":!self.source_disabled && self.recovery.is_none()})
    }
}
pub(super) struct Cutover {
    pub(super) id: String,
    pub(super) source: AssistanceSettings,
    pub(super) target: AssistanceSettings,
}
struct Source {
    actor: Arc<RuntimeActor<Engine>>,
    settings: AssistanceSettings,
    generation: u64,
}
enum Decision {
    Commit,
}
struct Live {
    home: PathBuf,
    signal: Arc<Signal>,
    decision: SyncSender<Decision>,
    thread: std::thread::JoinHandle<()>,
}
#[derive(Default)]
struct Pool {
    closed: bool,
    live: Option<Live>,
}
#[derive(Default)]
pub(super) struct Jobs {
    pool: Mutex<Pool>,
}
impl Jobs {
    pub(super) fn shutdown(&self) {
        let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        pool.closed = true;
        if let Some(live) = &pool.live {
            live.signal.revoke();
        }
    }
}
impl Drop for Jobs {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn error(code: &str) -> String {
    format!("native_context_assistance_{code}")
}
impl Service {
    pub(crate) fn prepare_switch(
        &self,
        home: &Path,
        request: SwitchRequest,
    ) -> Result<Value, String> {
        jobs::validate_request(&request)?;
        if let Some(old) = jobs::get(home, &request.job_id)? {
            if old.request != request {
                return Err(error("switch_idempotency_conflict"));
            }
            return self.switch_job(home, &request.job_id);
        }
        let mut pool = self
            .switches
            .pool
            .lock()
            .map_err(|_| error("switch_worker_unavailable"))?;
        if pool.closed {
            return Err(error("shutdown"));
        }
        if pool.live.as_ref().is_some_and(|l| !l.thread.is_finished()) {
            return Err(error("switch_busy"));
        }
        if let Some(old) = pool.live.take() {
            let _ = old.thread.join();
        }
        let owner = switching::Owner::acquire(home)?;
        let home = std::fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
        if let Some(old) = jobs::get(&home, &request.job_id)? {
            if old.request != request {
                return Err(error("switch_idempotency_conflict"));
            }
            drop(pool);
            return self.switch_job(&home, &request.job_id);
        }
        if registry::preparation_job_id_exists(&home, &request.job_id)? {
            return Err(error("switch_idempotency_conflict"));
        }
        if registry::lifecycle_job_count(&home)? >= jobs::MAX_JOBS {
            return Err(error("switch_job_limit"));
        }
        owner.prepare_for(&request)?;
        let current = input::capture(&self.state, &request)?;
        let mut job = current.job(request.clone())?;
        jobs::save(&home, &mut job, JobPhase::Queued, "queued")?;
        let signal = Arc::new(Signal::for_job(&job));
        {
            let mut state = lock(&self.state)?;
            if !current.matches(&state) {
                jobs::save(&home, &mut job, JobPhase::Cancelled, "source_changed")?;
                return Err(error("switch_selection_conflict"));
            }
            state.upgrade = Some(Arc::clone(&signal));
        }
        let (decision, receive) = mpsc::sync_channel(1);
        let (begin, start) = mpsc::sync_channel(1);
        let weak = Arc::downgrade(&self.state);
        let thread_signal = Arc::clone(&signal);
        let thread_home = home.clone();
        let thread = std::thread::Builder::new()
            .name("guard-cigar-switch".into())
            .spawn(move || {
                if start.recv().is_err() {
                    thread_signal.cancel.store(true, Ordering::Release);
                }
                input::run(
                    weak,
                    thread_home,
                    current,
                    owner,
                    job,
                    thread_signal,
                    receive,
                );
            })
            .map_err(|_| {
                signal.cancel.store(true, Ordering::Release);
                if let Ok(mut state) = lock(&self.state) {
                    state.upgrade = None;
                }
                error("switch_worker_unavailable")
            })?;
        let id = signal.request.job_id.clone();
        pool.live = Some(Live {
            home: home.clone(),
            signal,
            decision,
            thread,
        });
        begin
            .send(())
            .map_err(|_| error("switch_worker_unavailable"))?;
        drop(pool);
        self.switch_job(&home, &id)
    }
    pub(crate) fn switch_job(&self, home: &Path, id: &str) -> Result<Value, String> {
        let job = jobs::get(home, id)?.ok_or_else(|| error("switch_job_missing"))?;
        let canonical = std::fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
        let pool = self
            .switches
            .pool
            .lock()
            .map_err(|_| error("switch_worker_unavailable"))?;
        let live = pool
            .live
            .as_ref()
            .filter(|l| l.home == canonical && l.signal.request.job_id == id);
        let running = live.map(|l| !l.thread.is_finished());
        let job = if running != Some(true) {
            jobs::get(home, id)?.ok_or_else(|| error("switch_job_missing"))?
        } else {
            job
        };
        Ok(
            json!({"schema":job.schema,"operation":job.operation(),"job_id":job.request.job_id,
            "target_runtime_id":job.request.target_runtime_id,"source_runtime_id":(!job.is_initial()).then_some(&job.source_runtime_id),
            "expected_generation":job.recovery.as_ref().map_or(job.request.expected_generation, |a| a.expected_generation).to_string(),"phase":job.phase,"code":job.code,
            "recovery_attempt":job.recovery.as_ref().map(|a|a.describe()),
            "created_at_ms":job.created_at_ms,"updated_at_ms":job.updated_at_ms,"deadline_at_ms":job.deadline_at_ms,
            "prepared_data_generation":job.prepared_data_generation,"worker_live":running,
            "restoration_deadline_at_ms":job.restoration_deadline_at_ms,
            "cleanup_pending":live.is_some_and(|l| l.signal.pending_cleanup.active()),
            "failure_code":job.failure_code,"restoration_failure_code":job.restoration_failure_code,
            "cancel_requested":jobs::cancelled(home,&job)?,"reconnect_required":!job.source_disabled && job.recovery.is_none(),
            "keeps_disabled":job.source_disabled || job.recovery.is_some(),"initial_selection":job.is_initial(),
            "can_commit":job.phase==JobPhase::Ready && running==Some(true) && live.is_some_and(|l|l.signal.phase()==JobPhase::Ready && l.signal.matches_job(&job) && !l.signal.cancel.load(Ordering::Acquire)),
            "recovery_available":running!=Some(true) && (!job.phase.terminal() || job.phase==JobPhase::RecoveryRequired),
            "authority_restored":false}),
        )
    }
    pub(crate) fn commit_switch(
        &self,
        home: &Path,
        id: &str,
        generation: u64,
        reconnect: bool,
    ) -> Result<Value, String> {
        let job = jobs::get(home, id)?.ok_or_else(|| error("switch_job_missing"))?;
        if generation != job.request.expected_generation {
            return Err(error("switch_selection_conflict"));
        }
        if job.phase.terminal() {
            return self.switch_job(home, id);
        }
        if !reconnect && !job.source_disabled {
            return Err(error("switch_reconnect_acknowledgement_required"));
        }
        let canonical = std::fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
        {
            let pool = self
                .switches
                .pool
                .lock()
                .map_err(|_| error("switch_worker_unavailable"))?;
            let live = pool
                .live
                .as_ref()
                .filter(|l| {
                    l.home == canonical && l.signal.request.job_id == id && !l.thread.is_finished()
                })
                .ok_or_else(|| error("switch_recovery_required"))?;
            if live.signal.phase() != JobPhase::Ready
                || !live.signal.matches_job(&job)
                || live.signal.cancel.load(Ordering::Acquire)
            {
                return Err(error("switch_busy"));
            }
            live.decision
                .try_send(Decision::Commit)
                .map_err(|_| error("switch_busy"))?;
        }
        self.switch_job(home, id)
    }
    pub(crate) fn cancel_switch(&self, home: &Path, id: &str) -> Result<Value, String> {
        let job = jobs::get(home, id)?.ok_or_else(|| error("switch_job_missing"))?;
        if !job.phase.terminal() {
            let canonical = std::fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
            let pool = self
                .switches
                .pool
                .lock()
                .map_err(|_| error("switch_worker_unavailable"))?;
            if let Some(live) = pool
                .live
                .as_ref()
                .filter(|l| l.home == canonical && l.signal.request.job_id == id)
            {
                if live.signal.request_cancel_for(&job)? {
                    jobs::mark_cancel(home, &job)?;
                }
            } else {
                jobs::mark_cancel(home, &job)?;
            }
        }
        self.switch_job(home, id)
    }
    pub(super) fn drain_switch(&self, home: &Path) -> Result<(), String> {
        let signal = lock(&self.state)?.upgrade.clone();
        if let Some(signal) = signal {
            self.cancel_switch(home, &signal.request.job_id)?;
            let until = Instant::now() + Duration::from_millis(500);
            while !signal.cleaned.load(Ordering::Acquire) {
                if Instant::now() >= until {
                    return Err(error("switch_cleanup_pending"));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        Ok(())
    }
}

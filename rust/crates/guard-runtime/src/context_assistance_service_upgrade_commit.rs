//! The only live cutover path: pause, revoke native epoch, stop/acknowledge,
//! commit the coupled selection, then publish the already-verified actor.
use super::*;
use guard_cigar_release::SelectionPhase;

pub(super) struct Cutover<'a> {
    pub shared: &'a Weak<Mutex<State>>,
    pub home: &'a Path,
    pub source: &'a Source,
    pub owner: &'a mut switching::Owner,
    pub job: &'a mut SwitchJob,
    pub signal: &'a Arc<Signal>,
    pub candidate: &'a worker::Candidate,
    pub settings: &'a switching::SwitchSettings,
    pub deadline: &'a deadline::Deadline,
    pub restoration: &'a mut Option<restore::Snapshot>,
}
impl Cutover<'_> {
    pub(super) fn run(&mut self) -> Result<(), String> {
        worker::check(self.shared, self.source, self.signal)?;
        self.settings.check_current()?;
        self.settings.preflight_publish()?;
        self.candidate
            .actor
            .call(|runtime, _| runtime.recheck_artifacts())
            .map_err(|e| error(e.code()))?;
        self.owner.acknowledge_reconnect(&self.job.request.job_id)?;
        worker::step(
            self.home,
            self.job,
            self.signal,
            JobPhase::Quiescing,
            "quiescing",
        )?;
        let config = self.settings.source().clone();
        let producer = self.candidate.producer.clone();
        let (boundary, snapshot) = self
            .source
            .actor
            .pause_at_boundary(move |runtime, engine| {
                engine.upgrade_boundary(runtime, &config, &producer)
            })
            .map_err(|e| error(e.code()))?;
        if snapshot.semantic != self.candidate.semantic {
            return Err(error("switch_source_changed"));
        }
        worker::check(self.shared, self.source, self.signal)?;
        *self.restoration = Some(restore::Snapshot {
            boundary: snapshot.clone(),
            settings: self.settings.clone(),
        });
        let (target_pause, ()) = self
            .candidate
            .actor
            .pause_at_boundary(move |runtime, engine| {
                engine.apply_upgrade_boundary(runtime, snapshot)?;
                runtime.check_transport()
            })
            .map_err(|e| error(e.code()))?;
        self.owner.advance(SelectionPhase::StopIntent)?;
        let shared = self.shared.upgrade().ok_or_else(|| error("shutdown"))?;
        let generation = {
            let mut state = lock(&shared)?;
            if state.closed
                || state.stopping
                || self.signal.cancel.load(Ordering::Acquire)
                || state.generation != self.source.generation
                || state.settings != self.source.settings
                || state
                    .upgrade
                    .as_ref()
                    .is_none_or(|s| !Arc::ptr_eq(s, self.signal))
                || state
                    .runtime
                    .as_ref()
                    .is_none_or(|a| !Arc::ptr_eq(a, &self.source.actor))
            {
                return Err(error("switch_source_changed"));
            }
            let next = state
                .generation
                .checked_add(1)
                .ok_or_else(|| error("generation_exhausted"))?;
            // Ordinary revocation cancels a preparation. This native owner is
            // deliberately retained while only the source actor is revoked.
            self.signal.source_revoked.store(true, Ordering::Release);
            let signal = state.upgrade.take();
            let old = revoke_runtime(&mut state);
            state.upgrade = signal;
            drop(old);
            state.generation = next;
            state.cutover = Some(super::Cutover {
                id: self.job.request.job_id.clone(),
                source: self.source.settings.clone(),
                target: self.settings.target_settings().clone(),
            });
            state.error = Some("switching_runtime".into());
            next
        };
        if !boundary.close_and_wait(Duration::from_millis(500)) {
            return Err(error("switch_cleanup_pending"));
        }
        #[cfg(test)]
        if let Some(hook) = self.signal.source_closed_hook.lock().unwrap().take() {
            hook();
        }
        if self.signal.cancel.load(Ordering::Acquire) {
            return Err(error("switch_cancelled"));
        }
        worker::step(
            self.home,
            self.job,
            self.signal,
            JobPhase::Committing,
            "committing",
        )?;
        if let Err(code) = self.owner.commit(self.settings) {
            if !code.ends_with("switch_commit_outcome_unknown") {
                return Err(code);
            }
            self.owner
                .reconcile_committed(&self.job.request.job_id, self.settings)?;
        }
        if self.signal.cancel.load(Ordering::Acquire) {
            return Err(error("switch_cancelled"));
        }
        #[cfg(test)]
        if let Some(hook) = self.signal.committed_hook.lock().unwrap().take() {
            hook();
        }
        if self.signal.cancel.load(Ordering::Acquire) {
            return Err(error("switch_cancelled"));
        }
        self.settings.check_target_policy()?;
        self.owner.mark_healthy(&self.job.request.job_id)?;
        drop(target_pause);
        let mut state = lock(&shared)?;
        if state.closed
            || state.stopping
            || state.generation != generation
            || self.signal.cancel.load(Ordering::Acquire)
            || state
                .cutover
                .as_ref()
                .is_none_or(|f| f.id != self.job.request.job_id)
            || state
                .upgrade
                .as_ref()
                .is_none_or(|s| !Arc::ptr_eq(s, self.signal))
            || !self.candidate.actor.is_active()
        {
            return Err(error("switch_recovery_required"));
        }
        lifecycle::start_watcher(Arc::downgrade(&shared), generation, self.home.to_path_buf())
            .map_err(|_| error("settings_watcher_unavailable"))?;
        if self.candidate.notifications.as_ref().is_some_and(|n| {
            !crate::context_assistance_notifications::register(self.home.to_path_buf(), n)
        }) {
            return Err(error("notifications_unavailable"));
        }
        // Commit/cancel compete for one transition. A late Cancel request
        // cannot subsequently kill the now-serving actor through this job.
        if !self.signal.complete() {
            return Err(error("switch_cancelled"));
        }
        self.deadline.finish();
        state.settings = self.settings.target_settings().clone();
        let mut checked = self.candidate.actor.status();
        checked.active = false;
        state.last_check = Some(checked);
        state.runtime = Some(Arc::clone(&self.candidate.actor));
        state.retiring = None;
        state.notifications = self.candidate.notifications.clone();
        state.observations = Default::default();
        #[cfg(target_os = "macos")]
        {
            state.execution_ready = Arc::clone(&self.candidate.execution_ready);
        }
        state.last_used = Instant::now();
        state.error = None;
        state.cutover = None;
        self.signal.published.store(true, Ordering::Release);
        drop(state);
        #[cfg(test)]
        if let Some(hook) = self.signal.completion_hook.lock().unwrap().take() {
            hook();
        }
        // SDK/user work is already published. Any later error is metadata
        // reconciliation, never permission to close this serving actor.
        self.owner.complete_publication(&self.job.request.job_id)
    }
}

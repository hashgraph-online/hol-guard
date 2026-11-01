use super::*;

pub(super) fn configure(
    shared: &Mutex<State>,
    mut settings: AssistanceSettings,
    generation: Option<u64>,
) -> Result<(), String> {
    let old = {
        let mut state = lock(shared)?;
        if state.closed {
            return Err("native_context_assistance_shutdown".into());
        }
        if generation.is_some_and(|generation| generation != state.generation) {
            return Err("native_context_assistance_context_stale".into());
        }
        // Stop revokes authority before waiting for cleanup or disk I/O. A
        // concurrent read of the older on-disk opt-in must not reverse it.
        if state.stopping {
            if !settings.requested.enabled && settings.diagnostic.is_none() {
                state.stopping = false;
                // Also invalidate readers that started during Stop and saw
                // the old disk bytes before opt-out was persisted.
                state.generation = state
                    .generation
                    .checked_add(1)
                    .ok_or("native_context_assistance_generation_exhausted")?;
            } else {
                settings.requested.enabled = false;
                settings.effective.enabled = false;
            }
        }
        #[cfg(unix)]
        if !state.stopping
            && state
                .cutover
                .as_ref()
                .is_some_and(|f| settings == f.source || settings == f.target)
        {
            return Ok(());
        }
        if state.settings == settings {
            return Ok(());
        }
        if let Some(job) = &state.pending {
            job.cancel.store(true, Ordering::Release);
        }
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or("native_context_assistance_generation_exhausted")?;
        #[cfg(unix)]
        {
            state.cutover = None;
        }
        state.settings = settings;
        state.error = None;
        state.last_check = None;
        revoke_runtime(&mut state)
    };
    await_cleanup(old);
    Ok(())
}

pub(super) fn await_cleanup(actor: Option<Arc<RuntimeActor<Engine>>>) -> bool {
    actor
        .as_ref()
        .is_none_or(|actor| actor.close_and_wait(Duration::from_millis(500)))
}

pub(super) fn start_watcher(
    weak: Weak<Mutex<State>>,
    generation: u64,
    home: PathBuf,
) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("guard-cigar-settings".into())
        .spawn(move || loop {
            std::thread::sleep(Duration::from_secs(1));
            let Some(shared) = weak.upgrade() else {
                break;
            };
            let old = {
                let Ok(mut state) = lock(&shared) else {
                    break;
                };
                if state.generation != generation || state.runtime.is_none() {
                    break;
                }
                if state.last_used.elapsed()
                    >= Duration::from_secs(u64::from(
                        state.settings.effective.limits.idle_shutdown_seconds,
                    ))
                {
                    state.error = Some("runtime_idle".into());
                    revoke_runtime(&mut state)
                } else if !state
                    .runtime
                    .as_ref()
                    .expect("runtime checked above")
                    .status()
                    .active
                {
                    // The actor owns heartbeats/SDK calls. Only atomic liveness is
                    // read while holding the settings state.
                    state.error = Some("runtime_closed".into());
                    revoke_runtime(&mut state)
                } else {
                    None
                }
            };
            if old.is_some() {
                await_cleanup(old);
                break;
            }
            let current = crate::guard_config_load::context_assistance_config(&home)
                .unwrap_or_else(|_| AssistanceSettings::unavailable("configuration_unavailable"));
            if configure(&shared, current, Some(generation)).is_err() {
                break;
            }
        })
        .map(|_| ())
}

impl Service {
    pub(crate) fn stop(&self) -> Result<(), String> {
        let old = {
            let mut state = lock(&self.state)?;
            state.stopping = true;
            if let Some(job) = &state.pending {
                job.cancel.store(true, Ordering::Release);
            }
            state.generation = state
                .generation
                .checked_add(1)
                .ok_or("native_context_assistance_generation_exhausted")?;
            state.settings.requested.enabled = false;
            state.settings.effective.enabled = false;
            state.error = None;
            state.last_check = None;
            revoke_runtime(&mut state)
        };
        self.updates.cancel_active();
        await_cleanup(old);
        Ok(())
    }

    /// Resident teardown only. Reopening settings cannot restart this service.
    /// No persisted consent is changed, and no authority survives a new service.
    pub(crate) fn shutdown(&self) {
        let old = {
            // Poison recovery is limited to destructive in-memory cancellation.
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            state.closed = true;
            if let Some(job) = &state.pending {
                job.cancel.store(true, Ordering::Release);
            }
            state.generation = state.generation.saturating_add(1);
            state.settings.requested.enabled = false;
            state.settings.effective.enabled = false;
            state.last_check = None;
            revoke_runtime(&mut state)
        };
        self.updates.shutdown();
        #[cfg(unix)]
        self.switches.shutdown();
        await_cleanup(old);
    }
}

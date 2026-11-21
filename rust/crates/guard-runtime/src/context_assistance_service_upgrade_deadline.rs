//! Cancellation stays independent of a blocked SDK call. Success stops this
//! watcher before the prepared actor becomes the serving runtime.
use super::*;
use std::sync::Condvar;

pub(super) struct Deadline {
    done: Arc<(Mutex<bool>, Condvar)>,
}
impl Deadline {
    pub(super) fn start(
        home: PathBuf,
        job: SwitchJob,
        signal: Arc<Signal>,
        shared: Weak<Mutex<State>>,
    ) -> Result<Self, String> {
        let done = Arc::new((Mutex::new(false), Condvar::new()));
        let watched = Arc::clone(&done);
        std::thread::Builder::new()
            .name("guard-cigar-switch-deadline".into())
            .spawn(move || {
                let started = Instant::now();
                loop {
                    let stop = watched.0.lock().unwrap_or_else(|e| e.into_inner());
                    let stop = watched
                        .1
                        .wait_timeout(stop, Duration::from_millis(25))
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                    if *stop {
                        return;
                    }
                    drop(stop);
                    if started.elapsed() >= Duration::from_secs(120)
                        || job.recovery.as_ref().is_some_and(|a| {
                            jobs::now().map_or(true, |now| now >= a.deadline_at_ms)
                        })
                    {
                        signal.request_cancel();
                        return;
                    }
                    if signal.cancel.load(Ordering::Acquire) {
                        return;
                    }
                    if jobs::cancelled(&home, &job).unwrap_or(true)
                        || shared.upgrade().is_none_or(|s| {
                            lock(&s).map_or(true, |state| state.closed || state.stopping)
                        })
                    {
                        signal.request_cancel();
                        return;
                    }
                }
            })
            .map_err(|_| error("switch_worker_unavailable"))?;
        Ok(Self { done })
    }
    pub(super) fn restore(
        signal: Arc<Signal>,
        shared: Weak<Mutex<State>>,
        deadline_at_ms: u64,
    ) -> Result<Self, String> {
        let remaining = deadline_at_ms
            .checked_sub(jobs::now()?)
            .filter(|d| *d > 0 && *d <= 30_000)
            .ok_or_else(|| error("switch_restore_deadline_exceeded"))?;
        let done = Arc::new((Mutex::new(false), Condvar::new()));
        let watched = Arc::clone(&done);
        std::thread::Builder::new()
            .name("guard-cigar-restore-deadline".into())
            .spawn(move || {
                let started = Instant::now();
                loop {
                    let stop = watched.0.lock().unwrap_or_else(|e| e.into_inner());
                    let stop = watched
                        .1
                        .wait_timeout(stop, Duration::from_millis(25))
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                    if *stop {
                        return;
                    }
                    drop(stop);
                    if signal.authority_revoked.load(Ordering::Acquire)
                        || started.elapsed() >= Duration::from_millis(remaining)
                        || jobs::now().map_or(true, |now| now >= deadline_at_ms)
                        || shared.upgrade().is_none_or(|s| {
                            lock(&s).map_or(true, |state| state.closed || state.stopping)
                        })
                    {
                        // Do not race a successful publication's finish() and
                        // cancel the restored actor after it becomes the service.
                        let stop = watched.0.lock().unwrap_or_else(|e| e.into_inner());
                        if !*stop {
                            signal.restore_cancel.store(true, Ordering::Release);
                        }
                        return;
                    }
                }
            })
            .map_err(|_| error("switch_worker_unavailable"))?;
        Ok(Self { done })
    }
    /// Only while preparing the recovery process: commit is unavailable, so
    /// cancellation cannot race source revocation. Finish before publishing Ready.
    pub(super) fn preparing_recovery(signal: Arc<Signal>) -> Result<Self, String> {
        let cancel = Arc::clone(&signal.restore_cancel);
        Self::forward_cancel(signal, cancel)
    }
    /// Closing a temporary SDK must not cancel its parent selection job.
    pub(super) fn forward_cancel(
        signal: Arc<Signal>,
        cancel: Arc<AtomicBool>,
    ) -> Result<Self, String> {
        let done = Arc::new((Mutex::new(false), Condvar::new()));
        let watched = Arc::clone(&done);
        std::thread::Builder::new()
            .name("guard-cigar-recovery-preparation".into())
            .spawn(move || loop {
                let stop = watched.0.lock().unwrap_or_else(|e| e.into_inner());
                let stop = watched
                    .1
                    .wait_timeout(stop, Duration::from_millis(25))
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
                if *stop {
                    return;
                }
                if signal.cancel.load(Ordering::Acquire)
                    || signal.authority_revoked.load(Ordering::Acquire)
                {
                    cancel.store(true, Ordering::Release);
                    return;
                }
            })
            .map_err(|_| error("switch_worker_unavailable"))?;
        Ok(Self { done })
    }
    pub(super) fn finish(&self) {
        *self.done.0.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.done.1.notify_all();
    }
}
impl Drop for Deadline {
    fn drop(&mut self) {
        self.finish();
    }
}

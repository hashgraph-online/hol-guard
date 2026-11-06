//! One bounded optional control-plane lane. The actor owns the SDK process;
//! callers never hold a policy, evidence or settings lock across graph work.
use crate::{RuntimeError, RuntimeStatus, VerifiedRuntime};
use std::sync::{
    atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    mpsc::{self, Receiver, SyncSender, TrySendError},
    Arc, Mutex,
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const QUEUE_CAPACITY: usize = 4;
const CALL_TIMEOUT: Duration = Duration::from_secs(6);
type Job<S> = Box<dyn FnOnce(&mut VerifiedRuntime, &mut S) + Send>;
type Maintenance<S> =
    Box<dyn FnMut(&mut VerifiedRuntime, &mut S) -> Result<(), RuntimeError> + Send>;

/// Launch-side liveness only. Dropping this value cannot join an actor or wait
/// for cleanup while the executor owns its policy fence.
pub struct RuntimeActivity {
    cancel: Arc<AtomicBool>,
    alive: Arc<AtomicBool>,
}
impl RuntimeActivity {
    pub fn is_active(&self) -> bool {
        self.alive.load(Ordering::Acquire) && !self.cancel.load(Ordering::Acquire)
    }
}

/// Host-only handle, constructed from an actually verified process. No caller
/// facts or deserializable handle can construct it. `S` stays on this lane.
pub struct RuntimeActor<S: Send + 'static> {
    sender: Option<SyncSender<Job<S>>>,
    cancel: Arc<AtomicBool>,
    alive: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    queued: Arc<AtomicUsize>,
    cleaned: Arc<AtomicBool>,
    status: RuntimeStatus,
    done: Mutex<Receiver<()>>,
    thread: Option<JoinHandle<()>>,
}

/// A reversible admission pause before a lifecycle effect. It carries no SDK
/// grant; dropping it resumes only a still-live, never-stopped source actor.
pub struct Quiescence<'a, S: Send + 'static> {
    actor: &'a RuntimeActor<S>,
    resume: bool,
}
impl<S: Send + 'static> Quiescence<'_, S> {
    /// Consuming the pause makes SDK shutdown irreversible for this handle.
    pub fn close_and_wait(mut self, timeout: Duration) -> bool {
        self.resume = false;
        self.actor.close_and_wait(timeout)
    }
}
impl<S: Send + 'static> Drop for Quiescence<'_, S> {
    fn drop(&mut self) {
        if self.resume && self.actor.is_active() {
            self.actor.paused.store(false, Ordering::Release);
        }
    }
}

struct Queued(Arc<AtomicUsize>);
impl Drop for Queued {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
struct Running(Arc<AtomicBool>);
impl Drop for Running {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl<S: Send + 'static> RuntimeActor<S> {
    pub fn start(runtime: VerifiedRuntime, state: S) -> Result<Self, RuntimeError> {
        Self::start_inner(runtime, state, None)
    }
    pub fn start_with_maintenance(
        runtime: VerifiedRuntime,
        state: S,
        maintenance: impl FnMut(&mut VerifiedRuntime, &mut S) -> Result<(), RuntimeError>
            + Send
            + 'static,
    ) -> Result<Self, RuntimeError> {
        Self::start_inner(runtime, state, Some(Box::new(maintenance)))
    }
    fn start_inner(
        mut runtime: VerifiedRuntime,
        mut state: S,
        mut maintenance: Option<Maintenance<S>>,
    ) -> Result<Self, RuntimeError> {
        if !runtime.status().active || runtime.cancel.load(Ordering::Acquire) {
            return Err(RuntimeError::RuntimeClosed);
        }
        let status = runtime.status().clone();
        let cancel = Arc::clone(&runtime.cancel);
        let worker_cancel = Arc::clone(&cancel);
        let alive = Arc::new(AtomicBool::new(true));
        let worker_alive = Arc::clone(&alive);
        let paused = Arc::new(AtomicBool::new(false));
        let worker_paused = Arc::clone(&paused);
        let cleaned = Arc::new(AtomicBool::new(false));
        let worker_cleaned = Arc::clone(&cleaned);
        let (sender, receiver) = mpsc::sync_channel::<Job<S>>(QUEUE_CAPACITY);
        let (completed, done) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("guard-cigar-graph".into())
            .spawn(move || {
                let _running = Running(worker_alive);
                let mut last_health = Instant::now();
                let mut last_maintenance = Instant::now();
                while !worker_cancel.load(Ordering::Acquire) && runtime.status().active {
                    match receiver.recv_timeout(Duration::from_millis(100)) {
                        Ok(job) if !worker_cancel.load(Ordering::Acquire) => {
                            job(&mut runtime, &mut state);
                            last_health = Instant::now();
                        }
                        Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            if last_health.elapsed() >= Duration::from_secs(1) {
                                if runtime.check_transport().is_err() {
                                    break;
                                }
                                last_health = Instant::now();
                            }
                        }
                    }
                    if last_maintenance.elapsed() >= Duration::from_secs(1)
                        && !worker_paused.load(Ordering::Acquire)
                        && !worker_cancel.load(Ordering::Acquire)
                        && runtime.status().active
                    {
                        if let Some(operation) = maintenance.as_mut() {
                            if operation(&mut runtime, &mut state).is_err() {
                                break;
                            }
                        }
                        last_maintenance = Instant::now();
                    }
                }
                runtime.close();
                drop(runtime);
                // Drop retained private context before acknowledging cleanup.
                drop(state);
                drop(receiver);
                worker_cleaned.store(true, Ordering::Release);
                let _ = completed.try_send(());
            })
            .map_err(|_| RuntimeError::LaunchFailed)?;
        Ok(Self {
            sender: Some(sender),
            cancel,
            alive,
            paused,
            queued: Arc::new(AtomicUsize::new(0)),
            cleaned,
            status,
            done: Mutex::new(done),
            thread: Some(thread),
        })
    }

    pub fn status(&self) -> RuntimeStatus {
        let mut status = self.status.clone();
        status.active = self.is_active();
        status
    }

    pub fn is_active(&self) -> bool {
        self.alive.load(Ordering::Acquire) && !self.cancel.load(Ordering::Acquire)
    }

    /// Metadata only; admission in progress is included and capped at the
    /// fixed queue capacity. No actor/SDK operation is dispatched.
    pub fn pending_calls(&self) -> usize {
        self.queued.load(Ordering::Acquire).min(QUEUE_CAPACITY)
    }
    pub fn is_quiescent(&self) -> bool {
        self.is_active() && self.paused.load(Ordering::Acquire)
    }
    /// Close admission before placing the barrier. Previously queued calls
    /// also recheck admission when dispatched; none can mutate after it.
    /// The callback runs on the old lane after its dispatched work finishes.
    pub fn pause_at_boundary<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut VerifiedRuntime, &mut S) -> Result<T, RuntimeError> + Send + 'static,
    ) -> Result<(Quiescence<'_, S>, T), RuntimeError> {
        if !self.is_active() {
            return Err(RuntimeError::RuntimeClosed);
        }
        self.paused
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| RuntimeError::Busy)?;
        let pause = Quiescence {
            actor: self,
            resume: true,
        };
        let value = self.call_inner(Instant::now() + CALL_TIMEOUT, true, operation)?;
        Ok((pause, value))
    }

    pub fn activity(&self) -> RuntimeActivity {
        RuntimeActivity {
            cancel: Arc::clone(&self.cancel),
            alive: Arc::clone(&self.alive),
        }
    }

    /// Queue capacity is finite and the deadline includes queue time. An
    /// dispatched timeout closes the process generation. A queued timeout
    /// atomically abandons its job before mutation; neither outcome is retried.
    pub fn call<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut VerifiedRuntime, &mut S) -> Result<T, RuntimeError> + Send + 'static,
    ) -> Result<T, RuntimeError> {
        self.call_until(Instant::now() + CALL_TIMEOUT, operation)
    }

    /// Explicit executor consumers can impose a smaller optional budget. A
    /// dispatched timeout has unknown mutation outcome and closes the optional
    /// generation. The native command's approval remains outside this actor.
    pub fn call_until<T: Send + 'static>(
        &self,
        deadline: Instant,
        operation: impl FnOnce(&mut VerifiedRuntime, &mut S) -> Result<T, RuntimeError> + Send + 'static,
    ) -> Result<T, RuntimeError> {
        self.call_inner(deadline, false, operation)
    }
    fn call_inner<T: Send + 'static>(
        &self,
        deadline: Instant,
        barrier: bool,
        operation: impl FnOnce(&mut VerifiedRuntime, &mut S) -> Result<T, RuntimeError> + Send + 'static,
    ) -> Result<T, RuntimeError> {
        let deadline = deadline.min(Instant::now() + CALL_TIMEOUT);
        if Instant::now() >= deadline {
            return Err(RuntimeError::DeadlineExceeded);
        }
        if !self.status().active {
            return Err(RuntimeError::RuntimeClosed);
        }
        if !barrier && self.paused.load(Ordering::Acquire) {
            return Err(RuntimeError::Busy);
        }
        let (reply, result) = mpsc::sync_channel(1);
        let cancel = Arc::clone(&self.cancel);
        let paused = Arc::clone(&self.paused);
        // 0 queued, 1 started, 2 abandoned. Caller and worker compete for the
        // same transition; an expired queued closure can never run later.
        let dispatch = Arc::new(AtomicU8::new(0));
        let started = Arc::clone(&dispatch);
        self.queued.fetch_add(1, Ordering::AcqRel);
        let queued = Queued(Arc::clone(&self.queued));
        let task = Box::new(move |runtime: &mut VerifiedRuntime, state: &mut S| {
            drop(queued);
            if !barrier && paused.load(Ordering::Acquire) {
                let _ = reply.try_send(Err(RuntimeError::Busy));
                return;
            }
            if Instant::now() >= deadline
                || cancel.load(Ordering::Acquire)
                || started
                    .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
            {
                let _ = reply.try_send(Err(RuntimeError::Cancelled));
                return;
            }
            let value = operation(runtime, state);
            let value = if cancel.load(Ordering::Acquire) {
                Err(RuntimeError::Cancelled)
            } else {
                value
            };
            let _ = reply.try_send(value);
        });
        match self
            .sender
            .as_ref()
            .ok_or(RuntimeError::RuntimeClosed)?
            .try_send(task)
        {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(RuntimeError::Busy),
            Err(TrySendError::Disconnected(_)) => return Err(RuntimeError::RuntimeClosed),
        }
        loop {
            if self.cancel.load(Ordering::Acquire) {
                return Err(RuntimeError::Cancelled);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                if dispatch
                    .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    self.cancel.store(true, Ordering::Release);
                }
                return Err(RuntimeError::DeadlineExceeded);
            }
            match result.recv_timeout(remaining.min(Duration::from_millis(25))) {
                Ok(value) => return value,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(RuntimeError::RuntimeClosed)
                }
            }
        }
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
    }
    pub fn cleanup_finished(&self) -> bool {
        self.cleaned.load(Ordering::Acquire)
    }
    /// Destructive repair must wait for private host state to be dropped,
    /// not infer cleanup from cancellation or atomic availability alone.
    pub fn close_and_wait(&self, timeout: Duration) -> bool {
        self.cancel();
        if self.cleaned.load(Ordering::Acquire) {
            return true;
        }
        if let Ok(done) = self.done.try_lock() {
            let _ = done.recv_timeout(timeout.min(Duration::from_millis(500)));
        }
        self.cleaned.load(Ordering::Acquire)
    }
}

impl<S: Send + 'static> Drop for RuntimeActor<S> {
    fn drop(&mut self) {
        self.cancel();
        self.sender.take();
        if self.cleanup_finished() {
            // Private state and processes are already gone; dropping this
            // retired handle never waits under a service settings lock.
            self.thread.take();
            return;
        }
        // This runs after removing the actor from the settings lock. Normal
        // process cancellation polls every 25 ms. Never join a stuck host job.
        if self
            .done
            .get_mut()
            .is_ok_and(|done| done.recv_timeout(Duration::from_millis(500)).is_ok())
            || self.thread.as_ref().is_some_and(JoinHandle::is_finished)
        {
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

#[cfg(test)]
#[path = "actor_tests.rs"]
mod tests;

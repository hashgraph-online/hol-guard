//! Lazy, resident-local context jobs. Idle workers retire after one second.
//! Slots include response delivery, so slow readers cannot create more jobs.
use super::{write_bound_response, PendingRequest};
use crate::policy_store::PolicySnapshotStore;
use crate::resident_diagnostics::{observe, Phase};
use serde::Deserialize;
use std::collections::VecDeque;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const LIMIT: usize = 2;
const IDLE_TTL: Duration = Duration::from_secs(1);

struct Job {
    slot: Slot,
    pending: PendingRequest,
    request: Vec<u8>,
    store: Option<Arc<PolicySnapshotStore>>,
}

#[derive(Default)]
struct State {
    closed: bool,
    active: usize,
    workers: usize,
    jobs: VecDeque<Job>,
}
#[derive(Default)]
pub(super) struct Lane {
    state: Mutex<State>,
    idle: Condvar,
}
struct Slot(Arc<Lane>);
struct Worker {
    lane: Arc<Lane>,
    registered: bool,
}
impl Drop for Slot {
    fn drop(&mut self) {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.active -= 1;
        self.0.idle.notify_all();
    }
}

impl Worker {
    fn next_job(&mut self) -> Option<Job> {
        let deadline = Instant::now() + IDLE_TTL;
        let mut state = self
            .lane
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        loop {
            // Already admitted jobs retain their result even during close.
            if let Some(job) = state.jobs.pop_front() {
                return Some(job);
            }
            let remaining = deadline.checked_duration_since(Instant::now());
            if state.closed || remaining.is_none() {
                state.workers -= 1;
                self.registered = false;
                self.lane.idle.notify_all();
                return None;
            }
            state = self
                .lane
                .idle
                .wait_timeout(state, remaining.unwrap())
                .unwrap_or_else(|error| error.into_inner())
                .0;
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        if !self.registered {
            return;
        }
        let abandoned = {
            let mut state = self
                .lane
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.workers -= 1;
            if state.workers == 0 {
                std::mem::take(&mut state.jobs)
            } else {
                VecDeque::new()
            }
        };
        self.lane.idle.notify_all();
        // A worker lost before taking a job cannot strand its reservation or
        // cause an unevaluated request to be replayed. Refuse outside the lock.
        for mut job in abandoned {
            reject_busy(&mut job.pending, &job.request, job.store.as_deref());
        }
    }
}

fn run_job(job: Job) {
    let _slot = job.slot;
    let mut pending = job.pending;
    if crate::hardening::request_expired(pending.accepted_at) {
        let response =
            crate::resident_protocol::error_response("native_request_deadline_exceeded", true);
        let _ = write_bound_response(&mut *pending.stream, &pending.request_id, &response);
        return;
    }
    let response = match catch_unwind(AssertUnwindSafe(|| {
        observe(Phase::ResidentEvaluate, || {
            crate::resident_protocol::evaluate_resident_bytes(&job.request, job.store.as_deref())
        })
    })) {
        Ok(Ok(response)) => response,
        Ok(Err(reason)) => crate::resident_protocol::safe_error_response(&reason, false),
        Err(_) => crate::resident_protocol::error_response("native_runtime_panicked", false),
    };
    let _ = write_bound_response(&mut *pending.stream, &pending.request_id, &response);
}

fn start_worker(lane: Arc<Lane>) -> std::io::Result<()> {
    thread::Builder::new()
        .name("guard-cigar-request".into())
        .spawn(move || {
            let mut worker = Worker {
                lane,
                registered: true,
            };
            while let Some(job) = worker.next_job() {
                // A delivery panic must release its slot without losing the
                // worker that owns subsequent admitted requests.
                let _ = catch_unwind(AssertUnwindSafe(|| run_job(job)));
            }
        })
        .map(|_| ())
}

impl Lane {
    fn reserve(self: &Arc<Self>) -> Option<Slot> {
        let mut state = self.state.lock().ok()?;
        if state.closed || state.active >= LIMIT {
            return None;
        }
        state.active += 1;
        Some(Slot(Arc::clone(self)))
    }

    pub(super) fn enqueue(
        self: &Arc<Self>,
        pending: PendingRequest,
        request: Vec<u8>,
        store: Option<Arc<PolicySnapshotStore>>,
    ) {
        self.enqueue_with(pending, request, store, start_worker);
    }

    fn enqueue_with(
        self: &Arc<Self>,
        mut pending: PendingRequest,
        request: Vec<u8>,
        store: Option<Arc<PolicySnapshotStore>>,
        spawn: impl FnOnce(Arc<Lane>) -> std::io::Result<()>,
    ) {
        let Some(slot) = self.reserve() else {
            reject_busy(&mut pending, &request, store.as_deref());
            return;
        };
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.closed {
            drop(state);
            drop(slot);
            reject_busy(&mut pending, &request, store.as_deref());
            return;
        }
        if state.workers < state.active {
            state.workers += 1;
            // Nothing is queued or evaluated before a worker exists. A failed
            // spawn keeps the original frame available for a bound refusal.
            if spawn(Arc::clone(self)).is_err() {
                state.workers -= 1;
                drop(state);
                drop(slot);
                reject_busy(&mut pending, &request, store.as_deref());
                return;
            }
        }
        state.jobs.push_back(Job {
            slot,
            pending,
            request,
            store,
        });
        self.idle.notify_one();
    }

    pub(super) fn close(&self) {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .closed = true;
        self.idle.notify_all();
    }

    pub(super) fn drain(&self) {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        while state.active != 0 || (state.closed && state.workers != 0) {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            let Ok((next, _)) = self.idle.wait_timeout(state, remaining) else {
                break;
            };
            state = next;
        }
    }
}

fn reject_busy(pending: &mut PendingRequest, bytes: &[u8], store: Option<&PolicySnapshotStore>) {
    // Keep this decoder narrow. Instantiating the full resident operation enum
    // for a second JSON deserializer duplicates unrelated native code.
    #[derive(Deserialize)]
    #[serde(tag = "operation", content = "request", rename_all = "snake_case")]
    enum ContextRequest {
        ContextAssistance(crate::context_assistance_op::Request),
        ContextAgent(crate::context_assistance_agent_op::Request),
    }
    let response = (|| {
        let store = store.ok_or("native_context_assistance_resident_required")?;
        let value = crate::strict_json_value(bytes)?;
        let request = crate::strict_json::from_value(value)
            .map_err(|_| "native_context_assistance_request_invalid")?;
        match request {
            ContextRequest::ContextAssistance(request) => {
                crate::context_assistance_op::reject_busy(&request, store)
            }
            ContextRequest::ContextAgent(request) => {
                crate::context_assistance_agent_op::reject_busy(&request, store)
            }
        }
    })()
    .unwrap_or_else(|code: String| crate::resident_protocol::safe_error_response(&code, false));
    let _ = write_bound_response(&mut *pending.stream, &pending.request_id, &response);
}

/// Scheduling only: complete frame digest and native operation/scope validation
/// still run. String decoding handles escaped valid tags without a lane bypass.
pub(super) fn is_request(bytes: &[u8]) -> bool {
    #[derive(Deserialize)]
    struct Route {
        operation: String,
        request: Option<Request>,
    }
    #[derive(Deserialize)]
    struct Request {
        query: Option<Query>,
    }
    #[derive(Deserialize)]
    struct Query {
        kind: Option<String>,
        input: Option<Input>,
    }
    #[derive(Deserialize)]
    struct Input {
        action: Option<String>,
    }
    let Ok(route) = serde_json::from_slice::<Route>(bytes) else {
        return false;
    };
    let query = route.request.and_then(|request| request.query);
    match route.operation.as_str() {
        "context_agent" => {
            query
                .and_then(|query| query.input)
                .and_then(|input| input.action)
                .as_deref()
                != Some("discover")
        }
        "context_assistance" => matches!(
            query.and_then(|query| query.kind).as_deref(),
            Some(
                "installations" | "versions" | "workspace" | "workspace_access" | "workspace_grant"
            )
        ),
        _ => false,
    }
}

#[cfg(test)]
#[path = "resident_context_dispatch_tests.rs"]
mod tests;

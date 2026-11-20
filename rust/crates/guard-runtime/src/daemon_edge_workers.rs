//! The standalone daemon's background work: Cloud sync, bundle refresh, the
//! AIBOM inventory, storage maintenance, command-pack catalog upkeep, one-file
//! extraction cleanup, the plugin report, the runtime heartbeat, the idle
//! shutdown and the worker host.
//!
//! The daemon owns each schedule. One pass of a job answers `{"ok": bool}`:
//! the job waits its interval after a pass that succeeded and its backoff
//! after one that did not, or could not run at all. The heartbeat, the idle
//! hold and storage maintenance run here (`daemon_edge_worker_ticks.rs`);
//! every other pass is one Guard library call (`workers/ticks.py`).
//!
//! Workers that wait on their own signals rather than a tick (the command
//! queue, Cloud review sync, approval attention, the repair self-check, the
//! resident watchdog and workspace assessment) run in one worker host child
//! (`desktop daemon-workers`, `workers/host.py`). The daemon holds the
//! child's standard input open, restarts it when it exits and, by exiting,
//! closes that input, which stops it.

use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::super::library;
use super::super::reads::NativeReads;

/// One background job's schedule.
pub(super) struct Job {
    pub(super) call: &'static str,
    pub(super) first: Duration,
    pub(super) interval: Duration,
    pub(super) backoff: Duration,
}

const fn seconds(value: u64) -> Duration {
    Duration::from_secs(value)
}

/// The jobs the Python daemon ran on its own threads, with its intervals.
pub(super) const JOBS: [Job; 7] = [
    Job {
        call: "worker.cloud_sync",
        first: seconds(0),
        interval: seconds(30),
        backoff: seconds(10),
    },
    Job {
        call: "worker.bundle_refresh",
        first: seconds(0),
        interval: seconds(15 * 60),
        backoff: seconds(60),
    },
    Job {
        call: "worker.maintain_activity",
        first: seconds(0),
        interval: seconds(3_600),
        backoff: seconds(5),
    },
    Job {
        call: "worker.aibom_inventory",
        first: seconds(0),
        interval: seconds(15 * 60),
        backoff: seconds(60),
    },
    Job {
        call: "worker.onefile_reclaim",
        first: seconds(0),
        interval: seconds(3_600),
        backoff: seconds(3_600),
    },
    Job {
        call: "worker.extension_catalog",
        first: seconds(30),
        interval: seconds(300),
        backoff: seconds(300),
    },
    Job {
        call: "worker.plugin_telemetry",
        first: seconds(300),
        interval: seconds(6 * 3_600),
        backoff: seconds(6 * 3_600),
    },
];

/// The job that runs in the resident library process, so the refresh it
/// starts outlives the pass and the extension-control service it serves is
/// refreshed in place.
const RESIDENT_JOB: &str = "worker.extension_catalog";

const HEARTBEAT_INTERVAL: Duration = seconds(30);
/// The first wait before a worker host that exited is started again, doubled
/// on each exit up to `HOST_RESTART_MAX`.
const HOST_RESTART_MIN: Duration = seconds(5);
const HOST_RESTART_MAX: Duration = seconds(300);
/// A host that ran this long before exiting restarts after the shortest wait.
const HOST_STABLE: Duration = seconds(600);
const IDLE_POLL: Duration = seconds(1);
/// How long a pending review or queued Cloud event holds an idle daemon
/// before the next check.
const IDLE_HOLD: Duration = seconds(5);
/// The longest startup waits for the worker host's first policy publication.
const HOST_READY_WAIT: Duration = seconds(15);
/// The longest a starting daemon waits on the artifact reconcile, counted
/// from when the reconcile began, before it reports ready anyway. A reconcile
/// normally takes a few seconds; one held by its library call could keep the
/// daemon from answering hooks for that call's whole timeout.
const RECONCILE_READY_WAIT: Duration = seconds(30);
/// How long the reconcile's library call waits for its answer. It stays under
/// the library's own call timeout, so a reconcile that gives up leaves the
/// shared resident running: by then the daemon may be serving hooks through
/// that same process.
const RECONCILE_CALL_WAIT: Duration = seconds(110);

/// What the heartbeat records for this daemon.
#[derive(Clone)]
pub(super) struct Registration {
    pub(super) session_id: String,
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) started_at: String,
    pub(super) guard_home: std::path::PathBuf,
}

/// Starts every job, the heartbeat and the worker host. Threads end with the
/// process. The idle shutdown starts separately, through `exit_when_idle`,
/// once the rest of the start has finished.
pub(super) fn start(reads: &Arc<NativeReads>, registration: Registration) {
    for job in &JOBS {
        let reads = Arc::clone(reads);
        let _ = thread::Builder::new()
            .name(format!("daemon-{}", job.call))
            .spawn(move || run_job(&reads, job, thread::sleep));
    }
    let heartbeat_reads = Arc::clone(reads);
    let args = json!({
        "session_id": registration.session_id,
        "host": registration.host,
        "port": registration.port,
        "started_at": registration.started_at,
    });
    let _ = thread::Builder::new()
        .name("daemon-heartbeat".into())
        .spawn(move || loop {
            let _ = pass(&heartbeat_reads, "worker.runtime_heartbeat", args.clone());
            thread::sleep(HEARTBEAT_INTERVAL);
        });
    let host_reads = Arc::clone(reads);
    let (ready, host_ready) = mpsc::channel();
    let started = thread::Builder::new()
        .name("daemon-worker-host".into())
        .spawn(move || supervise_host(&host_reads, Some(ready), thread::sleep));
    if started.is_ok() {
        // The daemon reported ready only after its first policy publication;
        // the worker host owns that publication now.
        let _ = host_ready.recv_timeout(HOST_READY_WAIT);
    }
}

/// Exits the process once it has been idle for `timeout`. Startup work such as
/// the artifact reconcile holds no connection, so the daemon calls this only
/// after that work is done; started earlier, a slow reconcile could outlast
/// the timeout and the daemon would exit before it reported ready. The idle
/// clock restarts here for the same reason: a start that took longer than the
/// timeout is not idle time.
///
/// A reconcile still running when the daemon reported ready is passed as
/// `pending`: the idle clock starts only once it finishes, so an idle daemon
/// never exits partway through one.
pub(super) fn exit_when_idle(
    reads: &Arc<NativeReads>,
    registration: &Registration,
    timeout: Duration,
    pending: Option<Reconcile>,
) {
    reads.touch();
    let idle_reads = Arc::clone(reads);
    let (home, session_id, port) = (
        registration.guard_home.clone(),
        registration.session_id.clone(),
        registration.port,
    );
    let _ = thread::Builder::new()
        .name("daemon-idle".into())
        .spawn(move || {
            if let Some(pending) = pending {
                pending.finish();
                idle_reads.touch();
            }
            watch_idle(&idle_reads, timeout, thread::sleep);
            super::super::lifecycle::record(
                &home,
                "shutdown_requested",
                Some("idle_timeout"),
                Some(&session_id),
                Some(port),
            );
            std::process::exit(0);
        });
}

fn run_job(reads: &NativeReads, job: &Job, mut sleep: impl FnMut(Duration)) -> ! {
    sleep(job.first);
    loop {
        let wait = next_wait(job, pass(reads, job.call, json!({})));
        sleep(wait);
    }
}

/// The wait after one pass: its interval when it succeeded, its backoff when
/// it failed or could not run.
pub(super) fn next_wait(job: &Job, answer: Option<Value>) -> Duration {
    match answer.and_then(|answer| answer.get("ok").and_then(Value::as_bool)) {
        Some(true) => job.interval,
        _ => job.backoff,
    }
}

/// Refreshes the artifacts Guard already manages for the active runtime
/// (`reconcile_runtime_artifacts`). A failure leaves them for the next start.
///
/// The call names this daemon's own loopback URL. The daemon has not reported
/// ready while the reconcile runs, so a hook artifact that records the daemon
/// URL would otherwise ask this daemon whether it is live and wait out the
/// health probe on every cold start.
pub(super) fn reconcile_artifacts(reads: &NativeReads, user_home: Option<&str>, port: u16) {
    let Some(config) = reads.config() else {
        return;
    };
    let args = reconcile_args(user_home, port);
    let call = "worker.reconcile_artifacts";
    if ticks::native(reads, &config, call, &args).is_some() {
        return;
    }
    let _ = library::call_resident_within(&config, call, args, RECONCILE_CALL_WAIT);
}

/// The reconcile call's arguments: the user's home and this daemon's own URL.
fn reconcile_args(user_home: Option<&str>, port: u16) -> Value {
    json!({ "home": user_home, "daemon_url": format!("http://127.0.0.1:{port}") })
}

/// A reconcile running on its own thread. The thread signals `done` once the
/// reconcile has finished and its `reconciled` record is written; the sender
/// is dropped without a signal if the thread ends any other way.
pub(super) struct Reconcile {
    done: mpsc::Receiver<()>,
    started: Instant,
}

impl Reconcile {
    /// Waits until the reconcile finishes or `budget` has passed since it
    /// started. Returns `None` once it has finished, or the reconcile itself
    /// while it is still running, so the caller can report ready and wait on
    /// it later.
    pub(super) fn wait_until(self, budget: Duration) -> Option<Self> {
        let left = budget.saturating_sub(self.started.elapsed());
        match self.done.recv_timeout(left) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => None,
            Err(mpsc::RecvTimeoutError::Timeout) => Some(self),
        }
    }

    /// Blocks until the reconcile thread ends.
    fn finish(self) {
        let _ = self.done.recv();
    }
}

/// Starts `reconcile_artifacts` on its own thread, so it runs while the
/// worker host starts and a cold start pays for the slower of the two rather
/// than both. The daemon waits on it, up to `RECONCILE_READY_WAIT`, before it
/// reports ready. Without a thread the reconcile runs here and `None` is
/// returned.
pub(super) fn reconcile_beside(
    reads: &Arc<NativeReads>,
    user_home: Option<String>,
    guard_home: std::path::PathBuf,
    port: u16,
) -> Option<Reconcile> {
    let (worker_reads, worker_user, worker_home) =
        (Arc::clone(reads), user_home.clone(), guard_home.clone());
    let (done, finished) = mpsc::channel();
    let started = Instant::now();
    let spawned = thread::Builder::new()
        .name("daemon-reconcile".into())
        .spawn(move || {
            reconciled(&worker_reads, worker_user.as_deref(), &worker_home, port);
            let _ = done.send(());
        });
    match spawned {
        Ok(_) => Some(Reconcile {
            done: finished,
            started,
        }),
        Err(_) => {
            reconciled(reads, user_home.as_deref(), &guard_home, port);
            None
        }
    }
}

/// Waits on a reconcile started by `reconcile_beside`, up to
/// `RECONCILE_READY_WAIT` from its start. One still running then keeps
/// running: it is journaled as `reconcile_deferred` and returned, so the
/// daemon reports ready rather than leave every hook waiting on it.
pub(super) fn settle_before_ready(
    reconcile: Option<Reconcile>,
    guard_home: &std::path::Path,
) -> Option<Reconcile> {
    let pending = reconcile?.wait_until(RECONCILE_READY_WAIT)?;
    super::super::lifecycle::record(
        guard_home,
        "reconcile_deferred",
        Some("ready_wait_elapsed"),
        None,
        None,
    );
    Some(pending)
}

fn reconciled(
    reads: &NativeReads,
    user_home: Option<&str>,
    guard_home: &std::path::Path,
    port: u16,
) {
    reconcile_artifacts(reads, user_home, port);
    super::super::lifecycle::record(guard_home, "reconciled", None, None, None);
}

fn pass(reads: &NativeReads, call: &str, args: Value) -> Option<Value> {
    let config = reads.config()?;
    if let Some(answer) = ticks::native(reads, &config, call, &args) {
        return answer;
    }
    if call == RESIDENT_JOB {
        return library::call_resident(&config, call, args).ok();
    }
    library::call(&config, call, args).ok()
}

/// Keeps one worker host running for the life of the daemon.
fn supervise_host(
    reads: &NativeReads,
    mut ready: Option<mpsc::Sender<()>>,
    mut sleep: impl FnMut(Duration),
) -> ! {
    let mut wait = HOST_RESTART_MIN;
    loop {
        let started = std::time::Instant::now();
        let ran = reads
            .config()
            .and_then(|config| library::run_host(&config, ready.take()))
            .is_some();
        wait = next_host_wait(wait, ran.then(|| started.elapsed()));
        sleep(wait);
    }
}

/// The wait before the next worker host start. `ran` is how long the last
/// host ran, or `None` when it could not be started.
pub(super) fn next_host_wait(previous: Duration, ran: Option<Duration>) -> Duration {
    match ran {
        Some(ran) if ran >= HOST_STABLE => HOST_RESTART_MIN,
        _ => (previous * 2).clamp(HOST_RESTART_MIN, HOST_RESTART_MAX),
    }
}

/// Returns once the daemon has served nothing for `timeout` and no durable
/// work holds it: a connection in flight or a pending review keeps it up.
fn watch_idle(reads: &NativeReads, timeout: Duration, mut sleep: impl FnMut(Duration)) {
    loop {
        if reads.active_connections() > 0 || reads.idle_for() < timeout {
            sleep(IDLE_POLL);
            continue;
        }
        let held = pass(reads, "worker.idle_holds", json!({}))
            .and_then(|answer| answer.get("hold").and_then(Value::as_bool))
            .unwrap_or(false);
        if !held && reads.active_connections() == 0 && reads.idle_for() >= timeout {
            return;
        }
        sleep(IDLE_HOLD);
    }
}

#[path = "daemon_edge_worker_ticks.rs"]
mod ticks;

#[cfg(all(test, unix))]
#[path = "daemon_edge_workers_tests.rs"]
mod tests;

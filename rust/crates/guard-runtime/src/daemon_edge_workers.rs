//! The standalone daemon's background work: Cloud sync, bundle refresh, the
//! AIBOM inventory, storage maintenance, command-pack catalog upkeep, one-file
//! extraction cleanup, the plugin report, the runtime heartbeat, the idle
//! shutdown and the worker host.
//!
//! The daemon owns each schedule. One pass of a job is one Guard library call
//! (`workers/ticks.py`) answering `{"ok": bool}`: the job waits its interval
//! after a pass that succeeded and its backoff after one that did not, or
//! could not run at all.
//!
//! Workers that wait on their own signals rather than a tick (the command
//! queue, Cloud review sync, approval attention, the repair self-check, the
//! resident watchdog and workspace assessment) run in one worker host child
//! (`desktop daemon-workers`, `workers/host.py`). The daemon holds the
//! child's standard input open, restarts it when it exits and, by exiting,
//! closes that input, which stops it.

use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

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

/// What the heartbeat records for this daemon.
pub(super) struct Registration {
    pub(super) session_id: String,
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) started_at: String,
    pub(super) guard_home: std::path::PathBuf,
}

/// Starts every job, the heartbeat and, when `idle_timeout` is set, the idle
/// shutdown. Threads end with the process.
pub(super) fn start(
    reads: &Arc<NativeReads>,
    registration: Registration,
    idle_timeout: Option<Duration>,
) {
    for job in &JOBS {
        let reads = Arc::clone(reads);
        let _ = thread::Builder::new()
            .name(format!("daemon-{}", job.call))
            .spawn(move || run_job(&reads, job, thread::sleep));
    }
    let heartbeat_reads = Arc::clone(reads);
    let lifecycle = (
        registration.guard_home.clone(),
        registration.session_id.clone(),
        registration.port,
    );
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
    if let Some(timeout) = idle_timeout {
        let idle_reads = Arc::clone(reads);
        let _ = thread::Builder::new()
            .name("daemon-idle".into())
            .spawn(move || {
                watch_idle(&idle_reads, timeout, thread::sleep);
                let (home, session_id, port) = &lifecycle;
                super::super::lifecycle::record(
                    home,
                    "shutdown_requested",
                    Some("idle_timeout"),
                    Some(session_id),
                    Some(*port),
                );
                std::process::exit(0);
            });
    }
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
pub(super) fn reconcile_artifacts(reads: &NativeReads, user_home: Option<&str>) {
    let _ = pass(
        reads,
        "worker.reconcile_artifacts",
        json!({ "home": user_home }),
    );
}

fn pass(reads: &NativeReads, call: &str, args: Value) -> Option<Value> {
    let config = reads.config()?;
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

#[cfg(all(test, unix))]
#[path = "daemon_edge_workers_tests.rs"]
mod tests;

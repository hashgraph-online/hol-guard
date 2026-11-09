//! The standalone daemon's background work: Cloud sync, bundle refresh,
//! storage maintenance, command-pack catalog upkeep, the plugin report, the
//! runtime heartbeat and the idle shutdown.
//!
//! The daemon owns each schedule. One pass of a job is one Guard library call
//! (`workers/ticks.py`) answering `{"ok": bool}`: the job waits its interval
//! after a pass that succeeded and its backoff after one that did not, or
//! could not run at all.

use std::sync::Arc;
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
pub(super) const JOBS: [Job; 5] = [
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

const HEARTBEAT_INTERVAL: Duration = seconds(30);
const IDLE_POLL: Duration = seconds(1);
/// How long a pending review or queued Cloud event holds an idle daemon
/// before the next check.
const IDLE_HOLD: Duration = seconds(5);

/// What the heartbeat records for this daemon.
pub(super) struct Registration {
    pub(super) session_id: String,
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) started_at: String,
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
    if let Some(timeout) = idle_timeout {
        let idle_reads = Arc::clone(reads);
        let _ = thread::Builder::new()
            .name("daemon-idle".into())
            .spawn(move || {
                watch_idle(&idle_reads, timeout, thread::sleep);
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

fn pass(reads: &NativeReads, call: &str, args: Value) -> Option<Value> {
    let config = reads.config()?;
    library::call(&config, call, args).ok()
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

#[cfg(test)]
#[path = "daemon_edge_workers_tests.rs"]
mod tests;

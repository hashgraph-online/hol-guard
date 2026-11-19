//! Why a standalone daemon stopped, written to the lifecycle journal before
//! it goes.
//!
//! A daemon that ends without a record is indistinguishable from one that
//! was killed, so each way out of `daemon-serve` records its own cause:
//! SIGTERM, the launcher's input closing, a listener failure, a panic on the
//! main thread (with its `file.rs:line`) and a start that never published.
//! SIGKILL and crashes cannot record anything; the next daemon reports those
//! as `unclean_exit_detected`.
//!
//! SIGINT and SIGHUP are not watched. The daemon leaves its launcher's
//! session, so no terminal sends them, and a launcher may start it with
//! either ignored: blocking an ignored signal to wait for it would make the
//! daemon stop on a signal it used to survive. A daemon they end still
//! surfaces through the next daemon's `unclean_exit_detected`.

use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::super::lifecycle::{self, Details};

const EXITING: &str = "exiting";
const START_FAILED: &str = "start_failed";

/// Where the main thread last panicked, kept for the record written after
/// the unwind reaches `serve_recording_panic`.
static MAIN_PANIC_LOCATION: Mutex<Option<String>> = Mutex::new(None);

/// Records that this daemon is exiting, and why.
pub(super) fn exiting(home: &Path, reason: &str) {
    record(home, EXITING, reason, None);
}

/// Records a start that ended before the daemon published its state. A home
/// that does not exist is left alone: there is nothing of Guard's to record
/// in, and creating it would invent one.
pub(super) fn start_failed(home: &Path, reason: &str) {
    if home.is_dir() {
        record(home, START_FAILED, reason, None);
    }
}

fn record(home: &Path, event: &str, reason: &str, location: Option<&str>) {
    let details = Details {
        reason: Some(reason),
        location,
        ..Details::default()
    };
    lifecycle::record_details(home, std::process::id(), event, &details);
}

/// Runs the daemon's serve loop. A panic that unwinds out of it is recorded
/// as `exiting` with reason `panic` and the panic's location, then carries on
/// unwinding exactly as it would have.
pub(super) fn serve_recording_panic(home: &Path, serve: impl FnOnce() -> i32) -> i32 {
    remember_main_panic_location();
    match panic::catch_unwind(AssertUnwindSafe(serve)) {
        Ok(code) => code,
        Err(payload) => {
            let location = MAIN_PANIC_LOCATION
                .lock()
                .ok()
                .and_then(|mut location| location.take());
            record(home, EXITING, "panic", location.as_deref());
            panic::resume_unwind(payload)
        }
    }
}

/// Wraps the installed panic hook so a panic on the main thread also leaves
/// its location for `serve_recording_panic`. The existing hook still runs.
fn remember_main_panic_location() {
    let previous = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        if std::thread::current().name() == Some("main") {
            if let (Some(location), Ok(mut slot)) = (info.location(), MAIN_PANIC_LOCATION.lock()) {
                *slot = Some(panic_location(location.file(), location.line()));
            }
        }
        previous(info);
    }));
}

/// `daemon_edge_serve.rs:12` from a build path, without the directories.
fn panic_location(file: &str, line: u32) -> String {
    let name = file.rsplit(['/', '\\']).next().unwrap_or(file);
    format!("{name}:{line}")
}

/// Records `exiting` with reason `signal_term` when SIGTERM arrives, then
/// lets the signal end the process as it always did.
///
/// SIGTERM is blocked on the calling thread, which every thread spawned after
/// it inherits, and one watcher thread waits for it. Call this before the
/// daemon starts any thread. Child processes do not inherit the block: the
/// standard library clears the signal mask of every process it spawns.
#[cfg(unix)]
pub(super) fn record_termination(home: PathBuf) {
    use nix::sys::signal::{raise, SigSet, Signal};

    let mut watched = SigSet::empty();
    watched.add(Signal::SIGTERM);
    if watched.thread_block().is_err() {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("daemon-signal-watch".to_owned())
        .spawn(move || loop {
            let Ok(signal) = watched.wait() else {
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            };
            exiting(&home, "signal_term");
            // Delivered to this thread with it unblocked, the signal takes
            // its default action and ends the process. Should the launcher
            // have left it ignored, it is ignored again, and the watch resumes.
            let _ = watched.thread_unblock();
            let _ = raise(signal);
            let _ = watched.thread_block();
        });
    if spawned.is_err() {
        let _ = watched.thread_unblock();
    }
}

#[cfg(not(unix))]
pub(super) fn record_termination(_home: PathBuf) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_locations_keep_only_the_file_name() {
        assert_eq!(
            panic_location("/build/rust/crates/guard-runtime/src/daemon_edge.rs", 40),
            "daemon_edge.rs:40"
        );
        assert_eq!(panic_location("src\\daemon_edge.rs", 7), "daemon_edge.rs:7");
    }

    #[test]
    fn a_start_failure_in_a_missing_home_writes_nothing() {
        let parent = tempfile::tempdir().unwrap();
        let missing = parent.path().join("absent");
        start_failed(&missing, "launch_config_invalid");
        assert!(!missing.exists());
    }

    #[test]
    fn a_start_failure_is_journaled_with_its_reason() {
        let home = tempfile::tempdir().unwrap();
        start_failed(home.path(), "listen_failed");
        let (events, _) = lifecycle::load_events(home.path(), 10, false);
        let last = events.last().expect("a start_failed record");
        assert_eq!(last["event"], START_FAILED);
        assert_eq!(last["reason"], "listen_failed");
        assert_eq!(last["pid"], std::process::id());
    }
}

//! Daemon start for the native Claude, Codex, Cursor and bounded hook bridges: what a bridge
//! does when its daemon is unreachable or did not answer, in place of the
//! Python bridge it used to hand the hook to.
//!
//! The bridge runs the install-time daemon-start command once, isolated and
//! bounded by what is left of the hook deadline, then asks the daemon again
//! while it comes up. The start command only schedules the start, so the
//! bridge polls with a short backoff until the daemon answers or the wait
//! window closes. A hook with too little time left for both the start and
//! one request is never started for; the caller fails it closed.
//!
//! Nothing here decides a verdict: an answer still comes only from the
//! daemon, and every other outcome is the caller's fail-closed answer. The
//! start command runs only on this failure path, never per hook.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::claude_hook_bridge::home_directory;
use crate::claude_hook_bridge_http::remaining;
use crate::hook_process_spawn::{isolated_hook_environment, run_isolated_hook_process};

/// `HOL_GUARD_HOOK_FAILURE_KIND` for a daemon that is down or did not answer.
pub(crate) const TRANSPORT_FAILURE: &str = "transport-failure";

const FAILURE_KIND_ENV: &str = "HOL_GUARD_HOOK_FAILURE_KIND";
const DESKTOP_ENV: &str = "HOL_GUARD_DESKTOP";
const DESKTOP_PROXY_ENV: &str = "HOL_GUARD_DESKTOP_HOOK_PROXY";
/// The longest the start command may run, as `_DAEMON_START_TIMEOUT_SECONDS`.
const START_TIMEOUT: Duration = Duration::from_secs(8);
/// Below this much hook time the start is skipped and the hook fails closed.
const MINIMUM_START: Duration = Duration::from_millis(1500);
/// Hook time the start command never uses, so one request still fits.
const RETRY_RESERVE: Duration = Duration::from_secs(1);
/// The shortest request worth making after a pause.
pub(crate) const MINIMUM_REQUEST: Duration = Duration::from_millis(500);
/// The longest the bridge waits for a started daemon to come up.
const START_WAIT: Duration = Duration::from_secs(8);
// A daemon comes up within a few seconds; a short poll keeps a hook from
// idling up to a second after it is ready.
const FIRST_POLL: Duration = Duration::from_millis(50);
const MAX_POLL: Duration = Duration::from_millis(250);

/// Run `command` to start the daemon, inside `deadline`. `true` when it
/// exited zero in time. An empty command, a hook with less than
/// `MINIMUM_START` left, or no home directory runs nothing and is `false`.
pub(crate) fn start_daemon(command: &[String], failure_kind: &str, deadline: Instant) -> bool {
    let left = remaining(deadline);
    if command.is_empty() || left < MINIMUM_START {
        return false;
    }
    let Some(home) = home_directory() else {
        return false;
    };
    let source: BTreeMap<String, String> = std::env::vars_os()
        .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
        .collect();
    let mut environment = start_environment(&source);
    environment.insert(FAILURE_KIND_ENV.to_owned(), failure_kind.to_owned());
    let timeout = (left - RETRY_RESERVE).min(START_TIMEOUT);
    // An absolute deadline overrides the timeout, so pass the start's own
    // deadline: the hook's would let the start eat the retry reserve.
    let start_deadline = (Instant::now() + timeout).min(deadline);
    let result = run_isolated_hook_process(
        command,
        "",
        &home,
        &environment,
        Some(timeout.as_secs_f64()),
        None,
        None,
        Some(start_deadline),
    );
    result.returncode == Some(0)
        && !result.timed_out
        && !result.output_limit_exceeded
        && !result.containment_failed
}

/// `isolated_hook_environment()`: the allowlisted keys plus, for a Desktop
/// hook, the signed proxy selectors (`desktop_hook_proxy_context`), so a
/// Desktop daemon start runs as Python's did.
fn start_environment(source: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut environment = isolated_hook_environment(source);
    let proxy = source.get(DESKTOP_PROXY_ENV).filter(|proxy| {
        !proxy.is_empty() && !proxy.contains('\0') && Path::new(proxy.as_str()).is_absolute()
    });
    if let (Some("1"), Some(proxy)) = (source.get(DESKTOP_ENV).map(String::as_str), proxy) {
        environment.insert(DESKTOP_ENV.to_owned(), "1".to_owned());
        environment.insert(DESKTOP_PROXY_ENV.to_owned(), proxy.clone());
    }
    environment
}

/// One ask of a daemon that may still be starting.
pub(crate) enum Attempt<T> {
    /// The daemon answered, or failed in a way waiting cannot change.
    Settled(T),
    /// The daemon is not up yet: ask again after a pause.
    NotUp,
}

/// Ask with `attempt` until it settles, pausing with a doubling backoff.
/// `None` once the wait window or the hook deadline leaves no room for
/// another request.
pub(crate) fn await_daemon<T>(
    deadline: Instant,
    mut attempt: impl FnMut() -> Attempt<T>,
) -> Option<T> {
    let window_end = Instant::now() + START_WAIT;
    let stop = deadline
        .checked_sub(MINIMUM_REQUEST)
        .map_or(window_end, |last| last.min(window_end));
    let mut pause = FIRST_POLL;
    loop {
        if let Attempt::Settled(value) = attempt() {
            return Some(value);
        }
        if Instant::now() + pause >= stop {
            return None;
        }
        std::thread::sleep(pause);
        pause = (pause * 2).min(MAX_POLL);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn shell(script: &str) -> Vec<String> {
        vec!["/bin/sh".to_owned(), "-c".to_owned(), script.to_owned()]
    }

    #[test]
    fn a_start_runs_only_with_a_command_and_enough_time() {
        let home = tempfile::tempdir().unwrap();
        let marker = home.path().join("started");
        let touch = shell(&format!(": > '{}'", marker.display()));
        let soon = Instant::now() + Duration::from_secs(1);
        assert!(!start_daemon(&touch, TRANSPORT_FAILURE, soon));
        assert!(!start_daemon(
            &[],
            TRANSPORT_FAILURE,
            Instant::now() + START_TIMEOUT
        ));
        assert!(!marker.exists());
        assert!(start_daemon(
            &touch,
            TRANSPORT_FAILURE,
            Instant::now() + START_TIMEOUT
        ));
        assert!(marker.exists());
        assert!(!start_daemon(
            &shell("exit 3"),
            TRANSPORT_FAILURE,
            Instant::now() + START_TIMEOUT
        ));
    }

    #[test]
    fn the_start_command_is_told_why_the_daemon_is_restarted() {
        let home = tempfile::tempdir().unwrap();
        let seen = home.path().join("kind");
        let script = format!("printf %s \"${FAILURE_KIND_ENV}\" > '{}'", seen.display());
        assert!(start_daemon(
            &shell(&script),
            "overload",
            Instant::now() + START_TIMEOUT
        ));
        assert_eq!(std::fs::read_to_string(seen).unwrap(), "overload");
    }

    #[test]
    fn the_wait_ends_with_an_answer_or_the_deadline() {
        let mut asks = 0;
        let answer = await_daemon(Instant::now() + Duration::from_secs(5), || {
            asks += 1;
            if asks < 3 {
                Attempt::NotUp
            } else {
                Attempt::Settled(asks)
            }
        });
        assert_eq!(answer, Some(3));
        let started = Instant::now();
        let never = await_daemon(started + Duration::from_secs(1), || Attempt::<()>::NotUp);
        assert_eq!(never, None);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn the_start_environment_keeps_the_desktop_proxy_as_python_does() {
        let all: serde_json::Value = serde_json::from_str(include_str!(
            "../testdata/codex_hook_bridge/client_mode.json"
        ))
        .unwrap();
        let environment = |value: &serde_json::Value| -> BTreeMap<String, String> {
            value
                .as_object()
                .unwrap()
                .iter()
                .map(|(key, value)| (key.clone(), value.as_str().unwrap().to_owned()))
                .collect()
        };
        for case in all["start_environments"].as_array().unwrap() {
            assert_eq!(
                start_environment(&environment(&case["source"])),
                environment(&case["expected"]),
                "{case}"
            );
        }
    }
}

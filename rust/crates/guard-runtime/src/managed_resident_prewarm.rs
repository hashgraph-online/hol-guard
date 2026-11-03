#![forbid(unsafe_code)]

//! Bring this runtime's resident up before a session's first hook needs it.
//!
//! A cold resident costs the first interactive hook of a session the whole
//! start: the spawn, the startup lock, the catalog and the policy. The
//! session-start lane runs this once per session, detached, so that start
//! happens while the user is still reading their prompt.
//!
//! The request is the resident's own `health` operation, which answers from
//! the running process and decides nothing. Nothing here produces a verdict,
//! a receipt or an approval, and a prewarm that fails leaves the first hook
//! exactly where it was before.
//!
//! An ownerless resident retires once no client has held a lease for
//! `LEASE_EXPIRY` (`spawn_owner_lease_watcher`), so starting one and exiting
//! would retire it about a second later. The prewarm instead holds its own
//! client lease for a bounded window and then lets go: a session whose first
//! hook arrives inside the window finds the resident up and takes its own
//! lease, and a session that never uses a hook leaves nothing running.
//!
//! A resident some other client is already holding is left alone: the
//! prewarm returns before it takes a lease of its own, and so is a host whose
//! restart budget is nearly spent: nothing a user is waiting on may be
//! refused a spawn because a prewarm took the last one.
//!
//! The prewarm also asks the resident to start a resting CIGAR worker
//! (`context_assistance` kind `warm`), including when another client already
//! holds the resident: after an idle stop the resident is still up but the
//! worker is not, and without this the session's first prompt finds it
//! starting and gets only a list of files. The resident does nothing unless
//! project context is on and the harness is not watch-only, and a request
//! that fails changes nothing. A resident this prewarm just started has no
//! policy binding until the daemon pushes one, so it answers `waiting` and the
//! prewarm asks again for a bounded window.

use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;

use crate::resident_process_identity::executable_missing;
use crate::resident_state::{runtime_digest, state_scope};

/// The resident operation this asks for: it answers from the running
/// process, so it measures the start and nothing else.
const PREWARM_PAYLOAD: &[u8] = br#"{"operation":"health","request":{}}"#;
/// Budget for the start and the health answer together, above the client's
/// own 9 second start timeout so a slow start is still waited out.
const PREWARM_REQUEST_TIMEOUT: Duration = Duration::from_secs(12);
/// How long the prewarm keeps a resident it started alive. Long enough for
/// the first tool call of a session, short enough that an unused session
/// leaves no resident behind.
const PREWARM_HOLD: Duration = Duration::from_secs(120);
/// How often the hold rechecks that this runtime is still installed.
const PREWARM_POLL: Duration = Duration::from_millis(250);
/// The CIGAR warm answers once the worker start is scheduled, not when it is
/// up, so it needs little more than a busy resident's queue.
const WARM_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the prewarm keeps asking a resident that is still waiting for
/// its policy binding. The daemon pushes one within about a second of a new
/// resident; a daemon that is down never will.
const WARM_WAIT: Duration = Duration::from_secs(30);
/// How often the prewarm asks again while the resident is waiting.
const WARM_RETRY: Duration = Duration::from_millis(500);

pub(super) fn run(state_base: &Path) -> Result<(), String> {
    run_with_hold(
        state_base,
        PREWARM_HOLD,
        warm_payload(state_base).as_deref(),
    )
}

/// The prewarm with its hold window and the CIGAR warm request to send, if
/// any.
pub(super) fn run_with_hold(
    state_base: &Path,
    hold: Duration,
    warm: Option<&[u8]>,
) -> Result<(), String> {
    let digest = runtime_digest()?;
    let live = super::lease::any_live(state_base, &digest);
    // A held resident should answer without a spawn, but one that exited
    // since the check would be started again, so the budget gates both.
    if !super::restart_budget::speculative_spawn_allowed(&state_scope(state_base, &digest)?)? {
        return Ok(());
    }
    if live {
        if let Some(payload) = warm {
            warm_until_answered(WARM_WAIT, WARM_RETRY, || {
                super::lease::client_request(state_base, payload, WARM_REQUEST_TIMEOUT)
            });
        }
        return Ok(());
    }
    let started = Instant::now();
    let client_lease = super::lease::acquire(state_base)?;
    super::client_request_with_lease(
        state_base,
        PREWARM_PAYLOAD,
        PREWARM_REQUEST_TIMEOUT,
        &client_lease,
    )?;
    if let Some(payload) = warm {
        warm_until_answered(WARM_WAIT, WARM_RETRY, || {
            super::client_request_with_lease(
                state_base,
                payload,
                WARM_REQUEST_TIMEOUT,
                &client_lease,
            )
        });
    }
    hold_lease(
        hold.saturating_sub(started.elapsed()),
        std::env::current_exe().ok().as_deref(),
    );
    Ok(())
}

/// Send the CIGAR warm until the resident stops answering `waiting` or
/// `window` runs out. Any other answer, including an error, ends it: only a
/// missing policy binding is worth waiting for.
fn warm_until_answered(
    window: Duration,
    retry: Duration,
    mut send: impl FnMut() -> Result<Vec<u8>, String>,
) {
    let deadline = Instant::now() + window;
    loop {
        let waiting = send().ok().is_some_and(|answer| {
            serde_json::from_slice::<serde_json::Value>(&answer)
                .is_ok_and(|answer| answer["payload"]["warm"] == "waiting")
        });
        let left = deadline.saturating_duration_since(Instant::now());
        if !waiting || left.is_zero() {
            return;
        }
        thread::sleep(left.min(retry));
    }
}

/// The CIGAR warm request for the Guard home holding `state_base`, or `None`
/// when that home is not an absolute path the resident could match.
fn warm_payload(state_base: &Path) -> Option<Vec<u8>> {
    let guard_home = state_base.parent().filter(|home| home.is_absolute())?;
    let frame = json!({
        "operation": "context_assistance",
        "request": {
            "schema": "guard-context-assistance-request.v1",
            "request_id": "session-start-warm",
            "query": {"kind": "warm", "guard_home": guard_home.to_str()?, "input": {}},
        },
    });
    serde_json::to_vec(&frame).ok()
}

/// What identifies the installed file, so a replacement at the same path is
/// visible without rehashing a runtime every poll. An installer replaces the
/// executable atomically, which leaves the path in place and puts a different
/// file behind it: on Unix that is a new inode, and elsewhere a length and a
/// modification time that an installed build moves together.
fn executable_identity(path: &Path) -> Option<(u64, u64)> {
    let metadata = path.metadata().ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some((metadata.dev(), metadata.ino()))
    }
    #[cfg(not(unix))]
    {
        let modified = metadata
            .modified()
            .ok()
            .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |since| {
                u64::try_from(since.as_nanos()).unwrap_or(u64::MAX)
            });
        Some((metadata.len(), modified))
    }
}

/// Hold the lease for `window`, ending early when `executable` is no longer
/// the runtime that started this prewarm, so an upgrade does not keep the
/// replaced resident leased while the new one is trying to retire it. An
/// unknown executable only means this cannot watch for the upgrade; the
/// window still bounds the hold.
fn hold_lease(window: Duration, executable: Option<&Path>) {
    let deadline = Instant::now() + window;
    let installed = executable.and_then(executable_identity);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return;
        }
        if let Some(path) = executable {
            if executable_missing(path) {
                return;
            }
            // Only a reading that succeeded and names a different file ends
            // the hold: a path that cannot be read right now is not evidence
            // that it was replaced.
            if installed.is_some()
                && executable_identity(path).is_some_and(|now| Some(now) != installed)
            {
                return;
            }
        }
        thread::sleep(left.min(PREWARM_POLL));
    }
}

#[cfg(all(test, unix))]
#[path = "managed_resident_prewarm_tests.rs"]
mod tests;

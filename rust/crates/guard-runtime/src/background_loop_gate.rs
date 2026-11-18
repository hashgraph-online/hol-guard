//! When a degraded background loop may try again, and when it may say so.
//!
//! The resident library process that runs Guard's catalog refresh and authority
//! enrollment is replaced whenever the native daemon gives up on one of its
//! calls. Each replacement used to start every loop from a clean slate: the
//! catalog refresh fetched the release again, failed the same way, and wrote the
//! same two error lines, and enrollment wrote its skipped line again. A host
//! whose library process was replaced every few minutes logged close to a
//! thousand identical lines a day, which buried the line that said what changed.
//!
//! This ledger survives the process. It holds, for each named loop, how many
//! attempts in a row have failed, a digest of the failure they share, when the
//! loop last ran and when it last logged. It decides two things:
//!
//! * a loop that is failing waits before trying again, starting at five
//!   minutes and doubling to an hour, so a fault the network or the release
//!   will not fix by itself is not retried on every restart;
//! * a failure is logged when the loop starts failing, when the failure
//!   changes, and then at most every six hours while it stays the same, and the
//!   loop's recovery is reported once.
//!
//! A line counts as said only once the caller's log has taken it: the caller
//! confirms with the `logged` op. Until then the same failure, or the same
//! recovery, is offered again on the next outcome, so a failure seen before
//! the daemon's log is listening is not silenced for six hours.
//!
//! A healthy loop is never held back, so a host that is working refreshes
//! exactly as often as before. Nothing here decides whether a command is
//! allowed: these loops only maintain the catalog and its authority, and every
//! hook keeps failing closed on its own when they are degraded.
//!
//! The file holds no path, no error text and no free text: a failure is kept
//! only as a short digest of the key the caller named. A damaged or foreign
//! file counts as empty. Any fault in the gate is returned to the caller, which
//! then behaves as it did before this ledger existed.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::daemon_edge::standalone::write_private_atomic;

const REQUEST_SCHEMA: &str = "hol-guard-background-loop-gate.v1";
const LEDGER_SCHEMA: &str = "hol-guard-background-loops.v1";
const LEDGER_FILE: &str = "background-loops.json";
const LOCK_FILE: &str = "background-loops.lock";
const MAX_REQUEST_BYTES: u64 = 4 * 1024;
const MAX_LEDGER_BYTES: u64 = 8 * 1024;
const MAX_FAILURE_KEY_BYTES: usize = 256;
const LOCK_WAIT: Duration = Duration::from_millis(250);
const LOCK_POLL: Duration = Duration::from_millis(10);
/// The first wait after a failure. It matches the refresh timer a healthy
/// loop already runs on, so one transient failure costs nothing extra.
const FIRST_BACKOFF_MS: u64 = 5 * 60 * 1_000;
/// The longest a failing loop waits. A release or a network that recovers is
/// picked up within the hour.
const MAX_BACKOFF_MS: u64 = 60 * 60 * 1_000;
/// How often an unchanged failure is said again, so a daemon.log that was
/// rotated or handed over still shows that the loop has not recovered.
const RELOG_INTERVAL_MS: u64 = 6 * 60 * 60 * 1_000;
const DIGEST_HEX: usize = 16;

/// The loops this ledger keeps. A fixed list keeps the file a fixed size.
const LOOPS: &[&str] = &[
    "catalog_publication_refresh",
    "default_authority_enrollment",
    "installed_authority_migration",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    guard_home: PathBuf,
    op: String,
    #[serde(default)]
    r#loop: Option<String>,
    #[serde(default)]
    failure_key: Option<String>,
    #[serde(default)]
    now_ms: Option<u64>,
}

#[derive(Clone, Default, Deserialize, Serialize, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoopState {
    pub(crate) failures: u64,
    pub(crate) failure: Option<String>,
    pub(crate) failing_since_ms: u64,
    pub(crate) last_attempt_ms: u64,
    pub(crate) last_logged_ms: u64,
    pub(crate) suppressed: u64,
    /// A line was offered for the current failure and no log has taken it.
    #[serde(default)]
    pub(crate) log_pending: bool,
    /// The failures a recovery ended, while no log has taken that recovery.
    #[serde(default)]
    pub(crate) recovery_pending: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    schema: String,
    loops: BTreeMap<String, LoopState>,
}

impl Ledger {
    fn empty() -> Self {
        Self {
            schema: LEDGER_SCHEMA.to_owned(),
            loops: BTreeMap::new(),
        }
    }
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "background-loop-gate"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "background_loop_gate_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("background_loop_gate_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes)
        .map_err(|_| "background_loop_gate_request_invalid".to_owned())?;
    if request.schema != REQUEST_SCHEMA {
        return Err("background_loop_gate_request_invalid".to_owned());
    }
    let answer = answer(&request)?;
    serde_json::to_vec(&answer).map_err(|_| "background_loop_gate_encode_failed".to_owned())
}

fn answer(request: &Request) -> Result<Value, String> {
    let home = guard_home(&request.guard_home)?;
    let now = match request.now_ms {
        Some(simulated) if cfg!(test) => simulated,
        Some(_) => return Err("background_loop_gate_request_invalid".to_owned()),
        None => now_ms()?,
    };
    match request.op.as_str() {
        "status" => {
            let ledger = with_ledger(&home, |_| None)?;
            Ok(status(&ledger, now))
        }
        "attempt" => {
            let name = loop_name(request.r#loop.as_deref())?;
            let mut run = true;
            let mut retry_after_ms = 0;
            with_ledger(&home, |ledger| {
                let state = ledger.loops.entry(name.to_owned()).or_default();
                let wait = backoff_ms(state.failures);
                let elapsed = now.checked_sub(state.last_attempt_ms);
                // A clock that went backwards proves nothing about the wait,
                // so it never keeps a loop from running.
                if let Some(elapsed) = elapsed.filter(|elapsed| *elapsed < wait) {
                    run = false;
                    retry_after_ms = wait - elapsed;
                    return None;
                }
                state.last_attempt_ms = now;
                Some(())
            })?;
            Ok(
                json!({"ok": true, "run": run, "retry_after_seconds": retry_after_ms.div_ceil(1_000)}),
            )
        }
        "outcome" => {
            let name = loop_name(request.r#loop.as_deref())?;
            let failure = request
                .failure_key
                .as_deref()
                .map(failure_digest)
                .transpose()?;
            let mut verdict = json!({});
            with_ledger(&home, |ledger| {
                let state = ledger.loops.entry(name.to_owned()).or_default();
                verdict = record_outcome(state, failure, now);
                Some(())
            })?;
            Ok(verdict)
        }
        "logged" => {
            let name = loop_name(request.r#loop.as_deref())?;
            let failure = request
                .failure_key
                .as_deref()
                .map(failure_digest)
                .transpose()?;
            with_ledger(&home, |ledger| {
                let state = ledger.loops.entry(name.to_owned()).or_default();
                record_logged(state, failure.as_deref(), now).then_some(())
            })?;
            Ok(json!({"ok": true}))
        }
        _ => Err("background_loop_gate_request_invalid".to_owned()),
    }
}

/// Apply one outcome and say whether it is worth a line in the log.
pub(crate) fn record_outcome(state: &mut LoopState, failure: Option<String>, now: u64) -> Value {
    let Some(failure) = failure else {
        // A recovery no log has taken yet is offered again, with the count it
        // ended, until one does or the loop fails again.
        let failures = if state.failures > 0 {
            state.failures
        } else {
            state.recovery_pending
        };
        *state = LoopState {
            last_attempt_ms: state.last_attempt_ms,
            recovery_pending: failures,
            ..LoopState::default()
        };
        return json!({"ok": true, "log": false, "recovered": failures > 0, "failures": failures});
    };
    let started = state.failures == 0;
    let changed = state.failure.as_deref() != Some(failure.as_str());
    let due =
        now.saturating_sub(state.last_logged_ms) >= RELOG_INTERVAL_MS || now < state.last_logged_ms;
    if started {
        state.failing_since_ms = now;
        state.last_logged_ms = 0;
        state.suppressed = 0;
    }
    state.recovery_pending = 0;
    state.failures = state.failures.saturating_add(1);
    state.failure = Some(failure);
    // The previous line for this failure was never taken, so this one is
    // still the first the log will see.
    let log = started || changed || due || state.log_pending;
    let repeats = state.suppressed;
    // Every attempt counts as unlogged until a log confirms it took the line;
    // the confirmation then clears the count.
    state.suppressed = state.suppressed.saturating_add(1);
    state.log_pending = log;
    json!({
        "ok": true,
        "log": log,
        "recovered": false,
        "failures": state.failures,
        "repeats": if log { repeats } else { 0 },
    })
}

/// Note that a log took the line offered for `failure`, or the recovery
/// offered when `failure` is `None`. A confirmation for a failure that is no
/// longer current changes nothing, so a late caller cannot silence a newer one.
pub(crate) fn record_logged(state: &mut LoopState, failure: Option<&str>, now: u64) -> bool {
    match failure {
        Some(failure) => {
            if !state.log_pending || state.failure.as_deref() != Some(failure) {
                return false;
            }
            state.log_pending = false;
            state.last_logged_ms = now;
            state.suppressed = 0;
            true
        }
        None => {
            if state.recovery_pending == 0 {
                return false;
            }
            state.recovery_pending = 0;
            true
        }
    }
}

/// How long a loop that has failed `failures` times in a row waits.
pub(crate) fn backoff_ms(failures: u64) -> u64 {
    if failures == 0 {
        return 0;
    }
    let doublings = u32::try_from(failures - 1).unwrap_or(u32::MAX).min(16);
    FIRST_BACKOFF_MS
        .saturating_mul(1u64 << doublings)
        .min(MAX_BACKOFF_MS)
}

fn status(ledger: &Ledger, now: u64) -> Value {
    let loops = LOOPS
        .iter()
        .map(|name| {
            let state = ledger.loops.get(*name).cloned().unwrap_or_default();
            if state.failures == 0 {
                return json!({"loop": name, "state": "healthy"});
            }
            let next = state
                .last_attempt_ms
                .saturating_add(backoff_ms(state.failures))
                .saturating_sub(now);
            json!({
                "loop": name,
                "state": "failing",
                "failures": state.failures,
                "failing_for_seconds": now.saturating_sub(state.failing_since_ms) / 1_000,
                "next_attempt_in_seconds": next.div_ceil(1_000),
            })
        })
        .collect::<Vec<_>>();
    json!({"ok": true, "loops": loops})
}

fn loop_name(name: Option<&str>) -> Result<&'static str, String> {
    let name = name.ok_or_else(|| "background_loop_gate_loop_missing".to_owned())?;
    LOOPS
        .iter()
        .copied()
        .find(|known| *known == name)
        .ok_or_else(|| "background_loop_gate_loop_unknown".to_owned())
}

/// The ledger keeps only a short digest of the caller's failure key: enough to
/// tell one failure from another, and nothing a reader could learn from.
fn failure_digest(key: &str) -> Result<String, String> {
    if key.is_empty()
        || key.len() > MAX_FAILURE_KEY_BYTES
        || !key.bytes().all(|byte| (0x20..0x7f).contains(&byte))
    {
        return Err("background_loop_gate_failure_key_invalid".to_owned());
    }
    let digest = Sha256::digest(key.as_bytes());
    Ok(hex::encode(digest)[..DIGEST_HEX].to_owned())
}

fn guard_home(path: &Path) -> Result<PathBuf, String> {
    let invalid = || "background_loop_gate_guard_home_invalid".to_owned();
    if !path.is_absolute() {
        return Err(invalid());
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| invalid())?;
    if !metadata.is_dir() {
        return Err(invalid());
    }
    Ok(path.to_owned())
}

/// Read the ledger under its lock, let `change` edit it, and write it back
/// only when `change` says it changed something.
fn with_ledger(
    home: &Path,
    change: impl FnOnce(&mut Ledger) -> Option<()>,
) -> Result<Ledger, String> {
    let _lock = lock(home)?;
    let path = home.join(LEDGER_FILE);
    let mut ledger = read_ledger(&path).unwrap_or_else(Ledger::empty);
    ledger
        .loops
        .retain(|name, _| LOOPS.contains(&name.as_str()));
    if change(&mut ledger).is_some() {
        let encoded = serde_json::to_vec(&ledger)
            .map_err(|_| "background_loop_gate_encode_failed".to_owned())?;
        write_private_atomic(&path, &encoded)
            .map_err(|_| "background_loop_gate_write_failed".to_owned())?;
    }
    Ok(ledger)
}

/// A ledger that is missing, a link, too large, damaged or another schema
/// reads as empty: the next outcome rewrites it from nothing.
fn read_ledger(path: &Path) -> Option<Ledger> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_LEDGER_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(MAX_LEDGER_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    let ledger = serde_json::from_slice::<Ledger>(&bytes).ok()?;
    (ledger.schema == LEDGER_SCHEMA).then_some(ledger)
}

fn lock(home: &Path) -> Result<File, String> {
    let busy = || "background_loop_gate_busy".to_owned();
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(home.join(LOCK_FILE)).map_err(|_| busy())?;
    let deadline = Instant::now() + LOCK_WAIT;
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock || is_contended(&error) => {
                if Instant::now() >= deadline {
                    return Err(busy());
                }
                thread::sleep(LOCK_POLL);
            }
            Err(_) => return Err(busy()),
        }
    }
}

fn is_contended(error: &io::Error) -> bool {
    error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
}

fn now_ms() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .ok_or_else(|| "background_loop_gate_clock_invalid".to_owned())
}

#[cfg(test)]
#[path = "background_loop_gate_tests.rs"]
mod tests;

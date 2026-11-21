//! The locks an owned mutation takes, and why one can refuse.
//!
//! A lifecycle lock is one file per Codex configuration directory; the
//! installation lock is one file per Guard home. Each is taken with a bounded
//! wait: a lifecycle lock either waits for the caller's deadline or, for the
//! locks that only exclude a competing owner, a short grace that lets the
//! resident notice an owner that exited. A refusal carries the exception the
//! Python callers raised for it, so the clients keep their error codes and
//! messages.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::lease::try_lock;
use super::lock_files::{install_lock, lifecycle_lock, Refusal};

pub(super) const INSTALL_DEADLINE: &str = "Codex installation transaction deadline exceeded.";
pub(super) const LIFECYCLE_DEADLINE: &str = "Codex lifecycle transaction deadline exceeded.";
const LIFECYCLE_BUSY: &str =
    "codex_lifecycle_busy: another lifecycle operation owns this Codex configuration";
const LOCK_UNSAFE: &str = "Codex transaction ownership file is unsafe.";
/// Three of the resident reaper's 50 ms passes over the leases.
const GRACE: Duration = Duration::from_millis(150);
const POLL: Duration = Duration::from_millis(25);

/// Why an owned mutation stopped, in the exception the client raises for it.
#[derive(Debug)]
pub(crate) enum Failure {
    /// `TimeoutError(message)`.
    Timeout(&'static str),
    /// `RuntimeError(message)`.
    Runtime(String),
    /// `CodexHookIntegrityError(code, message)`.
    Integrity(String, String),
    /// `CodexHookIntegrityError(reason, message)` for a baseline the runtime
    /// refused to trust, chained to the `cause` reason the refusal named. The
    /// value is the `{reason, message, cause?}` the baseline answered.
    Untrusted(Value),
    /// `TransitionError(reason)`.
    Transition(&'static str),
    /// A publication fault, in the shape `Fault::to_json` answers.
    Fault(Value),
}

impl Failure {
    pub(crate) fn to_json(&self) -> Value {
        let failure = match self {
            Self::Timeout(message) => json!({ "kind": "timeout", "message": message }),
            Self::Runtime(message) => json!({ "kind": "runtime", "message": message }),
            Self::Integrity(code, message) => {
                json!({ "kind": "integrity", "code": code, "message": message })
            }
            Self::Untrusted(untrusted) => {
                let field = |key: &str| untrusted.get(key).cloned().unwrap_or(Value::Null);
                let mut failure = json!({
                    "kind": "integrity",
                    "code": field("reason"),
                    "message": field("message"),
                });
                if let Some(cause) = untrusted.get("cause") {
                    failure["cause"] = cause.clone();
                }
                failure
            }
            Self::Transition(reason) => json!({ "kind": "transition", "reason": reason }),
            Self::Fault(fault) => json!({ "kind": "fault", "fault": fault }),
        };
        json!({ "ok": false, "failure": failure })
    }
}

/// One lock file held by its open handle; dropping it releases the lock.
pub(crate) struct Held {
    pub(super) file: fs::File,
    pub(super) path: PathBuf,
}

/// How long a lifecycle lock may stay busy before the take refuses.
#[derive(Clone, Copy)]
pub(super) enum Limit {
    /// Only long enough to see an owner that has exited: the lock excludes a
    /// competitor and answers busy.
    Grace,
    /// Until the deadline: the caller waits its turn.
    Until(Instant),
}

fn locked_by(file: &mut fs::File, limit: Instant) -> std::io::Result<bool> {
    loop {
        if try_lock(file)? {
            return Ok(true);
        }
        let now = Instant::now();
        if now >= limit {
            return Ok(false);
        }
        std::thread::sleep(POLL.min(limit - now));
    }
}

fn integrity(code: String) -> Failure {
    let message = match code.as_str() {
        "codex_hook_manifest_directory_unsafe" => {
            "The Codex managed-hook directory is not a private regular directory."
        }
        "codex_hook_manifest_directory_owner_mismatch" => {
            "The Codex managed-hook directory has an unexpected owner."
        }
        "codex_hook_manifest_directory_permissions_unsafe" => {
            "The Codex managed-hook directory permissions are not owner-only."
        }
        _ => LOCK_UNSAFE,
    };
    Failure::Integrity(code, message.to_owned())
}

/// The lifecycle lock of one configuration directory. `deadline` bounds the
/// whole operation: a take that starts after it refuses at once.
pub(super) fn lock_directory(
    directory: &Path,
    limit: Limit,
    deadline: Option<Instant>,
) -> Result<Held, Failure> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err(Failure::Timeout(LIFECYCLE_DEADLINE));
    }
    let (mut file, path) =
        lifecycle_lock(directory).map_err(|Refusal(text)| Failure::Runtime(text))?;
    let until = match limit {
        Limit::Grace => Instant::now() + GRACE,
        Limit::Until(until) => until,
    };
    match locked_by(&mut file, until) {
        Ok(true) => Ok(Held { file, path }),
        Ok(false) => Err(match limit {
            Limit::Grace => Failure::Runtime(LIFECYCLE_BUSY.to_owned()),
            Limit::Until(_) => Failure::Timeout(LIFECYCLE_DEADLINE),
        }),
        Err(error) => Err(Failure::Runtime(Refusal::lifecycle("file", &error).0)),
    }
}

/// The installation lock of one Guard home, waiting until `deadline`.
pub(super) fn lock_install(guard_home: &Path, deadline: Instant) -> Result<Held, Failure> {
    let (mut file, path) = install_lock(guard_home).map_err(|Refusal(code)| integrity(code))?;
    match locked_by(&mut file, deadline) {
        Ok(true) => Ok(Held { file, path }),
        Ok(false) => Err(Failure::Timeout(INSTALL_DEADLINE)),
        Err(error) => Err(integrity(Refusal::lifecycle("file", &error).0)),
    }
}

//! `policy-integrity-key-mint --stdin`: the cross-process first mint of the
//! local policy-integrity signing key in the encrypted-file secret store.
//! Ported from `store_policy_integrity_key_mint.py`
//! (`mint_policy_integrity_key_once`).
//!
//! Processes that start together on a fresh Guard home can all find no key.
//! Without a lock each would mint its own and the last write would replace the
//! others, so a native verifier key derived from an earlier key would no longer
//! match the stored one. The mint therefore holds the same advisory lock file
//! Python's mint holds (`.policy-integrity-key-mint.lock`, an exclusive `flock`)
//! and reads the store again under it: a key another process wrote wins.
//!
//! The request is `{"guard_home"}`. The answer names a state and never carries
//! the key, which the caller reads back from its own store:
//!
//! - `present`: a key is stored, whether this process or another one wrote it;
//! - `armed`: no readable key, but native controls were already armed with one
//!   this process cannot read, so no second signing key is minted;
//! - `busy`: the mint lock was not taken in time;
//! - `unavailable`: the store could not be read or written.
//!
//! Only Unix answers: Python's mint lock on Windows is a byte-range lock this
//! process does not share, so Windows answers `unavailable` and the caller
//! keeps its own mint.

use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::json;

use crate::encrypted_secret_store::{b64url_encode, EncryptedFileSecretStore};
use crate::policy_integrity_resolver::{build_scoped_secret_ref, POLICY_INTEGRITY_KEY_REF};

pub(crate) const FEATURE: &str = "native-policy-integrity-key-mint-v1";
const COMMAND: &str = "policy-integrity-key-mint";
const MINT_LOCK_FILE_NAME: &str = ".policy-integrity-key-mint.lock";
const MINT_LOCK_TIMEOUT: Duration = Duration::from_secs(10);
const MINT_LOCK_RETRY: Duration = Duration::from_millis(10);
const MAX_REQUEST_BYTES: u64 = 8 * 1024;
const KEY_BYTES: usize = 32;
/// `NATIVE_RUNTIME_STATE_DIRECTORY` (`native_policy_snapshot_constants.py`).
const NATIVE_RUNTIME_STATE_DIRECTORY: &str = "native-runtime";
/// Files whose presence means native controls are armed with an existing key:
/// `AUTHORITY_FILE_NAME` (`native_command_control_authority.py`) and
/// `NATIVE_POLICY_VERIFIER_KEY_NAME`.
const ARMED_FILES: [&str; 2] = ["command-control-authority.v1.json", "policy-verifier.key"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    guard_home: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Minted {
    Present,
    Armed,
    Busy,
    Unavailable,
}

impl Minted {
    fn label(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Armed => "armed",
            Self::Busy => "busy",
            Self::Unavailable => "unavailable",
        }
    }
}

pub(crate) fn is_command(command: &str) -> bool {
    command == COMMAND
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "policy_integrity_key_mint_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("policy_integrity_key_mint_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes)
        .map_err(|_| "policy_integrity_key_mint_request_invalid".to_owned())?;
    if request.guard_home.is_empty() {
        return Err("policy_integrity_key_mint_request_invalid".to_owned());
    }
    let state = mint_once(Path::new(&request.guard_home));
    serde_json::to_vec(&json!({"state": state.label()}))
        .map_err(|_| "policy_integrity_key_mint_response_encode_failed".to_owned())
}

/// The scoped key ref Python builds from `guard_home.expanduser().resolve()`.
fn resolved_home(guard_home: &Path) -> Option<PathBuf> {
    fs::create_dir_all(guard_home).ok()?;
    fs::canonicalize(guard_home).ok()
}

fn armed(home: &Path) -> bool {
    let state = home.join(NATIVE_RUNTIME_STATE_DIRECTORY);
    ARMED_FILES
        .iter()
        .any(|name| fs::symlink_metadata(state.join(name)).is_ok())
}

fn fresh_key() -> Option<String> {
    let mut raw = [0u8; KEY_BYTES];
    getrandom::fill(&mut raw).ok()?;
    Some(b64url_encode(&raw))
}

/// Owner-only, like the `0o600` lock file Python's mint creates.
fn lock_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
}

/// Read the key under the mint lock, minting one only when none is stored and
/// native controls are not armed.
pub(crate) fn mint_once(guard_home: &Path) -> Minted {
    if !cfg!(unix) {
        return Minted::Unavailable;
    }
    let Some(home) = resolved_home(guard_home) else {
        return Minted::Unavailable;
    };
    let Ok(lock) = lock_options().open(home.join(MINT_LOCK_FILE_NAME)) else {
        return Minted::Unavailable;
    };
    let deadline = Instant::now() + MINT_LOCK_TIMEOUT;
    while fs2::FileExt::try_lock_exclusive(&lock).is_err() {
        if Instant::now() >= deadline {
            return Minted::Busy;
        }
        std::thread::sleep(MINT_LOCK_RETRY);
    }
    let state = locked_mint(&home);
    let _ = fs2::FileExt::unlock(&lock);
    state
}

fn locked_mint(home: &Path) -> Minted {
    let key_ref = build_scoped_secret_ref(POLICY_INTEGRITY_KEY_REF, home);
    let mut store = EncryptedFileSecretStore::new(home);
    if store.get_secret(&key_ref).is_some() {
        return Minted::Present;
    }
    if armed(home) {
        return Minted::Armed;
    }
    let Some(key) = fresh_key() else {
        return Minted::Unavailable;
    };
    if store.set_secret(&key_ref, &key).is_err() {
        return Minted::Unavailable;
    }
    if store.get_secret(&key_ref).is_some() {
        Minted::Present
    } else {
        Minted::Unavailable
    }
}

#[cfg(test)]
#[path = "policy_integrity_key_mint_tests.rs"]
mod tests;

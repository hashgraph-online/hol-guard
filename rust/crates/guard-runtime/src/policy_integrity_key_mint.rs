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
//!
//! On Linux the request may add `"keyring": {"service_name"}` when Python's
//! store mirrors the desktop keyring (Secret Service) into the vault. The mint
//! then keeps that store's rules (`mirrored`), and talks to the keyring the way
//! Python's `keyring` library does (`keyring_linux`). Any other platform
//! answers such a request `unavailable`.

use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
#[path = "policy_integrity_keyring_linux.rs"]
mod keyring_linux;
#[cfg(any(target_os = "linux", all(test, unix)))]
#[path = "policy_integrity_key_mint_mirrored.rs"]
mod mirrored;

use serde::Deserialize;
use serde_json::json;

use crate::encrypted_secret_store::{b64url_encode, EncryptedFileSecretStore};
use crate::policy_integrity_resolver::{build_scoped_secret_ref, POLICY_INTEGRITY_KEY_REF};

pub(crate) const FEATURE: &str = "native-policy-integrity-key-mint-v1";
/// The same mint for the store that mirrors the Linux desktop keyring.
pub(crate) const KEYRING_FEATURE: &str = "native-policy-integrity-key-mint-secret-service-v1";
/// `_POLICY_INTEGRITY_SERVICE_NAME` (`store_base.py`), the only keyring
/// service this mint writes to.
const KEYRING_SERVICE_NAME: &str = "hol-guard.policy-integrity";
const COMMAND: &str = "policy-integrity-key-mint";
const MINT_LOCK_FILE_NAME: &str = ".policy-integrity-key-mint.lock";
/// One budget for both lock waits (the mint lock and the store's init lock),
/// kept well inside the caller's 15 s deadline for the whole request.
const MINT_LOCK_BUDGET: Duration = Duration::from_secs(4);
const MINT_LOCK_RETRY: Duration = Duration::from_millis(10);
/// The keyring's whole share of that deadline (up to three D-Bus exchanges),
/// after the lock budget.
#[cfg(target_os = "linux")]
const KEYRING_BUDGET: Duration = Duration::from_secs(6);
/// The lock `EncryptedFileSecretStore._ensure_ready` (`store_base.py`) holds
/// while it creates `secrets/key.bin`.
const SECRETS_DIRECTORY: &str = "secrets";
const KEY_INIT_LOCK_FILE_NAME: &str = ".key-init.lock";
const STORE_KEY_FILE_NAME: &str = "key.bin";
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
    #[serde(default)]
    keyring: Option<KeyringRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringRequest {
    service_name: String,
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
    if request.guard_home.is_empty()
        || request
            .keyring
            .as_ref()
            .is_some_and(|keyring| keyring.service_name != KEYRING_SERVICE_NAME)
    {
        return Err("policy_integrity_key_mint_request_invalid".to_owned());
    }
    let state = match request.keyring {
        Some(_) => mint_once_mirrored(Path::new(&request.guard_home)),
        None => mint_once(Path::new(&request.guard_home)),
    };
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

/// An exclusive `flock` on a lock file, released when dropped.
struct Held(File);

impl Drop for Held {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.0);
    }
}

/// Take `path` before `deadline`: `Busy` when another holder keeps it,
/// `Unavailable` when the lock file cannot be opened.
fn hold(path: &Path, deadline: Instant) -> Result<Held, Minted> {
    let lock = lock_options().open(path).map_err(|_| Minted::Unavailable)?;
    while fs2::FileExt::try_lock_exclusive(&lock).is_err() {
        if Instant::now() >= deadline {
            return Err(Minted::Busy);
        }
        std::thread::sleep(MINT_LOCK_RETRY);
    }
    Ok(Held(lock))
}

/// Read the key under the mint lock, minting one only when none is stored and
/// native controls are not armed.
pub(crate) fn mint_once(guard_home: &Path) -> Minted {
    with_mint_lock(guard_home, locked_mint)
}

/// The mint for the Linux store that mirrors the desktop keyring.
#[cfg(target_os = "linux")]
fn mint_once_mirrored(guard_home: &Path) -> Minted {
    with_mint_lock(guard_home, |home, deadline| {
        let primary = keyring_linux::SecretServiceKeyring {
            service_name: KEYRING_SERVICE_NAME.to_owned(),
            deadline: Instant::now() + KEYRING_BUDGET,
        };
        locked_mint_mirrored(home, deadline, &primary)
    })
}

#[cfg(not(target_os = "linux"))]
fn mint_once_mirrored(_guard_home: &Path) -> Minted {
    Minted::Unavailable
}

fn with_mint_lock(guard_home: &Path, mint: impl FnOnce(&Path, Instant) -> Minted) -> Minted {
    if !cfg!(unix) {
        return Minted::Unavailable;
    }
    let Some(home) = resolved_home(guard_home) else {
        return Minted::Unavailable;
    };
    let deadline = Instant::now() + MINT_LOCK_BUDGET;
    match hold(&home.join(MINT_LOCK_FILE_NAME), deadline) {
        Ok(_mint) => mint(&home, deadline),
        Err(state) => state,
    }
}

/// The keyring mint under the mint lock, after the vault is ready.
#[cfg(any(target_os = "linux", all(test, unix)))]
fn locked_mint_mirrored(home: &Path, deadline: Instant, primary: &dyn mirrored::Primary) -> Minted {
    let key_ref = build_scoped_secret_ref(POLICY_INTEGRITY_KEY_REF, home);
    let mut store = EncryptedFileSecretStore::new(home);
    if let Err(state) = store_ready(home, &mut store, deadline) {
        return state;
    }
    mirrored::mint(home, &key_ref, &mut store, primary)
}

/// Load or create the store's encryption key under the lock Python's store
/// holds for it, so a fresh home never gets two `key.bin` files, one of which
/// would leave the other's secrets unreadable.
///
/// A `key.bin` that exists but holds no key is a damaged vault Python refuses
/// to read. It is left as it is and the mint answers `unavailable`, since
/// replacing it would orphan every secret encrypted under the lost key.
fn store_ready(
    home: &Path,
    store: &mut EncryptedFileSecretStore,
    deadline: Instant,
) -> Result<(), Minted> {
    let secrets = home.join(SECRETS_DIRECTORY);
    fs::create_dir_all(&secrets).map_err(|_| Minted::Unavailable)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))
            .map_err(|_| Minted::Unavailable)?;
    }
    let _init = hold(&secrets.join(KEY_INIT_LOCK_FILE_NAME), deadline)?;
    match fs::read(secrets.join(STORE_KEY_FILE_NAME)) {
        Ok(bytes) if bytes.trim_ascii().is_empty() => return Err(Minted::Unavailable),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(Minted::Unavailable),
    }
    store.ensure_ready().map_err(|_| Minted::Unavailable)
}

fn locked_mint(home: &Path, deadline: Instant) -> Minted {
    let key_ref = build_scoped_secret_ref(POLICY_INTEGRITY_KEY_REF, home);
    let mut store = EncryptedFileSecretStore::new(home);
    if let Err(state) = store_ready(home, &mut store, deadline) {
        return state;
    }
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

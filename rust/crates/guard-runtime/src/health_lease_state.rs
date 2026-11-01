//! `health-lease-state --stdin`: the private state files in the machine
//! state root.
//!
//! The health lease's pending outbox and last Cloud acknowledgement live
//! there beside the installation continuity record and the device-key
//! metadata. A read trusts a file only when it is a regular file of the state
//! owner that no one else can read or write and that held still while it was
//! read. The outbox is created once and never replaced while pending; the
//! other files are replaced in place. Every write goes through a private
//! temporary file that is synced before it takes the file's name, and the
//! directory is synced after. `mdm/health_lease.py`, `mdm/continuity.py` and
//! `mdm/device_key.py` keep their contracts, signatures and locks, and only
//! ask this command to move bytes.

use std::fs::{self, File, Metadata};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use base64ct::{Base64, Encoding};
use serde::Deserialize;
use serde_json::{json, Value};

const SCHEMA: &str = "health-lease-state.v1";
const OUTBOX_NAME: &str = "health-lease-outbox.json";
const ACK_NAME: &str = "health-lease-ack.json";
const CONTINUITY_NAME: &str = "installation-continuity.json";
const DEVICE_KEY_NAME: &str = "device-key.json";
/// `mdm/health_lease_contract.py`: a base64 snapshot, a signed lease and
/// framing.
const MAX_OUTBOX_BYTES: u64 = 4 * (256 * 1024_u64).div_ceil(3) + 32 * 1024 + 4096;
/// `mdm/health_lease_ack.py`.
const MAX_ACK_BYTES: u64 = 4096;
/// `mdm/continuity.py` and `mdm/device_key.py`.
const MAX_RECORD_BYTES: u64 = 64 * 1024;
/// The largest outbox, base64 encoded, and the request around it.
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
const STATE_ROOT_INVALID: &str = "health_lease_state_root_invalid";
const PENDING_CONFLICT: &str = "health_lease_pending_conflict";
const IO_FAILED: &str = "health_lease_state_io_failed";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    kind: String,
    state_root: PathBuf,
    owner_uid: u32,
    #[serde(default)]
    content: Option<String>,
}

#[derive(Clone, Copy)]
enum Kind {
    Outbox,
    Ack,
    Continuity,
    DeviceKey,
}

impl Kind {
    fn parse(kind: &str) -> Option<Self> {
        match kind {
            "outbox" => Some(Self::Outbox),
            "ack" => Some(Self::Ack),
            "continuity" => Some(Self::Continuity),
            "device_key" => Some(Self::DeviceKey),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Outbox => OUTBOX_NAME,
            Self::Ack => ACK_NAME,
            Self::Continuity => CONTINUITY_NAME,
            Self::DeviceKey => DEVICE_KEY_NAME,
        }
    }

    fn maximum(self) -> u64 {
        match self {
            Self::Outbox => MAX_OUTBOX_BYTES,
            Self::Ack => MAX_ACK_BYTES,
            Self::Continuity | Self::DeviceKey => MAX_RECORD_BYTES,
        }
    }

    fn acl_invalid(self) -> &'static str {
        match self {
            Self::Outbox => "health_lease_outbox_acl_invalid",
            Self::Ack => "health_lease_ack_acl_invalid",
            Self::Continuity => "installation_identity_acl_invalid",
            Self::DeviceKey => "device_key_acl_invalid",
        }
    }

    /// The file changed while it was read.
    fn invalid(self) -> &'static str {
        match self {
            Self::Outbox => "health_lease_outbox_invalid",
            Self::Ack => "health_lease_ack_invalid",
            Self::Continuity => "installation_identity_invalid",
            Self::DeviceKey => "device_key_metadata_changed",
        }
    }

    /// A write larger than the file's read bound, which would leave a file
    /// no later read accepts.
    fn too_large(self) -> &'static str {
        match self {
            Self::Outbox => "health_lease_outbox_too_large",
            Self::Ack => "health_lease_ack_too_large",
            Self::Continuity => "installation_identity_too_large",
            Self::DeviceKey => "device_key_metadata_too_large",
        }
    }

    fn state_root_invalid(self) -> &'static str {
        match self {
            Self::Outbox | Self::Ack => STATE_ROOT_INVALID,
            Self::Continuity => "installation_identity_state_root_invalid",
            Self::DeviceKey => "device_key_state_root_invalid",
        }
    }
}

/// A refused request, in the Python exception it is raised as.
#[derive(Debug, PartialEq, Eq)]
struct StateError {
    class: &'static str,
    reason_code: &'static str,
}

fn refused(class: &'static str, reason_code: &'static str) -> StateError {
    StateError { class, reason_code }
}

fn io_failed(_error: io::Error) -> StateError {
    refused("os", IO_FAILED)
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "health-lease-state"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "health_lease_state_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("health_lease_state_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes)
        .map_err(|_| "health_lease_state_request_invalid".to_owned())?;
    let response = respond(request)?;
    serde_json::to_vec(&response)
        .map_err(|_| "health_lease_state_response_encode_failed".to_owned())
}

fn respond(request: Request) -> Result<Value, String> {
    let invalid = || "health_lease_state_request_invalid".to_owned();
    if request.schema != SCHEMA {
        return Err(invalid());
    }
    let kind = Kind::parse(&request.kind).ok_or_else(invalid)?;
    let root = request.state_root.as_path();
    let outcome = match (request.op.as_str(), kind, request.content) {
        ("read", _, None) => read_private(root, kind, request.owner_uid).map(|content| {
            let content = content.map(|bytes| Base64::encode_string(&bytes));
            json!({"ok": true, "content": content})
        }),
        ("create", Kind::Outbox, Some(content)) => {
            let payload = Base64::decode_vec(&content).map_err(|_| invalid())?;
            create_new(root, kind, &payload).map(|()| json!({"ok": true}))
        }
        ("replace", Kind::Ack | Kind::Continuity | Kind::DeviceKey, Some(content)) => {
            let payload = Base64::decode_vec(&content).map_err(|_| invalid())?;
            replace(root, kind, &payload).map(|()| json!({"ok": true}))
        }
        ("remove", Kind::Outbox, None) => remove(root, kind).map(|()| json!({"ok": true})),
        _ => return Err(invalid()),
    };
    Ok(outcome.unwrap_or_else(
        |error| json!({"ok": false, "error_class": error.class, "reason_code": error.reason_code}),
    ))
}

/// The file's bytes, `None` when it does not exist. A link, a file someone
/// else owns or may read, an oversized file, or one that changed while read
/// is refused.
fn read_private(root: &Path, kind: Kind, owner_uid: u32) -> Result<Option<Vec<u8>>, StateError> {
    let mut file = match open_without_following(&root.join(kind.name())) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) if is_link_loop(&error) => {
            return Err(refused("permission", kind.acl_invalid()))
        }
        Err(error) => return Err(io_failed(error)),
    };
    let before = file.metadata().map_err(io_failed)?;
    if before.len() > kind.maximum() || !is_private_regular_file(&before, owner_uid) {
        return Err(refused("permission", kind.acl_invalid()));
    }
    let mut payload = Vec::new();
    Read::by_ref(&mut file)
        .take(kind.maximum() + 1)
        .read_to_end(&mut payload)
        .map_err(io_failed)?;
    let after = file.metadata().map_err(io_failed)?;
    if payload.len() as u64 != before.len() || identity(&before) != identity(&after) {
        return Err(refused("os", kind.invalid()));
    }
    Ok(Some(payload))
}

/// Give `payload` the file's name only when nothing holds it yet: a pending
/// outbox is durable evidence and is never overwritten.
fn create_new(root: &Path, kind: Kind, payload: &[u8]) -> Result<(), StateError> {
    require_state_root(root, kind)?;
    let target = root.join(kind.name());
    match fs::symlink_metadata(&target) {
        Ok(_) => return Err(refused("exists", PENDING_CONFLICT)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_failed(error)),
    }
    with_private_temporary(root, kind, payload, |temporary| {
        fs::hard_link(temporary, &target).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                refused("exists", PENDING_CONFLICT)
            } else {
                io_failed(error)
            }
        })
    })
}

fn replace(root: &Path, kind: Kind, payload: &[u8]) -> Result<(), StateError> {
    require_state_root(root, kind)?;
    let target = root.join(kind.name());
    with_private_temporary(root, kind, payload, |temporary| {
        fs::rename(temporary, &target).map_err(io_failed)
    })
}

fn remove(root: &Path, kind: Kind) -> Result<(), StateError> {
    match fs::remove_file(root.join(kind.name())) {
        Ok(()) => sync_directory(root).map_err(io_failed),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_failed(error)),
    }
}

fn require_state_root(root: &Path, kind: Kind) -> Result<(), StateError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        _ => Err(refused("os", kind.state_root_invalid())),
    }
}

/// Write `payload` to a fresh private file beside the target, sync it, let
/// `commit` give it the target's name, then sync the directory. The temporary
/// name is removed whatever happens. A payload past the file's read bound is
/// refused before anything is written.
fn with_private_temporary(
    root: &Path,
    kind: Kind,
    payload: &[u8],
    commit: impl FnOnce(&Path) -> Result<(), StateError>,
) -> Result<(), StateError> {
    if payload.len() as u64 > kind.maximum() {
        return Err(refused("os", kind.too_large()));
    }
    let suffix: String = crate::encrypted_secret_store::random_bytes(16)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let temporary = root.join(format!(".{}.{suffix}.tmp", kind.name()));
    let outcome = write_private_file(&temporary, payload)
        .map_err(io_failed)
        .and_then(|()| commit(&temporary))
        .and_then(|()| sync_directory(root).map_err(io_failed));
    if let Err(error) = fs::remove_file(&temporary) {
        if error.kind() != io::ErrorKind::NotFound && outcome.is_ok() {
            return Err(io_failed(error));
        }
    }
    outcome
}

#[cfg(unix)]
fn write_private_file(path: &Path, payload: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(path)?;
    file.write_all(payload)?;
    file.sync_all()?;
    // A umask cannot widen 0600, but a planted default ACL could; the bits
    // are restated.
    file.set_permissions(fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, payload: &[u8]) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(payload)?;
    file.sync_all()
}

#[cfg(unix)]
fn open_without_following(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

/// The reparse-point flag opens a link itself, which then reads as no
/// regular file.
#[cfg(windows)]
fn open_without_following(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(unix)]
fn is_link_loop(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(not(unix))]
fn is_link_loop(_error: &io::Error) -> bool {
    false
}

#[cfg(unix)]
fn is_private_regular_file(metadata: &Metadata, owner_uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;

    metadata.is_file() && metadata.uid() == owner_uid && metadata.mode() & 0o077 == 0
}

/// Windows reports no owner or mode bits here; the state root's own ACL is
/// what keeps the file private there.
#[cfg(not(unix))]
fn is_private_regular_file(metadata: &Metadata, _owner_uid: u32) -> bool {
    metadata.is_file()
}

/// What must hold still while the file is read: which file it is, its size
/// and its last status change.
#[cfg(unix)]
fn identity(metadata: &Metadata) -> [i128; 5] {
    use std::os::unix::fs::MetadataExt;

    [
        i128::from(metadata.dev()),
        i128::from(metadata.ino()),
        i128::from(metadata.size()),
        i128::from(metadata.ctime()),
        i128::from(metadata.ctime_nsec()),
    ]
}

#[cfg(windows)]
fn identity(metadata: &Metadata) -> [i128; 5] {
    use std::os::windows::fs::MetadataExt;

    [
        i128::from(metadata.file_size()),
        i128::from(metadata.creation_time()),
        i128::from(metadata.last_write_time()),
        0,
        0,
    ]
}

/// Make a new name durable. A filesystem that cannot sync a directory leaves
/// the write as durable as it can be, not failed.
#[cfg(unix)]
fn sync_directory(directory: &Path) -> io::Result<()> {
    match File::open(directory).and_then(|handle| handle.sync_all()) {
        Err(error)
            if !matches!(
                error.kind(),
                io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
            ) =>
        {
            Err(error)
        }
        _ => Ok(()),
    }
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
#[path = "health_lease_state_tests.rs"]
mod tests;

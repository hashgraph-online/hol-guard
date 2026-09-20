//! Linux-only admission for a private diagnostic receiver.
//!
//! These are before/after pathname metadata checks, not an atomic proof of a
//! datagram peer inode. The receiver must bind delivered messages to its owned
//! process cohort using kernel credentials and executable/start identities.

use std::fs;
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixDatagram;
use std::path::{Component, Path, PathBuf};

const SOCKET_ENV: &str = "HOL_GUARD_NATIVE_PHASE_SOCKET";
const DEVICE_ENV: &str = "HOL_GUARD_NATIVE_PHASE_DEVICE";
const INODE_ENV: &str = "HOL_GUARD_NATIVE_PHASE_INODE";

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

impl Identity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.permissions().mode() & 0o7777,
        }
    }
}

fn identity(path: &Path, directory: bool) -> Option<Identity> {
    let metadata = fs::symlink_metadata(path).ok()?;
    let current = Identity::from_metadata(&metadata);
    let expected_mode = if directory { 0o700 } else { 0o600 };
    if current.uid != nix::unistd::geteuid().as_raw() || current.mode != expected_mode {
        return None;
    }
    if (directory && !metadata.is_dir()) || (!directory && !metadata.file_type().is_socket()) {
        return None;
    }
    Some(current)
}

fn decimal_env(name: &str) -> Option<u64> {
    let value = std::env::var(name).ok()?;
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn acquire(path: &Path, device: u64, inode: u64) -> Option<UnixDatagram> {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().len() >= 108
        || !path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        || path.file_name()? != "phase.sock"
    {
        return None;
    }
    let parent = path.parent()?;
    if parent.parent()? != Path::new("/tmp")
        || !parent
            .file_name()?
            .to_str()?
            .starts_with("guard-native-phase-")
        || fs::canonicalize(parent).ok()? != parent
    {
        return None;
    }
    let parent_before = identity(parent, true)?;
    let endpoint_before = identity(path, false)?;
    if endpoint_before.device != device || endpoint_before.inode != inode {
        return None;
    }
    // This socket is diagnostic overhead. It is outside every measured request
    // socket call and is never substituted for an existing resident transport.
    let socket = UnixDatagram::unbound().ok()?;
    socket.set_nonblocking(true).ok()?;
    socket.connect(path).ok()?;
    if identity(parent, true)? != parent_before
        || identity(path, false)? != endpoint_before
        || socket.peer_addr().ok()?.as_pathname()? != path
    {
        return None;
    }
    Some(socket)
}

fn parse_start_ticks(bytes: &[u8], expected_pid: u32) -> Option<u64> {
    let text = std::str::from_utf8(bytes).ok()?;
    let (head, fields) = text.rsplit_once(") ")?;
    let pid = head.split_once(" (")?.0.parse::<u32>().ok()?;
    if pid != expected_pid {
        return None;
    }
    let value = fields.split_whitespace().nth(19)?;
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let start = value.parse().ok()?;
    (start != 0).then_some(start)
}

pub(super) fn self_start_ticks() -> Option<u64> {
    let mut bytes = Vec::with_capacity(4097);
    fs::File::open("/proc/self/stat")
        .ok()?
        .take(4097)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > 4096 {
        return None;
    }
    parse_start_ticks(&bytes, std::process::id())
}

pub(super) fn from_environment() -> Option<UnixDatagram> {
    let path = PathBuf::from(std::env::var_os(SOCKET_ENV)?);
    acquire(&path, decimal_env(DEVICE_ENV)?, decimal_env(INODE_ENV)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("native_phase_endpoint_tests.rs");
}

//! The resident sockets one prune removes: which directories hold them, and
//! when one is provably dead.

use std::fs::{self, Metadata};
use std::path::{Path, PathBuf};

use super::{mtime_seconds, name_of, owned, Host, Report, Settings, SocketState};

const SOCKET_PREFIXES: [&str; 2] = ["hook-v2-", "h3-"];
const SOCKET_ROOT_PREFIX: &str = "hgr-";
/// The resident binds its sockets under the fixed system tmp directory (see
/// `socket_directory_path`), so the prune looks there too.
pub(super) const SYSTEM_TMP_BASES: [&str; 2] = ["/private/tmp", "/tmp"];

pub(super) fn prune_socket(
    socket: &Path,
    report: &mut Report,
    settings: &Settings,
    host: &mut impl Host,
) {
    let Ok(metadata) = fs::symlink_metadata(socket) else {
        return;
    };
    if !is_socket(&metadata) {
        report.keep("not_socket");
        return;
    }
    if !owned(&metadata) {
        report.keep("foreign_owner");
        return;
    }
    if mtime_seconds(&metadata).is_none_or(|mtime| settings.now - mtime < settings.socket_min_age) {
        report.keep("recent_socket");
        return;
    }
    match host.probe_socket(socket) {
        SocketState::Gone => return,
        SocketState::Dead => {}
        SocketState::Live | SocketState::Unknown => {
            report.keep("socket_not_provably_dead");
            return;
        }
    }
    if !settings.dry_run {
        match fs::symlink_metadata(socket) {
            Ok(current) if is_socket(&current) && same_inode(&current, &metadata) => {}
            Ok(_) => {
                report.keep("socket_changed");
                return;
            }
            Err(_) => {
                report.error("socket_unlink_failed");
                return;
            }
        }
        if fs::remove_file(socket).is_err() {
            report.error("socket_unlink_failed");
            return;
        }
    }
    report.removed_socket(socket);
}

/// Resident sockets directly inside each root, never recursive.
pub(super) fn socket_candidates(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut sockets = Vec::new();
    for root in roots {
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };
        let mut found: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|candidate| {
                let name = name_of(candidate);
                name.ends_with(".sock")
                    && SOCKET_PREFIXES
                        .iter()
                        .any(|prefix| name.starts_with(prefix))
            })
            .collect();
        found.sort();
        sockets.extend(found);
    }
    sockets
}

/// The resident's socket directories, `<tmp>/hgr-*`, from the first base that
/// has any. Only real directories owned by this user and closed to group and
/// other writes count, so another local user cannot plant one for the prune
/// to walk.
pub(super) fn default_socket_roots(bases: &[&Path]) -> Vec<PathBuf> {
    for base in bases {
        let Ok(entries) = fs::read_dir(base) else {
            continue;
        };
        let mut roots: Vec<PathBuf> = entries
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(SOCKET_ROOT_PREFIX)
                    && entry.metadata().is_ok_and(|metadata| {
                        metadata.is_dir() && owned(&metadata) && !shared_writable(&metadata)
                    })
            })
            .map(|entry| entry.path())
            .collect();
        if !roots.is_empty() {
            roots.sort();
            return roots;
        }
    }
    Vec::new()
}

/// `Dead` only when `connect()` is refused. The connect never waits: a
/// listener with a full backlog reads as `Unknown`.
#[cfg(unix)]
pub(super) fn probe_socket(socket: &Path) -> SocketState {
    use nix::errno::Errno;
    use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
    use nix::sys::socket::{self, AddressFamily, SockFlag, SockType, UnixAddr};
    use std::os::fd::AsRawFd;

    let Ok(address) = UnixAddr::new(socket) else {
        return SocketState::Unknown;
    };
    let Ok(descriptor) = socket::socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    ) else {
        return SocketState::Unknown;
    };
    if fcntl(&descriptor, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).is_err()
        || fcntl(&descriptor, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).is_err()
    {
        return SocketState::Unknown;
    }
    match socket::connect(descriptor.as_raw_fd(), &address) {
        Ok(()) => SocketState::Live,
        Err(Errno::ECONNREFUSED) => SocketState::Dead,
        Err(Errno::ENOENT) => SocketState::Gone,
        Err(_) => SocketState::Unknown,
    }
}

#[cfg(not(unix))]
pub(super) fn probe_socket(_socket: &Path) -> SocketState {
    SocketState::Unknown
}

#[cfg(unix)]
fn is_socket(metadata: &Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;

    metadata.file_type().is_socket()
}

#[cfg(not(unix))]
fn is_socket(_metadata: &Metadata) -> bool {
    false
}

#[cfg(unix)]
fn shared_writable(metadata: &Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o022 != 0
}

#[cfg(not(unix))]
fn shared_writable(_metadata: &Metadata) -> bool {
    true
}

#[cfg(unix)]
fn same_inode(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_inode(_left: &Metadata, _right: &Metadata) -> bool {
    false
}

//! The kernel's answers for `codex-sandbox-check` on Linux.
//!
//! Codex's Linux sandbox runs each shell call with every mount read-only
//! except its writable roots, and with a seccomp filter that refuses to
//! create any socket but a Unix one. Both show in the process itself: a
//! write check on a read-only mount fails with `EROFS`, and creating an
//! internet socket fails with `EPERM`. A sandbox that confines a process
//! some other way (Landlock alone does not answer `access`, and a network
//! namespace still hands out sockets) is not confirmed, so the check fails
//! there.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{AtFlags, AT_FDCWD};
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};
use nix::unistd::{faccessat, getuid, AccessFlags, User};

/// Whether this process can open no internet socket, IPv4 or IPv6, of
/// either kind.
pub(super) fn denies_network() -> bool {
    [AddressFamily::Inet, AddressFamily::Inet6]
        .into_iter()
        .all(|family| {
            [SockType::Stream, SockType::Datagram]
                .into_iter()
                .all(|kind| refused(family, socket(family, kind, SockFlag::SOCK_CLOEXEC, None)))
        })
}

fn refused(family: AddressFamily, opened: nix::Result<OwnedFd>) -> bool {
    match opened {
        // Dropping the descriptor closes it.
        Ok(_) => false,
        Err(Errno::EPERM | Errno::EACCES) => true,
        // A kernel without IPv6 has no IPv6 network to reach.
        Err(Errno::EAFNOSUPPORT) => family == AddressFamily::Inet6,
        Err(_) => false,
    }
}

/// Whether the kernel refuses this process a write in the directory
/// `path`: its mount is read-only, or its permissions keep this process's
/// effective user out.
pub(super) fn denies_write(path: &Path) -> bool {
    if !path.is_dir() {
        return false;
    }
    matches!(
        faccessat(AT_FDCWD, path, AccessFlags::W_OK, AtFlags::AT_EACCESS),
        Err(Errno::EROFS | Errno::EACCES | Errno::EPERM)
    )
}

/// The home directory the account database records for this user.
pub(super) fn account_home() -> Option<PathBuf> {
    let home = User::from_uid(getuid()).ok()??.dir;
    home.is_absolute().then_some(home)
}

/// Linux has no per-user temporary directory beyond `$TMPDIR`, which the
/// caller already asks about.
pub(super) fn user_temp_dir() -> Option<PathBuf> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unsandboxed_process_reaches_the_network_and_writes_its_temp_dir() {
        let directory = tempfile::tempdir().unwrap();
        assert!(!denies_network());
        assert!(!denies_write(directory.path()));
    }

    #[test]
    fn a_missing_or_non_directory_path_is_not_confirmed() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("file");
        std::fs::write(&file, b"").unwrap();
        assert!(!denies_write(&file));
        assert!(!denies_write(&directory.path().join("missing")));
    }

    #[test]
    fn a_socket_refused_for_any_other_reason_is_not_confirmed() {
        assert!(refused(AddressFamily::Inet, Err(Errno::EPERM)));
        assert!(refused(AddressFamily::Inet6, Err(Errno::EACCES)));
        assert!(refused(AddressFamily::Inet6, Err(Errno::EAFNOSUPPORT)));
        assert!(!refused(AddressFamily::Inet, Err(Errno::EAFNOSUPPORT)));
        assert!(!refused(AddressFamily::Inet, Err(Errno::EMFILE)));
    }
}

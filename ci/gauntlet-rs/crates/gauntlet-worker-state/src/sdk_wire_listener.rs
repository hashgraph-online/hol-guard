//! One-use Rust-owned SDK tap socket directory, detached from the active
//! Python controller. Binding a listener is not a conformance observation.

use crate::linux_process::valid_cgroup;
use crate::{
    observe_sdk_relay_peer_in_cgroup_ineligible, ActiveLease, BoottimeDeadline, HeldSdkWirePeer,
    RunReservationJournal, SdkWirePeerPin,
};
use rustix::fs::{
    chmodat, chownat, fchmod, fchown, fstat, fsync, mkdirat, openat, statat, unlinkat, AtFlags,
    FileType, Mode, OFlags, Stat,
};
use rustix::process::{geteuid, Gid};
use serde_json::{json, Value};
use std::io::ErrorKind;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

const TAP_GID: u32 = 10001;
const DIRECTORY_MODE: u32 = 0o710;
const SOCKET_MODE: u32 = 0o660;
const FAMILY_NAMES: [&str; 2] = ["docs.sock", "mail.sock"];

pub struct SdkTapListeners {
    directory: OwnedFd,
    directory_name: String,
    directory_stat: Stat,
    socket_stats: [Stat; 2],
    listeners: [UnixListener; 2],
}

impl SdkTapListeners {
    pub fn directory_name(&self) -> &str {
        &self.directory_name
    }

    pub fn docs(&self) -> &UnixListener {
        &self.listeners[0]
    }

    pub fn mail(&self) -> &UnixListener {
        &self.listeners[1]
    }

    /// Accept one fixed-family SDK relay only while the Root lease and both
    /// listener inodes remain held. The caller supplies an independently
    /// observed agent cgroup and must still verify Bun ancestry and retain
    /// the returned peer for the full backend session.
    #[allow(clippy::too_many_arguments)]
    pub fn accept_sdk_peer_ineligible(
        &self,
        journal: &RunReservationJournal,
        lease: &ActiveLease,
        family: &str,
        expected_agent_cgroup: &str,
        deadline: &BoottimeDeadline,
        cancellation: &AtomicBool,
    ) -> Result<(UnixStream, SdkWirePeerPin, HeldSdkWirePeer), String> {
        if !valid_cgroup(expected_agent_cgroup) {
            return Err("outside SDK agent cgroup pin required".to_owned());
        }
        let index = match family {
            "docs" => 0,
            "mail" => 1,
            _ => return Err("fixed docs/mail SDK tap family required".to_owned()),
        };
        loop {
            if cancellation.load(Ordering::Acquire) {
                return Err("SDK tap accept cancelled".to_owned());
            }
            let remaining = deadline.remaining().map_err(|error| error.to_string())?;
            if remaining.is_zero() {
                return Err("SDK tap accept deadline expired".to_owned());
            }
            self.recheck(journal, lease)?;
            match self.listeners[index].accept() {
                Ok((socket, _)) => {
                    self.recheck(journal, lease)?;
                    socket
                        .set_nonblocking(false)
                        .map_err(|error| error.to_string())?;
                    let (pin, held) = observe_sdk_relay_peer_in_cgroup_ineligible(
                        &socket,
                        expected_agent_cgroup,
                    )?;
                    if cancellation.load(Ordering::Acquire)
                        || deadline
                            .remaining()
                            .map_err(|error| error.to_string())?
                            .is_zero()
                    {
                        return Err(
                            "SDK tap accept cancelled or expired during peer check".to_owned()
                        );
                    }
                    held.recheck(&socket)?;
                    self.recheck(journal, lease)?;
                    return Ok((socket, pin, held));
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(remaining.min(Duration::from_millis(20)));
                }
                Err(error) => return Err(format!("SDK tap accept failed: {error}")),
            }
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-sdk-tap-listeners.v1",
            "directory_name":self.directory_name,
            "families":["docs","mail"],
            "peer_identity_verified":false,
            "journal_durable":false,
            "execution_eligible":false,
        })
    }

    /// Verify the held directory against the visible one-use name and both
    /// fixed socket inodes while the worker still holds its active lease.
    pub fn recheck(
        &self,
        journal: &RunReservationJournal,
        lease: &ActiveLease,
    ) -> Result<(), String> {
        lease
            .verify(&journal.root)
            .map_err(|error| error.to_string())?;
        let held = fstat(&self.directory).map_err(|error| error.to_string())?;
        let visible = statat(
            &journal.root,
            self.directory_name.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|error| error.to_string())?;
        if !same_inode(&held, &self.directory_stat)
            || !same_inode(&visible, &self.directory_stat)
            || !exact_directory(&held)
            || !exact_directory(&visible)
        {
            return Err("SDK tap directory identity or permissions changed".to_owned());
        }
        for (name, original) in FAMILY_NAMES.iter().zip(self.socket_stats.iter()) {
            let visible = statat(&self.directory, *name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|error| error.to_string())?;
            if !same_inode(&visible, original) || !exact_socket(&visible) {
                return Err(format!("SDK tap socket identity changed: {name}"));
            }
        }
        Ok(())
    }

    /// Remove the exposed socket names only after the controller and tap
    /// children have stopped. Keep the empty one-use directory as a durable
    /// tombstone so a replay cannot bind fresh listeners for this run ID.
    pub fn close_and_tombstone_ineligible(
        self,
        journal: &RunReservationJournal,
        lease: &ActiveLease,
    ) -> Result<(), String> {
        self.recheck(journal, lease)?;
        let Self {
            directory,
            directory_name,
            listeners,
            ..
        } = self;
        drop(listeners);
        for name in FAMILY_NAMES {
            unlinkat(&directory, name, AtFlags::empty())
                .map_err(|error| format!("SDK tap socket teardown failed: {name}: {error}"))?;
        }
        fsync(&directory).map_err(|error| error.to_string())?;
        let visible = statat(
            &journal.root,
            directory_name.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|error| error.to_string())?;
        if !exact_directory(&visible) {
            return Err("SDK tap tombstone directory changed".to_owned());
        }
        fsync(&journal.root).map_err(|error| error.to_string())?;
        lease
            .verify(&journal.root)
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

fn same_inode(left: &Stat, right: &Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_mode == right.st_mode
        && left.st_nlink == right.st_nlink
}

fn exact_directory(stat: &Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::Directory
        && stat.st_uid == 0
        && stat.st_gid == TAP_GID
        && stat.st_mode & 0o7777 == DIRECTORY_MODE
        && stat.st_nlink >= 2
}

fn exact_socket(stat: &Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::Socket
        && stat.st_uid == 0
        && stat.st_gid == TAP_GID
        && stat.st_mode & 0o7777 == SOCKET_MODE
        && stat.st_nlink == 1
}

fn bind_one(directory: &OwnedFd, name: &str) -> Result<(UnixListener, Stat), String> {
    let relative = format!("/proc/self/fd/{}/{name}", directory.as_raw_fd());
    let listener = UnixListener::bind(&relative)
        .map_err(|error| format!("one-use SDK {name} listener bind failed: {error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("one-use SDK {name} listener nonblocking mode failed: {error}"))?;
    chownat(
        directory,
        name,
        None,
        Some(Gid::from_raw(TAP_GID)),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|error| format!("SDK {name} group assignment failed: {error}"))?;
    chmodat(
        directory,
        name,
        Mode::from_bits_truncate(SOCKET_MODE),
        AtFlags::empty(),
    )
    .map_err(|error| format!("SDK {name} socket mode failed: {error}"))?;
    let visible = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| format!("SDK {name} socket inspection failed: {error}"))?;
    if !exact_socket(&visible) {
        return Err(format!("SDK {name} socket has unsafe metadata"));
    }
    fsync(directory).map_err(|error| error.to_string())?;
    Ok((listener, visible))
}

/// Bind exactly docs/mail under an exclusive one-use hex run namespace in a
/// Root-owned private journal. An error leaves that namespace consumed for
/// later review; it must never trigger a direct-socket fallback.
pub fn bind_sdk_tap_listeners_ineligible(
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    run_id: &str,
) -> Result<SdkTapListeners, String> {
    if geteuid().as_raw() != 0 || !journal.root_owned {
        return Err("Linux Root-owned tap journal required".to_owned());
    }
    if run_id.len() != 16
        || !run_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("fixed 16-hex one-use SDK tap run ID required".to_owned());
    }
    lease
        .verify(&journal.root)
        .map_err(|error| error.to_string())?;
    let directory_name = format!("{run_id}.sdk-tap");
    mkdirat(
        &journal.root,
        directory_name.as_str(),
        Mode::from_bits_truncate(0o700),
    )
    .map_err(|error| format!("one-use SDK tap namespace unavailable: {error}"))?;
    let directory = openat(
        &journal.root,
        directory_name.as_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("SDK tap namespace open failed: {error}"))?;
    fchown(&directory, None, Some(Gid::from_raw(TAP_GID)))
        .map_err(|error| format!("SDK tap directory group failed: {error}"))?;
    fchmod(&directory, Mode::from_bits_truncate(DIRECTORY_MODE))
        .map_err(|error| format!("SDK tap directory mode failed: {error}"))?;
    let directory_stat = fstat(&directory).map_err(|error| error.to_string())?;
    if !exact_directory(&directory_stat) {
        return Err("SDK tap directory has unsafe metadata".to_owned());
    }
    fsync(&directory).map_err(|error| error.to_string())?;
    fsync(&journal.root).map_err(|error| error.to_string())?;
    let (docs, docs_stat) = bind_one(&directory, FAMILY_NAMES[0])?;
    let (mail, mail_stat) = bind_one(&directory, FAMILY_NAMES[1])?;
    let listeners = SdkTapListeners {
        directory,
        directory_name,
        directory_stat,
        socket_stats: [docs_stat, mail_stat],
        listeners: [docs, mail],
    };
    listeners.recheck(journal, lease)?;
    Ok(listeners)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::Command;

    #[test]
    #[ignore = "requires Linux Root for the one-use tap journal"]
    fn closed_tap_removes_sockets_but_refuses_rebinding() {
        let temporary = tempfile::Builder::new()
            .prefix("gauntlet-sdk-tombstone-")
            .tempdir_in("/root")
            .unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let journal = RunReservationJournal::open_root_owned(temporary.path()).unwrap();
        let lease = journal.acquire_active_lease().unwrap();
        let run_id = "9876543210abcdef";
        let listeners = bind_sdk_tap_listeners_ineligible(&journal, &lease, run_id).unwrap();
        listeners
            .close_and_tombstone_ineligible(&journal, &lease)
            .unwrap();
        let directory = temporary.path().join(format!("{run_id}.sdk-tap"));
        assert!(directory.is_dir());
        assert!(!directory.join("docs.sock").exists());
        assert!(!directory.join("mail.sock").exists());
        assert!(bind_sdk_tap_listeners_ineligible(&journal, &lease, run_id).is_err());
    }

    #[test]
    #[ignore = "requires Linux Root for the private worker journal"]
    fn binds_exact_root_sockets_and_refuses_replay_or_changed_mode() {
        let temporary = tempfile::Builder::new()
            .prefix("gauntlet-sdk-tap-")
            .tempdir_in("/root")
            .unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::metadata(temporary.path()).unwrap();
        assert_eq!(geteuid().as_raw(), 0);
        assert_eq!(metadata.uid(), 0);
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o700);
        let journal = RunReservationJournal::open_root_owned(temporary.path()).unwrap();
        let lease = journal.acquire_active_lease().unwrap();
        let listeners =
            bind_sdk_tap_listeners_ineligible(&journal, &lease, "0123456789abcdef").unwrap();
        listeners.recheck(&journal, &lease).unwrap();
        assert_eq!(listeners.to_json()["execution_eligible"], false);
        assert!(bind_sdk_tap_listeners_ineligible(&journal, &lease, "0123456789abcdef").is_err());
        let path = Path::new("/proc/self/fd")
            .join(listeners.directory.as_raw_fd().to_string())
            .join("docs.sock");
        let mut client = UnixStream::connect(&path).unwrap();
        let (mut server, _) = listeners.docs().accept().unwrap();
        client.write_all(b"x").unwrap();
        let mut byte = [0_u8; 1];
        server.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [b'x']);
        fs::set_permissions(
            temporary
                .path()
                .join(listeners.directory_name())
                .join("mail.sock"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(listeners.recheck(&journal, &lease).is_err());
    }

    #[test]
    #[ignore = "requires Linux Root and UID-10001 SDK socket peer"]
    fn bounded_accept_holds_real_sdk_peer_under_fixed_cgroup() {
        let temporary = tempfile::Builder::new()
            .prefix("gauntlet-sdk-accept-")
            .tempdir_in("/root")
            .unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let journal = RunReservationJournal::open_root_owned(temporary.path()).unwrap();
        let lease = journal.acquire_active_lease().unwrap();
        let listeners =
            bind_sdk_tap_listeners_ineligible(&journal, &lease, "fedcba9876543210").unwrap();
        let deadline = BoottimeDeadline::start(5).unwrap();
        let cancellation = AtomicBool::new(false);
        assert!(listeners
            .accept_sdk_peer_ineligible(
                &journal,
                &lease,
                "other",
                "/system.slice/x",
                &deadline,
                &cancellation
            )
            .is_err());
        assert!(listeners
            .accept_sdk_peer_ineligible(&journal, &lease, "docs", "/", &deadline, &cancellation)
            .is_err());
        cancellation.store(true, Ordering::Release);
        assert!(listeners
            .accept_sdk_peer_ineligible(
                &journal,
                &lease,
                "docs",
                "/system.slice/x",
                &deadline,
                &cancellation
            )
            .is_err());
        cancellation.store(false, Ordering::Release);

        // The inherited tap-directory descriptor models the container's
        // bind-mounted directory without exposing the private Root journal.
        let directory_fd = listeners.directory.as_raw_fd();
        let mut child = Command::new("/usr/bin/python3");
        child
            .arg("-c")
            .arg("import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.recv(1)")
            .arg(format!("/proc/self/fd/{directory_fd}/docs.sock"))
            .uid(10001)
            .gid(TAP_GID);
        // SAFETY: only clears CLOEXEC on one held test directory descriptor.
        // All inputs are fixed before spawn; no allocation occurs in the child.
        unsafe {
            child.pre_exec(move || {
                let flags = libc::fcntl(directory_fd, libc::F_GETFD);
                if flags < 0
                    || libc::fcntl(directory_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = child.spawn().unwrap();
        let cgroup_raw = fs::read_to_string(format!("/proc/{}/cgroup", child.id())).unwrap();
        let cgroup = cgroup_raw.trim_end().strip_prefix("0::").unwrap();
        let accepted = listeners.accept_sdk_peer_ineligible(
            &journal,
            &lease,
            "docs",
            cgroup,
            &deadline,
            &cancellation,
        );
        if accepted.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let (mut socket, pin, held) = accepted.unwrap();
        assert_eq!(pin.pid, child.id());
        assert_eq!(pin.cgroup, cgroup);
        held.recheck(&socket).unwrap();
        socket.write_all(b"x").unwrap();
        assert!(child.wait().unwrap().success());
    }
}

//! Ineligible Root launcher for one SDK tap child. The caller still owns the
//! job lease, fixed cgroup, listener, controller mount and terminal pin.

use crate::linux_process::{observe_process, parse_proc_stat, valid_cgroup};
use crate::sdk_wire_fd_handoff::receive_native_socket;
use crate::sdk_wire_peer::{
    authenticate_native_frontdoor_peer_ineligible, authenticate_sdk_relay_peer_ineligible,
    bind_sdk_relay_to_ancestor_ineligible, SdkWirePeerObservation, SdkWirePeerPin,
};
use crate::sdk_wire_pipe::read_sdk_tap_frame_pipe_checked_ineligible;
use crate::sdk_wire_tap::SdkWireObservation;
use crate::{hex, open_root_owned_public_directory, BoottimeDeadline, OwnedSdkTapCgroup};
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::fs::{fstat, openat, statat, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::process::{geteuid, pidfd_open, Pid, PidfdFlags};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const MAX_EXECUTABLE_BYTES: u64 = 32 * 1024 * 1024;
const READ_POLL: Duration = Duration::from_millis(250);
const TAP_UID: u32 = 10001;
const TAP_GID: u32 = 10001;
const ARG_COUNT: usize = 15;
#[cfg(target_os = "linux")]
const TMPFS_MAGIC: libc::c_long = 0x0102_1994;

#[cfg(target_os = "linux")]
fn isolate_tap_mounts() -> io::Result<()> {
    // SAFETY: all pointers are static NUL-terminated strings; this runs in
    // pre_exec before privilege drop, after the worker attached the cgroup.
    unsafe {
        if libc::unshare(libc::CLONE_NEWNS) != 0
            || libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_PRIVATE | libc::MS_REC,
                std::ptr::null(),
            ) != 0
            || libc::mount(
                c"tmpfs".as_ptr(),
                c"/tmp".as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                c"size=1048576,mode=0700,uid=10001,gid=10001"
                    .as_ptr()
                    .cast(),
            ) != 0
            || libc::mount(
                c"tmpfs".as_ptr(),
                c"/home".as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                c"size=4096,mode=0000,uid=0,gid=0".as_ptr().cast(),
            ) != 0
            || libc::mount(
                c"tmpfs".as_ptr(),
                c"/opt".as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                c"size=4096,mode=0000,uid=0,gid=0".as_ptr().cast(),
            ) != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn isolate_tap_mounts() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SDK tap mount isolation requires Linux",
    ))
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_tap_mounts(pid: u32) -> Result<(), String> {
    let parent = std::fs::read_link("/proc/self/ns/mnt").map_err(|error| error.to_string())?;
    let child =
        std::fs::read_link(format!("/proc/{pid}/ns/mnt")).map_err(|error| error.to_string())?;
    if parent == child {
        return Err("SDK tap mount namespace differs from fixed profile".to_owned());
    }
    for (path, uid, gid, mode, flags) in [
        (
            "/tmp",
            TAP_UID,
            TAP_GID,
            0o700,
            libc::ST_NOSUID | libc::ST_NODEV | libc::ST_NOEXEC,
        ),
        (
            "/home",
            0,
            0,
            0,
            libc::ST_RDONLY | libc::ST_NOSUID | libc::ST_NODEV | libc::ST_NOEXEC,
        ),
        (
            "/opt",
            0,
            0,
            0,
            libc::ST_RDONLY | libc::ST_NOSUID | libc::ST_NODEV | libc::ST_NOEXEC,
        ),
    ] {
        let child_path = format!("/proc/{pid}/root{path}");
        let stat = std::fs::metadata(&child_path).map_err(|error| error.to_string())?;
        let host = std::fs::metadata(path).map_err(|error| error.to_string())?;
        let name = CString::new(child_path).map_err(|error| error.to_string())?;
        let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
        let mut mount = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: name is NUL-terminated and both outputs point to writable storage.
        if unsafe { libc::statfs(name.as_ptr(), filesystem.as_mut_ptr()) } != 0
            || unsafe { libc::statvfs(name.as_ptr(), mount.as_mut_ptr()) } != 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        // SAFETY: both calls succeeded and initialized their outputs.
        let filesystem = unsafe { filesystem.assume_init() };
        let mount = unsafe { mount.assume_init() };
        if stat.dev() == host.dev()
            || stat.uid() != uid
            || stat.gid() != gid
            || stat.mode() & 0o7777 != mode
            || filesystem.f_type != TMPFS_MAGIC
            || mount.f_flag & flags != flags
        {
            return Err("SDK tap private path mount differs from fixed profile".to_owned());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn verify_tap_mounts(_pid: u32) -> Result<(), String> {
    Err("SDK tap mount isolation requires Linux".to_owned())
}

fn fixed_arm64_elf(raw: &[u8]) -> bool {
    raw.len() >= 64
        && raw[..4] == [0x7f, b'E', b'L', b'F']
        && raw[4] == 2
        && raw[5] == 1
        && raw[6] == 1
        && matches!(u16::from_le_bytes([raw[16], raw[17]]), 2 | 3)
        && u16::from_le_bytes([raw[18], raw[19]]) == 183
}

pub struct HeldSdkTapExecutable {
    descriptor: OwnedFd,
    snapshot: Stat,
    sha256: String,
}

impl HeldSdkTapExecutable {
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub(crate) fn recheck(&self) -> Result<(), String> {
        let current = fstat(&self.descriptor).map_err(|error| error.to_string())?;
        if !same_file(&current, &self.snapshot) {
            return Err("SDK tap executable inode or metadata changed".to_owned());
        }
        Ok(())
    }

    pub(crate) fn descriptor_fd(&self) -> libc::c_int {
        self.descriptor.as_raw_fd()
    }
}

fn same_file(left: &Stat, right: &Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_mode == right.st_mode
        && left.st_nlink == right.st_nlink
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
}

/// Hold and hash the exact Root-owned child ELF before any SDK socket is
/// accepted. Every directory ancestor is opened without following symlinks;
/// the executable itself is opened relative to that held parent.
pub fn open_pinned_sdk_tap_executable_ineligible(
    path: &Path,
    expected_sha256: &str,
) -> Result<HeldSdkTapExecutable, String> {
    if geteuid().as_raw() != 0 || !hex(expected_sha256, 64) || !path.is_absolute() {
        return Err("Root and outside SDK tap executable pin required".to_owned());
    }
    let parent_path = path
        .parent()
        .ok_or("SDK tap executable parent directory missing")?;
    let name = path
        .file_name()
        .ok_or("SDK tap executable filename missing")?;
    let parent = open_root_owned_public_directory(parent_path)
        .map_err(|error| format!("SDK tap executable parent unsafe: {error}"))?;
    let descriptor = openat(
        &parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("SDK tap executable unavailable: {error}"))?;
    let before = fstat(&descriptor).map_err(|error| error.to_string())?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_mode & 0o7777 != 0o555
        || before.st_nlink != 1
        || before.st_size <= 0
        || before.st_size as u64 > MAX_EXECUTABLE_BYTES
    {
        return Err("SDK tap executable lacks fixed Root-owned mode".to_owned());
    }
    let mut file = File::from(descriptor);
    let mut raw = Vec::new();
    file.by_ref()
        .take(MAX_EXECUTABLE_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|error| error.to_string())?;
    let after = fstat(&file).map_err(|error| error.to_string())?;
    let visible = statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| format!("SDK tap executable path changed: {error}"))?;
    let actual = format!("{:x}", Sha256::digest(&raw));
    if raw.len() as i64 != before.st_size
        || !same_file(&before, &after)
        || !same_file(&before, &visible)
        || !fixed_arm64_elf(&raw)
        || actual != expected_sha256
    {
        return Err("SDK tap executable bytes differ from outside pin".to_owned());
    }
    Ok(HeldSdkTapExecutable {
        descriptor: file.into(),
        snapshot: after,
        sha256: actual,
    })
}

pub(crate) struct DeadlineReader<'a> {
    pub(crate) stream: &'a UnixStream,
    pub(crate) deadline: &'a BoottimeDeadline,
    pub(crate) cancellation: &'a AtomicBool,
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.cancellation.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "SDK tap cancelled",
                ));
            }
            match self.deadline.remaining() {
                Ok(remaining) if remaining > Duration::ZERO => {}
                _ => return Err(io::Error::new(io::ErrorKind::TimedOut, "SDK tap deadline")),
            }
            match self.stream.read(output) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                result => return result,
            }
        }
    }
}

pub(crate) fn process_start(pid: u32, expected_cgroup: &str) -> Result<u64, String> {
    if !valid_cgroup(expected_cgroup) {
        return Err("outside SDK tap child cgroup pin required".to_owned());
    }
    let raw = std::fs::read(format!("/proc/{pid}/stat")).map_err(|error| error.to_string())?;
    let parsed = parse_proc_stat(&raw, pid).ok_or("SDK tap child start tick unavailable")?;
    observe_process(pid, parsed.start_ticks, expected_cgroup)
        .map_err(|error| format!("SDK tap child kernel identity unavailable: {error:?}"))?;
    Ok(parsed.start_ticks)
}

pub(crate) fn await_native_handoff(
    socket: &UnixStream,
    deadline: &BoottimeDeadline,
    cancellation: &AtomicBool,
) -> Result<UnixStream, String> {
    let wait = Timespec {
        tv_sec: 0,
        tv_nsec: 250_000_000,
    };
    loop {
        if cancellation.load(Ordering::Acquire)
            || deadline.remaining().map_err(|error| error.to_string())? == Duration::ZERO
        {
            return Err("Native socket handoff cancelled or timed out".to_owned());
        }
        let mut descriptors = [PollFd::new(socket, PollFlags::IN)];
        if poll(&mut descriptors, Some(&wait)).map_err(|error| error.to_string())? != 0 {
            return receive_native_socket(socket);
        }
    }
}

fn kill_and_reap(child: &mut Child) -> Result<(), String> {
    let _ = child.kill();
    let began = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) if began.elapsed() < Duration::from_secs(3) => {
                thread::sleep(Duration::from_millis(20))
            }
            Ok(None) => return Err("SDK tap child reap uncertain after SIGKILL".to_owned()),
            Err(error) => return Err(format!("SDK tap child reap uncertain: {error}")),
        }
    }
}

fn wait_success(
    child: &mut Child,
    deadline: &BoottimeDeadline,
    cancellation: &AtomicBool,
) -> Result<(), String> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                return Err(format!("SDK tap child exited unsuccessfully: {status}"))
            }
            Ok(None) => {}
            Err(error) => return Err(format!("SDK tap child wait unavailable: {error}")),
        }
        if cancellation.load(Ordering::Acquire) {
            return Err("SDK tap child cancelled before exit".to_owned());
        }
        let remaining = deadline.remaining().map_err(|error| error.to_string())?;
        if remaining == Duration::ZERO {
            return Err("SDK tap child exceeded job deadline".to_owned());
        }
        thread::sleep(remaining.min(Duration::from_millis(20)));
    }
}

/// Run one already accepted SDK connection under a Root-held exact executable
/// and reparse the child report. The caller must retain the lease/listeners,
/// separately pin the job cgroup and terminal, and ensure descendants are gone.
#[allow(clippy::too_many_arguments)]
pub fn run_pinned_sdk_tap_child_ineligible(
    executable: &HeldSdkTapExecutable,
    sdk_connection: UnixStream,
    native_directory: OwnedFd,
    family: &str,
    sdk_relay: &SdkWirePeerPin,
    sdk_ancestor: &SdkWirePeerPin,
    native_frontdoor: &SdkWirePeerPin,
    child_cgroup: &str,
    deadline: &BoottimeDeadline,
    cancellation: &AtomicBool,
) -> Result<(SdkWireObservation, SdkWirePeerPin, SdkWirePeerObservation), String> {
    run_pinned_sdk_tap_child_impl(
        executable,
        sdk_connection,
        native_directory,
        family,
        sdk_relay,
        sdk_ancestor,
        native_frontdoor,
        child_cgroup,
        None,
        deadline,
        cancellation,
    )
}

/// Attach the exact pinned child to a distinct one-use tap cgroup before
/// dropping UID/GID. The Root worker still owns cleanup under its lease.
#[allow(clippy::too_many_arguments)]
pub fn run_pinned_sdk_tap_child_in_group_ineligible(
    executable: &HeldSdkTapExecutable,
    sdk_connection: UnixStream,
    native_directory: OwnedFd,
    family: &str,
    sdk_relay: &SdkWirePeerPin,
    sdk_ancestor: &SdkWirePeerPin,
    native_frontdoor: &SdkWirePeerPin,
    group: &OwnedSdkTapCgroup,
    deadline: &BoottimeDeadline,
    cancellation: &AtomicBool,
) -> Result<(SdkWireObservation, SdkWirePeerPin, SdkWirePeerObservation), String> {
    run_pinned_sdk_tap_child_impl(
        executable,
        sdk_connection,
        native_directory,
        family,
        sdk_relay,
        sdk_ancestor,
        native_frontdoor,
        group.path(),
        Some(group),
        deadline,
        cancellation,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_pinned_sdk_tap_child_impl(
    executable: &HeldSdkTapExecutable,
    sdk_connection: UnixStream,
    native_directory: OwnedFd,
    family: &str,
    sdk_relay: &SdkWirePeerPin,
    sdk_ancestor: &SdkWirePeerPin,
    native_frontdoor: &SdkWirePeerPin,
    child_cgroup: &str,
    group: Option<&OwnedSdkTapCgroup>,
    deadline: &BoottimeDeadline,
    cancellation: &AtomicBool,
) -> Result<(SdkWireObservation, SdkWirePeerPin, SdkWirePeerObservation), String> {
    if geteuid().as_raw() != 0
        || !matches!(family, "docs" | "mail")
        || !valid_cgroup(child_cgroup)
        || cancellation.load(Ordering::Acquire)
        || deadline.remaining().map_err(|error| error.to_string())? == Duration::ZERO
    {
        return Err("Root SDK tap launch pins or deadline invalid".to_owned());
    }
    executable.recheck()?;
    let sdk_peer = authenticate_sdk_relay_peer_ineligible(&sdk_connection, sdk_relay)?;
    bind_sdk_relay_to_ancestor_ineligible(&sdk_connection, &sdk_peer, sdk_ancestor)?;
    let (report_parent, report_child) = UnixStream::pair().map_err(|error| error.to_string())?;
    let (handoff_parent, handoff_child) = UnixStream::pair().map_err(|error| error.to_string())?;
    report_parent
        .set_read_timeout(Some(READ_POLL))
        .map_err(|error| error.to_string())?;
    let passed = [
        sdk_connection.as_raw_fd(),
        native_directory.as_raw_fd(),
        report_child.as_raw_fd(),
        handoff_child.as_raw_fd(),
    ];
    let arguments = [
        "gauntlet-sdk-tap-child".to_owned(),
        family.to_owned(),
        passed[0].to_string(),
        passed[1].to_string(),
        passed[2].to_string(),
        passed[3].to_string(),
        sdk_relay.pid.to_string(),
        sdk_relay.start_ticks.to_string(),
        sdk_relay.cgroup.clone(),
        sdk_ancestor.pid.to_string(),
        sdk_ancestor.start_ticks.to_string(),
        sdk_ancestor.cgroup.clone(),
        native_frontdoor.pid.to_string(),
        native_frontdoor.start_ticks.to_string(),
        native_frontdoor.cgroup.clone(),
    ];
    let arguments = arguments
        .iter()
        .map(|argument| {
            CString::new(argument.as_str()).map_err(|_| "invalid tap argument".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let argument_ptrs = arguments
        .iter()
        .map(|argument| argument.as_ptr() as usize)
        .collect::<Vec<_>>();
    let executable_fd = executable.descriptor.as_raw_fd();
    let mut command = Command::new("/usr/bin/false");
    command
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(group) = group {
        if group.path() != child_cgroup {
            return Err("SDK tap cgroup differs from held one-use group".to_owned());
        }
        group
            .attach_child(&mut command)
            .map_err(|error| error.to_string())?;
    }
    // SAFETY: the child only executes fixed syscalls over prebuilt pointers
    // and held FDs. The exact hashed executable is invoked by descriptor;
    // no child path lookup or candidate-controlled environment is used.
    unsafe {
        command.pre_exec(move || {
            let _keep_arguments = &arguments;
            isolate_tap_mounts()?;
            for fd in passed {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            if libc::setsid() < 0
                || libc::setgroups(0, std::ptr::null()) != 0
                || libc::setresgid(TAP_GID, TAP_GID, TAP_GID) != 0
                || libc::setresuid(TAP_UID, TAP_UID, TAP_UID) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(io::Error::last_os_error());
            }
            libc::umask(0o077);
            let mut argv = [std::ptr::null(); ARG_COUNT + 1];
            for (slot, pointer) in argv.iter_mut().zip(&argument_ptrs) {
                *slot = *pointer as *const libc::c_char;
            }
            let env = [std::ptr::null::<libc::c_char>()];
            libc::syscall(
                libc::SYS_execveat,
                executable_fd,
                c"".as_ptr(),
                argv.as_ptr(),
                env.as_ptr(),
                libc::AT_EMPTY_PATH,
            );
            Err(io::Error::last_os_error())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("pinned SDK tap child spawn failed: {error}"))?;
    drop(report_child);
    drop(handoff_child);
    let pid = child.id();
    let result = (|| {
        let child_start = process_start(pid, child_cgroup)?;
        let pidfd = pidfd_open(
            Pid::from_raw(i32::try_from(pid).map_err(|_| "invalid tap child PID")?)
                .ok_or("invalid tap child PID")?,
            PidfdFlags::empty(),
        )
        .map_err(|error| format!("SDK tap child pidfd unavailable: {error}"))?;
        verify_tap_mounts(pid)?;
        sdk_peer.recheck(&sdk_connection)?;
        let native_socket = await_native_handoff(&handoff_parent, deadline, cancellation)?;
        let native_peer =
            authenticate_native_frontdoor_peer_ineligible(&native_socket, native_frontdoor)?;
        let report = read_sdk_tap_frame_pipe_checked_ineligible(
            DeadlineReader {
                stream: &report_parent,
                deadline,
                cancellation,
            },
            family,
            |_, _| {
                sdk_peer.recheck(&sdk_connection)?;
                native_peer.recheck(&native_socket)?;
                Ok(())
            },
        )?;
        if cancellation.load(Ordering::Acquire) {
            return Err("SDK tap child cancelled".to_owned());
        }
        native_peer.recheck(&native_socket)?;
        executable.recheck()?;
        wait_success(&mut child, deadline, cancellation)?;
        let _held_pidfd = pidfd;
        Ok((
            report,
            SdkWirePeerPin {
                pid,
                start_ticks: child_start,
                cgroup: child_cgroup.to_owned(),
            },
            native_peer.observation().clone(),
        ))
    })();
    if result.is_err() {
        #[cfg(test)]
        eprintln!(
            "SDK tap child test state before reap: {:?}",
            child.try_wait()
        );
        kill_and_reap(&mut child)?;
        #[cfg(test)]
        if let Some(stderr) = child.stderr.take() {
            let mut raw = Vec::new();
            let _ = stderr.take(1024).read_to_end(&mut raw);
            eprintln!(
                "SDK tap child test diagnostic: {}",
                String::from_utf8_lossy(&raw)
            );
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn parent_mount_namespace_cannot_satisfy_tap_profile() {
        assert!(verify_tap_mounts(std::process::id()).is_err());
    }

    #[test]
    fn rejects_missing_root_executable_pin() {
        assert!(open_pinned_sdk_tap_executable_ineligible(
            Path::new("/nonexistent-sdk-tap-child"),
            &"0".repeat(64)
        )
        .is_err());
    }

    #[test]
    fn refuses_pinned_script_or_foreign_architecture_as_tap_child() {
        assert!(!fixed_arm64_elf(b"#!/usr/bin/python3\n"));
        let mut header = [0_u8; 64];
        header[..4].copy_from_slice(b"\x7fELF");
        header[4] = 2;
        header[5] = 1;
        header[6] = 1;
        header[16..18].copy_from_slice(&3_u16.to_le_bytes());
        header[18..20].copy_from_slice(&62_u16.to_le_bytes());
        assert!(!fixed_arm64_elf(&header));
        header[18..20].copy_from_slice(&183_u16.to_le_bytes());
        assert!(fixed_arm64_elf(&header));
    }
}

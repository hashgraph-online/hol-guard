//! What makes a running Codex host trustworthy enough to read: its private
//! control socket, the marker Guard's own app-server leaves beside it, the
//! kernel identity of the process on the other end, and the check that none of
//! it changed.
//!
//! This is the retired Python `_socket_target`, `_managed_pid`,
//! `_host_identity_matches`, `_peer_identity` and `_is_codex_process` of
//! `runtime/codex_host_inventory.py`. A failure is a [`Stop`]: either the host
//! is simply not there (`Absent`, which is not an error to show) or the
//! `codex_host_*` code the page shows.

use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::cloud_request_text::py_strip;

pub(crate) const UNTRUSTED: &str = "codex_host_untrusted";
pub(crate) const CHANGED: &str = "codex_host_changed";
pub(crate) const INVALID: &str = "codex_host_invalid";
pub(crate) const UNAVAILABLE: &str = "codex_host_unavailable";
const MARKER: &str = "hol-guard-app-server.pid";

/// Why there is no snapshot.
#[derive(Debug, PartialEq)]
pub(crate) enum Stop {
    /// No Codex host is listening: nothing to show, and nothing to report.
    Absent,
    Code(&'static str),
}

pub(crate) type Probed<T> = Result<T, Stop>;

/// An `OSError`: a missing file is the host being absent, anything else is a
/// host that could not be read.
pub(crate) fn io_stop(error: &std::io::Error) -> Stop {
    if error.kind() == std::io::ErrorKind::NotFound {
        Stop::Absent
    } else {
        Stop::Code(UNAVAILABLE)
    }
}

fn untrusted<T>() -> Probed<T> {
    Err(Stop::Code(UNTRUSTED))
}

/// The socket Guard talks to and what it was when it was first trusted: the
/// resolved target and the device and inode of the alias and of the target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Pin {
    pub(crate) target: String,
    pub(crate) identity: [u64; 4],
}

fn euid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

/// `_socket_target`: pin Codex's private socket alias and its private resolved
/// socket.
pub(crate) fn socket_target(
    socket_path: &Path,
    trusted_socket: &impl Fn(&Path) -> bool,
) -> Probed<Pin> {
    let source = std::fs::symlink_metadata(socket_path).map_err(|e| io_stop(&e))?;
    let parent_path = socket_path.parent().unwrap_or(Path::new("/"));
    let parent = std::fs::symlink_metadata(parent_path).map_err(|e| io_stop(&e))?;
    if source.uid() != euid()
        || !parent.is_dir()
        || parent.uid() != euid()
        || parent.mode() & 0o077 != 0
    {
        return untrusted();
    }
    let target = if source.file_type().is_symlink() {
        let target = std::fs::read_link(socket_path).map_err(|e| io_stop(&e))?;
        if !target.is_absolute() {
            return untrusted();
        }
        target
    } else {
        socket_path.to_path_buf()
    };
    if !trusted_socket(&target) {
        return untrusted();
    }
    let resolved = std::fs::symlink_metadata(&target).map_err(|e| io_stop(&e))?;
    let target_parent = std::fs::symlink_metadata(target.parent().unwrap_or(Path::new("/")))
        .map_err(|e| io_stop(&e))?;
    if target_parent.mode() & 0o077 != 0 {
        return untrusted();
    }
    let Ok(target) = target.into_os_string().into_string() else {
        return untrusted();
    };
    Ok(Pin {
        target,
        identity: [source.dev(), source.ino(), resolved.dev(), resolved.ino()],
    })
}

/// `_managed_pid`: the pid in Guard's private, owner-only marker file.
pub(crate) fn managed_pid(marker: &Path) -> Probed<u32> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(marker)
        .map_err(|e| io_stop(&e))?;
    let metadata = file.metadata().map_err(|e| io_stop(&e))?;
    if !metadata.is_file()
        || metadata.uid() != euid()
        || metadata.mode() & 0o077 != 0
        || !(1..=32).contains(&metadata.len())
    {
        return untrusted();
    }
    let mut raw = Vec::new();
    file.take(33)
        .read_to_end(&mut raw)
        .map_err(|e| io_stop(&e))?;
    let Ok(text) = std::str::from_utf8(&raw).map(py_strip) else {
        return Err(Stop::Code(UNAVAILABLE));
    };
    if !raw.is_ascii() {
        return Err(Stop::Code(UNAVAILABLE));
    }
    let decimal = !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    match text.parse::<u32>() {
        Ok(pid) if decimal && 1 < pid && i32::try_from(pid).is_ok() => Ok(pid),
        _ => untrusted(),
    }
}

/// `_optional_managed_pid`: Codex's own daemon does not create Guard's marker.
pub(crate) fn optional_managed_pid(socket_path: &Path) -> Probed<Option<u32>> {
    let marker = socket_path.parent().unwrap_or(Path::new("/")).join(MARKER);
    match std::fs::symlink_metadata(&marker) {
        Ok(_) => managed_pid(&marker).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_stop(&error)),
    }
}

/// `_host_identity_matches`: the marker still names the host that was read.
/// The process itself was authenticated on the connected peer, so this only
/// pins the private socket and marker.
pub(crate) fn host_identity_matches(
    socket_path: &Path,
    pid: u32,
    expected: Option<u32>,
) -> Probed<bool> {
    let tracked = optional_managed_pid(socket_path)?;
    Ok(tracked == expected && tracked.map_or(pid > 1, |tracked| tracked == pid))
}

/// Both checks a snapshot needs to still describe the live host.
pub(crate) fn still_the_host(
    socket_path: &Path,
    trusted_socket: &impl Fn(&Path) -> bool,
    pin: &Pin,
    pid: u32,
    expected: Option<u32>,
) -> Probed<bool> {
    Ok(host_identity_matches(socket_path, pid, expected)?
        && socket_target(socket_path, trusted_socket)? == *pin)
}

/// The user and process on the other end of a connected socket, from the kernel.
pub(crate) struct Peer {
    pub(crate) uid: u32,
    pub(crate) pid: u32,
}

/// `_peer_identity`.
#[cfg(target_os = "linux")]
pub(crate) fn peer_identity(stream: &UnixStream) -> Probed<Peer> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

    let credentials = getsockopt(stream, PeerCredentials).map_err(|_| Stop::Code(UNAVAILABLE))?;
    let pid = u32::try_from(credentials.pid()).map_err(|_| Stop::Code(UNTRUSTED))?;
    Ok(Peer {
        uid: credentials.uid(),
        pid,
    })
}

/// `_peer_identity`: `getpeereid` for the user, `LOCAL_PEERPID` for the process.
#[cfg(target_os = "macos")]
pub(crate) fn peer_identity(stream: &UnixStream) -> Probed<Peer> {
    use nix::sys::socket::{getsockopt, sockopt::LocalPeerPid};

    let (uid, _gid) = nix::unistd::getpeereid(stream).map_err(|_| Stop::Code(UNTRUSTED))?;
    let pid = getsockopt(stream, LocalPeerPid).map_err(|_| Stop::Code(UNAVAILABLE))?;
    let pid = u32::try_from(pid).map_err(|_| Stop::Code(UNTRUSTED))?;
    Ok(Peer {
        uid: uid.as_raw(),
        pid,
    })
}

fn named_codex(text: &str) -> bool {
    Path::new(text).file_name() == Some(std::ffi::OsStr::new("codex"))
}

fn argument(bytes: &[u8]) -> Probed<&str> {
    std::str::from_utf8(bytes).map_err(|_| Stop::Code(UNAVAILABLE))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// A process whose `argv` is Codex run under Docker Desktop's translator
/// (`rosetta`), which can expose itself before the original `argv`.
pub(crate) fn translated_codex_process(arguments: &[u8]) -> Probed<bool> {
    if arguments.len() > 65_536 {
        return Ok(false);
    }
    let argv: Vec<&[u8]> = arguments.split(|byte| *byte == 0).collect();
    if named_codex(argument(argv[0])?) {
        return Ok(true);
    }
    if argv.len() < 4 || argv[0] != b"/run/rosetta/rosetta" || argv[1] != argv[2] {
        return Ok(false);
    }
    let program = argument(argv[1])?;
    Ok(Path::new(program).is_absolute() && named_codex(program) && argv[3] == b"app-server")
}

/// `_is_codex_process`.
#[cfg(target_os = "linux")]
pub(crate) fn is_codex_process(pid: u32) -> Probed<bool> {
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).map_err(|e| io_stop(&e))?;
    match exe.file_name().and_then(|name| name.to_str()) {
        Some("codex") => Ok(true),
        Some("rosetta") => {
            let mut arguments = Vec::new();
            std::fs::File::open(format!("/proc/{pid}/cmdline"))
                .and_then(|file| file.take(65_537).read_to_end(&mut arguments))
                .map_err(|e| io_stop(&e))?;
            translated_codex_process(&arguments)
        }
        _ => Ok(false),
    }
}

/// `_is_codex_process`: macOS names a process only through `ps`, bounded to a second.
#[cfg(target_os = "macos")]
pub(crate) fn is_codex_process(pid: u32) -> Probed<bool> {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let mut child = Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| io_stop(&e))?;
    let deadline = Instant::now() + Duration::from_secs(1);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Stop::Code(UNAVAILABLE));
            }
            Err(error) => return Err(io_stop(&error)),
        }
    };
    let mut output = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map_err(|e| io_stop(&e))?;
        output = String::from_utf8_lossy(&bytes).into_owned();
    }
    Ok(status.success() && named_codex(py_strip(&output)))
}

#[cfg(test)]
#[path = "codex_host_probe_tests.rs"]
mod tests;

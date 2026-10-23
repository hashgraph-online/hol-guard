//! Ineligible single-session SDK tap child. The Root owner pins and launches
//! this executable, passes only held descriptors, tracks its pidfd/cgroup,
//! and reaps it under the job deadline. The opt-in connector mode passes a
//! Native socket to Root without forwarding SDK or Native bytes itself.

use crate::sdk_wire_fd_handoff::send_native_socket;
use crate::sdk_wire_journal::SdkTapRetainedSession;
use crate::sdk_wire_journal::SdkTapWireOwner;
use crate::sdk_wire_peer::{
    authenticate_native_frontdoor_peer_ineligible, authenticate_sdk_relay_peer_ineligible,
    bind_sdk_relay_to_ancestor_ineligible, SdkWirePeerPin,
};
use crate::sdk_wire_pipe::SdkTapFramePipeWriter;
use crate::sdk_wire_tap::{
    relay_bounded_sdk_mcp_pair_with_frame_sink_ineligible, SdkWireObservation,
};
use rustix::fs::{fstat, FileType};
use rustix::process::{getegid, geteuid};
use std::io::Read;
use std::net::Shutdown;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;
use std::time::Duration;

const TAP_UID: u32 = 10001;
const TAP_GID: u32 = 10001;

pub struct SdkTapChildPins<'a> {
    pub family: &'a str,
    pub sdk_relay: &'a SdkWirePeerPin,
    pub sdk_ancestor: &'a SdkWirePeerPin,
    pub native_frontdoor: &'a SdkWirePeerPin,
}

fn require_unprivileged_child() -> Result<(), String> {
    if !cfg!(all(target_os = "linux", target_arch = "aarch64"))
        || geteuid().as_raw() != TAP_UID
        || getegid().as_raw() != TAP_GID
    {
        return Err("Linux ARM64 UID/GID-10001 SDK tap child required".to_owned());
    }
    // SAFETY: PR_GET_NO_NEW_PRIVS reads the current thread's scalar state.
    if unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1 {
        return Err("SDK tap child must have no-new-privileges".to_owned());
    }
    // SAFETY: a zero-sized query neither dereferences nor writes the null pointer.
    if unsafe { libc::getgroups(0, std::ptr::null_mut()) } != 0 {
        return Err("SDK tap child must have no supplementary groups".to_owned());
    }
    Ok(())
}

fn require_private_frontdoor_directory(directory: &OwnedFd) -> Result<(), String> {
    let stat = fstat(directory).map_err(|error| error.to_string())?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != 0
        || stat.st_gid != TAP_GID
        || stat.st_mode & 0o7777 != 0o710
        || stat.st_nlink < 2
    {
        return Err("SDK tap frontdoor directory metadata differs from fixed profile".to_owned());
    }
    Ok(())
}

/// Run exactly one already accepted SDK connection. This is a data-plane
/// diagnostic, never a verdict: the caller still must authenticate the child,
/// Root-parse the pipe and bind its journal to an outside host pin.
pub fn run_sdk_tap_child_once_ineligible(
    sdk_connection: UnixStream,
    native_directory: OwnedFd,
    report: UnixStream,
    native_handoff: UnixStream,
    pins: &SdkTapChildPins<'_>,
) -> Result<SdkTapRetainedSession, String> {
    require_unprivileged_child()?;
    require_private_frontdoor_directory(&native_directory)?;
    if !matches!(pins.family, "docs" | "mail") {
        return Err("fixed SDK tap family required".to_owned());
    }
    let sdk_peer = authenticate_sdk_relay_peer_ineligible(&sdk_connection, pins.sdk_relay)?;
    let ancestry =
        bind_sdk_relay_to_ancestor_ineligible(&sdk_connection, &sdk_peer, pins.sdk_ancestor)?;
    let backend_path = format!(
        "/proc/self/fd/{}/{}.sock",
        native_directory.as_raw_fd(),
        pins.family
    );
    let native_connection = UnixStream::connect(&backend_path)
        .map_err(|error| format!("fixed Native MCP frontdoor unavailable: {error}"))?;
    let native_peer =
        authenticate_native_frontdoor_peer_ineligible(&native_connection, pins.native_frontdoor)?;
    native_handoff
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    send_native_socket(&native_handoff, &native_connection)?;
    let held_sdk = sdk_connection
        .try_clone()
        .map_err(|error| error.to_string())?;
    let held_native = native_connection
        .try_clone()
        .map_err(|error| error.to_string())?;
    report
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    let mut writer = SdkTapFramePipeWriter::new(report);
    let wire = {
        let sink = Mutex::new(|direction, frame: &[u8]| {
            sdk_peer.recheck(&held_sdk)?;
            native_peer.recheck(&held_native)?;
            writer.write_frame(direction, frame)
        });
        relay_bounded_sdk_mcp_pair_with_frame_sink_ineligible(
            sdk_connection,
            native_connection,
            pins.family,
            &AtomicBool::new(false),
            &sink,
        )?
    };
    // A normal SDK stdio relay may exit immediately after EOF. Its live
    // pidfd/start/cgroup were checked for every forwarded frame above, so
    // requiring it to survive the final EOF would reject an honest session.
    require_private_frontdoor_directory(&native_directory)?;
    let report = writer.finish()?;
    report
        .shutdown(Shutdown::Write)
        .map_err(|error| error.to_string())?;
    Ok(SdkTapRetainedSession {
        wire_owner: SdkTapWireOwner::ChildReport,
        family: pins.family.to_owned(),
        sdk_peer: sdk_peer.observation().clone(),
        native_peer: native_peer.observation().clone(),
        sdk_ancestry: ancestry,
        wire,
    })
}

/// The PID-namespace child cannot resolve an outside socket peer's host PID:
/// Linux reports it as zero through SO_PEERCRED. Root authenticates both held
/// sockets before launch and before independently parsing every reported
/// frame. This child only forwards one bounded exchange and reports raw bytes.
pub fn run_sdk_tap_child_once_pidns_ineligible(
    sdk_connection: UnixStream,
    native_directory: OwnedFd,
    report: UnixStream,
    native_handoff: UnixStream,
    family: &str,
) -> Result<SdkWireObservation, String> {
    require_unprivileged_child()?;
    if unsafe { libc::getpid() } != 1 {
        return Err("PID-1 SDK tap child required".to_owned());
    }
    require_private_frontdoor_directory(&native_directory)?;
    if !matches!(family, "docs" | "mail") {
        return Err("fixed SDK tap family required".to_owned());
    }
    let backend_path = format!(
        "/proc/self/fd/{}/{}.sock",
        native_directory.as_raw_fd(),
        family
    );
    let native_connection = UnixStream::connect(&backend_path)
        .map_err(|error| format!("fixed Native MCP frontdoor unavailable: {error}"))?;
    native_handoff
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    send_native_socket(&native_handoff, &native_connection)?;
    report
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    let mut writer = SdkTapFramePipeWriter::new(report);
    let wire = {
        let sink = Mutex::new(|direction, frame: &[u8]| writer.write_frame(direction, frame));
        relay_bounded_sdk_mcp_pair_with_frame_sink_ineligible(
            sdk_connection,
            native_connection,
            family,
            &AtomicBool::new(false),
            &sink,
        )?
    };
    require_private_frontdoor_directory(&native_directory)?;
    let report = writer.finish()?;
    report
        .shutdown(Shutdown::Write)
        .map_err(|error| error.to_string())?;
    Ok(wire)
}

/// Connect to one fixed Native frontdoor as UID/GID 10001, hand its socket
/// to Root, then keep only the handoff control FD until Root finishes the
/// exchange. The inherited SDK and report FDs are closed before connect;
/// this PID-1 helper never reads or forwards candidate MCP bytes.
pub fn connect_native_once_pidns_ineligible(
    sdk_connection: UnixStream,
    native_directory: OwnedFd,
    report: UnixStream,
    mut native_handoff: UnixStream,
    family: &str,
) -> Result<(), String> {
    require_unprivileged_child()?;
    if unsafe { libc::getpid() } != 1 || !matches!(family, "docs" | "mail") {
        return Err("fixed PID-1 Native connector profile required".to_owned());
    }
    require_private_frontdoor_directory(&native_directory)?;
    drop(sdk_connection);
    drop(report);
    let backend_path = format!(
        "/proc/self/fd/{}/{}.sock",
        native_directory.as_raw_fd(),
        family
    );
    let native_connection = UnixStream::connect(&backend_path)
        .map_err(|error| format!("fixed Native MCP frontdoor unavailable: {error}"))?;
    native_handoff
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    send_native_socket(&native_handoff, &native_connection)?;
    drop(native_connection);
    native_handoff
        .set_read_timeout(Some(Duration::from_secs(300)))
        .map_err(|error| error.to_string())?;
    let mut done = [0_u8; 1];
    native_handoff
        .read_exact(&mut done)
        .map_err(|error| format!("Root Native relay completion unavailable: {error}"))?;
    if done != [1] {
        return Err("Root Native relay completion marker invalid".to_owned());
    }
    require_private_frontdoor_directory(&native_directory)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux_process::parse_proc_stat;
    use crate::sdk_wire_spawn::{
        open_pinned_sdk_tap_executable_ineligible, run_pinned_sdk_tap_child_in_group_ineligible,
        run_pinned_sdk_tap_child_ineligible,
    };
    use crate::{
        run_pinned_sdk_tap_child_in_pidns_ineligible,
        run_pinned_sdk_tap_root_relay_in_pidns_ineligible,
    };
    use crate::{BoottimeDeadline, OwnedSdkTapCgroup};
    use rustix::fs::{chownat, fchown, AtFlags};
    use rustix::process::Gid;
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixListener;
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    fn pin_for(pid: u32) -> SdkWirePeerPin {
        let stat = fs::read(format!("/proc/{pid}/stat")).unwrap();
        let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap();
        SdkWirePeerPin {
            pid,
            start_ticks: parse_proc_stat(&stat, pid).unwrap().start_ticks,
            cgroup: cgroup.trim_end().strip_prefix("0::").unwrap().to_owned(),
        }
    }

    fn group_directory(path: &Path) -> File {
        let directory = File::open(path).unwrap();
        fchown(&directory, None, Some(Gid::from_raw(TAP_GID))).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o710)).unwrap();
        directory
    }

    fn group_socket(directory: &File, name: &str, path: &Path) {
        chownat(
            directory,
            name,
            None,
            Some(Gid::from_raw(TAP_GID)),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o660)).unwrap();
    }

    #[test]
    fn refuses_unprivileged_data_plane_without_fixed_uid_or_frontdoor() {
        if geteuid().as_raw() == TAP_UID {
            return;
        }
        assert!(require_unprivileged_child().is_err());
    }

    fn run_root_child_exchange(use_pidns: bool, root_relay: bool) {
        assert!(!root_relay || use_pidns);
        assert_eq!(geteuid().as_raw(), 0);
        let binary = std::env::var("GAUNTLET_SDK_TAP_TEST_BINARY").unwrap();
        let binary_sha256 = std::env::var("GAUNTLET_SDK_TAP_TEST_SHA256").unwrap();
        let binary_metadata = fs::metadata(&binary).unwrap();
        assert_eq!(binary_metadata.uid(), 0);
        assert_eq!(binary_metadata.nlink(), 1);
        assert_eq!(binary_metadata.permissions().mode() & 0o7777, 0o555);
        let temporary = tempfile::Builder::new()
            .prefix("gauntlet-sdk-child-")
            .tempdir_in("/tmp")
            .unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o711)).unwrap();
        let sdk_dir = temporary.path().join("sdk");
        let native_dir = temporary.path().join("native");
        fs::create_dir(&sdk_dir).unwrap();
        fs::create_dir(&native_dir).unwrap();
        let sdk_directory = group_directory(&sdk_dir);
        let native_directory = group_directory(&native_dir);
        let sdk_path = sdk_dir.join("docs.sock");
        let native_path = native_dir.join("docs.sock");
        let sdk_listener = UnixListener::bind(&sdk_path).unwrap();
        let native_listener = UnixListener::bind(&native_path).unwrap();
        group_socket(&sdk_directory, "docs.sock", &sdk_path);
        group_socket(&native_directory, "docs.sock", &native_path);
        let request = b"{ \"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\"}\n";
        let response = b"{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}\n";
        let sdk_script = r#"import socket,sys,time
s=socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.sendall(b'{ "jsonrpc":"2.0","id":7,"method":"tools/call"}\n')
data=b''
while not data.endswith(b'\n'):
 chunk=s.recv(4096)
 if not chunk: sys.exit(9)
 data+=chunk
assert data==b'{"jsonrpc":"2.0","id":7,"result":{}}\n'
time.sleep(2)
"#;
        let mut sdk_process = Command::new("/usr/bin/python3")
            .arg("-c")
            .arg(sdk_script)
            .arg(&sdk_path)
            .uid(TAP_UID)
            .gid(TAP_GID)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        sdk_listener.set_nonblocking(true).unwrap();
        let sdk_started = Instant::now();
        let sdk_connection = loop {
            match sdk_listener.accept() {
                Ok((connection, _)) => break connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(sdk_started.elapsed() < Duration::from_secs(5));
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("SDK accept failed: {error}"),
            }
        };
        let sdk_pin = pin_for(sdk_process.id());
        let ancestor_pin = pin_for(std::process::id());
        let native_pin = ancestor_pin.clone();
        let server = std::thread::spawn(move || -> Result<(), String> {
            native_listener
                .set_nonblocking(true)
                .map_err(|error| error.to_string())?;
            let began = Instant::now();
            let mut connection = loop {
                match native_listener.accept() {
                    Ok((connection, _)) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if began.elapsed() >= Duration::from_secs(5) {
                            return Err("Native frontdoor connection timed out".to_owned());
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(error) => return Err(error.to_string()),
                }
            };
            connection
                .set_read_timeout(Some(Duration::from_secs(5)))
                .map_err(|error| error.to_string())?;
            let mut observed = vec![0_u8; request.len()];
            connection
                .read_exact(&mut observed)
                .map_err(|error| error.to_string())?;
            if observed != request {
                return Err("Native frontdoor received changed request".to_owned());
            }
            std::thread::sleep(Duration::from_millis(200));
            connection
                .write_all(response)
                .map_err(|error| error.to_string())?;
            connection
                .shutdown(Shutdown::Write)
                .map_err(|error| error.to_string())?;
            Ok(())
        });
        let executable =
            open_pinned_sdk_tap_executable_ineligible(Path::new(&binary), &binary_sha256).unwrap();
        assert!(
            open_pinned_sdk_tap_executable_ineligible(Path::new(&binary), &"0".repeat(64)).is_err()
        );
        let deadline = BoottimeDeadline::start(10).unwrap();
        let mut wrong_sdk = sdk_pin.clone();
        wrong_sdk.start_ticks += 1;
        assert!(run_pinned_sdk_tap_child_ineligible(
            &executable,
            sdk_connection.try_clone().unwrap(),
            native_directory.try_clone().unwrap().into(),
            "docs",
            &wrong_sdk,
            &ancestor_pin,
            &native_pin,
            &native_pin.cgroup,
            &deadline,
            &AtomicBool::new(false),
        )
        .is_err());
        let run_id = if root_relay {
            "edcba98765432103"
        } else if use_pidns {
            "edcba98765432102"
        } else {
            "edcba98765432101"
        };
        let mut tap_group = OwnedSdkTapCgroup::create(run_id).unwrap();
        assert!(OwnedSdkTapCgroup::create(run_id).is_err());
        let parent_observation = if root_relay {
            run_pinned_sdk_tap_root_relay_in_pidns_ineligible(
                &executable,
                sdk_connection,
                native_directory.into(),
                "docs",
                &sdk_pin,
                &ancestor_pin,
                &native_pin,
                &tap_group,
                &deadline,
                &AtomicBool::new(false),
            )
        } else if use_pidns {
            run_pinned_sdk_tap_child_in_pidns_ineligible(
                &executable,
                sdk_connection,
                native_directory.into(),
                "docs",
                &sdk_pin,
                &ancestor_pin,
                &native_pin,
                &tap_group,
                &deadline,
                &AtomicBool::new(false),
            )
        } else {
            run_pinned_sdk_tap_child_in_group_ineligible(
                &executable,
                sdk_connection,
                native_directory.into(),
                "docs",
                &sdk_pin,
                &ancestor_pin,
                &native_pin,
                &tap_group,
                &deadline,
                &AtomicBool::new(false),
            )
        };
        if parent_observation.is_err() {
            let _ = tap_group.kill();
        }
        tap_group.drain_and_remove().unwrap();
        let server_result = server.join().unwrap();
        let began = Instant::now();
        let sdk_status = loop {
            if let Some(status) = sdk_process.try_wait().unwrap() {
                break status;
            }
            if began.elapsed() >= Duration::from_secs(10) {
                sdk_process.kill().unwrap();
                sdk_process.wait().unwrap();
                panic!("SDK test client exceeded test deadline");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        if !sdk_status.success() {
            let mut stderr = String::new();
            sdk_process
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            panic!("SDK exited {sdk_status}: {stderr}");
        }
        server_result.unwrap();
        let (parent_observation, child_pin, observed_native) = parent_observation.unwrap();
        assert_eq!(
            child_pin.cgroup,
            format!("/system.slice/hol-gauntlet-rust-tap-{run_id}")
        );
        assert_eq!(parent_observation.completed_tool_calls, 1);
        assert_eq!(parent_observation.events.len(), 2);
        assert_eq!(observed_native.pid, native_pin.pid);
        assert_eq!(observed_native.start_ticks, native_pin.start_ticks);
        assert_eq!((observed_native.uid, observed_native.gid), (0, 0));
    }

    #[test]
    #[ignore = "requires Linux Root and a separately installed Root-owned ARM64 SDK tap child binary"]
    fn root_launches_uid_10001_child_and_reparses_actual_forwarded_frames() {
        run_root_child_exchange(false, false);
    }

    #[test]
    #[ignore = "requires Linux Root and a separately installed Root-owned ARM64 SDK tap child binary"]
    fn root_launches_pid_one_child_and_reparses_actual_forwarded_frames() {
        run_root_child_exchange(true, false);
    }

    #[test]
    #[ignore = "requires Linux Root and a separately pinned ARM64 PID-1 connector ELF"]
    fn root_forwards_actual_frames_after_pid_one_native_connector_handoff() {
        run_root_child_exchange(true, true);
    }
}

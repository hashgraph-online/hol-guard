//! Held Linux Unix-peer identity for the opt-in SDK tap. This authenticates
//! one outside-pinned process tuple, not SDK ancestry or a conformance result.

use crate::linux_process::{observe_process, parse_proc_stat, valid_cgroup};
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::fs::{open, openat, Mode, OFlags};
use rustix::process::{pidfd_open, Pid, PidfdFlags};
use serde_json::{json, Value};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

const SDK_UID: u32 = 10001;
const SDK_GID: u32 = 10001;
const MAX_ANCESTORS: usize = 8;
const MAX_STAT_BYTES: u64 = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdkWirePeerPin {
    pub pid: u32,
    pub start_ticks: u64,
    pub cgroup: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdkWirePeerObservation {
    pub pid: u32,
    pub start_ticks: u64,
    pub cgroup: String,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdkWireAncestryObservation {
    pub relay_pid: u32,
    pub ancestor_pid: u32,
    pub ancestor_start_ticks: u64,
    pub cgroup: String,
    pub hops: usize,
}

impl SdkWireAncestryObservation {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-sdk-wire-ancestry.v1",
            "relay_pid":self.relay_pid,
            "ancestor_pid":self.ancestor_pid,
            "ancestor_start_ticks":self.ancestor_start_ticks,
            "cgroup":self.cgroup,
            "hops":self.hops,
            "ancestor_executable_verified":false,
            "execution_eligible":false,
        })
    }
}

impl SdkWirePeerObservation {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-sdk-wire-peer.v1",
            "pid":self.pid,
            "start_ticks":self.start_ticks,
            "cgroup":self.cgroup,
            "uid":self.uid,
            "gid":self.gid,
            "sdk_ancestry_verified":false,
            "execution_eligible":false,
        })
    }
}

pub struct HeldSdkWirePeer {
    pidfd: OwnedFd,
    observation: SdkWirePeerObservation,
}

impl HeldSdkWirePeer {
    pub fn observation(&self) -> &SdkWirePeerObservation {
        &self.observation
    }

    /// Repeat both the socket credential and the pidfd/start/cgroup checks
    /// while the session is held. A disappeared peer is ineligible.
    pub fn recheck(&self, socket: &UnixStream) -> Result<(), String> {
        let credentials = peer_credentials(socket)?;
        if credentials
            != (
                self.observation.pid,
                self.observation.uid,
                self.observation.gid,
            )
        {
            return Err("MCP socket peer credentials changed".to_owned());
        }
        observe_process(
            self.observation.pid,
            self.observation.start_ticks,
            &self.observation.cgroup,
        )
        .map_err(|error| format!("MCP peer process identity unavailable: {error:?}"))?;
        if pidfd_exited(&self.pidfd)? {
            return Err("MCP peer pidfd exited".to_owned());
        }
        Ok(())
    }
}

fn peer_credentials(socket: &UnixStream) -> Result<(u32, u32, u32), String> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `credentials` and `length` are valid writable objects, and the
    // exact returned struct length is checked before reading its fields.
    let status = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if status != 0 || length as usize != std::mem::size_of::<libc::ucred>() {
        return Err("Linux MCP Unix peer credentials unavailable".to_owned());
    }
    let pid = u32::try_from(credentials.pid)
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or("invalid MCP socket peer PID")?;
    Ok((pid, credentials.uid, credentials.gid))
}

fn pidfd_exited(pidfd: &OwnedFd) -> Result<bool, String> {
    let mut descriptors = [PollFd::new(pidfd, PollFlags::IN)];
    let immediate = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    Ok(poll(&mut descriptors, Some(&immediate)).map_err(|error| error.to_string())? != 0)
}

fn authenticate_fixed_peer(
    socket: &UnixStream,
    pin: &SdkWirePeerPin,
    uid: u32,
    gid: u32,
) -> Result<HeldSdkWirePeer, String> {
    if pin.pid == 0 || pin.start_ticks == 0 {
        return Err("outside MCP peer PID/start pin required".to_owned());
    }
    let credentials = peer_credentials(socket)?;
    if credentials != (pin.pid, uid, gid) {
        return Err("MCP socket peer differs from fixed UID/GID/PID pin".to_owned());
    }
    let pid = Pid::from_raw(i32::try_from(pin.pid).map_err(|_| "invalid MCP peer PID")?)
        .ok_or("invalid MCP peer PID")?;
    let pidfd = pidfd_open(pid, PidfdFlags::empty())
        .map_err(|error| format!("MCP peer pidfd unavailable: {error}"))?;
    let held = HeldSdkWirePeer {
        pidfd,
        observation: SdkWirePeerObservation {
            pid: pin.pid,
            start_ticks: pin.start_ticks,
            cgroup: pin.cgroup.clone(),
            uid,
            gid,
        },
    };
    held.recheck(socket)?;
    Ok(held)
}

/// Require the actual SDK stdio relay's UID/GID-10001 socket peer to match
/// an outside-pinned process tuple. This does not yet bind it to Bun ancestry.
pub fn authenticate_sdk_relay_peer_ineligible(
    socket: &UnixStream,
    pin: &SdkWirePeerPin,
) -> Result<HeldSdkWirePeer, String> {
    authenticate_fixed_peer(socket, pin, SDK_UID, SDK_GID)
}

/// Discover the SDK relay tuple only after a separate worker observer has
/// pinned the agent cgroup. This is a kernel observation, not a Bun or source
/// identity: the caller must still match a sampled executable/ancestor and
/// hold the returned peer through the full relay session.
pub fn observe_sdk_relay_peer_in_cgroup_ineligible(
    socket: &UnixStream,
    expected_agent_cgroup: &str,
) -> Result<(SdkWirePeerPin, HeldSdkWirePeer), String> {
    if !valid_cgroup(expected_agent_cgroup) {
        return Err("outside SDK agent cgroup pin required".to_owned());
    }
    let (pid, uid, gid) = peer_credentials(socket)?;
    if (uid, gid) != (SDK_UID, SDK_GID) {
        return Err("SDK relay peer must be UID/GID 10001".to_owned());
    }
    let (start_ticks, _) = parent_link(pid, expected_agent_cgroup)?;
    let pin = SdkWirePeerPin {
        pid,
        start_ticks,
        cgroup: expected_agent_cgroup.to_owned(),
    };
    let held = authenticate_sdk_relay_peer_ineligible(socket, &pin)?;
    Ok((pin, held))
}

/// Require the controller's Root-owned Native frontdoor peer to match an
/// outside-pinned process tuple. This does not verify the listener inode.
pub fn authenticate_native_frontdoor_peer_ineligible(
    socket: &UnixStream,
    pin: &SdkWirePeerPin,
) -> Result<HeldSdkWirePeer, String> {
    authenticate_fixed_peer(socket, pin, 0, 0)
}

fn parent_link(pid: u32, cgroup: &str) -> Result<(u64, u32), String> {
    let proc = open(
        "/proc",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("MCP peer proc root unavailable: {error}"))?;
    let process = openat(
        &proc,
        pid.to_string(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("MCP peer proc directory unavailable: {error}"))?;
    let descriptor = openat(
        &process,
        "stat",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("MCP peer proc stat unavailable: {error}"))?;
    let mut raw = Vec::new();
    File::from(descriptor)
        .take(MAX_STAT_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|error| format!("MCP peer proc stat read failed: {error}"))?;
    let parsed = parse_proc_stat(&raw, pid).ok_or("invalid MCP peer proc stat")?;
    observe_process(pid, parsed.start_ticks, cgroup)
        .map_err(|error| format!("MCP ancestor identity unavailable: {error:?}"))?;
    Ok((parsed.start_ticks, parsed.parent_pid))
}

fn ancestor_chain(
    relay: &SdkWirePeerPin,
    ancestor: &SdkWirePeerPin,
) -> Result<Vec<(u32, u64, u32)>, String> {
    if relay.pid == ancestor.pid || relay.cgroup != ancestor.cgroup {
        return Err("MCP relay and SDK ancestor must be distinct in one cgroup".to_owned());
    }
    let mut chain = Vec::new();
    let mut current = relay.pid;
    for _ in 0..=MAX_ANCESTORS {
        let (start_ticks, parent_pid) = parent_link(current, &ancestor.cgroup)?;
        chain.push((current, start_ticks, parent_pid));
        if current == ancestor.pid {
            if start_ticks != ancestor.start_ticks {
                return Err("MCP SDK ancestor start tick differs from outside pin".to_owned());
            }
            return Ok(chain);
        }
        if parent_pid <= 1 || parent_pid == current {
            return Err("MCP relay has no bounded SDK ancestor".to_owned());
        }
        current = parent_pid;
    }
    Err("MCP relay exceeds bounded SDK ancestry".to_owned())
}

/// Join an authenticated SDK relay peer to one separately pinned ancestor
/// process in the same container cgroup. The ancestor's Bun executable and
/// exact command still require the separate live SDK executable proof.
pub fn bind_sdk_relay_to_ancestor_ineligible(
    socket: &UnixStream,
    peer: &HeldSdkWirePeer,
    ancestor: &SdkWirePeerPin,
) -> Result<SdkWireAncestryObservation, String> {
    if peer.observation.uid != SDK_UID || peer.observation.gid != SDK_GID {
        return Err("SDK ancestry requires the fixed UID-10001 relay".to_owned());
    }
    peer.recheck(socket)?;
    let relay = SdkWirePeerPin {
        pid: peer.observation.pid,
        start_ticks: peer.observation.start_ticks,
        cgroup: peer.observation.cgroup.clone(),
    };
    let first = ancestor_chain(&relay, ancestor)?;
    let second = ancestor_chain(&relay, ancestor)?;
    peer.recheck(socket)?;
    if first != second || first.first().map(|row| row.1) != Some(relay.start_ticks) {
        return Err("MCP SDK ancestry changed while sampled".to_owned());
    }
    Ok(SdkWireAncestryObservation {
        relay_pid: relay.pid,
        ancestor_pid: ancestor.pid,
        ancestor_start_ticks: ancestor.start_ticks,
        cgroup: ancestor.cgroup.clone(),
        hops: first.len() - 1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    fn pin_for(pid: u32) -> SdkWirePeerPin {
        let stat = fs::read(format!("/proc/{pid}/stat")).unwrap();
        let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap();
        SdkWirePeerPin {
            pid,
            start_ticks: parse_proc_stat(&stat, pid).unwrap().start_ticks,
            cgroup: cgroup.trim_end().strip_prefix("0::").unwrap().to_owned(),
        }
    }

    #[test]
    fn held_pidfd_rejects_wrong_start_tick_for_current_unix_peer() {
        let (client, _server) = UnixStream::pair().unwrap();
        let pin = pin_for(std::process::id());
        let held = authenticate_fixed_peer(
            &client,
            &pin,
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        )
        .unwrap();
        held.recheck(&client).unwrap();
        let mut wrong = pin.clone();
        wrong.start_ticks += 1;
        assert!(authenticate_fixed_peer(
            &client,
            &wrong,
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        )
        .is_err());
    }

    #[test]
    #[ignore = "requires Linux Root to verify fixed controller UID/GID"]
    fn exact_root_frontdoor_peer_is_held_and_wrong_pin_refuses() {
        let (client, server) = UnixStream::pair().unwrap();
        let pin = pin_for(std::process::id());
        let held = authenticate_native_frontdoor_peer_ineligible(&client, &pin).unwrap();
        held.recheck(&client).unwrap();
        assert_eq!(held.observation().to_json()["execution_eligible"], false);
        let mut wrong = pin.clone();
        wrong.start_ticks += 1;
        assert!(authenticate_native_frontdoor_peer_ineligible(&client, &wrong).is_err());
        assert!(authenticate_sdk_relay_peer_ineligible(&server, &pin).is_err());
    }

    #[test]
    #[ignore = "requires Linux Root to launch fixed UID/GID-10001 SDK peer"]
    fn uid_10001_child_socket_matches_held_pidfd_and_wrong_pid_refuses() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o711)).unwrap();
        let path = directory.path().join("docs.sock");
        let listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        let mut child = Command::new("/usr/bin/python3")
            .arg("-c")
            .arg("import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.recv(1)")
            .arg(&path)
            .uid(SDK_UID)
            .gid(SDK_GID)
            .spawn()
            .unwrap();
        let (socket, _) = listener.accept().unwrap();
        let pin = pin_for(child.id());
        let (discovered, observed) =
            observe_sdk_relay_peer_in_cgroup_ineligible(&socket, &pin.cgroup).unwrap();
        assert_eq!(discovered, pin);
        observed.recheck(&socket).unwrap();
        assert!(observe_sdk_relay_peer_in_cgroup_ineligible(
            &socket,
            "/system.slice/not-this-sdk-agent"
        )
        .is_err());
        assert!(observe_sdk_relay_peer_in_cgroup_ineligible(&socket, "/").is_err());
        let held = authenticate_sdk_relay_peer_ineligible(&socket, &pin).unwrap();
        held.recheck(&socket).unwrap();
        assert_eq!(held.observation().uid, SDK_UID);
        let parent = pin_for(std::process::id());
        let ancestry = bind_sdk_relay_to_ancestor_ineligible(&socket, &held, &parent).unwrap();
        assert_eq!(ancestry.hops, 1);
        assert_eq!(ancestry.to_json()["execution_eligible"], false);
        let mut wrong_parent = parent.clone();
        wrong_parent.start_ticks += 1;
        assert!(bind_sdk_relay_to_ancestor_ineligible(&socket, &held, &wrong_parent).is_err());
        let mut wrong = pin.clone();
        wrong.pid += 1;
        assert!(authenticate_sdk_relay_peer_ineligible(&socket, &wrong).is_err());
        socket.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(child.wait().unwrap().success());
        assert!(held.recheck(&socket).is_err());
    }
}

//! Opt-in staging SDK tap owned by the Root worker. These observations remain
//! diagnostic until a separate reader binds wire frames to signed Native
//! audit, physical effects, the host receipt and source-matched assets.

use crate::{
    bind_sdk_relay_to_ancestor_ineligible, bind_sdk_tap_listeners_ineligible,
    open_fixed_native_frontdoor_ineligible, open_pinned_sdk_tap_executable_ineligible,
    retain_sdk_tap_journal_ineligible, run_pinned_sdk_tap_child_in_group_ineligible,
    run_pinned_sdk_tap_child_in_pidns_ineligible,
    run_pinned_sdk_tap_root_relay_in_pidns_ineligible, ActiveLease, BoottimeDeadline,
    HeldSdkTapExecutable, OwnedSdkTapCgroup, RunReservationJournal, SdkTapJournalReceipt,
    SdkTapListeners, SdkTapRetainedSession, SdkTapWireOwner, SdkWirePeerPin, StagingRole,
    StartedMarker,
};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::thread;

pub struct CandidateSdkTapPins<'a> {
    pub executable_path: &'a str,
    pub executable_sha256: &'a str,
}

pub(crate) struct StagingTapV2 {
    executable: HeldSdkTapExecutable,
    listeners: Option<SdkTapListeners>,
    group: OwnedSdkTapCgroup,
    bun_sha256: String,
    mode: TapMode,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TapMode {
    LegacyChild,
    PidnsChild,
    PidnsRoot,
}

pub(crate) struct TapSessions {
    sessions: Vec<SdkTapRetainedSession>,
    children: Vec<SdkWirePeerPin>,
}

impl StagingTapV2 {
    pub(crate) fn prepare(
        pins: &CandidateSdkTapPins<'_>,
        bun_sha256: &str,
        run_id: &str,
        journal: &RunReservationJournal,
        lease: &ActiveLease,
    ) -> Result<Self, String> {
        Self::prepare_mode(
            pins,
            bun_sha256,
            run_id,
            journal,
            lease,
            TapMode::LegacyChild,
        )
    }

    pub(crate) fn prepare_pidns(
        pins: &CandidateSdkTapPins<'_>,
        bun_sha256: &str,
        run_id: &str,
        journal: &RunReservationJournal,
        lease: &ActiveLease,
    ) -> Result<Self, String> {
        Self::prepare_mode(
            pins,
            bun_sha256,
            run_id,
            journal,
            lease,
            TapMode::PidnsChild,
        )
    }

    pub(crate) fn prepare_root_relay_pidns(
        pins: &CandidateSdkTapPins<'_>,
        bun_sha256: &str,
        run_id: &str,
        journal: &RunReservationJournal,
        lease: &ActiveLease,
    ) -> Result<Self, String> {
        Self::prepare_mode(pins, bun_sha256, run_id, journal, lease, TapMode::PidnsRoot)
    }

    fn prepare_mode(
        pins: &CandidateSdkTapPins<'_>,
        bun_sha256: &str,
        run_id: &str,
        journal: &RunReservationJournal,
        lease: &ActiveLease,
        mode: TapMode,
    ) -> Result<Self, String> {
        let executable = open_pinned_sdk_tap_executable_ineligible(
            Path::new(pins.executable_path),
            pins.executable_sha256,
        )?;
        let listeners = bind_sdk_tap_listeners_ineligible(journal, lease, run_id)?;
        let group = match OwnedSdkTapCgroup::create(run_id) {
            Ok(group) => group,
            Err(error) => {
                listeners
                    .close_and_tombstone_ineligible(journal, lease)
                    .map_err(|cleanup| format!("SDK tap group unavailable and listener cleanup uncertain: {error}; {cleanup}"))?;
                return Err(format!("SDK tap group unavailable: {error}"));
            }
        };
        Ok(Self {
            executable,
            listeners: Some(listeners),
            group,
            bun_sha256: bun_sha256.to_owned(),
            mode,
        })
    }

    pub(crate) fn bun_sha256(&self) -> &str {
        &self.bun_sha256
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn run_sessions(
        &self,
        journal: &RunReservationJournal,
        lease: &ActiveLease,
        run_id: &str,
        role: StagingRole,
        controller: &SdkWirePeerPin,
        sdk_ancestor: &SdkWirePeerPin,
        deadline: &BoottimeDeadline,
        cancellation: &AtomicBool,
    ) -> Result<TapSessions, String> {
        let listeners = self
            .listeners
            .as_ref()
            .ok_or("SDK tap listeners already closed")?;
        listeners.recheck(journal, lease)?;
        let native = open_fixed_native_frontdoor_ineligible(run_id, role)?;
        let results = thread::scope(|scope| {
            let native = &native;
            let handles = ["docs", "mail"].map(|family| {
                scope.spawn(move || {
                    let (sdk_connection, sdk_relay, sdk_held) = listeners
                        .accept_sdk_peer_ineligible(
                            journal,
                            lease,
                            family,
                            &sdk_ancestor.cgroup,
                            deadline,
                            cancellation,
                        )?;
                    let sdk_ancestry = bind_sdk_relay_to_ancestor_ineligible(
                        &sdk_connection,
                        &sdk_held,
                        sdk_ancestor,
                    )?;
                    let native_directory = native.duplicate_directory()?;
                    let (wire, child, native_peer) = match self.mode {
                        TapMode::PidnsRoot => run_pinned_sdk_tap_root_relay_in_pidns_ineligible(
                            &self.executable,
                            sdk_connection,
                            native_directory,
                            family,
                            &sdk_relay,
                            sdk_ancestor,
                            controller,
                            &self.group,
                            deadline,
                            cancellation,
                        )?,
                        TapMode::PidnsChild => run_pinned_sdk_tap_child_in_pidns_ineligible(
                            &self.executable,
                            sdk_connection,
                            native_directory,
                            family,
                            &sdk_relay,
                            sdk_ancestor,
                            controller,
                            &self.group,
                            deadline,
                            cancellation,
                        )?,
                        TapMode::LegacyChild => run_pinned_sdk_tap_child_in_group_ineligible(
                            &self.executable,
                            sdk_connection,
                            native_directory,
                            family,
                            &sdk_relay,
                            sdk_ancestor,
                            controller,
                            &self.group,
                            deadline,
                            cancellation,
                        )?,
                    };
                    let session = SdkTapRetainedSession {
                        wire_owner: if self.mode == TapMode::PidnsRoot {
                            SdkTapWireOwner::RootForwarded
                        } else {
                            SdkTapWireOwner::ChildReport
                        },
                        family: family.to_owned(),
                        sdk_peer: sdk_held.observation().clone(),
                        native_peer,
                        sdk_ancestry,
                        wire,
                    };
                    Ok::<_, String>((session, child))
                })
            });
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .map_err(|_| "SDK tap session thread panicked".to_owned())?
                })
                .collect::<Result<Vec<_>, _>>()
        })?;
        // A successful exchange through a held socket is insufficient if the
        // controller replaced its visible frontdoor while the sessions ran.
        // Refuse the trace before it can be retained under an outside pin.
        native.recheck()?;
        let (sessions, children): (Vec<_>, Vec<_>) = results.into_iter().unzip();
        Ok(TapSessions { sessions, children })
    }

    pub(crate) fn retain_sessions(
        &self,
        journal: &RunReservationJournal,
        lease: &ActiveLease,
        started: &StartedMarker,
        sessions: &TapSessions,
    ) -> Result<SdkTapJournalReceipt, String> {
        retain_sdk_tap_journal_ineligible(journal, lease, started, &sessions.sessions)
    }

    /// Called only after the controller has stopped and both session threads
    /// have joined. Attempt all cleanup steps even when one fails.
    pub(crate) fn cleanup(
        &mut self,
        journal: &RunReservationJournal,
        lease: &ActiveLease,
    ) -> Result<(), String> {
        let killed = self.group.kill();
        let drained = self.group.drain_and_remove();
        let closed = self
            .listeners
            .take()
            .ok_or("SDK tap listeners already closed")?
            .close_and_tombstone_ineligible(journal, lease);
        if killed.is_err() || drained.is_err() || closed.is_err() {
            return Err(format!(
                "SDK tap cleanup uncertain: kill={:?}, drain={:?}, listeners={:?}",
                killed.err(),
                drained.err(),
                closed.err()
            ));
        }
        Ok(())
    }
}

impl TapSessions {
    pub(crate) fn summary(&self, receipt: &SdkTapJournalReceipt) -> Value {
        if self
            .sessions
            .iter()
            .any(|session| session.wire_owner != receipt.wire_owner)
        {
            return json!({"schema":"hol-gauntlet-staging-sdk-tap-summary-invalid.v1","execution_eligible":false});
        }
        let mut value = json!({
            "schema":"hol-gauntlet-staging-sdk-tap-summary.v2",
            "journal":receipt.to_json(),
            "child_processes":self.children.iter().map(|child| json!({
                "pid":child.pid,
                "start_ticks":child.start_ticks,
                "cgroup":child.cgroup,
            })).collect::<Vec<_>>(),
            "native_peer_independently_observed_by_root":true,
            "execution_eligible":false,
        });
        if receipt.wire_owner == SdkTapWireOwner::RootForwarded {
            value["schema"] = json!("hol-gauntlet-staging-sdk-tap-summary.v3");
            value["root_forwarded"] = json!(true);
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux_process::parse_proc_stat;
    use crate::read_sdk_tap_journal_ineligible;
    use gauntlet_contracts::WorkerRequest;
    use rustix::fs::{chownat, fchown, openat, AtFlags, Mode, OFlags};
    use rustix::process::Gid;
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    fn process_pin(pid: u32) -> SdkWirePeerPin {
        let stat = fs::read(format!("/proc/{pid}/stat")).unwrap();
        let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap();
        SdkWirePeerPin {
            pid,
            start_ticks: parse_proc_stat(&stat, pid).unwrap().start_ticks,
            cgroup: cgroup.trim_end().strip_prefix("0::").unwrap().to_owned(),
        }
    }

    fn run_two_family_root_exchange(mode: TapMode, replace_frontdoor: bool) {
        let binary = std::env::var("GAUNTLET_SDK_TAP_TEST_BINARY").unwrap();
        let binary_sha = std::env::var("GAUNTLET_SDK_TAP_TEST_SHA256").unwrap();
        let run_id = format!(
            "{:016x}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
        );
        let state = Path::new("/home").join(format!("hx-{run_id}"));
        let role = state.join("success");
        let front = role.join("front");
        fs::create_dir(&state).unwrap();
        fs::create_dir(&role).unwrap();
        fs::create_dir(&front).unwrap();
        for path in [&state, &role] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let front_fd = File::open(&front).unwrap();
        fchown(&front_fd, None, Some(Gid::from_raw(10001))).unwrap();
        fs::set_permissions(&front, fs::Permissions::from_mode(0o710)).unwrap();
        let sockets = ["docs", "mail"].map(|family| {
            let name = format!("{family}.sock");
            let path = front.join(&name);
            let listener = UnixListener::bind(&path).unwrap();
            chownat(
                &front_fd,
                name.as_str(),
                None,
                Some(Gid::from_raw(10001)),
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
            listener
        });
        let servers = sockets.map(|listener| {
            thread::spawn(move || -> Result<(), String> {
                let socket_path = listener
                    .local_addr()
                    .map_err(|error| error.to_string())?
                    .as_pathname()
                    .ok_or("Native test socket path missing")?
                    .to_owned();
                listener.set_nonblocking(true).map_err(|e| e.to_string())?;
                let began = Instant::now();
                let mut connection = loop {
                    match listener.accept() {
                        Ok((connection, _)) => break connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if began.elapsed() > Duration::from_secs(10) {
                                return Err("Native test frontdoor timed out".to_owned());
                            }
                            thread::sleep(Duration::from_millis(20));
                        }
                        Err(error) => return Err(error.to_string()),
                    }
                };
                let request = b"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\"}\n";
                let response = b"{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}\n";
                let mut bytes = vec![0; request.len()];
                connection
                    .read_exact(&mut bytes)
                    .map_err(|e| e.to_string())?;
                if bytes != request {
                    return Err("Native test request changed through tap".to_owned());
                }
                connection.write_all(response).map_err(|e| e.to_string())?;
                if replace_frontdoor && socket_path.ends_with("docs.sock") {
                    fs::remove_file(&socket_path).map_err(|e| e.to_string())?;
                    let _replacement =
                        UnixListener::bind(&socket_path).map_err(|e| e.to_string())?;
                    chownat(
                        rustix::fs::CWD,
                        &socket_path,
                        None,
                        Some(Gid::from_raw(10001)),
                        AtFlags::empty(),
                    )
                    .map_err(|e| e.to_string())?;
                    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660))
                        .map_err(|e| e.to_string())?;
                }
                Ok(())
            })
        });
        let temporary = tempfile::Builder::new()
            .prefix("gauntlet-candidate-tap-")
            .tempdir_in("/root")
            .unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let journal = RunReservationJournal::open_root_owned(temporary.path()).unwrap();
        let lease = journal.acquire_active_lease().unwrap();
        let request = WorkerRequest::parse(
            format!("{{\"action\":\"run\",\"deployment_digest\":\"{}\",\"job_id\":\"{run_id}\",\"schema\":\"hol-gauntlet-worker-request.v1\",\"source_sha\":\"{}\"}}", "b".repeat(64), "a".repeat(40)).as_bytes(),
        )
        .unwrap();
        let started = journal
            .reserve_keyed_under_lease(
                &lease,
                &request,
                &"a".repeat(40),
                &"b".repeat(64),
                &"c".repeat(64),
                &"d".repeat(64),
            )
            .unwrap();
        let tap_pins = CandidateSdkTapPins {
            executable_path: &binary,
            executable_sha256: &binary_sha,
        };
        let mut tap = match mode {
            TapMode::LegacyChild => {
                StagingTapV2::prepare(&tap_pins, &"a".repeat(64), &run_id, &journal, &lease)
            }
            TapMode::PidnsChild => {
                StagingTapV2::prepare_pidns(&tap_pins, &"a".repeat(64), &run_id, &journal, &lease)
            }
            TapMode::PidnsRoot => StagingTapV2::prepare_root_relay_pidns(
                &tap_pins,
                &"a".repeat(64),
                &run_id,
                &journal,
                &lease,
            ),
        }
        .unwrap();
        let tap_directory = openat(
            &journal.root,
            format!("{run_id}.sdk-tap"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let directory_fd = tap_directory.as_raw_fd();
        let script = r#"import os,socket,sys,time
children=[]
for family in ('docs','mail'):
 pid=os.fork()
 if pid==0:
  s=socket.socket(socket.AF_UNIX)
  s.connect('/proc/self/fd/'+sys.argv[1]+'/'+family+'.sock')
  s.sendall(b'{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\"}\n')
  data=b''
  while not data.endswith(b'\n'):
   part=s.recv(4096)
   if not part: os._exit(9)
   data+=part
  if data!=b'{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}\n': os._exit(8)
  time.sleep(3)
  os._exit(0)
 children.append(pid)
for pid in children:
 _,status=os.waitpid(pid,0)
 if status!=0: sys.exit(7)
"#;
        let mut sdk = Command::new("/usr/bin/python3");
        sdk.arg("-c")
            .arg(script)
            .arg(directory_fd.to_string())
            .uid(10001)
            .gid(10001)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        // SAFETY: only clears CLOEXEC on the already held test tap directory.
        unsafe {
            sdk.pre_exec(move || {
                let flags = libc::fcntl(directory_fd, libc::F_GETFD);
                if flags < 0
                    || libc::fcntl(directory_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut sdk = sdk.spawn().unwrap();
        let ancestor = process_pin(sdk.id());
        let controller = process_pin(std::process::id());
        let deadline = BoottimeDeadline::start(10).unwrap();
        let result = tap.run_sessions(
            &journal,
            &lease,
            &run_id,
            StagingRole::Success,
            &controller,
            &ancestor,
            &deadline,
            &AtomicBool::new(false),
        );
        let tap_error = result.as_ref().err().cloned();
        if result.is_err() && !replace_frontdoor {
            let _ = sdk.kill();
        }
        let status = sdk.wait().unwrap();
        let server_results = servers.map(|server| server.join().unwrap());
        tap.cleanup(&journal, &lease).unwrap();
        fs::remove_dir_all(&state).unwrap();
        for server in server_results {
            server.unwrap();
        }
        if replace_frontdoor {
            assert!(status.success());
            assert_eq!(
                result.err().unwrap(),
                "Native frontdoor socket changed: docs.sock"
            );
            return;
        }
        if !status.success() {
            let mut stderr = String::new();
            sdk.stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            panic!("SDK test relay exited {status}: {stderr}; tap error: {tap_error:?}");
        }
        let result = result.unwrap();
        let receipt = tap
            .retain_sessions(&journal, &lease, &started, &result)
            .unwrap();
        let retained =
            read_sdk_tap_journal_ineligible(&journal, &lease, &started, &receipt.sha256).unwrap();
        assert_eq!(receipt.sessions, 2);
        assert_eq!(receipt.events, 4);
        assert!(!retained.is_empty());
        let summary = result.summary(&receipt);
        assert_eq!(
            summary["schema"],
            if mode == TapMode::PidnsRoot {
                "hol-gauntlet-staging-sdk-tap-summary.v3"
            } else {
                "hol-gauntlet-staging-sdk-tap-summary.v2"
            }
        );
        assert_eq!(summary["native_peer_independently_observed_by_root"], true);
        assert!(tap
            .retain_sessions(&journal, &lease, &started, &result)
            .is_err());
        assert_eq!(result.sessions.len(), 2);
        assert_eq!(result.children.len(), 2);
        assert!(result.sessions.iter().all(
            |session| session.wire.completed_tool_calls == 1 && session.wire.events.len() == 2
        ));
        assert!(result.sessions.iter().all(|session| {
            session.native_peer.pid == controller.pid
                && session.native_peer.start_ticks == controller.start_ticks
                && session.native_peer.cgroup == controller.cgroup
                && (session.native_peer.uid, session.native_peer.gid) == (0, 0)
        }));
        assert!(!temporary
            .path()
            .join(format!("{run_id}.sdk-tap/docs.sock"))
            .exists());
        assert!(bind_sdk_tap_listeners_ineligible(&journal, &lease, &run_id).is_err());
        assert!(!Path::new(&format!(
            "/sys/fs/cgroup/system.slice/hol-gauntlet-rust-tap-{run_id}"
        ))
        .exists());
    }

    #[test]
    #[ignore = "requires Linux Root, UID 10001 and separately pinned ARM64 tap-child ELF"]
    fn worker_owns_both_real_sdk_sessions_and_tombstones_after_drain() {
        run_two_family_root_exchange(TapMode::LegacyChild, false);
    }

    #[test]
    #[ignore = "requires Linux Root, UID 10001 and separately pinned ARM64 tap-child ELF"]
    fn worker_owns_both_pid_one_sdk_sessions_and_tombstones_after_drain() {
        run_two_family_root_exchange(TapMode::PidnsChild, false);
    }

    #[test]
    #[ignore = "requires Linux Root, UID 10001 and a separately pinned ARM64 PID-1 connector ELF"]
    fn worker_owns_both_root_forwarded_pid_one_sessions_and_tombstones_after_drain() {
        run_two_family_root_exchange(TapMode::PidnsRoot, false);
    }

    #[test]
    #[ignore = "requires Linux Root, UID 10001 and a separately pinned ARM64 PID-1 connector ELF"]
    fn root_forwarded_sessions_refuse_native_socket_replacement_after_exchange() {
        run_two_family_root_exchange(TapMode::PidnsRoot, true);
    }
}

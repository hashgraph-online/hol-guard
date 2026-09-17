#[cfg(not(windows))]
use std::io::Write;
use std::path::Path;
#[cfg(not(windows))]
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(windows)]
use guard_runtime_windows_process::ManagedChild;

#[cfg(not(windows))]
type ManagedSupervisorChild = std::process::Child;
#[cfg(windows)]
type ManagedSupervisorChild = ManagedChild;

#[cfg(windows)]
#[path = "managed_resident_windows.rs"]
mod managed_resident_windows;

const SUPERVISOR_REAPER_THREAD_NAME: &str = "hol-guard-supervisor-reaper";
const SUPERVISOR_REAPER_STACK_SIZE: usize = 128 * 1024;
const SUPERVISOR_POLL_INTERVAL: Duration = Duration::from_millis(25);
const MANAGED_CHILD_EXIT_GRACE: Duration = Duration::from_millis(250);

#[derive(Clone, Debug)]
pub(crate) struct ParentIdentity {
    pub(crate) process_id: u32,
    pub(crate) start_marker: String,
}

fn try_wait_supervisor(child: &mut ManagedSupervisorChild) -> Result<Option<bool>, String> {
    #[cfg(not(windows))]
    {
        child
            .try_wait()
            .map(|status| status.map(|status| status.success()))
            .map_err(|_| "native_resident_supervisor_wait_failed".to_owned())
    }
    #[cfg(windows)]
    {
        child
            .try_wait_success()
            .map_err(|_| "native_resident_supervisor_wait_failed".to_owned())
    }
}

fn wait_supervisor_bounded(
    child: &mut ManagedSupervisorChild,
    timeout: Duration,
) -> Result<Option<bool>, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = try_wait_supervisor(child)? {
            return Ok(Some(status));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        thread::sleep(SUPERVISOR_POLL_INTERVAL.min(remaining));
    }
}

fn parent_is_alive(identity: &ParentIdentity) -> bool {
    crate::resident_state::validate_package_process_identity_with_marker(
        identity.process_id,
        &identity.start_marker,
    )
    .is_ok()
}

fn remove_managed_endpoint(state_base: &Path, generation: u64, digest: &str) {
    #[cfg(unix)]
    {
        let Ok(scope) = crate::resident_state::state_scope(state_base, digest) else {
            return;
        };
        let Ok(socket_parent) = crate::resident_state::socket_directory(&scope, digest) else {
            return;
        };
        let path = socket_parent.join(format!("h3-{}-{generation:016x}.sock", &digest[..8]));
        if std::fs::symlink_metadata(&path)
            .is_ok_and(|metadata| std::os::unix::fs::FileTypeExt::is_socket(&metadata.file_type()))
        {
            let _ = std::fs::remove_file(path);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (state_base, generation, digest);
    }
}

fn terminate_managed_child(
    child: &mut ManagedSupervisorChild,
    state_base: &Path,
    generation: u64,
    digest: &str,
) -> Result<(), String> {
    if try_wait_supervisor(child)?.is_some() {
        remove_managed_endpoint(state_base, generation, digest);
        return Ok(());
    }

    #[cfg(not(windows))]
    {
        #[cfg(unix)]
        {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            let process_group = i32::try_from(child.id())
                .map_err(|_| "native_resident_spawn_containment_failed".to_owned())?;
            match kill(Pid::from_raw(-process_group), Signal::SIGKILL) {
                Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
                Err(_) => {
                    // The direct child remains owned by this supervisor even
                    // if its private group cannot be addressed. Try the
                    // direct handle before reporting containment failure.
                    child
                        .kill()
                        .map_err(|_| "native_resident_spawn_containment_failed".to_owned())?;
                }
            }
        }
        #[cfg(not(unix))]
        child
            .kill()
            .map_err(|_| "native_resident_spawn_containment_failed".to_owned())?;

        // SIGKILL is unmaskable. Polling also reaps an exited child, so do not
        // fall back to an unbounded `wait` if the platform cannot report exit
        // within the containment budget.
        if wait_supervisor_bounded(child, MANAGED_CHILD_EXIT_GRACE)?.is_none() {
            return Err("native_resident_spawn_containment_failed".to_owned());
        }
    }
    #[cfg(windows)]
    child
        .terminate_with_timeout(MANAGED_CHILD_EXIT_GRACE)
        .map_err(|_| "native_resident_spawn_containment_failed".to_owned())?;

    remove_managed_endpoint(state_base, generation, digest);
    Ok(())
}

fn wait_supervisor(child: &mut ManagedSupervisorChild) -> Result<(), String> {
    #[cfg(not(windows))]
    {
        child
            .wait()
            .map(|_| ())
            .map_err(|_| "native_resident_supervisor_wait_failed".to_owned())
    }
    #[cfg(windows)]
    {
        child
            .wait_success()
            .map(|_| ())
            .map_err(|_| "native_resident_supervisor_wait_failed".to_owned())
    }
}

fn terminate_supervisor(child: &mut ManagedSupervisorChild) -> Result<(), String> {
    #[cfg(not(windows))]
    {
        if child
            .try_wait()
            .map_err(|_| "native_resident_spawn_containment_failed".to_owned())?
            .is_some()
        {
            return Ok(());
        }

        #[cfg(unix)]
        {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            let process_group = i32::try_from(child.id())
                .map_err(|_| "native_resident_spawn_containment_failed".to_owned())?;
            match kill(Pid::from_raw(-process_group), Signal::SIGKILL) {
                Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
                Err(_) => {
                    return Err("native_resident_spawn_containment_failed".to_owned());
                }
            }
        }
        #[cfg(not(unix))]
        child
            .kill()
            .map_err(|_| "native_resident_spawn_containment_failed".to_owned())?;

        if wait_supervisor_bounded(child, MANAGED_CHILD_EXIT_GRACE)
            .map_err(|_| "native_resident_spawn_containment_failed".to_owned())?
            .is_some()
        {
            Ok(())
        } else {
            Err("native_resident_spawn_containment_failed".to_owned())
        }
    }
    #[cfg(windows)]
    {
        child
            .terminate()
            .map_err(|_| "native_resident_spawn_containment_failed".to_owned())
    }
}

fn fail_spawn(mut child: ManagedSupervisorChild, reason: &str) -> Result<(), String> {
    match terminate_supervisor(&mut child) {
        Ok(()) => Err(reason.to_owned()),
        Err(error) => Err(error),
    }
}

/// Retain the supervisor handle until it exits so its parent can reap it.
///
/// The child is kept behind an `Arc<Mutex<Option<_>>>` until the thread has
/// successfully started. This preserves ownership on thread setup failure,
/// allowing the caller to terminate and wait for the supervisor fail-closed.
fn retain_supervisor(child: ManagedSupervisorChild) -> Result<(), String> {
    let child_slot = Arc::new(Mutex::new(Some(child)));
    let reaper_slot = Arc::clone(&child_slot);
    let thread_result = thread::Builder::new()
        .name(SUPERVISOR_REAPER_THREAD_NAME.to_owned())
        .stack_size(SUPERVISOR_REAPER_STACK_SIZE)
        .spawn(move || {
            let mut child = match reaper_slot.lock() {
                Ok(mut slot) => slot.take(),
                Err(poisoned) => poisoned.into_inner().take(),
            };
            if let Some(ref mut child) = child {
                let _ = wait_supervisor(child);
            }
        });

    if thread_result.is_ok() {
        return Ok(());
    }

    let mut child = match child_slot.lock() {
        Ok(mut slot) => slot.take(),
        Err(poisoned) => poisoned.into_inner().take(),
    };
    let Some(child) = child.as_mut() else {
        return Err("native_resident_spawn_containment_failed".to_owned());
    };
    match terminate_supervisor(child) {
        Ok(()) => Err("native_resident_supervisor_reaper_failed".to_owned()),
        Err(error) => Err(error),
    }
}

pub(crate) fn spawn_managed(
    state_base: &Path,
    generation: u64,
    digest: &str,
    token: &[u8],
    parent_identity: Option<ParentIdentity>,
) -> Result<(), String> {
    #[cfg(windows)]
    return managed_resident_windows::spawn_managed(
        state_base,
        generation,
        digest,
        token,
        parent_identity,
    );
    #[cfg(not(windows))]
    {
        let executable = std::env::current_exe()
            .map_err(|_| "native_resident_runtime_path_failed".to_owned())?;
        let mut command = Command::new(executable);
        command
            .arg("supervise-managed")
            .arg("--state-dir")
            .arg(state_base)
            .arg("--generation")
            .arg(generation.to_string())
            .arg("--runtime-sha256")
            .arg(digest);
        if let Some(parent_identity) = parent_identity {
            command
                .arg("--parent-process-id")
                .arg(parent_identity.process_id.to_string())
                .arg("--parent-process-start-marker")
                .arg(parent_identity.start_marker);
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // Keep the supervisor and its serving child in one private
            // process group so setup-failure containment addresses both.
            command.process_group(0);
        }
        let mut child = command
            .spawn()
            .map_err(|_| "native_resident_spawn_failed".to_owned())?;
        let mut stdin = match child.stdin.take() {
            Some(stdin) => stdin,
            None => return fail_spawn(child, "native_resident_spawn_stdin_failed"),
        };
        let write_result = stdin
            .write_all(hex_token(token).as_bytes())
            .and_then(|()| stdin.write_all(b"\n"))
            .and_then(|()| stdin.flush());
        drop(stdin);
        if write_result.is_err() {
            return fail_spawn(child, "native_resident_spawn_auth_failed");
        }
        retain_supervisor(child)
    }
}

pub(crate) fn supervise_managed(
    state_base: &Path,
    generation: u64,
    expected_digest: &str,
    token: &[u8],
    parent_identity: Option<ParentIdentity>,
) -> Result<(), String> {
    if let Some(identity) = parent_identity.as_ref() {
        if !parent_is_alive(identity) {
            return Err("native_resident_parent_identity_mismatch".to_owned());
        }
    }
    #[cfg(windows)]
    return managed_resident_windows::supervise_managed(
        state_base,
        generation,
        expected_digest,
        token,
        parent_identity,
    );
    #[cfg(not(windows))]
    {
        let executable = std::env::current_exe()
            .map_err(|_| "native_resident_runtime_path_failed".to_owned())?;
        let mut command = Command::new(executable);
        command
            .arg("serve-managed")
            .arg("--state-dir")
            .arg(state_base)
            .arg("--generation")
            .arg(generation.to_string())
            .arg("--owner-process-id")
            .arg(std::process::id().to_string())
            .arg("--runtime-sha256")
            .arg(expected_digest)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // Give the serving process its own group. The supervisor can
            // then contain the full serving tree without killing itself.
            command.process_group(0);
        }
        let mut child = command
            .spawn()
            .map_err(|_| "native_resident_spawn_failed".to_owned())?;
        let mut liveness_writer = match child.stdin.take() {
            Some(stdin) => stdin,
            None => return fail_spawn(child, "native_resident_spawn_stdin_failed"),
        };
        let write_result = liveness_writer
            .write_all(hex_token(token).as_bytes())
            .and_then(|()| liveness_writer.write_all(b"\n"))
            .and_then(|()| liveness_writer.flush());
        if write_result.is_err() {
            drop(liveness_writer);
            return match terminate_managed_child(
                &mut child,
                state_base,
                generation,
                expected_digest,
            ) {
                Ok(()) => Err("native_resident_spawn_auth_failed".to_owned()),
                Err(error) => Err(error),
            };
        }
        let status = loop {
            match try_wait_supervisor(&mut child)? {
                Some(status) => break status,
                None => {
                    if parent_identity
                        .as_ref()
                        .is_some_and(|identity| !parent_is_alive(identity))
                    {
                        drop(liveness_writer);
                        return match terminate_managed_child(
                            &mut child,
                            state_base,
                            generation,
                            expected_digest,
                        ) {
                            Ok(()) => Err("native_resident_parent_exit_contained".to_owned()),
                            Err(error) => Err(error),
                        };
                    }
                    thread::sleep(SUPERVISOR_POLL_INTERVAL);
                }
            }
        };
        drop(liveness_writer);
        if status {
            Ok(())
        } else {
            Err("native_resident_managed_exit_failed".to_owned())
        }
    }
}

fn hex_token(token: &[u8]) -> String {
    let mut output = String::with_capacity(token.len() * 2);
    for byte in token {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

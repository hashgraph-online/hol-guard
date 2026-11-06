#![forbid(unsafe_code)]

//! Owned-child startup and termination. Discovery-based generation cleanup
//! stays in containment; an empty discovery is not proof of descendant exit.

#[cfg(windows)]
use guard_runtime_windows_process::ManagedChild;
#[cfg(not(windows))]
use std::io::Write;
use std::path::Path;
#[cfg(not(windows))]
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use super::ManagedProcessIdentity;
#[cfg(not(windows))]
use crate::resident_state::validate_runtime_process_identity;
use crate::resident_state::{process_start_marker, runtime_digest};

#[cfg(not(windows))]
pub(in super::super) type SpawnedManaged = Child;
#[cfg(windows)]
pub(in super::super) type SpawnedManaged = ManagedChild;

pub(in super::super) fn spawn_managed_for_owner(
    state_base: &Path,
    generation: u64,
    digest: &str,
    token: &[u8],
    owner_process_id: u32,
    overall_deadline: Instant,
) -> Result<SpawnedManaged, String> {
    #[cfg(windows)]
    return super::super::managed_resident_windows::spawn_managed(
        state_base,
        generation,
        digest,
        token,
        owner_process_id,
        overall_deadline,
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
            .arg("--owner-process-id")
            .arg(owner_process_id.to_string())
            .arg("--runtime-sha256")
            .arg(digest)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // The supervisor and serving child form one containment unit.  The
        // child inherits this group before it can run, closing the startup
        // timeout race that otherwise strands serve-managed at PID 1.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command
            .spawn()
            .map_err(|_| "native_resident_spawn_failed".to_owned())?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            terminate_spawned_managed(
                &mut child,
                overall_deadline
                    .saturating_duration_since(Instant::now())
                    .min(super::super::MANAGED_STOP_TIMEOUT),
            )
            .err()
            .unwrap_or_else(|| "native_resident_spawn_stdin_failed".to_owned())
        })?;
        let write_result = stdin
            .write_all(hex_token(token).as_bytes())
            .and_then(|()| stdin.write_all(b"\n"))
            .and_then(|()| stdin.flush());
        if write_result.is_err() {
            terminate_spawned_managed(
                &mut child,
                overall_deadline
                    .saturating_duration_since(Instant::now())
                    .min(super::super::MANAGED_STOP_TIMEOUT),
            )?;
            return Err("native_resident_spawn_auth_failed".to_owned());
        }
        Ok(child)
    }
}

/// Renders the token for the one write that hands it to a child over stdin.
/// The rendering is a plaintext copy of the key, so it is cleared when the
/// caller drops it rather than left behind in a freed allocation.
pub(in super::super) fn hex_token(token: &[u8]) -> Zeroizing<String> {
    let mut output = Zeroizing::new(String::with_capacity(token.len() * 2));
    for byte in token {
        use std::fmt::Write as _;
        let _ = write!(*output, "{byte:02x}");
    }
    output
}

fn child_process_id(child: &SpawnedManaged) -> u32 {
    child.id()
}

#[cfg(not(windows))]
pub(in super::super) fn terminate_spawned_managed(
    child: &mut SpawnedManaged,
    timeout: Duration,
) -> Result<(), String> {
    let _ = timeout;
    if child
        .try_wait()
        .map_err(|_| "native_resident_spawn_containment_failed".to_owned())?
        .is_some()
    {
        // The child may have exited since the cleanup snapshot. Reaping it
        // proves nothing about an unpublished descendant in its old group.
        return Err("native_resident_spawn_containment_failed".to_owned());
    }
    let process_id = child.id();
    let start_marker = process_start_marker(process_id).ok();
    let runtime_identity_proven = start_marker.as_deref().is_some_and(|marker| {
        runtime_digest().is_ok_and(|digest| {
            validate_runtime_process_identity(process_id, marker, &digest).is_ok()
        })
    });
    if runtime_identity_proven {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        // spawn_managed_for_owner sets process_group(0), making the
        // supervisor PID the group ID inherited by serve-managed.  Keep the
        // identity proof immediately before addressing the group so a stale
        // or reused PID can never authorize a broad kill.
        match kill(Pid::from_raw(-(process_id as i32)), Signal::SIGKILL) {
            Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
            Err(_) => return Err("native_resident_spawn_containment_failed".to_owned()),
        }
    } else {
        child
            .kill()
            .map_err(|_| "native_resident_spawn_containment_failed".to_owned())?;
    }
    child
        .wait()
        .map_err(|_| "native_resident_spawn_containment_failed".to_owned())?;
    // Direct-child cleanup is still required when its runtime identity cannot
    // be proved, but must not be presented as containment of the whole group.
    runtime_identity_proven
        .then_some(())
        .ok_or_else(|| "native_resident_spawn_containment_failed".to_owned())
}

#[cfg(windows)]
pub(in super::super) fn terminate_spawned_managed(
    child: &mut SpawnedManaged,
    timeout: Duration,
) -> Result<(), String> {
    child
        .terminate_with_timeout(timeout)
        .map_err(|_| "native_resident_spawn_containment_failed".to_owned())
}

/// Observe the owned child handle, never a possibly reused process ID.
/// On Unix, an exited child is reaped. This says nothing about descendants:
/// cleanup must not infer their extinction from this result or an empty scope.
pub(in super::super) fn spawned_has_exited(child: &mut SpawnedManaged) -> Result<bool, String> {
    #[cfg(not(windows))]
    let result = child.try_wait().map(|status| status.is_some());
    #[cfg(windows)]
    let result = match child.wait_success_with_timeout(Duration::ZERO) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => Ok(false),
        Err(error) => Err(error),
    };
    result.map_err(|_| "native_resident_supervisor_wait_failed".to_owned())
}

pub(super) fn spawned_process_identities(
    child: &mut SpawnedManaged,
) -> Result<Vec<ManagedProcessIdentity>, String> {
    // Startup polling may already have reaped this child. Never sample that
    // PID again: it could now identify an unrelated process of this runtime.
    // When still live, its unreaped handle keeps the PID bound while sampled.
    if spawned_has_exited(child)? {
        // The Unix supervisor may have crashed after spawning serve-managed
        // but before it published any state. Its reaped PID cannot authorize
        // group signalling, and absent state cannot prove the child is gone.
        // Keep cleanup fail-closed rather than claiming complete containment.
        #[cfg(not(windows))]
        return Err("native_resident_spawn_containment_failed".to_owned());
        // Windows retains the owned JobObject for descendant termination.
        #[cfg(windows)]
        return Ok(Vec::new());
    }
    let process_id = child_process_id(child);
    Ok(vec![ManagedProcessIdentity {
        process_id,
        start_marker: process_start_marker(process_id).ok(),
        runtime_digest: runtime_digest().ok(),
    }])
}

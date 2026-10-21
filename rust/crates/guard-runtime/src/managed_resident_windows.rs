use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use guard_runtime_windows_process::{spawn_managed_child, ManagedChild};

use super::containment::hex_token;

pub(crate) fn spawn_managed(
    state_base: &Path,
    generation: u64,
    digest: &str,
    token: &[u8],
    owner_process_id: u32,
    overall_deadline: Instant,
) -> Result<ManagedChild, String> {
    let executable =
        std::env::current_exe().map_err(|_| "native_resident_runtime_path_failed".to_owned())?;
    let arguments = vec![
        OsString::from("supervise-managed"),
        OsString::from("--state-dir"),
        state_base.as_os_str().to_owned(),
        OsString::from("--generation"),
        OsString::from(generation.to_string()),
        OsString::from("--owner-process-id"),
        OsString::from(owner_process_id.to_string()),
        OsString::from("--runtime-sha256"),
        OsString::from(digest),
    ];
    let argument_refs: Vec<&OsStr> = arguments.iter().map(OsString::as_os_str).collect();
    let mut child = spawn_managed_child(&executable, &argument_refs)
        .map_err(|_| "native_resident_spawn_failed".to_owned())?;
    let write_result = {
        let Some(mut stdin) = child.take_stdin() else {
            super::containment::terminate_spawned_managed(
                &mut child,
                overall_deadline
                    .saturating_duration_since(Instant::now())
                    .min(super::MANAGED_STOP_TIMEOUT),
            )?;
            return Err("native_resident_spawn_stdin_failed".to_owned());
        };
        stdin
            .write_all(hex_token(token).as_bytes())
            .and_then(|()| stdin.write_all(b"\n"))
            .and_then(|()| stdin.flush())
    };
    if write_result.is_err() {
        super::containment::terminate_spawned_managed(
            &mut child,
            overall_deadline
                .saturating_duration_since(Instant::now())
                .min(super::MANAGED_STOP_TIMEOUT),
        )?;
        return Err("native_resident_spawn_auth_failed".to_owned());
    }
    Ok(child)
}

pub(crate) fn supervise_managed(
    state_base: &Path,
    generation: u64,
    expected_digest: &str,
    owner_process_id: u32,
    token: &[u8],
) -> Result<(), String> {
    let executable =
        std::env::current_exe().map_err(|_| "native_resident_runtime_path_failed".to_owned())?;
    let arguments = vec![
        OsString::from("serve-managed"),
        OsString::from("--state-dir"),
        state_base.as_os_str().to_owned(),
        OsString::from("--generation"),
        OsString::from(generation.to_string()),
        OsString::from("--owner-process-id"),
        OsString::from(std::process::id().to_string()),
        OsString::from("--runtime-sha256"),
        OsString::from(expected_digest),
    ];
    let owner = ManagedOwner {
        state_base,
        digest: expected_digest,
        process_id: owner_process_id,
    };
    supervise_managed_child(&executable, &arguments, token, &owner)
}

/// The process and runtime clients that keep a supervised resident alive.
struct ManagedOwner<'a> {
    state_base: &'a Path,
    digest: &'a str,
    process_id: u32,
}

fn supervise_managed_child(
    executable: &Path,
    arguments: &[OsString],
    token: &[u8],
    owner: &ManagedOwner<'_>,
) -> Result<(), String> {
    let argument_refs: Vec<&OsStr> = arguments.iter().map(OsString::as_os_str).collect();
    // Claim the scope before the spawn, so a stop sees this supervisor from
    // the start of the run until its exit record is written rather than only
    // once the record is under way.
    // A failure here must leave no serving child, as on Unix.
    let supervised = super::exit_record::supervised_scope(owner.state_base, owner.digest)?;
    let started = Instant::now();
    let mut child = spawn_managed_child(executable, &argument_refs)
        .map_err(|_| "native_resident_spawn_failed".to_owned())?;
    let mut liveness_writer = child.take_stdin().ok_or_else(|| {
        let _ = child.terminate_with_timeout(super::MANAGED_STOP_TIMEOUT);
        "native_resident_spawn_stdin_failed".to_owned()
    })?;
    let write_result = liveness_writer
        .write_all(hex_token(token).as_bytes())
        .and_then(|()| liveness_writer.write_all(b"\n"))
        .and_then(|()| liveness_writer.flush());
    if write_result.is_err() {
        let _ = child.terminate_with_timeout(super::MANAGED_STOP_TIMEOUT);
        return Err("native_resident_spawn_auth_failed".to_owned());
    }
    // Like the Unix supervisor, close the child's stdin once the owner and all
    // runtime clients are gone instead of holding it until the idle timeout.
    let child_done = Arc::new(AtomicBool::new(false));
    let watcher = super::spawn_owner_lease_watcher(
        executable.to_owned(),
        owner.state_base,
        owner.digest,
        owner.process_id,
        liveness_writer,
        Arc::clone(&child_done),
    );
    let status_result =
        child.wait_success_with_timeout(super::MANAGED_IDLE_TIMEOUT + super::MANAGED_STOP_TIMEOUT);
    let ran_for = started.elapsed();
    child_done.store(true, Ordering::Release);
    let _ = watcher.join();
    let status_success =
        status_result.map_err(|_| "native_resident_supervisor_wait_failed".to_owned())?;
    // Windows spawns the serving child without a stderr pipe, so the record
    // carries the supervisor's own classification of this exit.
    super::exit_record::record_supervised_exit(supervised, None, status_success, None, ran_for);
    if status_success {
        Ok(())
    } else {
        Err("native_resident_managed_exit_failed".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::io::{self, Read};
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const CHILD_MARKER_ENV: &str = "HOL_GUARD_TEST_LIVENESS_CHILD_MARKER";
    const CHILD_PARENT_ENV: &str = "HOL_GUARD_TEST_LIVENESS_CHILD_PARENT";
    const EOF_MARKER_ENV: &str = "HOL_GUARD_TEST_LIVENESS_EOF_MARKER";
    const EOF_STARTED_ENV: &str = "HOL_GUARD_TEST_LIVENESS_EOF_STARTED";
    const ORPHAN_EOF_MARKER_ENV: &str = "HOL_GUARD_TEST_ORPHAN_EOF_MARKER";
    const ORPHAN_PARENT_ENV: &str = "HOL_GUARD_TEST_ORPHAN_PARENT";
    // The supervisor claims its state scope before the spawn, and a scope is
    // named by a full runtime digest.
    const RUNTIME_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    /// The scope is created below an owner-only state base, as a provisioned
    /// Guard home has one.
    fn private_state_base(directory: &Path) -> std::path::PathBuf {
        crate::resident_state::ensure_private_directory(&directory.join("state"), true)
            .expect("create private state base")
    }

    #[test]
    fn liveness_pipe_remains_open_while_child_runs_and_closes_after_wait() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_nanos();
        let directory = env::temp_dir().join(format!(
            "guard-runtime-liveness-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create liveness test directory");
        let child_marker = directory.join("child-open");
        let eof_marker = directory.join("pipe-closed");
        let eof_started = directory.join("eof-probe-started");
        env::set_var(CHILD_MARKER_ENV, &child_marker);
        env::set_var(CHILD_PARENT_ENV, std::process::id().to_string());
        env::set_var(EOF_MARKER_ENV, &eof_marker);
        env::set_var(EOF_STARTED_ENV, &eof_started);

        let executable = env::current_exe().expect("locate test executable");
        let arguments = [
            OsString::from("liveness_pipe_child_probe"),
            OsString::from("--nocapture"),
        ];
        // The test process stays alive, so only the supervisor's wait closes the pipe.
        let owner = ManagedOwner {
            state_base: &private_state_base(&directory),
            digest: RUNTIME_DIGEST,
            process_id: std::process::id(),
        };
        let result = supervise_managed_child(&executable, &arguments, &[0x5a; 32], &owner);

        env::remove_var(CHILD_MARKER_ENV);
        env::remove_var(CHILD_PARENT_ENV);
        env::remove_var(EOF_MARKER_ENV);
        env::remove_var(EOF_STARTED_ENV);

        assert!(
            result.is_ok(),
            "supervisor child should exit successfully: {result:?}"
        );
        assert!(child_marker.exists(), "child did not observe an open pipe");
        wait_for_marker(&eof_marker);
        assert!(eof_started.exists(), "EOF probe did not start");
        let _ = fs::remove_file(child_marker);
        let _ = fs::remove_file(eof_marker);
        let _ = fs::remove_file(eof_started);
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn liveness_pipe_closes_once_owner_and_clients_are_gone() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_nanos();
        let directory = env::temp_dir().join(format!(
            "guard-runtime-orphan-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create orphan test directory");
        let eof_marker = directory.join("pipe-closed");
        env::set_var(ORPHAN_EOF_MARKER_ENV, &eof_marker);
        env::set_var(ORPHAN_PARENT_ENV, std::process::id().to_string());
        let mut exited = Command::new("cmd")
            .args(["/C", "exit"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn short-lived owner");
        let owner_process_id = exited.id();
        exited.wait().expect("wait for short-lived owner");
        // `exited` keeps its process handle open, so the dead owner's process
        // object stays queryable, as it does while a real parent holds it.

        let executable = env::current_exe().expect("locate test executable");
        let arguments = [
            OsString::from("orphan_child_probe"),
            OsString::from("--nocapture"),
        ];
        // The owner has exited and the state base holds no client leases, so the
        // child must see EOF while it is still running, not after the idle timeout.
        let owner = ManagedOwner {
            state_base: &private_state_base(&directory),
            digest: RUNTIME_DIGEST,
            process_id: owner_process_id,
        };
        let started = Instant::now();
        let result = supervise_managed_child(&executable, &arguments, &[0x5a; 32], &owner);
        env::remove_var(ORPHAN_EOF_MARKER_ENV);
        env::remove_var(ORPHAN_PARENT_ENV);

        assert!(
            result.is_ok(),
            "orphaned child did not see its pipe close: {result:?}"
        );
        assert!(eof_marker.exists(), "orphaned child did not record EOF");
        assert!(started.elapsed() < Duration::from_secs(10));
        let _ = fs::remove_file(eof_marker);
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn orphan_child_probe() {
        // The environment is process-wide, so this test also runs in the parent
        // while the variables are set; only the spawned child acts on them.
        let spawned = env::var(ORPHAN_PARENT_ENV)
            .is_ok_and(|parent| parent != std::process::id().to_string());
        let Some(eof_marker) = env::var_os(ORPHAN_EOF_MARKER_ENV).filter(|_| spawned) else {
            return;
        };
        // Fail instead of hanging when the supervisor never closes the pipe.
        thread::spawn(|| {
            thread::sleep(Duration::from_secs(15));
            std::process::exit(3);
        });
        let mut auth = [0u8; 65];
        io::stdin()
            .read_exact(&mut auth)
            .expect("read supervisor authentication token");
        let mut rest = Vec::new();
        io::stdin()
            .read_to_end(&mut rest)
            .expect("read liveness pipe");
        fs::write(eof_marker, b"closed").expect("write closed marker");
    }

    #[test]
    fn liveness_pipe_child_probe() {
        // As in `orphan_child_probe`, only the spawned child acts on the
        // process-wide variables the parent sets.
        let spawned =
            env::var(CHILD_PARENT_ENV).is_ok_and(|parent| parent != std::process::id().to_string());
        let Some(child_marker) = env::var_os(CHILD_MARKER_ENV).filter(|_| spawned) else {
            return;
        };
        let eof_marker = env::var_os(EOF_MARKER_ENV).expect("EOF marker is configured");
        let eof_started = env::var_os(EOF_STARTED_ENV).expect("EOF start marker is configured");
        let mut auth = [0u8; 65];
        io::stdin()
            .read_exact(&mut auth)
            .expect("read supervisor authentication token");
        let monitor = Command::new(env::current_exe().expect("locate test executable"))
            .args(["liveness_pipe_eof_probe", "--nocapture"])
            .stdin(Stdio::inherit())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn EOF probe");
        wait_for_marker(Path::new(&eof_started));
        assert!(
            !Path::new(&eof_marker).exists(),
            "liveness pipe closed before supervisor wait"
        );
        fs::write(child_marker, b"open").expect("write child marker");
        drop(monitor);
    }

    #[test]
    fn liveness_pipe_eof_probe() {
        // The grandchild inherits the parent's PID in `CHILD_PARENT_ENV` and
        // runs with its own, so the parent never reads its harness's stdin.
        let spawned =
            env::var(CHILD_PARENT_ENV).is_ok_and(|parent| parent != std::process::id().to_string());
        let Some(eof_started) = env::var_os(EOF_STARTED_ENV).filter(|_| spawned) else {
            return;
        };
        let eof_marker = env::var_os(EOF_MARKER_ENV).expect("EOF marker is configured");
        fs::write(eof_started, b"started").expect("write EOF probe marker");
        let mut byte = [0u8; 1];
        let bytes_read = io::stdin().read(&mut byte).expect("read liveness pipe");
        assert_eq!(
            bytes_read, 0,
            "liveness pipe did not close after supervisor wait"
        );
        fs::write(eof_marker, b"closed").expect("write closed marker");
    }

    fn wait_for_marker(path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !path.exists() {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for liveness marker"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

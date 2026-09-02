use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::Path;

use guard_runtime_windows_process::{spawn_managed_child, ManagedChild};

use super::containment::hex_token;

pub(crate) fn spawn_managed(
    state_base: &Path,
    generation: u64,
    digest: &str,
    token: &[u8],
    owner_process_id: u32,
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
            let _ = child.terminate_with_timeout(super::MANAGED_STOP_TIMEOUT);
            return Err("native_resident_spawn_stdin_failed".to_owned());
        };
        stdin
            .write_all(hex_token(token).as_bytes())
            .and_then(|()| stdin.write_all(b"\n"))
            .and_then(|()| stdin.flush())
    };
    if write_result.is_err() {
        let _ = child.terminate_with_timeout(super::MANAGED_STOP_TIMEOUT);
        return Err("native_resident_spawn_auth_failed".to_owned());
    }
    Ok(child)
}

pub(crate) fn supervise_managed(
    state_base: &Path,
    generation: u64,
    expected_digest: &str,
    _owner_process_id: u32,
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
    supervise_managed_child(&executable, &arguments, token)
}

fn supervise_managed_child(
    executable: &Path,
    arguments: &[OsString],
    token: &[u8],
) -> Result<(), String> {
    let argument_refs: Vec<&OsStr> = arguments.iter().map(OsString::as_os_str).collect();
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
    let status_result =
        child.wait_success_with_timeout(super::MANAGED_IDLE_TIMEOUT + super::MANAGED_STOP_TIMEOUT);
    drop(liveness_writer);
    let status_success =
        status_result.map_err(|_| "native_resident_supervisor_wait_failed".to_owned())?;
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
    const EOF_MARKER_ENV: &str = "HOL_GUARD_TEST_LIVENESS_EOF_MARKER";
    const EOF_STARTED_ENV: &str = "HOL_GUARD_TEST_LIVENESS_EOF_STARTED";

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
        env::set_var(EOF_MARKER_ENV, &eof_marker);
        env::set_var(EOF_STARTED_ENV, &eof_started);

        let executable = env::current_exe().expect("locate test executable");
        let arguments = [
            OsString::from("liveness_pipe_child_probe"),
            OsString::from("--nocapture"),
        ];
        let result = supervise_managed_child(&executable, &arguments, &[0x5a; 32]);

        env::remove_var(CHILD_MARKER_ENV);
        env::remove_var(EOF_MARKER_ENV);
        env::remove_var(EOF_STARTED_ENV);

        assert!(result.is_ok(), "supervisor child should exit successfully");
        assert!(child_marker.exists(), "child did not observe an open pipe");
        wait_for_marker(&eof_marker);
        assert!(eof_started.exists(), "EOF probe did not start");
        let _ = fs::remove_file(child_marker);
        let _ = fs::remove_file(eof_marker);
        let _ = fs::remove_file(eof_started);
        let _ = fs::remove_dir(directory);
    }

    #[test]
    fn liveness_pipe_child_probe() {
        let Some(child_marker) = env::var_os(CHILD_MARKER_ENV) else {
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
        let Some(eof_started) = env::var_os(EOF_STARTED_ENV) else {
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

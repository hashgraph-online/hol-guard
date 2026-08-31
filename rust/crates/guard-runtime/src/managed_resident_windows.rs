use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::Path;

use guard_runtime_windows_process::spawn_managed_child;

use super::hex_token;

pub(crate) fn spawn_managed(
    state_base: &Path,
    generation: u64,
    digest: &str,
    token: &[u8],
) -> Result<(), String> {
    let executable =
        std::env::current_exe().map_err(|_| "native_resident_runtime_path_failed".to_owned())?;
    let arguments = vec![
        OsString::from("supervise-managed"),
        OsString::from("--state-dir"),
        state_base.as_os_str().to_owned(),
        OsString::from("--generation"),
        OsString::from(generation.to_string()),
        OsString::from("--runtime-sha256"),
        OsString::from(digest),
    ];
    let argument_refs: Vec<&OsStr> = arguments.iter().map(OsString::as_os_str).collect();
    let mut child = spawn_managed_child(&executable, &argument_refs)
        .map_err(|_| "native_resident_spawn_failed".to_owned())?;
    let write_result = {
        let mut stdin = child
            .take_stdin()
            .ok_or_else(|| "native_resident_spawn_stdin_failed".to_owned())?;
        stdin
            .write_all(hex_token(token).as_bytes())
            .and_then(|()| stdin.write_all(b"\n"))
            .and_then(|()| stdin.flush())
    };
    if write_result.is_err() {
        let _ = child.terminate();
        return Err("native_resident_spawn_auth_failed".to_owned());
    }
    Ok(())
}

pub(crate) fn supervise_managed(
    state_base: &Path,
    generation: u64,
    expected_digest: &str,
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
    let argument_refs: Vec<&OsStr> = arguments.iter().map(OsString::as_os_str).collect();
    let mut child = spawn_managed_child(&executable, &argument_refs)
        .map_err(|_| "native_resident_spawn_failed".to_owned())?;
    let write_result = {
        let mut liveness_writer = child
            .take_stdin()
            .ok_or_else(|| "native_resident_spawn_stdin_failed".to_owned())?;
        liveness_writer
            .write_all(hex_token(token).as_bytes())
            .and_then(|()| liveness_writer.write_all(b"\n"))
            .and_then(|()| liveness_writer.flush())
    };
    if write_result.is_err() {
        let _ = child.terminate();
        return Err("native_resident_spawn_auth_failed".to_owned());
    }
    let status_success = child
        .wait_success()
        .map_err(|_| "native_resident_supervisor_wait_failed".to_owned())?;
    if status_success {
        Ok(())
    } else {
        Err("native_resident_managed_exit_failed".to_owned())
    }
}

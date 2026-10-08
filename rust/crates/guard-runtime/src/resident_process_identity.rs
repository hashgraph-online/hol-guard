#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

const MAX_RUNTIME_BYTES: u64 = 128 * 1024 * 1024;

#[cfg(not(windows))]
pub(crate) fn executable_missing(path: &Path) -> bool {
    path.metadata()
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

#[cfg(windows)]
pub(crate) fn process_start_marker(process_id: u32) -> Result<String, String> {
    guard_runtime_windows_process::process_start_marker(process_id)
        .map_err(|_| "native_resident_process_identity_unavailable".to_owned())
}

/// Return the parent captured while a legacy supervisor is starting.
///
/// The current launcher passes an explicit owner identity. This fallback keeps
/// older seven-argument supervisor invocations bounded to the one-shot
/// launcher that created them, instead of making the supervisor its own
/// lifetime owner after that launcher exits.
pub(crate) fn parent_process_id() -> Option<u32> {
    let pid = Pid::from_u32(std::process::id());
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing(),
    );
    system
        .process(pid)
        .and_then(|process| process.parent())
        .map(|parent| parent.as_u32())
        .filter(|parent| *parent > 0)
}

#[cfg(not(windows))]
pub(crate) fn process_start_marker(process_id: u32) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    if let Some(marker) = linux_process_start_marker(process_id) {
        return Ok(marker);
    }
    #[cfg(target_os = "macos")]
    if let Some(marker) = darwin_process_start_marker(process_id) {
        return Ok(marker);
    }
    let pid = Pid::from_u32(process_id);
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
    );
    let process = system
        .process(pid)
        .ok_or_else(|| "native_resident_process_identity_unavailable".to_owned())?;
    Ok(format!("posix:{}", process.start_time()))
}

/// Prove that a process no longer exists without treating identity lookup
/// errors as proof of death.
#[cfg(unix)]
pub(crate) fn process_is_definitively_gone(process_id: u32) -> Result<bool, String> {
    use nix::errno::Errno;
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    if process_id == 0 || process_id > i32::MAX as u32 {
        return Ok(true);
    }
    match kill(Pid::from_raw(process_id as i32), None) {
        Ok(()) | Err(Errno::EPERM) | Err(Errno::EACCES) => Ok(false),
        Err(Errno::ESRCH) => Ok(true),
        Err(_) => Err("native_resident_process_identity_unavailable".to_owned()),
    }
}

#[cfg(windows)]
pub(crate) fn process_is_definitively_gone(process_id: u32) -> Result<bool, String> {
    guard_runtime_windows_process::wait_for_process_exit(process_id, std::time::Duration::ZERO)
        .map_err(|_| "native_resident_process_identity_unavailable".to_owned())
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn process_is_definitively_gone(_process_id: u32) -> Result<bool, String> {
    Err("native_resident_process_identity_unavailable".to_owned())
}

#[cfg(target_os = "macos")]
fn darwin_process_start_marker(process_id: u32) -> Option<String> {
    let info =
        libproc::proc_pid::pidinfo::<libproc::bsd_info::BSDInfo>(process_id as i32, 0).ok()?;
    Some(format!(
        "darwin:{}:{}",
        info.pbi_start_tvsec, info.pbi_start_tvusec
    ))
}

#[cfg(target_os = "linux")]
fn linux_process_start_marker(process_id: u32) -> Option<String> {
    let contents = fs::read_to_string(format!("/proc/{process_id}/stat")).ok()?;
    let (_, suffix) = contents.rsplit_once(')')?;
    let start_ticks = suffix.split_whitespace().nth(19)?.parse::<u64>().ok()?;
    Some(format!("linux:{start_ticks}"))
}

pub(crate) fn validate_package_process_identity(
    process_id: u32,
    expected_start_marker: &str,
) -> Result<(), String> {
    let process_path = process_executable_path(process_id)?;
    let expected_path = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|_| "native_resident_runtime_path_failed".to_owned())?;
    if process_path != expected_path {
        // Onefile launchers extract identical signed runtimes into distinct
        // directories. Bind to the runtime bytes, not that temporary path.
        if executable_digest(&process_path)? != crate::resident_state::runtime_digest()? {
            return Err("native_resident_process_identity_mismatch".to_owned());
        }
    }
    validate_process_start_marker(process_id, expected_start_marker)
}

pub(crate) fn validate_runtime_process_identity(
    process_id: u32,
    expected_start_marker: &str,
    expected_digest: &str,
) -> Result<(), String> {
    let process_path = process_executable_path(process_id)?;
    if executable_digest(&process_path)? != expected_digest {
        return Err("native_resident_process_identity_mismatch".to_owned());
    }
    validate_process_start_marker(process_id, expected_start_marker)
}

pub(crate) fn validate_process_start_marker(
    process_id: u32,
    expected_start_marker: &str,
) -> Result<(), String> {
    let actual_start_marker = process_start_marker(process_id)?;
    if !crate::constant_time_eq(
        actual_start_marker.as_bytes(),
        expected_start_marker.as_bytes(),
    ) {
        return Err("native_resident_process_identity_mismatch".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn process_executable_path(process_id: u32) -> Result<PathBuf, String> {
    let path = libproc::proc_pid::pidpath(process_id as i32)
        .map_err(|_| "native_resident_process_identity_unavailable".to_owned())?;
    fs::canonicalize(path).map_err(|_| "native_resident_process_identity_unavailable".to_owned())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn process_executable_path(process_id: u32) -> Result<PathBuf, String> {
    fs::canonicalize(format!("/proc/{process_id}/exe"))
        .map_err(|_| "native_resident_process_identity_unavailable".to_owned())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android")))]
fn process_executable_path(process_id: u32) -> Result<PathBuf, String> {
    let pid = Pid::from_u32(process_id);
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
    );
    let executable = system
        .process(pid)
        .and_then(|process| process.exe())
        .ok_or_else(|| "native_resident_process_identity_unavailable".to_owned())?;
    fs::canonicalize(executable)
        .map_err(|_| "native_resident_process_identity_unavailable".to_owned())
}

fn executable_digest(executable: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(executable)
        .map_err(|_| "native_resident_process_identity_unavailable".to_owned())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || (metadata.len() > MAX_RUNTIME_BYTES && !cfg!(test))
    {
        return Err("native_resident_process_identity_unavailable".to_owned());
    }
    let mut file = File::open(executable)
        .map_err(|_| "native_resident_process_identity_unavailable".to_owned())?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| "native_resident_process_identity_unavailable".to_owned())?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(crate::resident_state_encoding::hex_bytes(
        &hasher.finalize(),
    ))
}

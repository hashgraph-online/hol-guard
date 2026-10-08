#![forbid(unsafe_code)]

use std::fs;
use sysinfo::{Pid, ProcessRefreshKind, ProcessStatus, ProcessesToUpdate, System, UpdateKind};

/// Return an identity marker that changes whenever a PID is recycled.
///
/// The executable-path check below establishes that the process belongs to
/// this runtime package.  The start marker supplies the lifetime component;
/// checking the PID alone would let a later process inherit a dead stream's
/// supervisor contract.
pub(crate) fn process_start_marker(process_id: u32) -> Result<String, String> {
    if process_id == 0 {
        return Err("native_resident_process_identity_unavailable".to_owned());
    }
    #[cfg(windows)]
    {
        return guard_runtime_windows_process::process_start_marker(process_id)
            .map_err(|_| "native_resident_process_identity_unavailable".to_owned());
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        linux_process_start_marker(process_id)
            .ok_or_else(|| "native_resident_process_identity_unavailable".to_owned())
    }
    #[cfg(target_os = "macos")]
    {
        darwin_process_start_marker(process_id)
            .ok_or_else(|| "native_resident_process_identity_unavailable".to_owned())
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        windows
    )))]
    {
        // Do not fall back to sysinfo's seconds-resolution timestamp. A
        // recycled PID could otherwise pass the parent-liveness check during
        // the same second as the original process.
        Err("native_resident_process_identity_unavailable".to_owned())
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn linux_process_start_marker(process_id: u32) -> Option<String> {
    // `/proc/<pid>/stat` places the process name in parentheses and permits
    // parentheses in that name, so split from the final `)` before counting
    // fields. Field 22 (starttime) is field 20 in the suffix after field 2.
    let contents = fs::read_to_string(format!("/proc/{process_id}/stat")).ok()?;
    let (_, suffix) = contents.rsplit_once(')')?;
    let start_ticks = suffix.split_whitespace().nth(19)?.parse::<u64>().ok()?;
    Some(format!("linux:{start_ticks}"))
}

#[cfg(target_os = "macos")]
fn darwin_process_start_marker(process_id: u32) -> Option<String> {
    let process_id = i32::try_from(process_id).ok()?;
    let info = libproc::proc_pid::pidinfo::<libproc::bsd_info::BSDInfo>(process_id, 0).ok()?;
    Some(format!(
        "darwin:{}:{}",
        info.pbi_start_tvsec, info.pbi_start_tvusec
    ))
}

pub(crate) fn package_process_start_marker(process_id: u32) -> Result<String, String> {
    validate_package_process_identity(process_id)?;
    process_start_marker(process_id)
}

pub(crate) fn validate_package_process_identity_with_marker(
    process_id: u32,
    expected_start_marker: &str,
) -> Result<(), String> {
    validate_package_process_identity(process_id)?;
    let actual_start_marker = process_start_marker(process_id)?;
    if !crate::constant_time_eq(
        actual_start_marker.as_bytes(),
        expected_start_marker.as_bytes(),
    ) {
        return Err("native_resident_process_identity_mismatch".to_owned());
    }
    Ok(())
}

pub(crate) fn validate_package_process_identity(process_id: u32) -> Result<(), String> {
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
    if process_is_terminal(process.status()) {
        return Err("native_resident_process_identity_unavailable".to_owned());
    }
    let executable = process
        .exe()
        .ok_or_else(|| "native_resident_process_identity_unavailable".to_owned())?;
    let expected_path = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|_| "native_resident_runtime_path_failed".to_owned())?;
    let process_path = fs::canonicalize(executable)
        .map_err(|_| "native_resident_process_identity_unavailable".to_owned())?;
    if process_path != expected_path {
        return Err("native_resident_process_identity_mismatch".to_owned());
    }
    Ok(())
}

pub(crate) fn process_is_terminal(status: ProcessStatus) -> bool {
    matches!(status, ProcessStatus::Zombie)
}

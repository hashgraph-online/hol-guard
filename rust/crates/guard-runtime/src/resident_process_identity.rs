#![forbid(unsafe_code)]

use std::fs;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

#[cfg(windows)]
pub(crate) fn process_start_marker(process_id: u32) -> Result<String, String> {
    guard_runtime_windows_process::process_start_marker(process_id)
        .map_err(|_| "native_resident_process_identity_unavailable".to_owned())
}

#[cfg(not(windows))]
pub(crate) fn process_start_marker(process_id: u32) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    if let Some(marker) = linux_process_start_marker(process_id) {
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
    let expected_path = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|_| "native_resident_runtime_path_failed".to_owned())?;
    let process_path = fs::canonicalize(executable)
        .map_err(|_| "native_resident_process_identity_unavailable".to_owned())?;
    if process_path != expected_path {
        return Err("native_resident_process_identity_mismatch".to_owned());
    }
    let actual_start_marker = process_start_marker(process_id)?;
    if !crate::constant_time_eq(
        actual_start_marker.as_bytes(),
        expected_start_marker.as_bytes(),
    ) {
        return Err("native_resident_process_identity_mismatch".to_owned());
    }
    Ok(())
}

//! `supervisor-verdict`'s `windows-install` and `windows-remove` ops register
//! and delete the SYSTEM health task the way `mdm/supervisor.py` did before
//! them. The installer writes the task definition to a new file under the
//! machine state root, hands it to the pinned `schtasks` and deletes it
//! whatever `schtasks` answered. The caller has already checked that it runs
//! on Windows as an administrator.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use super::nt_path::nt_normpath;
use super::probe::{nt_join, windows_context, Runner};
use super::{
    verdict, Request, ABSENT_HRESULTS, HEALTH_ARGUMENTS, RUNNING, START_BOUNDARY, TASK_NAMESPACE,
    WINDOWS_TASK_NAME,
};

const SECURITY_DESCRIPTOR: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";
const TEMPORARY_ATTEMPTS: u32 = 100;
const SETTINGS: [(&str, &str); 7] = [
    ("MultipleInstancesPolicy", "IgnoreNew"),
    ("DisallowStartIfOnBatteries", "false"),
    ("StopIfGoingOnBatteries", "false"),
    ("StartWhenAvailable", "true"),
    ("Enabled", "true"),
    ("Hidden", "true"),
    ("ExecutionTimeLimit", "PT5M"),
];

/// Whether the request carries only the Windows directory, the executable
/// and, for an install, the state root.
fn carries_only_task_fields(request: &Request) -> bool {
    request.plist.is_null()
        && request.plist_path.is_none()
        && request.plist_file.is_none()
        && request.stdout_log.is_none()
        && request.stderr_log.is_none()
        && request.disabled.is_none()
        && request.loaded.is_none()
        && request.task.is_none()
}

fn failure(error: &str) -> Value {
    json!({"ok": false, "error": error})
}

pub(super) fn windows_install(request: &Request, runner: &mut impl Runner) -> Option<Value> {
    if !carries_only_task_fields(request) {
        return None;
    }
    let windows_directory = request.windows_directory.as_deref()?;
    let state_root = Path::new(request.state_root.as_deref()?);
    let executable = Path::new(&request.executable);
    let runtime_present = std::fs::symlink_metadata(executable)
        .is_ok_and(|metadata| metadata.file_type().is_file())
        && std::fs::metadata(state_root).is_ok_and(|metadata| metadata.is_dir());
    if !runtime_present {
        return Some(failure("supervisor_runtime_absent"));
    }
    let Some((system_directory, environment)) = windows_context(windows_directory) else {
        return Some(failure("windows_system_drive_unavailable"));
    };
    let Ok((temporary, file)) = create_temporary(state_root) else {
        return Some(failure("supervisor_registration_write_failed"));
    };
    let written = write_synced(file, &task_xml(&request.executable));
    let registered = written.is_ok() && {
        let temporary_name = temporary.to_string_lossy();
        let environment: Vec<(&str, &str)> = environment
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        let arguments = [
            "/Create",
            "/TN",
            WINDOWS_TASK_NAME,
            "/XML",
            temporary_name.as_ref(),
            "/F",
            "/HRESULT",
        ];
        runner
            .run(
                &nt_join(&system_directory, "schtasks.exe"),
                &arguments,
                &system_directory,
                &environment,
            )
            .is_ok_and(|probe| probe.returncode == 0)
    };
    let _ = std::fs::remove_file(&temporary);
    Some(match (written, registered) {
        (Err(_), _) => failure("supervisor_registration_write_failed"),
        (Ok(()), false) => failure("supervisor_registration_failed"),
        (Ok(()), true) => verdict(RUNNING),
    })
}

pub(super) fn windows_remove(request: &Request, runner: &mut impl Runner) -> Option<Value> {
    if !carries_only_task_fields(request) || request.state_root.is_some() {
        return None;
    }
    let windows_directory = request.windows_directory.as_deref()?;
    let Some((system_directory, environment)) = windows_context(windows_directory) else {
        return Some(failure("windows_system_drive_unavailable"));
    };
    let environment: Vec<(&str, &str)> = environment
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    let arguments = ["/Delete", "/TN", WINDOWS_TASK_NAME, "/F", "/HRESULT"];
    let removed = runner
        .run(
            &nt_join(&system_directory, "schtasks.exe"),
            &arguments,
            &system_directory,
            &environment,
        )
        .is_ok_and(|probe| probe.returncode == 0 || ABSENT_HRESULTS.contains(&probe.returncode));
    Some(if removed {
        json!({"ok": true, "state": "absent"})
    } else {
        failure("supervisor_removal_failed")
    })
}

/// A new `health-task-*.xml` under `directory` that no other process opened
/// first, readable only by its owner where the platform has modes.
fn create_temporary(directory: &Path) -> io::Result<(PathBuf, File)> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    for attempt in 0..TEMPORARY_ATTEMPTS {
        let candidate = directory.join(format!(
            "health-task-{}-{nanos:x}-{attempt}.xml",
            process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::ErrorKind::AlreadyExists.into())
}

fn write_synced(mut file: File, bytes: &[u8]) -> io::Result<()> {
    file.write_all(bytes)?;
    file.sync_all()
}

/// The task definition as `ElementTree.tostring(..., encoding="utf-16",
/// xml_declaration=True)` wrote it: a little-endian byte order mark, then
/// UTF-16.
pub(super) fn task_xml(executable: &str) -> Vec<u8> {
    let settings: String = SETTINGS
        .iter()
        .map(|(name, value)| format!("<{name}>{value}</{name}>"))
        .collect();
    let text = format!(
        "<?xml version='1.0' encoding='utf-16'?>\n\
         <Task xmlns=\"{TASK_NAMESPACE}\" version=\"1.4\">\
         <RegistrationInfo><URI>{uri}</URI>\
         <SecurityDescriptor>{SECURITY_DESCRIPTOR}</SecurityDescriptor></RegistrationInfo>\
         <Triggers><TimeTrigger><Enabled>true</Enabled>\
         <StartBoundary>{START_BOUNDARY}</StartBoundary>\
         <Repetition><Interval>PT5M</Interval><StopAtDurationEnd>false</StopAtDurationEnd>\
         </Repetition></TimeTrigger></Triggers>\
         <Principals><Principal id=\"System\"><UserId>S-1-5-18</UserId>\
         <LogonType>ServiceAccount</LogonType><RunLevel>HighestAvailable</RunLevel>\
         </Principal></Principals>\
         <Settings>{settings}</Settings>\
         <Actions Context=\"System\"><Exec><Command>{command}</Command>\
         <Arguments>{arguments}</Arguments></Exec></Actions></Task>",
        uri = escape_text(WINDOWS_TASK_NAME),
        command = escape_text(&nt_normpath(executable)),
        arguments = HEALTH_ARGUMENTS.join(" "),
    );
    let mut bytes = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

/// Character data escaped the way `ElementTree` escapes element text.
fn escape_text(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
#[path = "supervisor_install_tests.rs"]
mod tests;

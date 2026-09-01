#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::io::Write;
use std::process::Command;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Stdio;

use super::{MAX_SECRET_TEXT_BYTES, SERVICE_NAME};

#[cfg(target_os = "macos")]
pub(super) fn read_platform_secret(account: &str) -> Result<Option<String>, String> {
    let output = Command::new("/usr/bin/security")
        .args([
            "find-generic-password",
            "-a",
            account,
            "-s",
            SERVICE_NAME,
            "-w",
        ])
        .output()
        .map_err(|_| "native_approval_secure_state_unavailable".to_owned())?;
    if !output.status.success() {
        return Ok(None);
    }
    let value = String::from_utf8(output.stdout)
        .map_err(|_| "native_approval_secure_state_invalid".to_owned())?;
    if value.len() > MAX_SECRET_TEXT_BYTES {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    Ok(Some(value.trim().to_owned()))
}

#[cfg(target_os = "macos")]
pub(super) fn write_platform_secret(account: &str, value: &str) -> Result<(), String> {
    if value.len() > MAX_SECRET_TEXT_BYTES {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    let executable = std::env::current_exe()
        .ok()
        .and_then(|path| std::fs::canonicalize(path).ok())
        .ok_or_else(|| "native_approval_secure_state_unavailable".to_owned())?;
    let mut child = Command::new("/usr/bin/security")
        .args([
            "add-generic-password",
            "-U",
            "-a",
            account,
            "-s",
            SERVICE_NAME,
            "-T",
        ])
        .arg(executable)
        .arg("-w")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "native_approval_secure_state_unavailable".to_owned())?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "native_approval_secure_state_unavailable".to_owned())?;
    stdin
        .write_all(value.as_bytes())
        .and_then(|()| stdin.write_all(b"\n"))
        .map_err(|_| "native_approval_secure_state_unavailable".to_owned())?;
    drop(stdin);
    let status = child
        .wait()
        .map_err(|_| "native_approval_secure_state_unavailable".to_owned())?;
    if status.success() {
        Ok(())
    } else {
        Err("native_approval_secure_state_unavailable".to_owned())
    }
}

#[cfg(target_os = "linux")]
pub(super) fn read_platform_secret(account: &str) -> Result<Option<String>, String> {
    let output = Command::new("/usr/bin/secret-tool")
        .args(["lookup", "service", SERVICE_NAME, "account", account])
        .output()
        .map_err(|_| "native_approval_secure_state_unavailable".to_owned())?;
    if !output.status.success() {
        return Ok(None);
    }
    let value = String::from_utf8(output.stdout)
        .map_err(|_| "native_approval_secure_state_invalid".to_owned())?;
    if value.len() > MAX_SECRET_TEXT_BYTES {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    Ok(Some(value.trim().to_owned()))
}

#[cfg(target_os = "linux")]
pub(super) fn write_platform_secret(account: &str, value: &str) -> Result<(), String> {
    if value.len() > MAX_SECRET_TEXT_BYTES {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    let mut child = Command::new("/usr/bin/secret-tool")
        .args([
            "store",
            "--label",
            "HOL Guard native approval enrollment",
            "service",
            SERVICE_NAME,
            "account",
            account,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "native_approval_secure_state_unavailable".to_owned())?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| "native_approval_secure_state_unavailable".to_owned())?
        .write_all(value.as_bytes())
        .map_err(|_| "native_approval_secure_state_unavailable".to_owned())?;
    let status = child
        .wait()
        .map_err(|_| "native_approval_secure_state_unavailable".to_owned())?;
    if status.success() {
        Ok(())
    } else {
        Err("native_approval_secure_state_unavailable".to_owned())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(super) fn read_platform_secret(_account: &str) -> Result<Option<String>, String> {
    Err("native_approval_secure_state_unavailable".to_owned())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(super) fn write_platform_secret(_account: &str, _value: &str) -> Result<(), String> {
    Err("native_approval_secure_state_unavailable".to_owned())
}

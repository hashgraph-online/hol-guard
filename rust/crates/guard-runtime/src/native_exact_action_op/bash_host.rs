//! Final native-sink observations, not a permission or an admission receipt.
//! The resident still captures code, checks current policy, and claims consent.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use guard_contained_process::{Isolation, PinnedCommand};
use guard_contracts::{
    GuardExecutionEnvironmentV1, NativeBashCaptureV1, MAX_EXECUTION_ENVIRONMENT_NAMES,
    MAX_EXECUTION_ENVIRONMENT_NAME_BYTES, MAX_EXECUTION_ENVIRONMENT_PATH_BYTES,
    NATIVE_BASH_SELECTED_ENVIRONMENT_NAMES,
};

/// Called in the native sink process started by the actual host tool, never
/// in the long-lived resident as a substitute for the host's environment.
pub(crate) fn observe_current(
    intended: &NativeBashCaptureV1,
    deadline: Instant,
    cancel: &AtomicBool,
) -> io::Result<NativeBashCaptureV1> {
    let cwd = std::env::current_dir()?.canonicalize()?;
    let mut observed = restamp(intended, &cwd, std::env::vars_os())?;
    observed.file_creation_mask = Some(creation_mask(&cwd, deadline, cancel)?);
    Ok(observed)
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "bash_host_observation_unavailable",
    )
}

fn restamp(
    intended: &NativeBashCaptureV1,
    cwd: &Path,
    environment: impl IntoIterator<Item = (OsString, OsString)>,
) -> io::Result<NativeBashCaptureV1> {
    let mut names = Vec::new();
    let mut selected = BTreeMap::new();
    let mut context = BTreeMap::new();
    for (name, value) in environment {
        let name = name.into_string().map_err(|_| invalid())?;
        if name.is_empty()
            || name.len() > MAX_EXECUTION_ENVIRONMENT_NAME_BYTES
            || name.chars().any(char::is_control)
            || names.len() >= MAX_EXECUTION_ENVIRONMENT_NAMES
        {
            return Err(invalid());
        }
        if names.contains(&name) {
            return Err(invalid());
        }
        names.push(name.clone());
        if NATIVE_BASH_SELECTED_ENVIRONMENT_NAMES.contains(&name.as_str())
            || matches!(name.as_str(), "HOME" | "PATH")
        {
            let value = value.into_string().map_err(|_| invalid())?;
            if value.len() > MAX_EXECUTION_ENVIRONMENT_PATH_BYTES || value.contains('\0') {
                return Err(invalid());
            }
            if NATIVE_BASH_SELECTED_ENVIRONMENT_NAMES.contains(&name.as_str()) {
                selected.insert(name.clone(), value.clone());
            }
            context.insert(name, value);
        }
    }
    names.sort();
    let home = context.get("HOME").ok_or_else(invalid)?;
    if !Path::new(home).is_absolute() || !Path::new(home).is_dir() {
        return Err(invalid());
    }
    let mut observed = intended.clone();
    observed.cwd = cwd.to_str().ok_or_else(invalid)?.into();
    observed.home_dir = home.clone();
    observed.environment = selected;
    observed.file_creation_mask = None; // A previous hook's value cannot survive restamping.
    let mut material = b"hol.guard.bash.final-environment.v1\0".to_vec();
    material.extend(serde_json::to_vec(&(&names, &context)).map_err(|_| invalid())?);
    observed.execution_environment = GuardExecutionEnvironmentV1 {
        path: context.get("PATH").cloned().unwrap_or_default(),
        home: Some(home.clone()),
        environment_names: names,
        environment_digest: guard_policy_snapshot::digest_bytes(&material),
        ..GuardExecutionEnvironmentV1::unavailable()
    };
    if !observed.execution_environment.has_valid_shape() {
        return Err(invalid());
    }
    Ok(observed)
}

/// A short-lived, readonly system shell inherits the sink's real mask. Reading
/// it there avoids changing the mask of either the sink or resident process.
fn creation_mask(cwd: &Path, deadline: Instant, cancel: &AtomicBool) -> io::Result<u32> {
    let command = PinnedCommand::new(
        Path::new("/bin/sh"),
        &[OsStr::new("-c"), OsStr::new("umask")],
        cwd,
        &[],
    )?;
    if !command.has_readonly_system_image()? {
        return Err(invalid());
    }
    let result = command.capture(&[], 64, deadline, cancel, Isolation::default())?;
    if result.exit_code != Some(0)
        || !result.stderr.is_empty()
        || result.output_limited
        || result.timed_out
        || result.cancelled
    {
        return Err(invalid());
    }
    parse_mask(&result.stdout)
}

fn parse_mask(bytes: &[u8]) -> io::Result<u32> {
    let digits = bytes.strip_suffix(b"\n").ok_or_else(invalid)?;
    if !(3..=4).contains(&digits.len()) || !digits.iter().all(|byte| (b'0'..=b'7').contains(byte)) {
        return Err(invalid());
    }
    let text = std::str::from_utf8(digits).map_err(|_| invalid())?;
    let mask = u32::from_str_radix(text, 8).map_err(|_| invalid())?;
    if mask > 0o777 {
        return Err(invalid());
    }
    Ok(mask)
}

#[cfg(test)]
#[path = "bash_host_tests.rs"]
mod tests;

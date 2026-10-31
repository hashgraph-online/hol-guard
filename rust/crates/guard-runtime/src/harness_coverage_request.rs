//! The coverage request a managed user leaves for the administrator: the
//! harnesses activation installed, written by the user into their own Guard
//! home and read back only when it is a private regular file of the home's
//! owner that held still while read.

use std::fs::{self, Metadata};
use std::io::{self, Read};
use std::path::Path;

use guard_command::inventory_fingerprints::python_compact_json;
use serde_json::{json, Value};

use super::artifacts::{open_without_following, stamp};
use super::{permission_error, value_error, CoverageError, ErrorClass};

const SCHEMA_VERSION: &str = "hol-guard-harness-coverage-request.v1";
const REQUEST_NAME: &str = "mdm-harness-coverage-request.json";
const MAX_REQUEST_BYTES: u64 = 256 * 1024;
const REQUEST_ABSENT: &str = "harness_coverage_request_absent";
const REQUEST_ACL_INVALID: &str = "harness_coverage_request_acl_invalid";
const REQUEST_INVALID: &str = "harness_coverage_request_invalid";
const REQUEST_CHANGED: &str = "harness_coverage_request_changed";
const REQUEST_CAPACITY_EXCEEDED: &str = "harness_coverage_request_capacity_exceeded";
const REQUEST_IO_FAILED: &str = "harness_coverage_request_io_failed";

fn io_failed(_error: io::Error) -> CoverageError {
    CoverageError {
        class: ErrorClass::Os,
        reason_code: REQUEST_IO_FAILED,
    }
}

fn request_path(home: &Path) -> std::path::PathBuf {
    home.join(".hol-guard").join(REQUEST_NAME)
}

/// Replace the user's request with the installs activation recorded.
pub(crate) fn write_request(home: &Path, installs: &[Value]) -> Result<(), CoverageError> {
    let request = json!({"installs": installs, "schemaVersion": SCHEMA_VERSION});
    let mut payload = python_compact_json(&request).into_bytes();
    payload.push(b'\n');
    if payload.len() as u64 > MAX_REQUEST_BYTES {
        return Err(value_error(REQUEST_CAPACITY_EXCEEDED));
    }
    crate::managed_policy_file_trust::replace_restricted_file(&request_path(home), &payload)
        .map_err(io_failed)
}

/// The installs the user's request lists. The request is refused unless it
/// and the Guard home holding it belong to the home's owner, no one else may
/// write either, and the file held still while it was read.
pub(super) fn read_request(home: &Path) -> Result<Vec<Value>, CoverageError> {
    let target = request_path(home);
    let home_metadata = fs::metadata(home).map_err(io_failed)?;
    let lstat = |path: &Path| match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(value_error(REQUEST_ABSENT)),
        Err(error) => Err(io_failed(error)),
    };
    let guard_metadata = lstat(&home.join(".hol-guard"))?;
    let linked = lstat(&target)?;
    if !request_acl_is_private(&home_metadata, &guard_metadata, &linked) {
        return Err(permission_error(REQUEST_ACL_INVALID));
    }
    let mut file = open_without_following(&target).map_err(io_failed)?;
    let opened = file.metadata().map_err(io_failed)?;
    if !opened.is_file() || opened.len() > MAX_REQUEST_BYTES || !same_file(&opened, &linked) {
        return Err(value_error(REQUEST_INVALID));
    }
    let mut payload = Vec::new();
    file.by_ref()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut payload)
        .map_err(io_failed)?;
    drop(file);
    let settled = fs::symlink_metadata(&target).map_err(io_failed)?;
    if !settled.is_file() || stamp(&linked) != stamp(&opened) || stamp(&opened) != stamp(&settled) {
        return Err(value_error(REQUEST_CHANGED));
    }
    if payload.len() as u64 > MAX_REQUEST_BYTES {
        return Err(value_error(REQUEST_CAPACITY_EXCEEDED));
    }
    parse_request(&payload).ok_or(value_error(REQUEST_INVALID))
}

/// The device and inode, which name the file itself.
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    stamp(left).1[..2] == stamp(right).1[..2]
}

fn parse_request(payload: &[u8]) -> Option<Vec<Value>> {
    let Ok(Value::Object(mut request)) = serde_json::from_slice::<Value>(payload) else {
        return None;
    };
    if request.len() != 2
        || request.get("schemaVersion").and_then(Value::as_str) != Some(SCHEMA_VERSION)
    {
        return None;
    }
    let Some(Value::Array(installs)) = request.remove("installs") else {
        return None;
    };
    installs.iter().all(Value::is_object).then_some(installs)
}

#[cfg(unix)]
fn request_acl_is_private(home: &Metadata, guard_home: &Metadata, request: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    guard_home.is_dir()
        && guard_home.uid() == home.uid()
        && guard_home.mode() & 0o022 == 0
        && request.is_file()
        && request.uid() == home.uid()
        && request.mode() & 0o077 == 0
        && request.len() <= MAX_REQUEST_BYTES
}

/// Windows reports no owner or permission bits these checks could read, so a
/// request there is never trusted.
#[cfg(not(unix))]
fn request_acl_is_private(_home: &Metadata, _guard_home: &Metadata, _request: &Metadata) -> bool {
    false
}

#[cfg(test)]
#[path = "harness_coverage_request_tests.rs"]
mod tests;

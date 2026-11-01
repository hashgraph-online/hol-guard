//! `onefile-open-paths --stdin`: the names of the PyInstaller `_MEI*`
//! extraction directories under a temp root that some process still uses
//! (`guard/onefile_open_paths.py` before it moved here).
//!
//! An unmarked extraction directory records no owner pid, so the only proof
//! that it is dead is that no process has a file in it open or mapped, or
//! uses it as its working directory, executable or root. The scan is one pass
//! over the whole machine and fails closed: Linux reads `/proc` and falls back
//! to `lsof`, macOS runs `lsof`, and any error, timeout or missing tool
//! answers `{"in_use": null}`. Callers read `null` as "unknown" and skip every
//! unmarked reclaim. Other platforms always answer `null`.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Value};

const SCHEMA: &str = "onefile-open-paths.v1";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_IN_USE_NAMES: usize = 4096;
const EXTRACTION_PREFIX: &[u8] = b"_MEI";
/// `lsof` resolved only from fixed operating-system locations.
const TRUSTED_LSOF_PATHS: [&str; 2] = ["/usr/sbin/lsof", "/usr/bin/lsof"];
const LSOF_TIMEOUT: Duration = Duration::from_secs(90);
const LSOF_OUTPUT_LIMIT: u64 = 256 * 1024 * 1024;
const ESRCH: i32 = 3;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    temp_root: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Platform {
    Linux,
    MacOs,
    Other,
}

impl Platform {
    fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Other
        }
    }
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "onefile-open-paths"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "onefile_open_paths_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("onefile_open_paths_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let temp_root = temp_root(&request)?;
    let in_use = scan(
        &temp_root,
        Platform::current(),
        Path::new("/proc"),
        system_lsof,
    );
    serde_json::to_vec(&answer(in_use))
        .map_err(|_| "onefile_open_paths_response_encode_failed".to_owned())
}

fn invalid() -> String {
    "onefile_open_paths_request_invalid".to_owned()
}

fn temp_root(request: &Request) -> Result<PathBuf, String> {
    let temp_root = PathBuf::from(&request.temp_root);
    if request.schema != SCHEMA || !temp_root.is_absolute() {
        return Err(invalid());
    }
    Ok(temp_root)
}

fn answer(in_use: Option<BTreeSet<String>>) -> Value {
    match in_use {
        Some(names) if names.len() <= MAX_IN_USE_NAMES => json!({ "in_use": names }),
        _ => json!({ "in_use": Value::Null }),
    }
}

/// The names in use, or `None` when the scan could not be completed.
fn scan(
    temp_root: &Path,
    platform: Platform,
    proc_root: &Path,
    lsof: impl FnOnce() -> Option<Vec<u8>>,
) -> Option<BTreeSet<String>> {
    let prefixes = root_prefixes(temp_root);
    if platform == Platform::Linux && proc_root.is_dir() {
        if let Some(found) = scan_proc(&prefixes, proc_root) {
            return Some(found);
        }
    }
    match platform {
        Platform::Linux | Platform::MacOs => names_from_lsof(&lsof()?, &prefixes),
        Platform::Other => None,
    }
}

/// The temp root as given and as resolved, without trailing separators.
fn root_prefixes(temp_root: &Path) -> BTreeSet<Vec<u8>> {
    let mut prefixes = BTreeSet::new();
    prefixes.insert(trimmed(path_bytes(temp_root)));
    if let Ok(resolved) = fs::canonicalize(temp_root) {
        prefixes.insert(trimmed(path_bytes(&resolved)));
    }
    prefixes
}

fn path_bytes(path: &Path) -> &[u8] {
    path.as_os_str().as_encoded_bytes()
}

fn trimmed(bytes: &[u8]) -> Vec<u8> {
    let end = bytes
        .iter()
        .rposition(|byte| *byte != b'/' && *byte != b'\\')
        .map_or(0, |index| index + 1);
    bytes[..end].to_vec()
}

fn collect_extraction_name(
    path: &[u8],
    prefixes: &BTreeSet<Vec<u8>>,
    found: &mut BTreeSet<String>,
) {
    for prefix in prefixes {
        let Some(rest) = path
            .strip_prefix(prefix.as_slice())
            .and_then(|rest| rest.strip_prefix(b"/"))
        else {
            continue;
        };
        let name = rest.split(|byte| *byte == b'/').next().unwrap_or_default();
        // Deliberately looser than the reclaim name pattern: over-reporting a
        // directory as in use only delays its reclaim.
        if name.starts_with(EXTRACTION_PREFIX) {
            found.insert(String::from_utf8_lossy(name).into_owned());
        }
        return;
    }
}

fn scan_proc(prefixes: &BTreeSet<Vec<u8>>, proc_root: &Path) -> Option<BTreeSet<String>> {
    let entries = fs::read_dir(proc_root)
        .ok()?
        .collect::<io::Result<Vec<_>>>()
        .ok()?
        .into_iter()
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.as_encoded_bytes();
            !name.is_empty() && name.iter().all(u8::is_ascii_digit)
        })
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    if entries.is_empty() {
        return None;
    }
    let own_uid = current_uid();
    let mut found = BTreeSet::new();
    for entry in entries {
        match scan_proc_entry(&entry, prefixes, &mut found) {
            Ok(()) => {}
            // Another user's process cannot own a directory this user may
            // delete; an unreadable process of this user is unprovable.
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                let owner = fs::metadata(&entry)
                    .ok()
                    .and_then(|metadata| metadata_uid(&metadata));
                if owner.is_some() && owner == own_uid {
                    return None;
                }
            }
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(ESRCH) => {}
            Err(_) => return None,
        }
    }
    Some(found)
}

fn scan_proc_entry(
    entry: &Path,
    prefixes: &BTreeSet<Vec<u8>>,
    found: &mut BTreeSet<String>,
) -> io::Result<()> {
    let maps = fs::read(entry.join("maps"))?;
    for line in maps.split(|byte| *byte == b'\n') {
        if let Some(index) = line.iter().position(|byte| *byte == b'/') {
            let path = &line[index..];
            let path = path.strip_suffix(b" (deleted)").unwrap_or(path);
            collect_extraction_name(path, prefixes, found);
        }
    }
    for link in ["cwd", "exe", "root"] {
        collect_link(&entry.join(link), prefixes, found)?;
    }
    for descriptor in fs::read_dir(entry.join("fd"))? {
        collect_link(&descriptor?.path(), prefixes, found)?;
    }
    Ok(())
}

fn collect_link(
    link: &Path,
    prefixes: &BTreeSet<Vec<u8>>,
    found: &mut BTreeSet<String>,
) -> io::Result<()> {
    match fs::read_link(link) {
        Ok(target) => {
            collect_extraction_name(path_bytes(&target), prefixes, found);
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn current_uid() -> Option<u32> {
    Some(nix::unistd::getuid().as_raw())
}

#[cfg(not(unix))]
fn current_uid() -> Option<u32> {
    None
}

#[cfg(unix)]
fn metadata_uid(metadata: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;

    Some(metadata.uid())
}

#[cfg(not(unix))]
fn metadata_uid(_metadata: &fs::Metadata) -> Option<u32> {
    None
}

/// The extraction names in `lsof -F n` output. Empty output means not even
/// this process was seen, so it proves nothing.
fn names_from_lsof(stdout: &[u8], prefixes: &BTreeSet<Vec<u8>>) -> Option<BTreeSet<String>> {
    if stdout.is_empty() {
        return None;
    }
    let mut found = BTreeSet::new();
    for line in stdout.split(|byte| *byte == b'\n') {
        if let Some(path) = line.strip_prefix(b"n") {
            collect_extraction_name(path, prefixes, &mut found);
        }
    }
    Some(found)
}

fn lsof_path() -> Option<PathBuf> {
    TRUSTED_LSOF_PATHS
        .iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .map(Path::to_path_buf)
}

/// Stdout of one bounded `lsof` run over every process. Exit 1 means lsof
/// skipped something it could not inspect, which may be the very process
/// holding an extraction directory open, so only a clean exit counts.
fn system_lsof() -> Option<Vec<u8>> {
    let mut command = Command::new(lsof_path()?);
    command
        .args(["-n", "-P", "-w", "-F", "n"])
        .env_clear()
        .env("LC_ALL", "C");
    bounded_stdout(command, LSOF_OUTPUT_LIMIT, LSOF_TIMEOUT)
}

/// Stdout of `command` when it exits cleanly within `timeout` and writes at
/// most `limit` bytes. Output past the limit kills the child at once rather
/// than leaving it blocked on a full pipe until the timeout.
fn bounded_stdout(mut command: Command, limit: u64, timeout: Duration) -> Option<Vec<u8>> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    };
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.take(limit + 1).read_to_end(&mut bytes);
        let _ = sender.send(bytes);
    });
    let deadline = Instant::now() + timeout;
    let mut output = None;
    let status = loop {
        if output.is_none() {
            if let Ok(bytes) = receiver.try_recv() {
                if bytes.len() as u64 > limit {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                output = Some(bytes);
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    let bytes = match output {
        Some(bytes) => bytes,
        None => receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .ok()?,
    };
    if !status.success() || bytes.len() as u64 > limit {
        return None;
    }
    Some(bytes)
}

#[cfg(test)]
#[path = "onefile_open_paths_tests.rs"]
mod tests;

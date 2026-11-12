//! `windows-trusted-directories --stdin`: the Windows directories Guard
//! trusts without reading the environment (`guard/windows_paths.py` before
//! they moved here). Each answer is a real, final path that is not a reparse
//! point, or `null`.
//!
//! - `system_directories` answers the Windows and System32 directories the
//!   kernel reports, only when System32 sits directly inside Windows both as
//!   reported and as resolved.
//! - `system_executable` answers one regular file below System32 that
//!   resolves inside it.
//! - `user_profile` and `roaming_appdata` answer the known folders, which
//!   Windows reads from the registry rather than from `USERPROFILE` or
//!   `APPDATA`.
//! - `local_temp` answers `AppData\Local\Temp` in that profile: `TEMP` and
//!   the Local AppData known folder both follow the requesting environment.
//!
//! Off Windows every answer is `null`.

use std::io::Read;

use serde::Deserialize;
use serde_json::{json, Value};

const SCHEMA: &str = "windows-trusted-directories.v1";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_RELATIVE_PARTS: usize = 16;
const MAX_PART_CHARS: usize = 260;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    #[serde(default)]
    relative_parts: Vec<String>,
}

/// The directory facts the answers are built from.
trait Directories {
    fn kernel_windows(&self) -> Option<String>;
    fn kernel_system(&self) -> Option<String>;
    fn user_profile(&self) -> Option<String>;
    fn roaming_appdata(&self) -> Option<String>;
    fn real_directory(&self, path: &str) -> Option<String>;
    fn real_regular_file(&self, path: &str) -> Option<String>;
}

struct SystemDirectories;

impl Directories for SystemDirectories {
    fn kernel_windows(&self) -> Option<String> {
        guard_runtime_windows_process::kernel_windows_directory()
    }

    fn kernel_system(&self) -> Option<String> {
        guard_runtime_windows_process::kernel_system_directory()
    }

    fn user_profile(&self) -> Option<String> {
        guard_runtime_windows_process::user_profile_directory()?
            .into_os_string()
            .into_string()
            .ok()
    }

    fn roaming_appdata(&self) -> Option<String> {
        guard_runtime_windows_process::roaming_appdata_directory()?
            .into_os_string()
            .into_string()
            .ok()
    }

    fn real_directory(&self, path: &str) -> Option<String> {
        guard_runtime_windows_process::real_directory(path)
    }

    fn real_regular_file(&self, path: &str) -> Option<String> {
        guard_runtime_windows_process::real_regular_file(path)
    }
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "windows-trusted-directories"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "windows_trusted_directories_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("windows_trusted_directories_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes)
        .map_err(|_| "windows_trusted_directories_request_invalid".to_owned())?;
    let answer = answer(&request, &SystemDirectories)?;
    serde_json::to_vec(&answer)
        .map_err(|_| "windows_trusted_directories_response_encode_failed".to_owned())
}

fn answer<D: Directories>(request: &Request, directories: &D) -> Result<Value, String> {
    let invalid = || "windows_trusted_directories_request_invalid".to_owned();
    if request.schema != SCHEMA
        || request.relative_parts.len() > MAX_RELATIVE_PARTS
        || (request.op != "system_executable" && !request.relative_parts.is_empty())
    {
        return Err(invalid());
    }
    let paths = match request.op.as_str() {
        "system_directories" => {
            system_directories(directories).map(|(windows, system)| vec![windows, system])
        }
        "system_executable" => {
            system_executable(directories, &request.relative_parts).map(|path| vec![path])
        }
        "user_profile" => user_profile(directories).map(|path| vec![path]),
        "roaming_appdata" => directories
            .roaming_appdata()
            .and_then(|path| directories.real_directory(&path))
            .map(|path| vec![path]),
        "local_temp" => user_profile(directories)
            .and_then(|profile| {
                directories.real_directory(&format!(r"{profile}\AppData\Local\Temp"))
            })
            .map(|path| vec![path]),
        _ => return Err(invalid()),
    };
    Ok(json!({ "paths": paths }))
}

fn user_profile<D: Directories>(directories: &D) -> Option<String> {
    directories.real_directory(&directories.user_profile()?)
}

fn system_directories<D: Directories>(directories: &D) -> Option<(String, String)> {
    let windows = directories.kernel_windows()?;
    let system = directories.kernel_system()?;
    if !is_absolute(&windows)
        || !is_absolute(&system)
        || !base_name(&system).eq_ignore_ascii_case("system32")
        || fold(parent(&system)) != fold(&windows)
    {
        return None;
    }
    let windows = directories.real_directory(&windows)?;
    let system = directories.real_directory(&system)?;
    (fold(parent(&system)) == fold(&windows)).then_some((windows, system))
}

fn system_executable<D: Directories>(directories: &D, parts: &[String]) -> Option<String> {
    if parts.is_empty()
        || parts.iter().any(|part| {
            part.is_empty()
                || part.chars().count() > MAX_PART_CHARS
                || part.contains('\0')
                || is_rooted(part)
        })
    {
        return None;
    }
    let (_windows, system) = system_directories(directories)?;
    let resolved = directories.real_regular_file(&format!(r"{system}\{}", parts.join(r"\")))?;
    let inside = format!(r"{}\", fold(&system));
    fold(&resolved).starts_with(&inside).then_some(resolved)
}

fn is_separator(character: char) -> bool {
    character == '\\' || character == '/'
}

/// `ntpath.isabs`: a drive and a root, or a UNC root.
fn is_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    let drive_root = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && is_separator(char::from(bytes[2]));
    let unc = path.starts_with(r"\\") || path.starts_with("//");
    drive_root || unc
}

/// A part `ntpath.isabs` or a drive would move off the base it joins.
fn is_rooted(part: &str) -> bool {
    part.starts_with(is_separator) || part.contains(':')
}

fn trim_separators(path: &str) -> &str {
    path.trim_end_matches(is_separator)
}

fn base_name(path: &str) -> &str {
    let path = trim_separators(path);
    path.rsplit(is_separator).next().unwrap_or(path)
}

fn parent(path: &str) -> &str {
    let path = trim_separators(path);
    path.rfind(is_separator)
        .map_or("", |index| trim_separators(&path[..index]))
}

/// `ntpath.normcase` without trailing separators.
fn fold(path: &str) -> String {
    trim_separators(path).replace('/', r"\").to_lowercase()
}

#[cfg(test)]
#[path = "windows_trusted_directories_tests.rs"]
mod tests;

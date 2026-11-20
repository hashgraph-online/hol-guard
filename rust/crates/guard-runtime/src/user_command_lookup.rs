//! `user_command_lookup`: where a CLI the user installed outside the process
//! PATH lives.
//!
//! Guard Desktop starts the daemon with only the system directories on PATH,
//! so a plain PATH lookup misses CLIs from Homebrew, npm and nvm, bun or a
//! tool's own installer, and diagnostics then report a working tool as broken.
//! Under that bare PATH this kind searches the install directories a terminal
//! PATH normally has; the tool's own installer directories (`extra`) are
//! searched under any PATH. Every candidate must pass the same ownership and
//! write checks. Only availability checks use the answer: launch and probe
//! commands keep resolving through PATH, so nothing found here is executed.
//!
//! A relative directory would resolve against the resident's working
//! directory rather than the caller's, so it is never searched.

use serde_json::{json, Map, Value};

use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

/// Installer directories one request may name.
const MAX_EXTRA_DIRECTORIES: usize = 64;

fn text<'a>(args: &'a Map<String, Value>, key: &str) -> Result<&'a str, &'static str> {
    args.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)
}

fn optional_text<'a>(
    args: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, &'static str> {
    match args.get(key) {
        Some(Value::String(text)) => Ok(Some(text.as_str())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(ERR_INVALID),
    }
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let command = text(args, "command")?;
    let home = text(args, "home")?;
    let path = optional_text(args, "path")?;
    let extra = args
        .get("extra")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    if extra.len() > MAX_EXTRA_DIRECTORIES {
        return Err(ERR_INVALID);
    }
    let extra = extra
        .iter()
        .map(|entry| entry.as_str().ok_or(ERR_INVALID))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({ "path": lookup::find(command, home, path, &extra) }))
}

#[cfg(unix)]
mod lookup {
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    use nix::unistd::{access, getuid, AccessFlags};

    /// The bare default PATH launchd and GUI launchers hand to apps.
    const SYSTEM_ONLY_PATH_ENTRIES: [&str; 4] = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];
    const FIXED_DIRECTORIES: [&str; 3] = [
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/home/linuxbrew/.linuxbrew/bin",
    ];
    const HOME_DIRECTORIES: [&str; 9] = [
        ".local/bin",
        "bin",
        ".bun/bin",
        ".npm-global/bin",
        ".volta/bin",
        ".asdf/shims",
        ".cargo/bin",
        "Library/pnpm",
        ".local/share/pnpm",
    ];

    /// `_system_only_path`: PATH is non-empty and names only system directories.
    pub(super) fn system_only_path(value: Option<&str>) -> bool {
        let entries: Vec<&str> = value
            .unwrap_or("")
            .split(':')
            .filter(|entry| !entry.is_empty())
            .map(|entry| match entry.trim_end_matches('/') {
                "" => "/",
                trimmed => trimmed,
            })
            .collect();
        !entries.is_empty()
            && entries
                .iter()
                .all(|entry| SYSTEM_ONLY_PATH_ENTRIES.contains(entry))
    }

    /// One part of `_node_version_key`: a number when every character is an
    /// ASCII digit, else below every number. A number is its digits without
    /// leading zeros, ordered by length and then text.
    type VersionPart = Option<(usize, String)>;

    pub(super) fn version_key(name: &str) -> Vec<VersionPart> {
        name.trim_start_matches('v')
            .split('.')
            .map(|part| {
                if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                    return None;
                }
                let digits = match part.trim_start_matches('0') {
                    "" => "0",
                    digits => digits,
                };
                Some((digits.len(), digits.to_owned()))
            })
            .collect()
    }

    /// The installed nvm Node releases, newest first. An unreadable folder
    /// lists none.
    fn node_versions(home: &Path) -> Vec<PathBuf> {
        let Ok(entries) = fs::read_dir(home.join(".nvm/versions/node")) else {
            return Vec::new();
        };
        let Ok(mut versions) = entries
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()
        else {
            return Vec::new();
        };
        // A stable sort on the reversed order keeps equal keys in listing
        // order, as `sorted(..., reverse=True)` does.
        versions.sort_by(|left, right| {
            let key = |path: &PathBuf| {
                version_key(&path.file_name().unwrap_or_default().to_string_lossy())
            };
            key(right).cmp(&key(left))
        });
        versions
    }

    /// `_user_command_directories`: install directories a terminal PATH
    /// normally has and a GUI-launched app does not.
    fn user_directories(command: &str, home: &Path) -> Vec<PathBuf> {
        let mut directories: Vec<PathBuf> = FIXED_DIRECTORIES.iter().map(PathBuf::from).collect();
        directories.extend(HOME_DIRECTORIES.iter().map(|relative| home.join(relative)));
        directories.push(home.join(format!(".{command}")).join("bin"));
        directories.extend(
            node_versions(home)
                .into_iter()
                .map(|version| version.join("bin")),
        );
        directories
    }

    /// `_user_owned_executable`: match what the user's terminal would run,
    /// but only when both the install directory and the directory holding the
    /// resolved target are owned by root or the user and nobody else can
    /// write to them. Package managers such as bun install world-writable
    /// entrypoints, so the file's own mode is not checked.
    pub(super) fn user_owned_executable(candidate: &Path) -> bool {
        let Ok(resolved) = fs::canonicalize(candidate) else {
            return false;
        };
        let (Some(install), Some(holder)) = (candidate.parent(), resolved.parent()) else {
            return false;
        };
        let (Ok(file), Ok(install), Ok(holder)) = (
            fs::metadata(&resolved),
            fs::metadata(install),
            fs::metadata(holder),
        ) else {
            return false;
        };
        let uid = getuid().as_raw();
        let owned = |owner: u32| owner == 0 || owner == uid;
        if !owned(file.uid()) {
            return false;
        }
        if [install, holder]
            .iter()
            .any(|directory| !owned(directory.uid()) || directory.mode() & 0o022 != 0)
        {
            return false;
        }
        file.is_file() && access(&resolved, AccessFlags::X_OK).is_ok()
    }

    /// `_which_from_user_directories`.
    pub(super) fn find(
        command: &str,
        home: &str,
        path: Option<&str>,
        extra: &[&str],
    ) -> Option<String> {
        if command.contains('/') {
            return None;
        }
        let mut directories = if system_only_path(path) {
            user_directories(command, Path::new(home))
        } else {
            Vec::new()
        };
        directories.extend(extra.iter().map(PathBuf::from));
        directories
            .into_iter()
            .filter(|directory| directory.is_absolute())
            .map(|directory| directory.join(command))
            .find(|candidate| user_owned_executable(candidate))
            .and_then(|candidate| candidate.to_str().map(str::to_owned))
    }
}

#[cfg(not(unix))]
mod lookup {
    /// Windows resolves commands through PATH and PATHEXT alone.
    pub(super) fn find(
        _command: &str,
        _home: &str,
        _path: Option<&str>,
        _extra: &[&str],
    ) -> Option<String> {
        None
    }
}

#[cfg(all(test, unix))]
#[path = "user_command_lookup_tests.rs"]
mod tests;

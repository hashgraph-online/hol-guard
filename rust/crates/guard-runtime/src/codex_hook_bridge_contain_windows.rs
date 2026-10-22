//! The Windows halves of the Codex contained rewrite, ported from
//! `contained_zcode_response`: the PowerShell-quoted sink command
//! (`windows_powershell_quote.py`), the bootstrap's forward-slash package
//! root (`_sink_command_prefix`), and the request snapshot in the profile's
//! own temporary directory (`_request_root`).

use std::io::Write;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const BOOTSTRAP_HEAD: &str = "import sys;sys.path.insert(0, ";
const BOOTSTRAP_TAIL: &str =
    ");from codex_plugin_scanner.cli import main;raise SystemExit(main(sys.argv[1:]))";
/// PowerShell ends a single-quoted literal at any of these.
const SINGLE_QUOTES: [char; 5] = ['\'', '\u{2018}', '\u{2019}', '\u{201a}', '\u{201b}'];
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const REQUEST_DIRECTORY_PREFIX: &str = "hol-guard-contained-test-";
const REQUEST_FILE_NAME: &str = "request.json";
const NAME_ATTEMPTS: usize = 16;
const NAME_CHARACTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789_";
const STALE_AFTER: Duration = Duration::from_secs(86_400);
const MAX_SCANNED_ENTRIES: usize = 4096;

/// `powershell_join(argv)`: each argument one single-quoted literal behind
/// the call operator, or `None` for an argument Windows PowerShell 5.1
/// cannot carry through to the native command line unchanged.
pub(super) fn powershell_join(argv: &[String]) -> Option<String> {
    if argv.is_empty() || !argv.iter().all(|argument| quotable(argument)) {
        return None;
    }
    let quoted: Vec<String> = argv
        .iter()
        .map(|argument| {
            let mut literal = String::with_capacity(argument.len() + 2);
            literal.push('\'');
            for character in argument.chars() {
                if SINGLE_QUOTES.contains(&character) {
                    literal.push(character);
                }
                literal.push(character);
            }
            literal.push('\'');
            literal
        })
        .collect();
    Some(format!("& {}", quoted.join(" ")))
}

/// PowerShell 5.1 drops an empty argument, cannot pass a double quote, and
/// leaves a trailing backslash in front of the closing quote it adds around
/// an argument with whitespace.
fn quotable(argument: &str) -> bool {
    if argument.is_empty() || argument.contains('"') {
        return false;
    }
    if argument
        .chars()
        .any(|character| u32::from(character) < 0x20 || u32::from(character) == 0x7f)
    {
        return false;
    }
    !(argument.ends_with('\\') && argument.chars().any(char::is_whitespace))
}

/// `_sink_command_prefix` on Windows: the isolated bootstrap with its
/// package root written with forward slashes, which needs no escaping. A
/// bootstrap that does not hold the plain single-quoted root `repr` writes
/// is left as it is, as `str.replace` leaves it when nothing matches; a
/// frozen Guard has no bootstrap.
pub(super) fn sink_prefix(prefix: &[String]) -> Vec<String> {
    let mut command = prefix.to_vec();
    if let [_, _, _, bootstrap] = command.as_mut_slice() {
        if let Some(rewritten) = forward_slash_bootstrap(bootstrap) {
            *bootstrap = rewritten;
        }
    }
    command
}

fn forward_slash_bootstrap(bootstrap: &str) -> Option<String> {
    let literal = bootstrap
        .strip_prefix(BOOTSTRAP_HEAD)?
        .strip_suffix(BOOTSTRAP_TAIL)?;
    let inner = literal.strip_prefix('\'')?.strip_suffix('\'')?;
    let mut root = String::with_capacity(inner.len());
    let mut characters = inner.chars();
    while let Some(character) = characters.next() {
        match character {
            '\\' if characters.next() == Some('\\') => root.push('/'),
            '\\' | '\'' => return None,
            other => root.push(other),
        }
    }
    Some(format!("{BOOTSTRAP_HEAD}'{root}'{BOOTSTRAP_TAIL}"))
}

/// `Path(value).expanduser().resolve(strict=True)`, when it is a directory
/// named in UTF-8. Only the current user's `~` is expanded; another user's
/// home is declined rather than guessed.
pub(super) fn resolved_workspace(value: &str) -> Option<String> {
    let expanded = match value.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with(['/', '\\']) => {
            let home = crate::claude_hook_bridge::home_directory()?;
            format!("{}{rest}", home.to_str()?)
        }
        Some(_) => return None,
        None if value.is_empty() => ".".to_owned(),
        None => value.to_owned(),
    };
    let resolved = std::fs::canonicalize(expanded).ok()?;
    resolved.is_dir().then_some(())?;
    Some(plain_path(resolved.to_str()?))
}

/// The path without the verbatim prefix `canonicalize` adds, as
/// `Path.resolve` returns it.
fn plain_path(text: &str) -> String {
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    text.strip_prefix(r"\\?\").unwrap_or(text).to_owned()
}

/// `trusted_windows_local_temp()`: `AppData\Local\Temp` under the profile
/// Windows records for this user, never `TEMP`, which the shell that runs
/// the sink may set differently from this hook. The sink looks for the
/// snapshot directly inside it.
fn trusted_local_temp() -> Option<PathBuf> {
    let temp = guard_runtime_windows_process::user_profile_directory()?
        .join("AppData")
        .join("Local")
        .join("Temp");
    let metadata = std::fs::symlink_metadata(&temp).ok()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return None;
    }
    let resolved = std::fs::canonicalize(&temp).ok()?;
    Some(PathBuf::from(plain_path(resolved.to_str()?)))
}

/// Write `serialized` as a fresh request snapshot in a new directory named
/// as `mkdtemp` names one: the request path, or `None` with nothing left
/// behind.
pub(super) fn write_snapshot(serialized: &[u8]) -> Option<PathBuf> {
    let temp = trusted_local_temp()?;
    cleanup_stale_requests(&temp);
    for _ in 0..NAME_ATTEMPTS {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).ok()?;
        let suffix: String = random
            .iter()
            .map(|byte| char::from(NAME_CHARACTERS[usize::from(*byte) % NAME_CHARACTERS.len()]))
            .collect();
        let directory = temp.join(format!("{REQUEST_DIRECTORY_PREFIX}{suffix}"));
        match std::fs::create_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return None,
        }
        let request = directory.join(REQUEST_FILE_NAME);
        if write_request(&request, serialized).is_some() {
            return Some(request);
        }
        let _ = std::fs::remove_file(&request);
        let _ = std::fs::remove_dir(&directory);
        return None;
    }
    None
}

/// `cleanup_stale_zcode_requests` on Windows: a snapshot whose call never
/// ran is reclaimed after a full day. Only a plain directory holding a plain
/// request file is removed; a reparse point at either level is left alone.
fn cleanup_stale_requests(temp: &Path) {
    let Some(cutoff) = SystemTime::now().checked_sub(STALE_AFTER) else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(temp) else {
        return;
    };
    for entry in entries.take(MAX_SCANNED_ENTRIES).flatten() {
        let named = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(REQUEST_DIRECTORY_PREFIX));
        if named {
            let _ = reclaim(&entry.path(), cutoff);
        }
    }
}

fn reclaim(directory: &Path, cutoff: SystemTime) -> Option<()> {
    let parent = std::fs::symlink_metadata(directory).ok()?;
    if !plain(&parent) || !parent.is_dir() || parent.modified().ok()? > cutoff {
        return None;
    }
    let request = directory.join(REQUEST_FILE_NAME);
    let file = std::fs::symlink_metadata(&request).ok()?;
    if !plain(&file) || !file.is_file() || file.modified().ok()? > cutoff {
        return None;
    }
    std::fs::remove_file(&request).ok()?;
    std::fs::remove_dir(directory).ok()
}

fn plain(metadata: &std::fs::Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
}

fn write_request(path: &Path, serialized: &[u8]) -> Option<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .ok()?;
    file.write_all(serialized).ok()?;
    file.sync_all().ok()
}

#[cfg(test)]
#[path = "codex_hook_bridge_contain_windows_tests.rs"]
mod tests;

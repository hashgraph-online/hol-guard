//! `hook-launch-scan --stdin`: whether a harness's Guard-owned hook
//! artifacts still launch an older native runtime copy or another Guard
//! install's Python (`runtime_artifact_reconciliation.py` and
//! `foreign_hook_interpreter.py` before the scan moved here).
//!
//! The resident refuses a hook bridge whose runtime digest differs from its
//! own, and a launcher left by a different Guard install keeps the
//! install-time file proof satisfied while every hook reaches a client the
//! resident no longer serves. Either way the reconciliation pass rewrites the
//! harness. This command only reads; Python still owns the rewrite.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::daemon_lifecycle_text::{py_isspace as py_space, shlex_split};
use crate::guard_store_json::dumps_default;

const COMMAND: &str = "hook-launch-scan";
const SCHEMA: &str = "hook-launch-scan.v1";
const MAX_REQUEST_BYTES: u64 = 256 * 1024;
const MAX_PATHS: usize = 64;
/// Guard writes hook artifacts of a few kilobytes. A manifest path that names
/// a far larger file is not one of them; stop there rather than read to EOF.
const PIN_SCAN_MAX_BYTES: u64 = 16 * 1024 * 1024;
const CLIENT_SCAN_MAX_BYTES: u64 = 2 * 1024 * 1024;
const BINARY_SNIFF_BYTES: usize = 8192;
const LOOKBEHIND_CHARS: usize = 2048;
const LOOKAHEAD_CHARS: usize = 1024;
const PACKAGE: &str = "codex_plugin_scanner";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    paths: Vec<String>,
    /// The digest a frozen build's hook commands should pin; `None` skips the
    /// pin scan, since a source install never repins them.
    runtime_digest: Option<String>,
    /// `None` skips the interpreter scan.
    interpreter: Option<Interpreter>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Interpreter {
    /// The interpreter this Guard bakes into hook artifacts, or `None` when
    /// frozen: a frozen Guard has no Python install of its own, so every
    /// launcher that runs the Guard package through an interpreter belongs to
    /// another install.
    current: Option<String>,
    guard_home: String,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == COMMAND
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "hook_launch_scan_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("hook_launch_scan_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes)
        .map_err(|_| "hook_launch_scan_request_invalid".to_owned())?;
    if request.schema != SCHEMA || request.paths.len() > MAX_PATHS {
        return Err("hook_launch_scan_request_invalid".to_owned());
    }
    serde_json::to_vec(&scan(&request))
        .map_err(|_| "hook_launch_scan_response_unencodable".to_owned())
}

fn scan(request: &Request) -> Value {
    let paths = || request.paths.iter().map(Path::new);
    let stale_runtime = request.runtime_digest.as_deref().is_some_and(|digest| {
        paths().any(|path| names_stale_runtime(path, digest, PIN_SCAN_MAX_BYTES))
    });
    let foreign_interpreter = request.interpreter.as_ref().is_some_and(|interpreter| {
        let home = posix(&interpreter.guard_home);
        let current = interpreter.current.as_deref();
        paths().any(|path| names_foreign_interpreter(path, current, &home))
    });
    json!({"stale_runtime": stale_runtime, "foreign_interpreter": foreign_interpreter})
}

/// At most `limit` bytes of a regular file, or `None` when it cannot be read.
fn read_prefix(path: &Path, limit: u64) -> Option<Vec<u8>> {
    if !fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(limit)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(bytes)
}

/// Whether one artifact still launches a runtime copy other than `digest`.
fn names_stale_runtime(path: &Path, digest: &str, limit: u64) -> bool {
    let Some(bytes) = read_prefix(path, limit) else {
        return false;
    };
    runtime_pins(&String::from_utf8_lossy(&bytes))
        .iter()
        .any(|pin| *pin != digest)
}

/// Every digest a hook command pins: a frozen build launches its runtime from
/// the content-addressed durable copy `native-runtime/<sha256>/hol-guard-runtime[.exe]`,
/// and JSON configs may escape the separator. Requiring the executable name
/// keeps a preserved user field that only names the directory from counting.
fn runtime_pins(text: &str) -> BTreeSet<&str> {
    static PIN: OnceLock<Regex> = OnceLock::new();
    let pin = PIN.get_or_init(|| {
        Regex::new(r"native-runtime[/\\]+([0-9a-f]{64})[/\\]+hol-guard-runtime(?:\.exe)?")
            .expect("runtime pin pattern")
    });
    let mut pins = BTreeSet::new();
    let mut at = 0;
    while let Some(found) = pin.captures_at(text, at) {
        let (Some(whole), Some(digest)) = (found.get(0), found.get(1)) else {
            break;
        };
        let next = text[whole.end()..].chars().next();
        if !next.is_some_and(|c| is_word(c) || matches!(c, '.' | '-')) {
            pins.insert(digest.as_str());
        }
        // The match starts with an ASCII letter, so this is a char boundary.
        at = whole.start() + 1;
    }
    pins
}

/// Whether one Guard-owned artifact launches an interpreter other than
/// `current`. Only an invocation of Guard's own client counts: one that
/// imports the package, or runs a worker under the Guard home. A user hook
/// that happens to run `python -I` is left alone.
fn names_foreign_interpreter(path: &Path, current: Option<&str>, home: &str) -> bool {
    let Some(bytes) = read_prefix(path, CLIENT_SCAN_MAX_BYTES) else {
        return false;
    };
    if bytes[..bytes.len().min(BINARY_SNIFF_BYTES)].contains(&0) {
        return false;
    }
    let text = String::from_utf8_lossy(&bytes);
    if commands(&text)
        .iter()
        .any(|command| names_foreign_client(command, current, home))
    {
        return true;
    }
    names_foreign_powershell_launcher(&text, current, home)
}

/// One string per command a JSON hook config holds, else the whole text.
///
/// A config lists a user's hooks beside Guard's. Scanning each command on its
/// own keeps a user's `python -I -c` from being read with the Guard client
/// that follows it in the file. An argv of strings is read as Python's
/// `json.dumps` spells it.
fn commands(text: &str) -> Vec<String> {
    let Ok(root) = serde_json::from_str::<Value>(text) else {
        return vec![text.to_owned()];
    };
    let mut commands = Vec::new();
    let mut pending = vec![&root];
    while let Some(value) = pending.pop() {
        match value {
            Value::String(command) => commands.push(command.clone()),
            Value::Object(fields) => pending.extend(fields.values()),
            Value::Array(items) => {
                if !items.is_empty() && items.iter().all(Value::is_string) {
                    commands.extend(dumps_default(value));
                }
                pending.extend(items);
            }
            _ => {}
        }
    }
    commands
}

fn names_foreign_client(text: &str, current: Option<&str>, home: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let clients = isolated_clients(&chars);
    for (index, &(start, end)) in clients.iter().enumerate() {
        let before = &chars[start.saturating_sub(LOOKBEHIND_CHARS)..start];
        let Some(candidate) = interpreter_before(before) else {
            continue;
        };
        // The next isolated client starts another command.
        let next = clients
            .get(index + 1)
            .map_or(chars.len(), |&(next, _)| next);
        let ahead: String = chars[end..next.min(end + LOOKAHEAD_CHARS)].iter().collect();
        let ahead = posix(&ahead);
        if (ahead.contains(PACKAGE) || ahead.contains(home))
            && is_other_interpreter(&candidate, current)
        {
            return true;
        }
    }
    false
}

/// Every isolated hook client, as `(start, end)` char offsets.
///
/// A source install runs every hook client isolated: `<python> -I -s <worker>`,
/// `<python> -I -s -m codex_plugin_scanner.cli` or `<python> -I -c <bootstrap>`.
/// The flag after `-I` separates those from the stdlib-only
/// `<python> -I <script>` clients, which do not depend on which Guard install
/// owns the interpreter. The separators cover a shell word, a JSON or Python
/// argv, and a JSON-escaped argv.
fn isolated_clients(chars: &[char]) -> Vec<(usize, usize)> {
    let mut clients = Vec::new();
    let mut at = 0;
    while at < chars.len() {
        match isolated_client_at(chars, at) {
            Some(end) => {
                clients.push((at, end));
                at = end;
            }
            None => at += 1,
        }
    }
    clients
}

fn isolated_client_at(chars: &[char], at: usize) -> Option<usize> {
    if chars.get(at..at + 2)? != &['-', 'I'][..] {
        return None;
    }
    if at > 0 && !client_boundary(chars[at - 1]) {
        return None;
    }
    let flag = at
        + 2
        + chars[at + 2..]
            .iter()
            .take_while(|&&c| argv_separator(c))
            .count();
    if flag == at + 2
        || chars.get(flag) != Some(&'-')
        || !matches!(chars.get(flag + 1), Some('s' | 'c' | 'm'))
    {
        return None;
    }
    let end = flag + 2;
    if chars.get(end).is_some_and(|&c| is_word(c) || c == '-') {
        return None;
    }
    Some(end)
}

/// The interpreter path just before an isolated client's `-I`.
fn interpreter_before(before: &[char]) -> Option<String> {
    if let Some(word) = shell_word(before) {
        if is_absolute(&word) {
            return Some(word);
        }
    }
    let found = argv_item_before(before)?;
    // A JSON-escaped argv leaves the closing quote's backslash on the path
    // and doubles every separator in a Windows one.
    Some(found.trim_end_matches('\\').replace("\\\\", "\\"))
}

/// The quoted shell word that ends `before`, unquoted.
///
/// `shlex.quote` writes a path holding an apostrophe as adjacent quoted
/// fragments (`'/opt/O'"'"'Brien/python'`); this takes the whole word. Only
/// a word with quoting counts, and only one that is a single shell word.
fn shell_word(before: &[char]) -> Option<String> {
    let end = before.iter().rposition(|&c| !py_space(c))? + 1;
    if end == before.len() {
        return None;
    }
    let start = (0..end).find(|&start| {
        (start == 0 || py_space(before[start - 1]) || before[start - 1] == '=')
            && is_shell_word(&before[start..end])
    })?;
    let word: String = before[start..end].iter().collect();
    if !word.contains(['\'', '"']) {
        return None;
    }
    match shlex_split(&word)?.as_slice() {
        [only] => Some(only.clone()),
        _ => None,
    }
}

/// Whether `word` is quoted fragments and plain characters, end to end.
fn is_shell_word(word: &[char]) -> bool {
    let mut index = 0;
    while index < word.len() {
        match word[index] {
            quote @ ('\'' | '"') => {
                let Some(close) = word[index + 1..]
                    .iter()
                    .position(|&c| matches!(c, '\r' | '\n') || c == quote)
                else {
                    return false;
                };
                if word[index + 1 + close] != quote {
                    return false;
                }
                index += close + 2;
            }
            c if py_space(c) || matches!(c, '\\' | ',' | '[' | '=') => return false,
            _ => index += 1,
        }
    }
    !word.is_empty()
}

/// The first quoted or bare argv item followed only by separators to the end
/// of `before`.
fn argv_item_before(before: &[char]) -> Option<String> {
    // Every index at or after `tail` starts a run of separators to the end.
    let tail = before
        .iter()
        .rposition(|&c| !argv_separator(c))
        .map_or(0, |last| last + 1);
    for (start, &c) in before.iter().enumerate() {
        if matches!(c, '\'' | '"') {
            let Some(close) = before[start + 1..]
                .iter()
                .position(|&next| matches!(next, '\r' | '\n') || next == c)
                .map(|offset| start + 1 + offset)
            else {
                continue;
            };
            if before[close] == c && close > start + 1 && close + 1 >= tail {
                return Some(before[start + 1..close].iter().collect());
            }
        } else if !bare_stop(c) && (start == 0 || bare_stop(before[start - 1])) {
            let end = start
                + before[start..]
                    .iter()
                    .take_while(|&&next| !bare_stop(next))
                    .count();
            if end >= tail {
                return Some(before[start..end].iter().collect());
            }
        }
    }
    None
}

/// The PowerShell form of the Cline launcher names the interpreter and worker
/// on consecutive lines instead of one command.
fn names_foreign_powershell_launcher(text: &str, current: Option<&str>, home: &str) -> bool {
    static LAUNCHER: OnceLock<Regex> = OnceLock::new();
    let launcher = LAUNCHER.get_or_init(|| {
        Regex::new(r"(?m)^\$Python = '((?:[^'\r\n]|'')+)'\r?\n\$Worker = '((?:[^'\r\n]|'')+)'")
            .expect("powershell launcher pattern")
    });
    launcher.captures_iter(text).any(|found| {
        let (Some(python), Some(worker)) = (found.get(1), found.get(2)) else {
            return false;
        };
        posix(&worker.as_str().replace("''", "'")).starts_with(home)
            && is_other_interpreter(&python.as_str().replace("''", "'"), current)
    })
}

fn is_other_interpreter(candidate: &str, current: Option<&str>) -> bool {
    if !is_absolute(candidate) {
        // Not an interpreter path: a word that merely sat before a flag.
        return false;
    }
    current.is_none_or(|current| normcase(candidate) != normcase(current))
}

/// `Path(value).is_absolute() or PureWindowsPath(value).is_absolute()`.
fn is_absolute(value: &str) -> bool {
    (cfg!(not(windows)) && value.starts_with('/')) || is_windows_absolute(value)
}

fn is_windows_absolute(value: &str) -> bool {
    let separator = |c: char| matches!(c, '\\' | '/');
    let chars: Vec<char> = value.chars().take(3).collect();
    match chars.as_slice() {
        [drive, ':', root] => !separator(*drive) && separator(*root),
        [first, second, third] if separator(*first) && separator(*second) => {
            if separator(*third) {
                return false;
            }
            let mut parts = value[2..].split(separator);
            let server = parts.next().unwrap_or_default();
            let share = parts.next().unwrap_or_default();
            !server.is_empty() && !share.is_empty()
        }
        _ => false,
    }
}

/// `os.path.normcase`.
fn normcase(value: &str) -> String {
    if cfg!(windows) {
        value.replace('/', "\\").to_lowercase()
    } else {
        value.to_owned()
    }
}

fn posix(value: &str) -> String {
    value.replace("\\\\", "/").replace('\\', "/")
}

/// Python's `\w` on text.
fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn client_boundary(c: char) -> bool {
    py_space(c) || matches!(c, '\'' | '"' | ',' | '[')
}

fn argv_separator(c: char) -> bool {
    py_space(c) || matches!(c, '\'' | '"' | ',' | '\\')
}

fn bare_stop(c: char) -> bool {
    py_space(c) || matches!(c, '\'' | '"' | ',' | '[' | '=')
}

#[cfg(test)]
#[path = "hook_launch_scan_tests.rs"]
mod tests;

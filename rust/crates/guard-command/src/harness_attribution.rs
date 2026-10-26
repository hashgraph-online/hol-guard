//! Attribute a Guard invocation to the AI harness that spawned it.
//!
//! Mirrors `codex_plugin_scanner.guard.runtime.harness_attribution`. Package
//! shims run `hol-guard protect` inside the environment of the shell that ran
//! the intercepted command, so a harness that executed it leaves presence-only
//! runtime markers behind. The resolved slug feeds request identity, receipts,
//! and user-facing attribution only; policy scoping never keys off it.

use std::collections::{HashMap, HashSet};

/// Explicit override stamped by Guard onto the children it spawns.
const ORIGIN_HARNESS_ENV: &str = "HOL_GUARD_ORIGIN_HARNESS";

/// The slugs `origin_harness_env` is willing to stamp, and therefore the only
/// ones the override is honoured for. An unrecognised value falls through to
/// the marker families below rather than being returned verbatim.
const ORIGIN_HARNESS_VALUES: &[&str] = &[
    "claude-code",
    "codex",
    "copilot",
    "cursor",
    "gemini",
    "grok",
    "omp",
    "opencode",
    "pi",
    "zcode",
    "devin",
];

/// `adapters.zcode_config.ZCODE_ENV_HINTS` / `ZCODE_BUNDLE_IDENTIFIER`.
const ZCODE_ENV_MARKERS: &[&str] = &[
    "ZCODE_BASE_URL",
    "ZCODE_APP_VERSION",
    "ZCODE_ENV",
    "ZCODE_RUNTIME_ENV",
    "ZCODE_PROCESS_LABEL",
    "ZCODE_RG_BINARY",
    "ZAI_OAUTH_ORIGIN",
    "ZAI_OAUTH_CLIENT_ID",
];
const ZCODE_BUNDLE_IDENTIFIER: &str = "dev.zcode.app";
const BUNDLE_IDENTIFIER_ENV: &str = "__CFBundleIdentifier";

const CLAUDE_CODE_ENV_MARKERS: &[&str] = &["CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"];
const CURSOR_ENV_MARKERS: &[&str] = &[
    "CURSOR_VERSION",
    "CURSOR_PROJECT_DIR",
    "CURSOR_TRACE_ID",
    "CURSOR_SESSION_ID",
    "CURSOR_TRANSCRIPT_PATH",
];
const CODEX_ENV_MARKERS: &[&str] = &["CODEX_SANDBOX", "CODEX_THREAD_ID"];
const GROK_ENV_MARKERS: &[&str] = &["GROK_AGENT", "GROK_SESSION_ID"];
const OPENCODE_ENV_MARKERS: &[&str] = &["OPENCODE_CONFIG_CONTENT"];
const DEVIN_ENV_MARKERS: &[&str] = &["DEVIN_PROJECT_DIR"];

const PROCESS_HARNESSES: &[(&str, &str)] = &[
    ("codex", "codex"),
    ("claude", "claude-code"),
    ("cursor", "cursor"),
    ("cursor-agent", "cursor"),
    ("zcode", "zcode"),
    ("zcode-cli", "zcode"),
    ("grok", "grok"),
    ("pi", "pi"),
    ("omp", "omp"),
    ("opencode", "opencode"),
    ("devin", "devin"),
];

const APP_PATH_MARKERS: &[(&str, &str)] = &[
    ("/codex.app/", "codex"),
    ("/cursor.app/", "cursor"),
    ("/grok.app/", "grok"),
    ("/claude.app/", "claude-code"),
    ("/opencode.app/", "opencode"),
    ("/zcode.app/", "zcode"),
    ("/devin.app/", "devin"),
];

/// Python walks at most eight generations before giving up.
const PARENT_HOPS: usize = 8;

/// Python passes `timeout=0.5` to its `/bin/ps` call.
#[cfg(unix)]
const PS_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);
#[cfg(unix)]
const PS_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);

/// `harness.strip().lower().replace("_", "-")`.
fn normalize_slug(value: &str) -> String {
    value.trim().to_lowercase().replace('_', "-")
}

/// A marker counts only when its value is a non-empty string after stripping.
/// An exported-but-empty `CURSOR_VERSION=` is not an attribution signal.
fn env_marker_present(env: &HashMap<String, String>, markers: &[&str]) -> bool {
    markers
        .iter()
        .any(|key| env.get(*key).is_some_and(|value| !value.trim().is_empty()))
}

/// `runtime.harness_attribution.resolve_environment_harness`.
///
/// The marker families are disjoint in practice; the fixed order below is the
/// deterministic tie-breaker when more than one matches, and it is the order
/// Python documents and tests. ZCode wins over every other family because its
/// app embeds another harness's CLI, so both sets of markers are present.
pub fn resolve_environment_harness_from(env: &HashMap<String, String>) -> Option<String> {
    if let Some(origin) = env.get(ORIGIN_HARNESS_ENV) {
        let slug = normalize_slug(origin);
        if ORIGIN_HARNESS_VALUES.contains(&slug.as_str()) {
            return Some(slug);
        }
    }
    if env_marker_present(env, ZCODE_ENV_MARKERS) {
        return Some("zcode".to_string());
    }
    if env
        .get(BUNDLE_IDENTIFIER_ENV)
        .is_some_and(|bundle| bundle.trim() == ZCODE_BUNDLE_IDENTIFIER)
    {
        return Some("zcode".to_string());
    }
    for (markers, slug) in [
        (CLAUDE_CODE_ENV_MARKERS, "claude-code"),
        (CURSOR_ENV_MARKERS, "cursor"),
        (CODEX_ENV_MARKERS, "codex"),
        (GROK_ENV_MARKERS, "grok"),
        (OPENCODE_ENV_MARKERS, "opencode"),
        (DEVIN_ENV_MARKERS, "devin"),
    ] {
        if env_marker_present(env, markers) {
            return Some(slug.to_string());
        }
    }
    None
}

/// `resolve_environment_harness(os.environ)`.
pub fn resolve_environment_harness() -> Option<String> {
    resolve_environment_harness_from(&std::env::vars().collect())
}

/// `runtime.harness_attribution._harness_from_executable`.
///
/// Python builds a `PurePath`, which on the POSIX hosts this walk runs on
/// splits on `/` alone, so a backslash never ends the basename here. The
/// app-path fallback is what normalizes separators, and it does so on the
/// whole original path.
pub fn harness_from_executable(path: &str) -> Option<&'static str> {
    let name = path.rsplit('/').next().unwrap_or(path).to_lowercase();
    let name = name.strip_suffix(".exe").unwrap_or(name.as_str());
    if let Some((_, slug)) = PROCESS_HARNESSES.iter().find(|(known, _)| *known == name) {
        return Some(*slug);
    }
    let posix = path.replace('\\', "/").to_lowercase();
    APP_PATH_MARKERS
        .iter()
        .find(|(marker, _)| posix.contains(marker))
        .map(|(_, slug)| *slug)
}

/// Split one `ps -axo pid=,ppid=,comm=` row the way `str.split(maxsplit=2)`
/// does: runs of whitespace collapse, and the third field keeps its interior
/// spacing. A row with fewer than three fields is skipped, exactly as Python's
/// three-way unpack raises `ValueError` and the loop continues.
fn ps_row_fields(row: &str) -> Option<(&str, &str, &str)> {
    fn take_token(text: &str) -> Option<(&str, &str)> {
        let text = text.trim_start();
        if text.is_empty() {
            return None;
        }
        let end = text.find(char::is_whitespace).unwrap_or(text.len());
        Some((&text[..end], &text[end..]))
    }

    let (process, rest) = take_token(row.trim())?;
    let (parent, rest) = take_token(rest)?;
    let executable = rest.trim_start();
    if executable.is_empty() {
        return None;
    }
    Some((process, parent, executable))
}

/// Read the process table within the Python timeout, or give up.
#[cfg(unix)]
fn read_process_table() -> Option<String> {
    use std::io::Read;

    let mut child = std::process::Command::new("/bin/ps")
        .args(["-axo", "pid=,ppid=,comm="])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;

    // Drain the pipe alongside the poll loop; `try_wait` alone would leave a
    // large process table blocked on a full pipe buffer past the deadline.
    let reader = child.stdout.take().map(|mut pipe| {
        std::thread::spawn(move || {
            let mut buffer = Vec::new();
            pipe.read_to_end(&mut buffer).map(|_| buffer)
        })
    });

    let deadline = std::time::Instant::now() + PS_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.map(std::thread::JoinHandle::join);
                return None;
            }
            Ok(None) => std::thread::sleep(PS_POLL_INTERVAL),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.map(std::thread::JoinHandle::join);
                return None;
            }
        }
    };
    if !status.success() {
        let _ = reader.map(std::thread::JoinHandle::join);
        return None;
    }
    let stdout = reader?.join().ok()?.ok()?;
    Some(String::from_utf8_lossy(&stdout).into_owned())
}

#[cfg(not(unix))]
fn read_process_table() -> Option<String> {
    // Python returns `None` on Windows before it ever reaches `/bin/ps`, so
    // there is no behaviour here to keep parity with rather than an absent
    // one: the origin simply stays unknown.
    None
}

#[cfg(unix)]
fn parent_pid() -> Option<i64> {
    Some(i64::from(std::os::unix::process::parent_id()))
}

#[cfg(not(unix))]
fn parent_pid() -> Option<i64> {
    None
}

/// `runtime.harness_attribution.resolve_parent_process_harness`.
///
/// Best-effort display attribution when a harness supplies no env marker.
/// Executable names only, never arguments or process environments; the walk is
/// bounded in both generations and elapsed time, and any failure leaves the
/// origin unknown. This signal must never be used as an authorization or
/// policy selector.
pub fn resolve_parent_process_harness() -> Option<String> {
    let table = read_process_table()?;
    let mut parents: HashMap<i64, (i64, String)> = HashMap::new();
    for row in table.lines() {
        let Some((process, parent, executable)) = ps_row_fields(row) else {
            continue;
        };
        let (Ok(process), Ok(parent)) = (process.parse::<i64>(), parent.parse::<i64>()) else {
            continue;
        };
        parents.insert(process, (parent, executable.to_string()));
    }

    let mut pid = parent_pid()?;
    let mut seen: HashSet<i64> = HashSet::new();
    for _ in 0..PARENT_HOPS {
        if pid <= 1 || !seen.insert(pid) {
            break;
        }
        let Some((parent, executable)) = parents.get(&pid) else {
            break;
        };
        pid = *parent;
        if let Some(harness) = harness_from_executable(executable) {
            return Some(harness.to_string());
        }
    }
    None
}

#[cfg(test)]
#[path = "harness_attribution_tests.rs"]
mod tests;

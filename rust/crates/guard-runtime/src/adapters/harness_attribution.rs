//! `runner_authority` kind `harness_attribution`: which harness started a
//! Guard process, for display and request identity. It replaces the Python
//! `guard/runtime/harness_attribution.py`.
//!
//! - `environment` answers the harness whose presence-only runtime markers
//!   appear in the caller's `env`.
//! - `parent` walks the caller's parent processes (`ppid` is the caller's own,
//!   which only it knows) and answers the nearest harness executable. Only
//!   executable names are read, never arguments or process environments, and
//!   the walk is bounded in depth and time. A failure leaves the origin unknown.
//! - `runtime_hook` answers the harness a hook runs as: Claude-compatible
//!   hooks that run inside Cursor are Cursor's.
//! - `origin_env` answers the variable that stamps a known harness onto a
//!   Guard-spawned child.
//!
//! None of these answers is an authorization or a policy selector.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};
use crate::cloud_request_text::py_strip;

pub(crate) const ORIGIN_HARNESS_ENV: &str = "HOL_GUARD_ORIGIN_HARNESS";
const PARENT_TIMEOUT: Duration = Duration::from_millis(500);
const PARENT_DEPTH: usize = 8;

const CURSOR_ENV_MARKERS: [&str; 5] = [
    "CURSOR_VERSION",
    "CURSOR_PROJECT_DIR",
    "CURSOR_TRACE_ID",
    "CURSOR_SESSION_ID",
    "CURSOR_TRANSCRIPT_PATH",
];
const ZCODE_ENV_MARKERS: [&str; 8] = [
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
/// Presence-only, non-secret markers each harness runtime injects into the
/// environment of the commands it runs, in the order that breaks a tie.
const CLAUDE_CODE_ENV_MARKERS: [&str; 2] = ["CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"];
const FAMILIES: [(&[&str], &str); 7] = [
    (&CLAUDE_CODE_ENV_MARKERS, "claude-code"),
    (&CURSOR_ENV_MARKERS, "cursor"),
    (&["CODEX_SANDBOX", "CODEX_THREAD_ID"], "codex"),
    (&["GROK_AGENT", "GROK_SESSION_ID"], "grok"),
    (&["OPENCODE_CONFIG_CONTENT"], "opencode"),
    (&["DEVIN_PROJECT_DIR"], "devin"),
    (&["MUSE_SESSION_ID", "MUSE_THREAD_ID"], "muse"),
];
const ORIGIN_HARNESS_VALUES: [&str; 12] = [
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
    "muse",
];
const PROCESS_HARNESSES: [(&str, &str); 13] = [
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
    ("muse", "muse"),
    ("muse-bin", "muse"),
];
const APP_PATH_MARKERS: [(&str, &str); 7] = [
    ("/codex.app/", "codex"),
    ("/cursor.app/", "cursor"),
    ("/grok.app/", "grok"),
    ("/claude.app/", "claude-code"),
    ("/opencode.app/", "opencode"),
    ("/zcode.app/", "zcode"),
    ("/devin.app/", "devin"),
];

type Env = BTreeMap<String, String>;

fn present(env: &Env, markers: &[&str]) -> bool {
    markers.iter().any(|key| {
        env.get(*key)
            .is_some_and(|value| !py_strip(value).is_empty())
    })
}

fn slug(text: &str) -> String {
    py_strip(text).to_lowercase().replace('_', "-")
}

/// The harness whose runtime markers appear in `env`, if any.
pub(crate) fn environment_harness(env: &Env) -> Option<&'static str> {
    if let Some(origin) = env.get(ORIGIN_HARNESS_ENV) {
        let origin = slug(origin);
        if let Some(known) = ORIGIN_HARNESS_VALUES.iter().find(|known| **known == origin) {
            return Some(known);
        }
    }
    if present(env, &ZCODE_ENV_MARKERS)
        || env
            .get("__CFBundleIdentifier")
            .is_some_and(|bundle| py_strip(bundle) == ZCODE_BUNDLE_IDENTIFIER)
    {
        return Some("zcode");
    }
    FAMILIES
        .iter()
        .find(|(markers, _)| present(env, markers))
        .map(|(_, harness)| *harness)
}

fn cursor_detected(env: &Env) -> bool {
    present(env, &CURSOR_ENV_MARKERS)
}

/// The harness a hook invocation runs as. Claude Code's own markers win, so a
/// Claude session started from a Cursor terminal, which inherits Cursor's
/// variables, stays Claude.
pub(crate) fn runtime_hook_harness<'a>(requested: &'a str, env: &Env) -> &'a str {
    if matches!(slug(requested).as_str(), "claude" | "claude-code")
        && cursor_detected(env)
        && !present(env, &CLAUDE_CODE_ENV_MARKERS)
    {
        "cursor"
    } else {
        requested
    }
}

fn origin_env(harness: &str) -> Value {
    let slug = slug(harness);
    if ORIGIN_HARNESS_VALUES.contains(&slug.as_str()) {
        json!({ (ORIGIN_HARNESS_ENV): slug })
    } else {
        json!({})
    }
}

/// The last real component of a path, as `PurePath(path).name` reads it.
fn file_name(path: &str) -> &str {
    path.rsplit('/')
        .find(|part| !part.is_empty() && *part != ".")
        .unwrap_or("")
}

fn harness_from_executable(path: &str) -> Option<&'static str> {
    let lower = file_name(path).to_lowercase();
    let name = lower.strip_suffix(".exe").unwrap_or(&lower);
    if let Some((_, harness)) = PROCESS_HARNESSES
        .iter()
        .find(|(process, _)| *process == name)
    {
        return Some(harness);
    }
    let posix = path.replace('\\', "/").to_lowercase();
    APP_PATH_MARKERS
        .iter()
        .find(|(marker, _)| posix.contains(marker))
        .map(|(_, harness)| *harness)
}

/// One `pid ppid comm` row; the executable keeps its inner spacing.
fn row(line: &str) -> Option<(i64, (i64, &str))> {
    let line = py_strip(line);
    let (process, rest) = line.split_once(char::is_whitespace)?;
    let rest = rest.trim_start();
    let (parent, executable) = rest.split_once(char::is_whitespace)?;
    Some((
        process.parse().ok()?,
        (parent.parse().ok()?, executable.trim_start()),
    ))
}

/// The nearest harness executable among the ancestors of `ppid` in a
/// `pid ppid comm` table.
fn parent_harness(table: &str, ppid: i64) -> Option<&'static str> {
    let parents: HashMap<i64, (i64, &str)> = table.lines().filter_map(row).collect();
    let mut pid = ppid;
    let mut seen = HashSet::new();
    for _ in 0..PARENT_DEPTH {
        if pid <= 1 || seen.contains(&pid) || !parents.contains_key(&pid) {
            break;
        }
        seen.insert(pid);
        let (parent, executable) = parents[&pid];
        pid = parent;
        if let Some(harness) = harness_from_executable(executable) {
            return Some(harness);
        }
    }
    None
}

fn parent(ppid: i64) -> Option<&'static str> {
    let table = crate::posix_processes::parent_table(PARENT_TIMEOUT)?;
    parent_harness(&table, ppid)
}

fn env_field(args: &Map<String, Value>) -> Result<Env, &'static str> {
    args.get("env")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|(key, value)| Ok((key.clone(), value.as_str().ok_or(ERR_INVALID)?.to_owned())))
        .collect()
}

fn ppid_field(args: &Map<String, Value>) -> Result<i64, &'static str> {
    args.get("ppid").and_then(Value::as_i64).ok_or(ERR_INVALID)
}

fn text_field<'a>(args: &'a Map<String, Value>, key: &str) -> Result<&'a str, &'static str> {
    args.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    match text_field(args, "op")? {
        "environment" => Ok(json!({ "harness": environment_harness(&env_field(args)?) })),
        "parent" => Ok(json!({ "harness": parent(ppid_field(args)?) })),
        "runtime_hook" => {
            let requested = text_field(args, "requested")?;
            Ok(json!({ "harness": runtime_hook_harness(requested, &env_field(args)?) }))
        }
        "origin_env" => Ok(json!({ "env": origin_env(text_field(args, "harness")?) })),
        _ => Err(ERR_INVALID),
    }
}

#[cfg(test)]
#[path = "harness_attribution_tests.rs"]
mod tests;

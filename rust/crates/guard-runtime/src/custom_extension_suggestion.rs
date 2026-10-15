//! Rank observed CLIs for custom-extension suggestions.
//!
//! Port of the former Python `custom_extension_suggestion` module; parity
//! vectors are recorded by `scripts/record_custom_extension_suggestion_vectors.py`.
//! Pure: the answer depends only on the request.

use guard_contracts::{SuggestionToolV1, SuggestionVerdictV1};

use super::context_digest_local_cli::python_whitespace;

const MAX_TOOLS: usize = 4_096;
const MIN_CLI_SCORE: i64 = 15;
const ERR_TOO_MANY_TOOLS: &str = "native_custom_extension_suggestion_too_many_tools";

const SEARCH_TOOLS: &[&str] = &[
    "rg", "ripgrep", "ag", "ack", "fd", "fzf", "grep", "egrep", "fgrep",
];
const IDENTITY_TOOLS: &[&str] = &["whoami", "id", "groups", "logname", "users", "who", "w"];
const RECORDER_TOOLS: &[&str] = &["script", "scriptreplay", "typescript", "asciinema"];
const TEST_RUNNER_NAMES: &[&str] = &[
    "vitest",
    "jest",
    "mocha",
    "ava",
    "tap",
    "jasmine",
    "karma",
    "pytest",
    "py.test",
    "nosetests",
    "unittest",
    "phpunit",
    "rspec",
    "playwright",
    "cypress",
];
const GENERIC_NAMES: &[&str] = &[
    "script", "test", "tests", "run", "start", "build", "main", "index", "app", "bin", "cli",
    "tool", "tools", "helper", "util", "utils", "cmd", "exec", "tmp", "temp", "out", "output",
    "data", "default", "command",
];
const RESERVED_TOOL_NAMES: &[&str] = &["hol-guard", "hol_guard", "guard"];
const PACKAGE_STORE_MARKERS: &[&str] = &[
    "/node_modules/",
    "\\node_modules\\",
    "/.pnpm/",
    "/.venv/",
    "/venv/",
    "/site-packages/",
    "/__pycache__/",
    "/.nvm/",
    "/nvm/versions/",
];
const SYSTEM_BIN_PREFIXES: &[&str] = &["/bin/", "/usr/bin/", "/usr/sbin/", "/sbin/"];
const PATH_CLASSES: &[&str] = &[
    "unknown",
    "package-store",
    "system-bin",
    "user-tool",
    "project-tool",
    "registry-package",
];
const WINDOWS_SYSTEM_PREFIXES: &[&str] = &[
    "/windows/system32/",
    "/windows/syswow64/",
    "/windows/system/",
];
const SCRIPT_SUFFIXES: &[&str] = &["py", "js", "mjs", "cjs", "ts", "tsx", "jsx", "rb", "sh"];
const SHELL_UTILITIES: &[&str] = &[
    "[",
    "alias",
    "awk",
    "basename",
    "base64",
    "bat",
    "cat",
    "cd",
    "chmod",
    "chown",
    "clear",
    "column",
    "cp",
    "curl",
    "cut",
    "date",
    "df",
    "diff",
    "dirname",
    "du",
    "echo",
    "env",
    "false",
    "file",
    "find",
    "grep",
    "gzip",
    "head",
    "hexdump",
    "history",
    "hostname",
    "htop",
    "jq",
    "kill",
    "less",
    "ln",
    "ls",
    "lsof",
    "man",
    "md5",
    "mkdir",
    "more",
    "mv",
    "nano",
    "nc",
    "nice",
    "nl",
    "nohup",
    "nvim",
    "open",
    "paste",
    "patch",
    "pbcopy",
    "pbpaste",
    "ping",
    "printf",
    "ps",
    "pwd",
    "readlink",
    "realpath",
    "reset",
    "rev",
    "rm",
    "rmdir",
    "rsync",
    "scp",
    "sed",
    "seq",
    "sha256sum",
    "shasum",
    "sleep",
    "sort",
    "ssh",
    "stat",
    "stty",
    "sudo",
    "tail",
    "tar",
    "tee",
    "test",
    "time",
    "timeout",
    "tmux",
    "top",
    "touch",
    "tput",
    "tr",
    "true",
    "tty",
    "type",
    "uname",
    "uniq",
    "unalias",
    "unzip",
    "vim",
    "watch",
    "wc",
    "wget",
    "which",
    "xargs",
    "xxd",
    "yes",
    "yq",
    "zip",
];

/// One verdict per tool, in request order.
pub(crate) fn suggestion_verdicts(
    tools: &[SuggestionToolV1],
) -> Result<Vec<SuggestionVerdictV1>, &'static str> {
    if tools.len() > MAX_TOOLS {
        return Err(ERR_TOO_MANY_TOOLS);
    }
    Ok(tools.iter().map(verdict).collect())
}

fn verdict(tool: &SuggestionToolV1) -> SuggestionVerdictV1 {
    let normalized = normalize_tool_name(&tool.name);
    let score = suggestion_score(tool, &normalized);
    let pinned = matches!(tool.surface.as_str(), "mcp" | "package-scripts");
    SuggestionVerdictV1 {
        score,
        suggestable: pinned || score >= MIN_CLI_SCORE,
        path_class: path_class(tool.source_path.as_deref()),
        common_utility: is_common_utility(&normalized),
        reject_message: reject_message(&normalized),
    }
}

fn suggestion_score(tool: &SuggestionToolV1, normalized: &str) -> i64 {
    if matches!(tool.surface.as_str(), "mcp" | "package-scripts") {
        return 100;
    }
    if !name_is_suggestable(normalized) {
        return 0;
    }
    let path_class = path_class(tool.source_path.as_deref());
    if path_class == "package-store" {
        return 0;
    }
    let mut score = 10;
    if name_is_distinctive(normalized) {
        score += 20;
    }
    if tool.observed_count >= 2 {
        score += 10;
    }
    if tool.observed_count >= 5 {
        score += 10;
    }
    if tool.help_status.as_deref() == Some("ok") {
        score += 10;
        if tool.kind == "script" {
            score += 5;
        }
    }
    if matches!(path_class.as_str(), "user-tool" | "project-tool") {
        score += 5;
    }
    if path_class == "system-bin" {
        score -= 20;
    }
    score.max(0)
}

/// `is_common_shell_utility`: whether `name` is a common shell utility.
pub(crate) fn is_common_tool_name(name: &str) -> bool {
    is_common_utility(&normalize_tool_name(name))
}

fn is_common_utility(normalized: &str) -> bool {
    SHELL_UTILITIES.contains(&normalized)
        || SEARCH_TOOLS.contains(&normalized)
        || IDENTITY_TOOLS.contains(&normalized)
        || RECORDER_TOOLS.contains(&normalized)
}

fn reject_message(normalized: &str) -> String {
    if SEARCH_TOOLS.contains(&normalized) {
        format!("{normalized} is a common search tool, not a custom extension.")
    } else if IDENTITY_TOOLS.contains(&normalized) {
        format!("{normalized} is a built-in identity command, not a custom extension.")
    } else if RECORDER_TOOLS.contains(&normalized) {
        format!("{normalized} is a built-in terminal recorder, not a custom extension.")
    } else {
        format!("{normalized} is a built-in shell command, not a custom extension.")
    }
}

fn name_is_suggestable(normalized: &str) -> bool {
    let keys = name_keys(normalized);
    let any_in = |names: &[&str]| keys.iter().any(|key| names.contains(key));
    if keys.iter().any(|key| is_common_utility(key)) || any_in(RESERVED_TOOL_NAMES) {
        return false;
    }
    if any_in(TEST_RUNNER_NAMES) || any_in(GENERIC_NAMES) {
        return false;
    }
    !looks_like_test_file(normalized)
}

fn name_is_distinctive(normalized: &str) -> bool {
    let stem = first_dot_part(normalized);
    if normalized.contains('-') || normalized.contains('_') {
        return stem.chars().count() >= 4;
    }
    if normalized.contains('.') {
        return !GENERIC_NAMES.contains(&stem) && stem.chars().count() >= 3;
    }
    normalized.chars().count() >= 6
}

fn looks_like_test_file(name: &str) -> bool {
    let lowered = name.to_lowercase();
    if lowered.starts_with("test_") && lowered.ends_with(".py") {
        return true;
    }
    let Some((stem, suffix)) = lowered.rsplit_once('.') else {
        return false;
    };
    if !SCRIPT_SUFFIXES.contains(&suffix) {
        return false;
    }
    [".test", ".spec", "_test", "_spec"]
        .iter()
        .any(|ending| stem.ends_with(ending))
}

pub(crate) fn path_class(source_path: Option<&str>) -> String {
    let Some(source_path) = source_path.filter(|path| !path.is_empty()) else {
        return "unknown".to_owned();
    };
    if PATH_CLASSES.contains(&source_path) {
        return source_path.to_owned();
    }
    let lowered = source_path.replace('\\', "/").to_lowercase();
    let padded = format!("/{}/", lowered.trim_matches('/'));
    if PACKAGE_STORE_MARKERS
        .iter()
        .any(|marker| padded.contains(marker) || lowered.contains(marker))
    {
        return "package-store".to_owned();
    }
    if SYSTEM_BIN_PREFIXES
        .iter()
        .any(|prefix| lowered == prefix[..prefix.len() - 1] || lowered.starts_with(prefix))
        || is_windows_system_bin(&lowered)
    {
        return "system-bin".to_owned();
    }
    "user-tool".to_owned()
}

fn is_windows_system_bin(posix_lower: &str) -> bool {
    let mut remainder = strip_drive(posix_lower);
    if let Some(rest) = remainder.strip_prefix("//?/") {
        remainder = strip_drive(rest);
    }
    let remainder = if remainder.starts_with('/') {
        remainder.to_owned()
    } else {
        format!("/{remainder}")
    };
    WINDOWS_SYSTEM_PREFIXES
        .iter()
        .any(|prefix| remainder.starts_with(prefix))
}

/// Python `s[2:]` when `s[1] == ":"`, counted in characters.
fn strip_drive(value: &str) -> &str {
    let mut chars = value.char_indices();
    match (chars.next(), chars.next()) {
        (Some(_), Some((index, ':'))) => &value[index + 1..],
        _ => value,
    }
}

fn name_keys(normalized: &str) -> Vec<&str> {
    let mut keys = vec![normalized];
    if normalized.contains('.') {
        keys.push(first_dot_part(normalized));
    }
    keys
}

fn first_dot_part(value: &str) -> &str {
    value.split_once('.').map_or(value, |(stem, _)| stem)
}

fn normalize_tool_name(name: &str) -> String {
    let base = name.trim_matches(python_whitespace).to_lowercase();
    if base.ends_with(".exe") || base.ends_with(".cmd") {
        return base[..base.len() - 4].to_owned();
    }
    base
}

#[cfg(test)]
#[path = "custom_extension_suggestion_tests.rs"]
mod tests;

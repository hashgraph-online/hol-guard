//! Normalize transparent shell wrappers before Guard evaluates a command
//! (`runtime/shell_command_wrappers.py`, 426 lines — verbatim).

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::command_launcher_floors::shlex_quote;
use crate::env_wrapper::parse_env_wrapper;

pub const SHELL_COMMAND_NORMALIZE_MAX_BYTES: usize = 8192;

const SHELL_CONTROL_TOKENS: &[&str] = &["&&", "||", ";", "|", "|&", "&"];
const LEAN_CTX_BINARIES: &[&str] = &["lean-ctx"];
const SHELL_STRING_WRAPPERS: &[&str] = &["ash", "bash", "dash", "fish", "sh", "zsh"];
const NICE_OPTION_FLAGS_WITH_VALUES: &[&str] = &["-n", "--adjustment"];
const STDBUF_VALUE_FLAGS: &[&str] = &["-i", "-o", "-e"];
const TIME_OPTION_FLAGS_WITH_VALUES: &[&str] = &["-f", "-o", "--format", "--output"];
const TRUSTED_INSTALL_DIRS: &[&str] = &["/opt/homebrew/bin", "/usr/local/bin"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShellCommandNormalization {
    pub raw_command: String,
    pub normalized_command: String,
    pub wrapper_chain: Vec<String>,
}

/// `normalize_transparent_shell_command` (:31-49).
pub fn normalize_transparent_shell_command(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> ShellCommandNormalization {
    let stripped = command_text.trim();
    if stripped.is_empty() || stripped.len() > SHELL_COMMAND_NORMALIZE_MAX_BYTES {
        return ShellCommandNormalization {
            raw_command: stripped.to_owned(),
            normalized_command: stripped.to_owned(),
            wrapper_chain: Vec::new(),
        };
    }
    let (normalized_command, wrapper_chain) = normalize_command_text(stripped, 0, cwd, home_dir);
    ShellCommandNormalization {
        raw_command: stripped.to_owned(),
        normalized_command: normalized_command.unwrap_or_else(|| stripped.to_owned()),
        wrapper_chain,
    }
}

/// `_normalize_command_text` (:52-75) → `(normalized, wrappers)` where
/// `normalized=None` maps to Python's `command_text` fallback in the caller.
fn normalize_command_text(
    command_text: &str,
    depth: usize,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> (Option<String>, Vec<String>) {
    if depth > 8 {
        return (Some(command_text.to_owned()), Vec::new());
    }
    let parts = match crate::shell_tokens(command_text, false) {
        Ok(p) => p,
        Err(_) => return (Some(command_text.to_owned()), Vec::new()),
    };
    if parts.is_empty() {
        return (Some(command_text.to_owned()), Vec::new());
    }
    let (prefix_env, index) = consume_leading_env_assignments(&parts, 0);
    let (normalized, wrappers) =
        normalize_parts(&parts[index..], depth, cwd, home_dir, Some(prefix_env));
    if wrappers.is_empty() {
        return (Some(command_text.to_owned()), Vec::new());
    }
    match normalized {
        None => (None, wrappers),
        Some(n) => (Some(n), wrappers),
    }
}

/// `_normalize_parts` (:78-179) → `(text | None, wrappers)`.
fn normalize_parts(
    parts: &[String],
    depth: usize,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    initial_env: Option<Vec<String>>,
) -> (Option<String>, Vec<String>) {
    let mut current: Vec<String> = parts.to_vec();
    let mut preserved_env: Vec<String> = initial_env.unwrap_or_default();
    let mut wrappers: Vec<String> = Vec::new();
    while !current.is_empty() {
        let (current_env, env_index) = consume_leading_env_assignments(&current, 0);
        if !current_env.is_empty() {
            preserved_env.extend(current_env);
            current = current[env_index..].to_vec();
            if current.is_empty() {
                break;
            }
        }
        let command_name = command_name(&current[0], &preserved_env, cwd, home_dir);
        if LEAN_CTX_BINARIES.contains(&command_name.as_str()) {
            let normalized = unwrap_lean_ctx(&current);
            let Some((inner_command, suffix)) = normalized else {
                break;
            };
            wrappers.push(command_name);
            let (inner_text, inner_wrappers) =
                normalize_command_text(&inner_command, depth + 1, cwd, home_dir);
            let inner_text = inner_text.unwrap_or_else(|| inner_command.clone());
            let suffix_text = if suffix.is_empty() {
                String::new()
            } else {
                join_shell_tokens(&suffix)
            };
            let mut inner_command_text = join_command_fragments(&[&inner_text, &suffix_text]);
            if !preserved_env.is_empty() {
                inner_command_text = join_command_fragments(&[
                    &join_shell_tokens(&preserved_env),
                    &inner_command_text,
                ]);
            }
            let mut chain = wrappers.clone();
            chain.extend(inner_wrappers);
            return (Some(inner_command_text), chain);
        }
        if SHELL_STRING_WRAPPERS.contains(&command_name.as_str()) {
            let normalized = unwrap_shell_string_wrapper(&current);
            let Some((inner_command, suffix)) = normalized else {
                break;
            };
            wrappers.push(command_name);
            let (inner_text, inner_wrappers) =
                normalize_command_text(&inner_command, depth + 1, cwd, home_dir);
            let inner_text = inner_text.unwrap_or_else(|| inner_command.clone());
            let suffix_text = if suffix.is_empty() {
                String::new()
            } else {
                join_shell_tokens(&suffix)
            };
            let mut inner_command_text = join_command_fragments(&[&inner_text, &suffix_text]);
            if !preserved_env.is_empty() {
                inner_command_text = join_command_fragments(&[
                    &join_shell_tokens(&preserved_env),
                    &inner_command_text,
                ]);
            }
            let mut chain = wrappers.clone();
            chain.extend(inner_wrappers);
            return (Some(inner_command_text), chain);
        }
        if command_name == "env" {
            let (next_parts, env_prefix) = strip_env_wrapper(&current, cwd);
            let Some(next_parts) = next_parts else {
                break;
            };
            wrappers.push("env".to_owned());
            preserved_env.extend(env_prefix);
            current = next_parts;
            continue;
        }
        if command_name == "command" {
            let Some(next_parts) = strip_command_wrapper(&current) else {
                break;
            };
            wrappers.push("command".to_owned());
            current = next_parts;
            continue;
        }
        if command_name == "time" {
            let Some(next_parts) = strip_time_wrapper(&current) else {
                break;
            };
            wrappers.push("time".to_owned());
            current = next_parts;
            continue;
        }
        if command_name == "nice" {
            let Some(next_parts) = strip_nice_wrapper(&current) else {
                break;
            };
            wrappers.push("nice".to_owned());
            current = next_parts;
            continue;
        }
        if command_name == "nohup" {
            let Some(next_parts) = strip_nohup_wrapper(&current) else {
                break;
            };
            wrappers.push("nohup".to_owned());
            current = next_parts;
            continue;
        }
        if command_name == "stdbuf" {
            let Some(next_parts) = strip_stdbuf_wrapper(&current) else {
                break;
            };
            wrappers.push("stdbuf".to_owned());
            current = next_parts;
            continue;
        }
        break;
    }
    let mut current_text = join_shell_tokens(&current);
    if !preserved_env.is_empty() {
        current_text = join_command_fragments(&[&join_shell_tokens(&preserved_env), &current_text]);
    }
    (Some(current_text), wrappers)
}

/// `_consume_leading_env_assignments` (:181-188).
fn consume_leading_env_assignments(parts: &[String], start: usize) -> (Vec<String>, usize) {
    let mut prefix = Vec::new();
    let mut index = start;
    while index < parts.len() && env_assignment_re(&parts[index]) {
        prefix.push(parts[index].clone());
        index += 1;
    }
    (prefix, index)
}

fn env_assignment_re(token: &str) -> bool {
    // `^[A-Za-z_][A-Za-z0-9_]*=.*$` fullmatch.
    match token.find('=') {
        None => false,
        Some(i) => {
            let name = &token[..i];
            !name.is_empty()
                && name
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_alphabetic() || c == '_')
                    .unwrap_or(false)
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
    }
}

/// `_unwrap_lean_ctx` (:191-203).
fn unwrap_lean_ctx(parts: &[String]) -> Option<(String, Vec<String>)> {
    let mut index = 1usize;
    while index < parts.len() {
        let token = &parts[index];
        if token == "--" {
            break;
        }
        if token == "-c" || token == "--command" {
            if index + 1 >= parts.len() {
                return None;
            }
            return Some((parts[index + 1].clone(), parts[index + 2..].to_vec()));
        }
        index += 1;
    }
    None
}

/// `_unwrap_shell_string_wrapper` (:206-220).
fn unwrap_shell_string_wrapper(parts: &[String]) -> Option<(String, Vec<String>)> {
    let mut index = 1usize;
    while index < parts.len() {
        let token = &parts[index];
        if token == "--" {
            break;
        }
        if token.starts_with('-') && !token.starts_with("--") && token[1..].contains('c') {
            if index + 1 >= parts.len() {
                return None;
            }
            return Some((parts[index + 1].clone(), parts[index + 2..].to_vec()));
        }
        if token.starts_with('-') {
            index += 1;
            continue;
        }
        return None;
    }
    None
}

/// `_strip_env_wrapper` (:223-229).
fn strip_env_wrapper(parts: &[String], cwd: Option<&Path>) -> (Option<Vec<String>>, Vec<String>) {
    let parsed = parse_env_wrapper(&parts[1..], None, cwd);
    if !parsed.complete || parsed.executable_argv.is_empty() {
        return (None, Vec::new());
    }
    let env_prefix: Vec<String> = parsed
        .environment_delta
        .assignments
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect();
    (Some(parsed.executable_argv), env_prefix)
}

/// `_strip_command_wrapper` (:232-244).
fn strip_command_wrapper(parts: &[String]) -> Option<Vec<String>> {
    let mut index = 1usize;
    while index < parts.len() {
        let token = &parts[index];
        if token == "--" {
            return Some(parts[index + 1..].to_vec());
        }
        if !token.starts_with('-') {
            return Some(parts[index..].to_vec());
        }
        if token[1..].contains('v') || token[1..].contains('V') {
            return None;
        }
        index += 1;
    }
    None
}

/// `_strip_time_wrapper` (:247-267).
fn strip_time_wrapper(parts: &[String]) -> Option<Vec<String>> {
    let mut index = 1usize;
    while index < parts.len() {
        let token = &parts[index];
        if token == "--" {
            return Some(parts[index + 1..].to_vec());
        }
        if TIME_OPTION_FLAGS_WITH_VALUES.contains(&token.as_str()) {
            if index + 1 >= parts.len() {
                return None;
            }
            index += 2;
            continue;
        }
        if token.starts_with("--format=") || token.starts_with("--output=") {
            index += 1;
            continue;
        }
        if (token.starts_with("-f") && token != "-f") || (token.starts_with("-o") && token != "-o")
        {
            index += 1;
            continue;
        }
        if token.starts_with('-') {
            index += 1;
            continue;
        }
        return Some(parts[index..].to_vec());
    }
    None
}

/// `_strip_nice_wrapper` (:270-286).
fn strip_nice_wrapper(parts: &[String]) -> Option<Vec<String>> {
    let mut index = 1usize;
    while index < parts.len() {
        let token = &parts[index];
        if token == "--" {
            return Some(parts[index + 1..].to_vec());
        }
        if NICE_OPTION_FLAGS_WITH_VALUES.contains(&token.as_str()) {
            if index + 1 >= parts.len() {
                return None;
            }
            index += 2;
            continue;
        }
        if token.starts_with("--adjustment=") || (token.starts_with("-n") && token != "-n") {
            index += 1;
            continue;
        }
        if token.starts_with('-') {
            index += 1;
            continue;
        }
        return Some(parts[index..].to_vec());
    }
    None
}

/// `_strip_nohup_wrapper` (:289-292).
fn strip_nohup_wrapper(parts: &[String]) -> Option<Vec<String>> {
    let mut index = 1usize;
    while index < parts.len() && parts[index].starts_with('-') {
        index += 1;
    }
    if index >= parts.len() {
        None
    } else {
        Some(parts[index..].to_vec())
    }
}

/// `_strip_stdbuf_wrapper` (:295-313).
fn strip_stdbuf_wrapper(parts: &[String]) -> Option<Vec<String>> {
    let mut index = 1usize;
    while index < parts.len() {
        let token = &parts[index];
        if token == "--" {
            return Some(parts[index + 1..].to_vec());
        }
        if STDBUF_VALUE_FLAGS.contains(&token.as_str()) {
            if index + 1 >= parts.len() {
                return None;
            }
            index += 2;
            continue;
        }
        if STDBUF_VALUE_FLAGS
            .iter()
            .any(|flag| token.starts_with(flag))
        {
            index += 1;
            continue;
        }
        if token.starts_with('-') {
            index += 1;
            continue;
        }
        return Some(parts[index..].to_vec());
    }
    None
}

/// `_command_name` (:316-334).
fn command_name(
    token: &str,
    env_assignments: &[String],
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> String {
    if !token.contains('/') && !token.contains('\\') {
        if env_assignments_override_path(env_assignments) {
            return String::new();
        }
        return token.to_lowercase();
    }
    let command_path = Path::new(token);
    if !command_path.is_absolute() {
        return String::new();
    }
    if !is_trusted_absolute_command_path(command_path, cwd, home_dir) {
        return String::new();
    }
    command_path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

/// `is_trusted_absolute_command_path` (:337-349).
pub fn is_trusted_absolute_command_path(
    command_path: &Path,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> bool {
    if path_is_under(command_path, cwd) || !stable_non_writable_path(command_path) {
        return false;
    }
    if root_owned_path_chain(command_path) {
        return true;
    }
    path_is_under_trusted_install_dir(command_path, home_dir)
}

/// `_stable_non_writable_path` (:352-362).
fn stable_non_writable_path(path: &Path) -> bool {
    for candidate in path.ancestors() {
        if candidate.is_symlink() {
            if !trusted_symlink_component(candidate) {
                return false;
            }
            continue;
        }
        if !path_is_non_writable(candidate) {
            return false;
        }
        if candidate == candidate.parent().unwrap_or(candidate) {
            break;
        }
    }
    true
}

/// `_root_owned_path_chain` (:365-366).
fn root_owned_path_chain(path: &Path) -> bool {
    path.ancestors().all(path_is_root_owned)
}

/// `_path_is_under_trusted_install_dir` (:369-371).
fn path_is_under_trusted_install_dir(path: &Path, _home_dir: Option<&Path>) -> bool {
    TRUSTED_INSTALL_DIRS
        .iter()
        .any(|d| path_is_under(path, Some(Path::new(d))))
}

/// `_path_is_under` (:374-381).
fn path_is_under(path: &Path, base: Option<&Path>) -> bool {
    let Some(base) = base else {
        return false;
    };
    let resolved = resolve(path);
    let base_resolved = resolve(base);
    resolved.starts_with(&base_resolved)
}

/// `Path.resolve(strict=False)` — canonicalize what exists; fall back to the
/// lexically normalized absolute path for missing tails.
fn resolve(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// `_path_is_root_owned` (:384-385). Missing path → not root-owned.
/// POSIX-only concept; Windows ACLs have no st_uid — treat as not root-owned
/// so downstream checks fall to the non-writable leg (fail-closed parity with
/// the Python early-exit on non-POSIX).
fn path_is_root_owned(path: &Path) -> bool {
    #[cfg(unix)]
    {
        std::fs::metadata(path)
            .map(|m| m.uid() == 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

/// `_trusted_symlink_component` (:388-397).
fn trusted_symlink_component(path: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    if meta.uid() != 0 {
        return false;
    }
    #[cfg(not(unix))]
    let _ = &meta;
    let Ok(resolved) = std::fs::canonicalize(path) else {
        return false;
    };
    path_is_root_owned(&resolved) && path_is_non_writable(&resolved)
}

/// `_path_is_non_writable` (:400-401).
fn path_is_non_writable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        std::fs::metadata(path)
            .map(|m| m.mode() & 0o022 == 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        std::fs::metadata(path)
            .map(|m| m.permissions().readonly())
            .unwrap_or(false)
    }
}

/// `_env_assignments_override_path` (:404-405).
fn env_assignments_override_path(env_assignments: &[String]) -> bool {
    env_assignments
        .iter()
        .any(|a| a.split('=').next() == Some("PATH"))
}

/// `_join_command_fragments` (:408-409).
fn join_command_fragments(fragments: &[&str]) -> String {
    fragments
        .iter()
        .filter(|f| !f.is_empty())
        .map(|f| f.to_string())
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_owned()
}

/// `_join_shell_tokens` (:412-419).
fn join_shell_tokens(tokens: &[String]) -> String {
    let rendered: Vec<String> = tokens
        .iter()
        .map(|token| {
            if SHELL_CONTROL_TOKENS.contains(&token.as_str()) {
                token.clone()
            } else {
                shlex_quote(token)
            }
        })
        .collect();
    rendered.join(" ").trim().to_owned()
}

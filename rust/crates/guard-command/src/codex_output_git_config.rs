//! Git configuration scan for the Codex tool-output review: does a repository
//! (through its config include tree) enable an external diff helper?
//!
//! Anything the retired Python let escape as an exception (`OSError` other than
//! "not there", a symlink loop) is `Err` here and decides "not unconfigured".

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;

use crate::codex_output_env::Ctx;
use crate::codex_output_fs as pyfs;
use crate::codex_output_git_conditions::include_section_is_active;
use crate::codex_output_py::{py_lstrip, py_rstrip, py_splitlines, py_strip, PyPath};

pub(crate) type R<T> = Result<T, ()>;

pub(crate) const WS: &str = r"[\s\x1c-\x1f]";

pub(crate) fn cached(cell: &'static OnceLock<Regex>, pattern: String) -> &'static Regex {
    cell.get_or_init(|| Regex::new(&pattern).expect("static pattern"))
}

pub(crate) fn env_truthy(ctx: &Ctx, name: &str) -> bool {
    ctx.host.env(name).is_some_and(|value| !value.is_empty())
}

pub(crate) fn resolve(path: &PyPath) -> R<PyPath> {
    pyfs::resolve(path).ok_or(())
}

pub(crate) fn expand(ctx: &Ctx, path: &str) -> R<PyPath> {
    ctx.expanduser(path).ok_or(())
}

/// `_git_repo_diff_helpers_are_unconfigured`.
pub(crate) fn repo_diff_helpers_are_unconfigured(ctx: &Ctx, cwd: Option<&PyPath>) -> bool {
    unconfigured(ctx, cwd).unwrap_or(false)
}

fn unconfigured(ctx: &Ctx, cwd: Option<&PyPath>) -> R<bool> {
    let Some(cwd) = cwd else {
        return Ok(false);
    };
    if env_truthy(ctx, "GIT_EXTERNAL_DIFF")
        || env_truthy(ctx, "GIT_CONFIG_COUNT")
        || env_truthy(ctx, "GIT_CONFIG_PARAMETERS")
    {
        return Ok(false);
    }
    let config_paths = repo_config_paths(ctx, cwd)?;
    if config_paths.is_empty() {
        return Ok(true);
    }
    let repo_dir = repo_root(ctx, cwd)?;
    let mut seen = HashSet::new();
    for config_path in &config_paths {
        if !tree_disables_diff_helpers(ctx, config_path, &mut seen, repo_dir.as_ref())? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn with_parents(path: &PyPath) -> Vec<PyPath> {
    let mut chain = vec![path.clone()];
    chain.extend(path.pop_parent_components());
    chain
}

/// `_git_repo_config_paths`.
pub(crate) fn repo_config_paths(ctx: &Ctx, cwd: &PyPath) -> R<Vec<PyPath>> {
    let mut current = resolve(cwd)?;
    if pyfs::is_file(&current)? {
        current = current.parent();
    }
    for candidate in with_parents(&current) {
        let git_path = candidate.join(".git");
        if pyfs::is_dir(&git_path)? {
            let mut paths = global_config_paths(ctx)?;
            paths.push(git_path.join("config"));
            paths.push(git_path.join("config.worktree"));
            return Ok(paths);
        }
        if pyfs::is_file(&git_path)? {
            let Some(git_dir) = git_dir_from_file(&git_path)? else {
                return Ok(Vec::new());
            };
            let common_dir = git_common_dir(&git_dir)?;
            let mut paths = global_config_paths(ctx)?;
            paths.push(git_dir.join("config"));
            paths.push(git_dir.join("config.worktree"));
            if common_dir != git_dir {
                paths.push(common_dir.join("config"));
                paths.push(common_dir.join("config.worktree"));
            }
            return Ok(paths);
        }
    }
    global_config_paths(ctx)
}

/// `_git_repo_root`.
fn repo_root(ctx: &Ctx, cwd: &PyPath) -> R<Option<PyPath>> {
    let mut current = if cwd.is_absolute() {
        cwd.clone()
    } else {
        ctx.process_cwd.join(&cwd.to_string())
    };
    if pyfs::is_file(&current)? {
        current = current.parent();
    }
    for candidate in with_parents(&current) {
        if pyfs::exists(&candidate.join(".git"))? {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

/// `_git_global_config_paths`.
fn global_config_paths(ctx: &Ctx) -> R<Vec<PyPath>> {
    let mut paths = Vec::new();
    match ctx
        .host
        .env("GIT_CONFIG_SYSTEM")
        .filter(|value| !value.is_empty())
    {
        Some(system) => {
            if system != "/dev/null" {
                paths.push(expand(ctx, &system)?);
            }
        }
        None => {
            if !env_truthy(ctx, "GIT_CONFIG_NOSYSTEM") {
                paths.push(PyPath::new("/etc/gitconfig"));
            }
        }
    }
    match ctx
        .host
        .env("GIT_CONFIG_GLOBAL")
        .filter(|value| !value.is_empty())
    {
        Some(global) => {
            if global != "/dev/null" {
                paths.push(expand(ctx, &global)?);
            }
        }
        None => {
            if let Some(home) = ctx.host.env("HOME").filter(|value| !value.is_empty()) {
                let home_path = expand(ctx, &home)?;
                paths.push(home_path.join(".gitconfig"));
                let xdg = ctx
                    .host
                    .env("XDG_CONFIG_HOME")
                    .unwrap_or_else(|| home_path.join(".config").to_string());
                paths.push(expand(ctx, &xdg)?.join("git").join("config"));
            }
        }
    }
    Ok(paths)
}

/// `_git_dir_from_file`: `Ok(None)` is Python's `None`.
pub(crate) fn git_dir_from_file(git_file: &PyPath) -> R<Option<PyPath>> {
    let Some(text) = pyfs::read_text_ignore(git_file) else {
        return Ok(None);
    };
    let content = py_strip(&text);
    let prefix = "gitdir:";
    if !content
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    {
        return Ok(None);
    }
    let raw_path = py_strip(&content[prefix.len()..]);
    let git_dir = PyPath::new(raw_path);
    if git_dir.is_absolute() {
        return Ok(Some(git_dir));
    }
    Ok(Some(resolve(&git_file.parent().join(raw_path))?))
}

/// `_git_common_dir`.
pub(crate) fn git_common_dir(git_dir: &PyPath) -> R<PyPath> {
    let common_dir_file = git_dir.join("commondir");
    if !pyfs::is_file(&common_dir_file)? {
        return Ok(git_dir.clone());
    }
    let Some(text) = pyfs::read_text_ignore(&common_dir_file) else {
        return Ok(git_dir.clone());
    };
    let raw_path = py_strip(&text);
    let common_dir = PyPath::new(raw_path);
    if common_dir.is_absolute() {
        return Ok(common_dir);
    }
    resolve(&git_dir.join(raw_path))
}

pub(crate) fn tree_disables_diff_helpers(
    ctx: &Ctx,
    config_path: &PyPath,
    seen: &mut HashSet<PyPath>,
    repo_dir: Option<&PyPath>,
) -> R<bool> {
    let normalized = resolve(&expand(ctx, &config_path.to_string())?)?;
    if !seen.insert(normalized.clone()) {
        return Ok(true);
    }
    if !pyfs::is_file(&normalized)? {
        return Ok(true);
    }
    let Some(config_text) = pyfs::read_text_ignore(&normalized) else {
        return Ok(false);
    };
    if config_enables_diff_helper(&config_text) {
        return Ok(false);
    }
    for included in include_paths(ctx, &config_text, true, &normalized.parent(), repo_dir)? {
        if !tree_disables_diff_helpers(ctx, &included, seen, repo_dir)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// `_git_config_value_without_inline_comment`.
pub(crate) fn value_without_inline_comment(raw_value: &str) -> String {
    let value = py_strip(raw_value);
    let Some(first) = value.chars().next() else {
        return value.to_owned();
    };
    if first == '\'' || first == '"' {
        let mut escaped = false;
        let mut parsed = String::new();
        for c in value.chars().skip(1) {
            if escaped {
                parsed.push(c);
                escaped = false;
                continue;
            }
            if c == '\\' {
                escaped = true;
                continue;
            }
            if c == first {
                return parsed;
            }
            parsed.push(c);
        }
        return parsed;
    }
    let chars: Vec<char> = value.chars().collect();
    for (index, c) in chars.iter().enumerate() {
        if (*c == '#' || *c == ';')
            && (index == 0 || crate::codex_output_py::is_py_space(chars[index - 1]))
        {
            let head: String = chars[..index].iter().collect();
            return py_strip(&head).to_owned();
        }
    }
    value.to_owned()
}

fn line_continues(line: &str) -> bool {
    line.chars().rev().take_while(|c| *c == '\\').count() % 2 == 1
}

/// `_git_config_logical_lines`.
pub(crate) fn logical_lines(config_text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut pending = String::new();
    for raw_line in py_splitlines(config_text) {
        let line = py_rstrip(&raw_line);
        if line_continues(line) {
            pending.push_str(&line[..line.len() - 1]);
            continue;
        }
        if !pending.is_empty() {
            lines.push(format!("{pending}{}", py_lstrip(line)));
            pending.clear();
            continue;
        }
        lines.push(line.to_owned());
    }
    if !pending.is_empty() {
        lines.push(pending);
    }
    lines
}

/// `_git_config_enables_diff_helper`.
pub(crate) fn config_enables_diff_helper(config_text: &str) -> bool {
    static CELL: OnceLock<Regex> = OnceLock::new();
    let pattern = cached(
        &CELL,
        format!(r"(?i)^{WS}*(?:command|external|textconv){WS}*="),
    );
    logical_lines(config_text)
        .iter()
        .any(|line| pattern.is_match(line))
}

pub(crate) fn section_name(line: &str) -> Option<String> {
    static CELL: OnceLock<Regex> = OnceLock::new();
    let pattern = cached(&CELL, format!(r"^\[([^\]]+)\](?:{WS}*[#;].*)?$"));
    pattern
        .captures(line)
        .map(|captures| py_strip(&captures[1]).to_owned())
}

/// `_git_config_include_paths`.
pub(crate) fn include_paths(
    ctx: &Ctx,
    config_text: &str,
    allow_hasconfig: bool,
    base_dir: &PyPath,
    repo_dir: Option<&PyPath>,
) -> R<Vec<PyPath>> {
    static CELL: OnceLock<Regex> = OnceLock::new();
    let key = cached(&CELL, format!(r"(?i)^path{WS}*={WS}*(.+)$"));
    let mut paths = Vec::new();
    let mut section_active = false;
    for raw_line in logical_lines(config_text) {
        let line = py_strip(&raw_line);
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(section) = section_name(line) {
            section_active =
                include_section_is_active(ctx, &section, allow_hasconfig, base_dir, repo_dir)?;
            continue;
        }
        if !section_active {
            continue;
        }
        let Some(captures) = key.captures(line) else {
            continue;
        };
        let value = value_without_inline_comment(&captures[1]);
        let include_path = expand(ctx, &value)?;
        if include_path.is_absolute() {
            paths.push(include_path);
        } else {
            paths.push(resolve(&base_dir.join(&include_path.to_string()))?);
        }
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_detection_and_values_follow_python() {
        assert!(config_enables_diff_helper(
            "[diff \"x\"]\n  textconv = cat\n"
        ));
        assert!(config_enables_diff_helper("[diff]\n\texternal=foo"));
        assert!(!config_enables_diff_helper("[core]\n\tautocrlf = true\n"));
        assert!(config_enables_diff_helper(
            "[diff \"x\"]\n  text\\\nconv = cat\n"
        ));
        assert_eq!(value_without_inline_comment("a/b # note"), "a/b");
        assert_eq!(value_without_inline_comment("\"a b\" # n"), "a b");
        assert_eq!(value_without_inline_comment("a#b"), "a#b");
        assert!(line_continues("a\\"));
        assert!(!line_continues("a\\\\"));
    }
}

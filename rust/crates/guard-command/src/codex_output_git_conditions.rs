//! Git config include-condition matching (`gitdir`, `onbranch`, `hasconfig`).

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;

use crate::codex_output_env::Ctx;
use crate::codex_output_fnmatch::fnmatchcase;
use crate::codex_output_fs as pyfs;
use crate::codex_output_git_config::{
    cached, expand, git_dir_from_file, include_paths, logical_lines, repo_config_paths, resolve,
    section_name, value_without_inline_comment, R, WS,
};
use crate::codex_output_py::{py_strip, PyPath};

fn strip_prefix_chars(text: &str, count: usize) -> String {
    text.chars().skip(count).collect()
}

/// `_git_include_section_is_active`.
pub(crate) fn include_section_is_active(
    ctx: &Ctx,
    section: &str,
    allow_hasconfig: bool,
    base_dir: &PyPath,
    repo_dir: Option<&PyPath>,
) -> R<bool> {
    static QUOTED: OnceLock<Regex> = OnceLock::new();
    let lower = section.to_lowercase();
    if lower == "include" {
        return Ok(true);
    }
    if !lower.starts_with("includeif") {
        return Ok(false);
    }
    let Some(repo_dir) = repo_dir else {
        return Ok(false);
    };
    let quoted = cached(&QUOTED, r#""([^"]+)""#.to_owned());
    let condition = match quoted.captures(section) {
        Some(captures) => captures[1].to_owned(),
        None => py_strip(section.strip_prefix("includeif").unwrap_or(section)).to_owned(),
    };
    let condition_lower = condition.to_lowercase();
    if condition_lower.starts_with("gitdir/i:") {
        return gitdir_condition_matches(
            ctx,
            &strip_prefix_chars(&condition, 9),
            base_dir,
            repo_dir,
            false,
        );
    }
    if condition_lower.starts_with("gitdir:") {
        return gitdir_condition_matches(
            ctx,
            &strip_prefix_chars(&condition, 7),
            base_dir,
            repo_dir,
            true,
        );
    }
    if condition_lower.starts_with("onbranch:") {
        return onbranch_condition_matches(&strip_prefix_chars(&condition, 9), repo_dir);
    }
    if allow_hasconfig && condition_lower.starts_with("hasconfig:") {
        return hasconfig_condition_matches(ctx, &strip_prefix_chars(&condition, 10), repo_dir);
    }
    Ok(false)
}

fn gitdir_condition_matches(
    ctx: &Ctx,
    pattern: &str,
    base_dir: &PyPath,
    repo_dir: &PyPath,
    case_sensitive: bool,
) -> R<bool> {
    let pattern_text = gitdir_condition_pattern(ctx, pattern, base_dir)?;
    let patterns = gitdir_condition_patterns(&pattern_text);
    let mut candidates: Vec<String> = path_aliases(repo_dir)?
        .iter()
        .map(gitdir_condition_candidate)
        .collect();
    if let Some(git_dir) = effective_git_dir(repo_dir)? {
        candidates.extend(
            path_aliases(&git_dir)?
                .iter()
                .map(gitdir_condition_candidate),
        );
    }
    Ok(candidates.iter().any(|candidate| {
        patterns.iter().any(|item| {
            if case_sensitive {
                fnmatchcase(candidate, item)
            } else {
                fnmatchcase(&candidate.to_lowercase(), &item.to_lowercase())
            }
        })
    }))
}

fn path_aliases(path: &PyPath) -> R<Vec<PyPath>> {
    let resolved = resolve(path)?;
    if &resolved == path {
        return Ok(vec![path.clone()]);
    }
    Ok(vec![path.clone(), resolved])
}

fn gitdir_condition_candidate(path: &PyPath) -> String {
    format!("{}/", path.to_string().trim_end_matches('/'))
}

fn gitdir_condition_patterns(pattern_text: &str) -> Vec<String> {
    if pattern_text.ends_with("/**") {
        return vec![pattern_text.to_owned()];
    }
    if pattern_text.ends_with('/') {
        return vec![pattern_text.to_owned(), format!("{pattern_text}**")];
    }
    vec![
        pattern_text.to_owned(),
        format!("{pattern_text}/"),
        format!("{pattern_text}/**"),
    ]
}

fn gitdir_condition_pattern(ctx: &Ctx, pattern: &str, base_dir: &PyPath) -> R<String> {
    let expanded = py_strip(pattern);
    let pattern_path = expand(ctx, expanded)?;
    if pattern_path.is_absolute() {
        return Ok(pattern_path.to_string());
    }
    if expanded.starts_with("./") || expanded.starts_with("../") {
        return Ok(resolve(&base_dir.join(&pattern_path.to_string()))?.to_string());
    }
    Ok(format!("**/{expanded}"))
}

fn effective_git_dir(repo_dir: &PyPath) -> R<Option<PyPath>> {
    let git_path = repo_dir.join(".git");
    if pyfs::is_dir(&git_path)? {
        return Ok(Some(git_path));
    }
    if pyfs::is_file(&git_path)? {
        return git_dir_from_file(&git_path);
    }
    Ok(None)
}

fn onbranch_condition_matches(pattern: &str, repo_dir: &PyPath) -> R<bool> {
    let git_dir = repo_dir.join(".git");
    let head_path = if pyfs::is_dir(&git_dir)? {
        Some(git_dir.join("HEAD"))
    } else if pyfs::is_file(&git_dir)? {
        git_dir_from_file(&git_dir)?.map(|parsed| parsed.join("HEAD"))
    } else {
        None
    };
    let Some(head_path) = head_path else {
        return Ok(false);
    };
    if !pyfs::is_file(&head_path)? {
        return Ok(false);
    }
    let Some(text) = pyfs::read_text_ignore(&head_path) else {
        return Ok(false);
    };
    let head = py_strip(&text);
    let Some(branch) = head.strip_prefix("ref: refs/heads/") else {
        return Ok(false);
    };
    let normalized = if pattern.ends_with('/') {
        format!("{pattern}**")
    } else {
        pattern.to_owned()
    };
    Ok(fnmatchcase(branch, &normalized))
}

fn hasconfig_condition_matches(ctx: &Ctx, condition: &str, repo_dir: &PyPath) -> R<bool> {
    let Some((key_pattern, value_pattern)) = condition.split_once(':') else {
        return Ok(false);
    };
    if key_pattern.is_empty() || value_pattern.is_empty() {
        return Ok(false);
    }
    if key_pattern.to_lowercase() != "remote.*.url" {
        return Ok(false);
    }
    let mut seen = HashSet::new();
    for config_path in repo_config_paths(ctx, repo_dir)? {
        let urls = remote_urls_from_config_tree(ctx, &config_path, &mut seen, repo_dir)?;
        if urls.iter().any(|value| fnmatchcase(value, value_pattern)) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn remote_urls_from_config_tree(
    ctx: &Ctx,
    config_path: &PyPath,
    seen: &mut HashSet<PyPath>,
    repo_dir: &PyPath,
) -> R<Vec<String>> {
    let normalized = resolve(&expand(ctx, &config_path.to_string())?)?;
    if !seen.insert(normalized.clone()) {
        return Ok(Vec::new());
    }
    if !pyfs::is_file(&normalized)? {
        return Ok(Vec::new());
    }
    let Some(config_text) = pyfs::read_text_ignore(&normalized) else {
        return Ok(Vec::new());
    };
    let mut urls = remote_urls_from_config(&config_text);
    for included in include_paths(
        ctx,
        &config_text,
        false,
        &normalized.parent(),
        Some(repo_dir),
    )? {
        urls.extend(remote_urls_from_config_tree(
            ctx, &included, seen, repo_dir,
        )?);
    }
    Ok(urls)
}

fn remote_urls_from_config(config_text: &str) -> Vec<String> {
    static CELL: OnceLock<Regex> = OnceLock::new();
    let key = cached(&CELL, format!(r"(?i)^url{WS}*={WS}*(.+)$"));
    let mut urls = Vec::new();
    let mut in_remote_section = false;
    for raw_line in logical_lines(config_text) {
        let line = py_strip(&raw_line);
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(section) = section_name(line) {
            in_remote_section = section.to_lowercase().starts_with("remote ");
            continue;
        }
        if !in_remote_section {
            continue;
        }
        if let Some(captures) = key.captures(line) {
            urls.push(value_without_inline_comment(&captures[1]));
        }
    }
    urls
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gitdir_patterns_follow_python() {
        assert_eq!(gitdir_condition_patterns("/x/"), vec!["/x/", "/x/**"]);
    }
}

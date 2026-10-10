//! Source-path classification (`runtime/source_paths.py`) for the Codex
//! tool-output review. Decisions and reason codes match the retired Python.

use std::path::{Path, PathBuf};

use crate::codex_output_env::Ctx;
use crate::codex_output_fs as pyfs;
use crate::codex_output_py::{py_strip, strip_quotes, PyPath};
use crate::false_positive_rules::{
    target_is_known_skill_doc_path, SOURCE_INSPECTION_BENIGN_DOTFILES,
    SOURCE_INSPECTION_EXTENSIONS, SOURCE_INSPECTION_PARTS, SOURCE_INSPECTION_SENSITIVE_PARTS,
};
use crate::shell_secret_read_support::classify_secret_path;

const EXTRA_EXTERNAL_SENSITIVE: &[&str] = &[
    "auth",
    "authorization",
    "credential",
    "credentials",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "passwd",
    "password",
    "private-key",
    "private_key",
    "secret",
    "secrets",
    "token",
    "tokens",
];

pub(crate) fn is_benign_source_dotfile(name: &str) -> bool {
    name == ".worktrees" || SOURCE_INSPECTION_BENIGN_DOTFILES.contains(&name)
}

pub(crate) fn is_sensitive_search_basename(name: &str) -> bool {
    name == "id_rsa" || SOURCE_INSPECTION_SENSITIVE_PARTS.contains(&name)
}

fn is_external_sensitive(name: &str) -> bool {
    is_sensitive_search_basename(name) || EXTRA_EXTERNAL_SENSITIVE.contains(&name)
}

fn is_source_part(name: &str) -> bool {
    SOURCE_INSPECTION_PARTS.contains(&name)
}

fn is_source_extension(suffix: &str) -> bool {
    SOURCE_INSPECTION_EXTENSIONS.contains(&suffix)
}

fn has_source_prefix(normalized: &str) -> bool {
    SOURCE_INSPECTION_PARTS
        .iter()
        .any(|part| normalized.starts_with(&format!("{part}/")))
}

/// `_hidden_parts_are_allowed_source` over already-lowered parts.
pub(crate) fn hidden_parts_are_allowed_source(parts: &[String]) -> bool {
    let hidden: Vec<&str> = parts
        .iter()
        .map(String::as_str)
        .filter(|part| part.starts_with('.'))
        .collect();
    if hidden.is_empty() || hidden.iter().all(|part| is_benign_source_dotfile(part)) {
        return true;
    }
    let workflow = parts
        .windows(2)
        .any(|pair| pair[0] == ".github" && pair[1] == "workflows");
    workflow && hidden == [".github"]
}

/// `SourcePathDecision` without the resolved path no caller reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SourceDecision {
    pub allowed: bool,
    pub reason_code: &'static str,
}

fn deny(reason_code: &'static str) -> SourceDecision {
    SourceDecision {
        allowed: false,
        reason_code,
    }
}

fn allow(reason_code: &'static str) -> SourceDecision {
    SourceDecision {
        allowed: true,
        reason_code,
    }
}

/// `path_contains_symlink`: `true` also when `path` escapes `base_dir`.
pub(crate) fn path_contains_symlink(path: &PyPath, base_dir: &PyPath) -> bool {
    let Some(relative) = path.relative_to(base_dir) else {
        return true;
    };
    let mut candidate = base_dir.clone();
    for part in relative {
        candidate = candidate.join(&part);
        if pyfs::is_symlink(&candidate).unwrap_or(true) {
            return true;
        }
    }
    false
}

fn path_contains_symlink_component(path: &PyPath) -> bool {
    let mut candidate = PyPath::new(path.root());
    for part in path.components() {
        if part == ".." {
            candidate = candidate.parent();
            continue;
        }
        candidate = candidate.join(part);
        if pyfs::is_symlink(&candidate).unwrap_or(true) {
            return true;
        }
    }
    false
}

fn is_immediate_sibling_git_checkout(path: &PyPath, workspace: &PyPath) -> bool {
    let parent = workspace.parent();
    let Some(relative) = path.relative_to(&parent) else {
        return false;
    };
    let Some(first) = relative.first() else {
        return false;
    };
    let checkout = parent.join(first);
    if checkout == *workspace {
        return false;
    }
    let marker = checkout.join(".git");
    let Ok(linked) = pyfs::is_symlink(&marker) else {
        return false;
    };
    if linked {
        return false;
    }
    match (pyfs::is_file(&marker), pyfs::is_dir(&marker)) {
        (Ok(file), Ok(dir)) => file || dir,
        _ => false,
    }
}

fn external_filename_is_sensitive(path: &PyPath) -> bool {
    let filename = path.name().to_lowercase();
    let stem = PyPath::new(&filename).stem().to_owned();
    if is_external_sensitive(&filename) || is_external_sensitive(&stem) {
        return true;
    }
    stem.replace(['-', '.'], "_").split('_').any(|token| {
        !token.is_empty()
            && (is_external_sensitive(token) || is_external_sensitive(&format!(".{token}")))
    })
}

/// `resolve_source_candidate_path`. `base` is `(cwd or Path.cwd())`.
pub(crate) fn resolve_source_candidate_path(
    target: &str,
    cwd: Option<&PyPath>,
    home_dir: Option<&PyPath>,
    ctx: &Ctx,
) -> Option<PyPath> {
    let stripped = strip_quotes(py_strip(target));
    if stripped.is_empty() {
        return None;
    }
    if stripped.starts_with('~') {
        let home = home_dir?;
        if stripped == "~" {
            return pyfs::resolve(home);
        }
        let rest = stripped.strip_prefix("~/")?;
        return pyfs::resolve(&home.join(rest));
    }
    let target_path = PyPath::new(stripped);
    if target_path.is_absolute() {
        return Some(target_path);
    }
    let base = pyfs::resolve(cwd.unwrap_or(&ctx.process_cwd))?;
    Some(base.join(&target_path.to_string()))
}

fn std_path(path: Option<&PyPath>) -> Option<PathBuf> {
    path.map(|value| PathBuf::from(value.to_string()))
}

/// `source_path_is_allowed`.
pub(crate) fn source_path_is_allowed(
    target: &str,
    cwd: Option<&PyPath>,
    home_dir: Option<&PyPath>,
    ctx: &Ctx,
    allow_external_source: bool,
) -> SourceDecision {
    let stripped = strip_quotes(py_strip(target));
    if stripped.is_empty() {
        return deny("empty_path");
    }
    let normalized_text = stripped.replace('\\', "/");
    let lexical: Vec<&str> = normalized_text
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    if lexical.contains(&"..") {
        return deny("path_traversal");
    }
    if stripped.chars().any(|c| matches!(c, '*' | '?' | '{' | '}')) {
        return deny("glob_pattern");
    }
    let cwd_std = std_path(cwd);
    let home_std = std_path(Some(home_dir.unwrap_or(&ctx.default_home)));
    if classify_secret_path(stripped, cwd_std.as_deref(), home_std.as_deref()).is_some() {
        return deny("sensitive_basename");
    }
    if lexical
        .iter()
        .any(|part| is_sensitive_search_basename(&part.to_lowercase()))
    {
        return deny("sensitive_basename");
    }
    if target_is_known_skill_doc_path(stripped, home_std.as_deref()) {
        return allow("known_skill_doc_path");
    }
    if let Some(home) = home_dir {
        let safety = home.join(".hol-support").join("SAFETY.md");
        if (stripped == "~/.hol-support/SAFETY.md" || stripped == safety.to_string())
            && pyfs::is_file(&safety) == Ok(true)
            && pyfs::is_symlink(&safety) == Ok(false)
        {
            return allow("guard_safety_doc_path");
        }
    }
    let Some(base_dir) = pyfs::resolve(cwd.unwrap_or(&ctx.process_cwd)) else {
        return deny("unresolved_path");
    };
    let external_requested = PyPath::new(stripped).is_absolute() || stripped.starts_with("~/");
    let target_path = match (stripped.strip_prefix("~/"), home_dir) {
        (Some(rest), Some(home)) => Some(home.join(rest)),
        _ => resolve_source_candidate_path(stripped, Some(&base_dir), home_dir, ctx),
    };
    let Some(target_path) = target_path else {
        return deny("unresolved_path");
    };

    let inside_lexically = target_path.relative_to(&base_dir).is_some();
    if inside_lexically {
        if path_contains_symlink(&target_path, &base_dir) {
            return deny("symlink_in_path");
        }
    } else {
        if !allow_external_source || !external_requested {
            return deny("absolute_path_outside_workspace");
        }
        if path_contains_symlink_component(&target_path) {
            return deny("symlink_in_path");
        }
    }
    let Some(candidate) = pyfs::resolve(&target_path) else {
        return deny("absolute_path_outside_workspace");
    };
    let parts: Vec<String> = if let Some(relative) = candidate.relative_to(&base_dir) {
        relative
    } else {
        return external_decision(
            stripped,
            &candidate,
            &base_dir,
            home_dir,
            allow_external_source && external_requested,
        );
    };
    if parts.is_empty() {
        return deny("empty_resolved_path");
    }
    let lowered: Vec<String> = parts.iter().map(|part| part.to_lowercase()).collect();
    if lowered
        .iter()
        .any(|part| is_sensitive_search_basename(part))
    {
        return deny("sensitive_basename");
    }
    if !hidden_parts_are_allowed_source(&lowered) {
        return deny("unsafe_hidden_dir");
    }
    let normalized = parts.join("/");
    if SOURCE_INSPECTION_PARTS.contains(&normalized.as_str()) {
        return allow("source_prefix_exact");
    }
    if has_source_prefix(&normalized) {
        return allow("source_prefix");
    }
    if lowered.iter().any(|part| is_source_part(part)) {
        return allow("source_inspection_part");
    }
    let literal = PyPath::new(stripped);
    if is_benign_source_dotfile(&literal.name().to_lowercase()) {
        return allow("benign_source_dotfile");
    }
    if is_source_extension(&literal.suffix().to_lowercase()) {
        return allow("source_extension");
    }
    deny("not_source_like")
}

fn external_decision(
    stripped: &str,
    candidate: &PyPath,
    base_dir: &PyPath,
    home_dir: Option<&PyPath>,
    external_allowed: bool,
) -> SourceDecision {
    if !external_allowed {
        return deny("absolute_path_outside_workspace");
    }
    let Some(home) = home_dir else {
        return deny("external_home_unavailable");
    };
    let Some(resolved_home) = pyfs::resolve(home) else {
        return deny("external_home_unavailable");
    };
    if pyfs::exists(&resolved_home) != Ok(true) || pyfs::is_dir(&resolved_home) != Ok(true) {
        return deny("external_home_unavailable");
    }
    if candidate.relative_to(&resolved_home).is_none() {
        return deny("external_target_outside_home");
    }
    if !is_immediate_sibling_git_checkout(candidate, base_dir) {
        return deny("external_target_not_sibling_git_checkout");
    }
    let readable = pyfs::exists(candidate) == Ok(true)
        && (pyfs::is_file(candidate) == Ok(true) || pyfs::is_dir(candidate) == Ok(true));
    if !readable {
        return deny("external_target_not_readable");
    }
    let parts: Vec<String> = candidate.components().to_vec();
    let lowered: Vec<String> = parts.iter().map(|part| part.to_lowercase()).collect();
    if lowered.iter().any(|part| is_external_sensitive(part))
        || external_filename_is_sensitive(candidate)
    {
        return deny("sensitive_basename");
    }
    if !hidden_parts_are_allowed_source(&lowered) {
        return deny("unsafe_hidden_dir");
    }
    let normalized = parts.join("/");
    let source_like = has_source_prefix(&normalized)
        || lowered.iter().any(|part| is_source_part(part))
        || is_source_extension(&PyPath::new(stripped).suffix().to_lowercase());
    if !source_like {
        return deny("not_source_like");
    }
    allow("external_source_path")
}

/// Convenience for callers holding std paths.
pub(crate) fn py_path(path: &Path) -> PyPath {
    PyPath::new(&path.to_string_lossy())
}

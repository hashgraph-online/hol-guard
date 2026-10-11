//! Native search-scope proof for Claude Code's structured `Grep` tool.
//!
//! Claude's `Grep` searches hidden files, honors ignore files, and skips
//! `.git`. A directory search is allowed only after a bounded metadata walk
//! shows that no sensitive file is reachable. File contents are never read;
//! only ignore files are parsed. Any ambiguity falls back to normal review.

use super::search_scope_filter::{Override, SearchFilter};
use super::search_scope_ignore::{
    is_ignored, load_ignore_file, slash_path, IgnoreRule, IgnoreTiers, ScopeUnproven,
};
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};
use std::rc::Rc;

const MAX_SCOPE_ENTRIES: usize = 20_000;
const MAX_SCOPE_DEPTH: usize = 64;
const MAX_ANCESTORS: usize = 64;

/// Keys Claude Code documents for `Grep`. Unknown keys could change scope.
const CLAUDE_GREP_KEYS: &[&str] = &[
    "pattern",
    "path",
    "glob",
    "type",
    "output_mode",
    "-i",
    "-n",
    "-A",
    "-B",
    "-C",
    "context",
    "head_limit",
    "offset",
    "multiline",
];

/// True when a Claude `Grep` directory search cannot reach a sensitive file.
/// A single-file target returns false so the existing file-read proof decides.
pub(super) fn claude_grep_directory_scope_proven(
    payload: &Value,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    let Some(input) = claude_grep_input(payload) else {
        return false;
    };
    let target = match input.get("path") {
        None => ".",
        Some(Value::String(path)) if !path.is_empty() => path.as_str(),
        Some(_) => return false,
    };
    let Some(filter) = SearchFilter::from_input(input) else {
        return false;
    };
    let Some(root) = verified_directory_root(target, home_dir, cwd) else {
        return false;
    };
    walk_scope(&root, &filter, true).is_ok()
}

/// True when a Claude `Glob` returns only names under a verified directory
/// whose whole reachable tree holds no sensitive file. The pattern must stay
/// inside that directory: relative, no `..`, no alternation or escapes.
pub(super) fn claude_glob_scope_proven(
    payload: &Value,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    let Some(root) = payload.as_object() else {
        return false;
    };
    if root.get("tool_name").and_then(Value::as_str) != Some("Glob")
        || ["toolInput", "tool_args", "arguments", "input", "parameters"]
            .iter()
            .any(|key| root.contains_key(*key))
    {
        return false;
    }
    let Some(input) = root.get("tool_input").and_then(Value::as_object) else {
        return false;
    };
    if input
        .keys()
        .any(|key| !matches!(key.as_str(), "pattern" | "path"))
    {
        return false;
    }
    let Some(pattern) = input.get("pattern").and_then(Value::as_str) else {
        return false;
    };
    if pattern.is_empty()
        || pattern.len() > 1024
        || pattern.starts_with(['/', '~', '\\'])
        || pattern.contains(['\0', '\n', '\r', '$', '`', '\\', '{', '}', '(', ')', '!'])
        || pattern.split('/').any(|part| part == "..")
        || pattern.as_bytes().get(1) == Some(&b':')
    {
        return false;
    }
    let target = match input.get("path") {
        None => ".",
        Some(Value::String(path)) if !path.is_empty() => path.as_str(),
        Some(_) => return false,
    };
    unfiltered_directory_scope_proven(target, home_dir, cwd)
}

/// Host-neutral variant for hosts whose search semantics are not modeled
/// (Oh My Pi `grep`). No filter or ignore file narrows the scope: any
/// sensitive file reachable below the directory fails the proof, so the
/// result is at least as strict as the host's real search.
pub(super) fn unfiltered_directory_scope_proven(
    target: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    let Some(filter) = SearchFilter::from_input(&Map::new()) else {
        return false;
    };
    if !super::safe_reads::bounded_omp_directory_read_target(target, home_dir, cwd) {
        return false;
    }
    let candidate = if Path::new(target).is_absolute() {
        PathBuf::from(target)
    } else if let Some(stripped) = target.strip_prefix("~/") {
        match home_dir {
            Some(home) => Path::new(home).join(stripped),
            None => return false,
        }
    } else if target == "~" {
        return false;
    } else {
        match cwd {
            Some(cwd) => Path::new(cwd).join(target),
            None => return false,
        }
    };
    if guard_secure_fs::contains_symlink_component(&candidate) {
        return false;
    }
    std::fs::canonicalize(candidate)
        .ok()
        .filter(|root| root.is_dir())
        .is_some_and(|root| walk_scope(&root, &filter, false).is_ok())
}

fn claude_grep_input(payload: &Value) -> Option<&Map<String, Value>> {
    let root = payload.as_object()?;
    if root.get("tool_name").and_then(Value::as_str) != Some("Grep") {
        return None;
    }
    // Alternate spellings could carry a second, conflicting input.
    if ["toolInput", "tool_args", "arguments", "input", "parameters"]
        .iter()
        .any(|key| root.contains_key(*key))
    {
        return None;
    }
    let input = root.get("tool_input")?.as_object()?;
    if input
        .keys()
        .any(|key| !CLAUDE_GREP_KEYS.contains(&key.as_str()))
    {
        return None;
    }
    input
        .get("pattern")?
        .as_str()
        .filter(|pattern| !pattern.is_empty())?;
    if let Some(mode) = input.get("output_mode") {
        if !matches!(
            mode.as_str(),
            Some("content" | "files_with_matches" | "count")
        ) {
            return None;
        }
    }
    Some(input)
}

fn verified_directory_root(
    target: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> Option<PathBuf> {
    if !super::safe_reads::verified_path_context(home_dir, cwd) {
        return None;
    }
    if !super::safe_reads::bounded_read_target(target, home_dir, cwd, true) {
        return None;
    }
    let candidate = if Path::new(target).is_absolute() {
        PathBuf::from(target)
    } else {
        Path::new(cwd?).join(target)
    };
    if guard_secure_fs::contains_symlink_component(&candidate) {
        return None;
    }
    let canonical = std::fs::canonicalize(candidate).ok()?;
    canonical.is_dir().then_some(canonical)
}

/// Locate the enclosing repository so its `.gitignore` files apply, as
/// ripgrep honors them only inside a Git repository.
fn repository_root(root: &Path) -> Option<PathBuf> {
    root.ancestors()
        .take(MAX_ANCESTORS)
        .find(|directory| std::fs::symlink_metadata(directory.join(".git")).is_ok())
        .map(Path::to_path_buf)
}

/// `.ignore` and `.rgignore` rules from every ancestor above the search
/// root, outermost first. ripgrep reads these with or without a repository.
fn ancestor_custom_rules(root: &Path, tiers: &mut IgnoreTiers) -> Result<(), ScopeUnproven> {
    let ancestors: Vec<&Path> = root.ancestors().skip(1).take(MAX_ANCESTORS).collect();
    if root.ancestors().skip(1).nth(MAX_ANCESTORS).is_some() {
        return Err(ScopeUnproven);
    }
    for directory in ancestors.into_iter().rev() {
        load_custom_rules(directory, tiers)?;
    }
    Ok(())
}

fn load_custom_rules(directory: &Path, tiers: &mut IgnoreTiers) -> Result<(), ScopeUnproven> {
    let base = slash_path(directory).ok_or(ScopeUnproven)?;
    load_ignore_file(&directory.join(".ignore"), &base, &mut tiers.ignore)?;
    load_ignore_file(&directory.join(".rgignore"), &base, &mut tiers.rgignore)
}

/// Repository exclude rules and `.gitignore` files from the repository root
/// down to the search root's parent.
fn ancestor_git_rules(root: &Path, repository: &Path) -> Result<Vec<IgnoreRule>, ScopeUnproven> {
    let mut rules = Vec::new();
    let git_directory = repository.join(".git");
    if std::fs::symlink_metadata(&git_directory).is_ok_and(|metadata| metadata.is_dir()) {
        let base = slash_path(repository).ok_or(ScopeUnproven)?;
        load_ignore_file(
            &git_directory.join("info").join("exclude"),
            &base,
            &mut rules,
        )?;
    }
    let mut chain: Vec<&Path> = root
        .ancestors()
        .skip(1)
        .take_while(|directory| directory.starts_with(repository))
        .collect();
    chain.reverse();
    for directory in chain {
        let base = slash_path(directory).ok_or(ScopeUnproven)?;
        load_ignore_file(&directory.join(".gitignore"), &base, &mut rules)?;
    }
    Ok(rules)
}

fn sensitive_scope_file(path: &Path) -> bool {
    guard_secure_fs::sensitive_path_family(path).is_some()
        || guard_secure_fs::credential_named_path(path)
}

struct PendingDirectory {
    path: PathBuf,
    depth: usize,
    tiers: Rc<IgnoreTiers>,
}

fn walk_scope(
    root: &Path,
    filter: &SearchFilter,
    honor_ignores: bool,
) -> Result<(), ScopeUnproven> {
    let repository = repository_root(root).filter(|_| honor_ignores);
    let mut tiers = IgnoreTiers::default();
    if let Some(repository) = &repository {
        tiers.git = ancestor_git_rules(root, repository)?;
    }
    if honor_ignores {
        ancestor_custom_rules(root, &mut tiers)?;
    }
    let mut pending = vec![PendingDirectory {
        path: root.to_path_buf(),
        depth: 0,
        tiers: Rc::new(tiers),
    }];
    let mut inspected = 0_usize;
    while let Some(directory) = pending.pop() {
        if directory.depth > MAX_SCOPE_DEPTH {
            return Err(ScopeUnproven);
        }
        let base = slash_path(&directory.path).ok_or(ScopeUnproven)?;
        let mut tiers = (*directory.tiers).clone();
        if repository.is_some() {
            // A nested repository may not inherit outer git rules. Dropping
            // them can only widen the modeled scope.
            if directory.depth > 0 && std::fs::symlink_metadata(directory.path.join(".git")).is_ok()
            {
                tiers.git.clear();
            }
            load_ignore_file(&directory.path.join(".gitignore"), &base, &mut tiers.git)?;
        }
        if honor_ignores {
            load_custom_rules(&directory.path, &mut tiers)?;
        }
        let tiers = Rc::new(tiers);
        let entries = std::fs::read_dir(&directory.path).map_err(|_| ScopeUnproven)?;
        for entry in entries {
            let entry = entry.map_err(|_| ScopeUnproven)?;
            inspected += 1;
            if inspected > MAX_SCOPE_ENTRIES {
                return Err(ScopeUnproven);
            }
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_str().ok_or(ScopeUnproven)?;
            // The Claude walk models ripgrep and skips .git. The host-neutral
            // walk has no such model, so it must inspect repository metadata.
            if name == ".git" && honor_ignores {
                continue;
            }
            // Metadata only: never follow links or open a candidate secret.
            let metadata = std::fs::symlink_metadata(&path).map_err(|_| ScopeUnproven)?;
            if metadata.file_type().is_symlink() {
                // Claude's Grep does not follow links. Still refuse a link
                // whose name or file target is sensitive, in case it would.
                let target = std::fs::canonicalize(&path).ok();
                if sensitive_scope_file(&path)
                    || target
                        .as_deref()
                        .is_some_and(|target| target.is_file() && sensitive_scope_file(target))
                {
                    return Err(ScopeUnproven);
                }
                continue;
            }
            let is_directory = metadata.is_dir();
            if !is_directory && !metadata.is_file() {
                return Err(ScopeUnproven);
            }
            let searched = match filter.override_for(name, is_directory) {
                Override::Skipped => continue,
                Override::Searched => true,
                Override::Undecided => {
                    let rendered = slash_path(&path).ok_or(ScopeUnproven)?;
                    if honor_ignores && is_ignored(&tiers, &rendered, is_directory)? {
                        continue;
                    }
                    is_directory || filter.type_allows(name)
                }
            };
            if is_directory {
                pending.push(PendingDirectory {
                    path,
                    depth: directory.depth + 1,
                    tiers: Rc::clone(&tiers),
                });
            } else if searched && sensitive_scope_file(&path) {
                return Err(ScopeUnproven);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "search_scope_tests.rs"]
mod tests;

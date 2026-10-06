//! Native search-scope proof for Claude Code's structured `Grep` tool.
//!
//! Claude's `Grep` searches hidden files, honors `.gitignore`, and skips
//! `.git`. A directory search is allowed only after a bounded metadata walk
//! shows that no sensitive file is reachable. File contents are never read;
//! only ignore files are parsed. Any ambiguity falls back to normal review.

use super::search_scope_glob::{expand_braces, glob_matches};
use super::search_scope_ignore::{is_ignored, load_ignore_file, IgnoreRule, ScopeUnproven};
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};
use std::rc::Rc;

const MAX_SCOPE_ENTRIES: usize = 20_000;
const MAX_SCOPE_DEPTH: usize = 64;
const MAX_REPOSITORY_ANCESTORS: usize = 64;

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
    walk_scope(&root, &filter).is_ok()
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

/// The structured `glob` filter. `None` from `from_input` means the filter
/// cannot be modeled, so the caller must not claim a proof.
struct SearchFilter {
    include: Vec<String>,
    exclude: Vec<String>,
}

impl SearchFilter {
    fn from_input(input: &Map<String, Value>) -> Option<Self> {
        let mut filter = Self {
            include: Vec::new(),
            exclude: Vec::new(),
        };
        let Some(glob) = input.get("glob") else {
            return Some(filter);
        };
        let glob = glob.as_str()?;
        // Hosts may split lists on whitespace or commas; that would add
        // globs this proof did not model.
        if glob.is_empty() || glob.contains(char::is_whitespace) || has_top_level_comma(glob) {
            return None;
        }
        let (negated, body) = match glob.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, glob),
        };
        let expanded = expand_braces(body).ok()?;
        for pattern in &expanded {
            // Prove the pattern parses before it is used to skip files.
            glob_matches(pattern, "probe").ok()?;
        }
        // Path-shaped globs depend on ripgrep's match base. Never let one
        // skip a file: drop exclusions and treat inclusion as unrestricted.
        if expanded.iter().any(|pattern| pattern.contains('/')) {
            return Some(filter);
        }
        if negated {
            filter.exclude = expanded;
        } else {
            filter.include = expanded;
        }
        Some(filter)
    }

    /// Whether the host search reads this file. Only basename globs reach
    /// here; an unmatched pattern error never skips a file.
    fn searches(&self, relative: &str) -> bool {
        let basename = relative.rsplit('/').next().unwrap_or(relative);
        if self
            .exclude
            .iter()
            .any(|pattern| glob_matches(pattern, basename).unwrap_or(false))
        {
            return false;
        }
        self.include.is_empty()
            || self
                .include
                .iter()
                .any(|pattern| glob_matches(pattern, basename).unwrap_or(true))
    }
}

fn has_top_level_comma(glob: &str) -> bool {
    let mut depth = 0_i32;
    for character in glob.chars() {
        match character {
            '{' => depth += 1,
            '}' => depth -= 1,
            ',' if depth == 0 => return true,
            _ => {}
        }
    }
    false
}

/// Locate the enclosing repository so its ignore files apply, as ripgrep's
/// `.gitignore` handling only applies inside a Git repository.
fn repository_root(root: &Path) -> Option<PathBuf> {
    let mut current = Some(root);
    for _ in 0..MAX_REPOSITORY_ANCESTORS {
        let directory = current?;
        if std::fs::symlink_metadata(directory.join(".git")).is_ok() {
            return Some(directory.to_path_buf());
        }
        current = directory.parent();
    }
    None
}

fn relative_slash_path(path: &Path, base: &Path) -> Option<String> {
    let relative = path.strip_prefix(base).ok()?;
    let mut rendered = Vec::new();
    for component in relative.components() {
        rendered.push(component.as_os_str().to_str()?.to_owned());
    }
    Some(rendered.join("/"))
}

fn ancestor_rules(root: &Path, repository: &Path) -> Result<Vec<IgnoreRule>, ScopeUnproven> {
    let mut rules = Vec::new();
    let git_directory = repository.join(".git");
    if std::fs::symlink_metadata(&git_directory).is_ok_and(|metadata| metadata.is_dir()) {
        load_ignore_file(&git_directory.join("info").join("exclude"), "", &mut rules)?;
    }
    let relative = relative_slash_path(root, repository).ok_or(ScopeUnproven)?;
    let mut directory = repository.to_path_buf();
    let mut base = String::new();
    load_ignore_file(&directory.join(".gitignore"), &base, &mut rules)?;
    for part in relative.split('/').filter(|part| !part.is_empty()) {
        directory.push(part);
        base = if base.is_empty() {
            part.to_owned()
        } else {
            format!("{base}/{part}")
        };
        // An ignored ancestor would make the search root itself ignored;
        // ripgrep still searches an explicit root, so keep walking.
        load_ignore_file(&directory.join(".gitignore"), &base, &mut rules)?;
    }
    Ok(rules)
}

fn sensitive_scope_file(path: &Path) -> bool {
    guard_secure_fs::sensitive_path_family(path).is_some()
        || guard_secure_fs::credential_named_path(path)
}

fn walk_scope(root: &Path, filter: &SearchFilter) -> Result<(), ScopeUnproven> {
    let repository = repository_root(root);
    let rules = match &repository {
        Some(repository) => ancestor_rules(root, repository)?,
        None => Vec::new(),
    };
    let repository_base = repository.as_deref().unwrap_or(root);
    let mut pending = vec![(root.to_path_buf(), 0_usize, Rc::new(rules))];
    let mut inspected = 0_usize;
    while let Some((directory, depth, inherited)) = pending.pop() {
        if depth > MAX_SCOPE_DEPTH {
            return Err(ScopeUnproven);
        }
        let mut rules = Rc::clone(&inherited);
        if repository.is_some() && depth > 0 {
            let base = relative_slash_path(&directory, repository_base).ok_or(ScopeUnproven)?;
            // A nested repository may not inherit outer rules. Dropping them
            // can only widen the modeled scope.
            let nested = std::fs::symlink_metadata(directory.join(".git")).is_ok();
            let mut extended = if nested {
                Vec::new()
            } else {
                (*inherited).clone()
            };
            let before = extended.len();
            load_ignore_file(&directory.join(".gitignore"), &base, &mut extended)?;
            if nested || extended.len() != before {
                rules = Rc::new(extended);
            }
        }
        let entries = std::fs::read_dir(&directory).map_err(|_| ScopeUnproven)?;
        for entry in entries {
            let entry = entry.map_err(|_| ScopeUnproven)?;
            inspected += 1;
            if inspected > MAX_SCOPE_ENTRIES {
                return Err(ScopeUnproven);
            }
            let path = entry.path();
            if entry.file_name() == ".git" {
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
            if repository.is_some() {
                let relative = relative_slash_path(&path, repository_base).ok_or(ScopeUnproven)?;
                if is_ignored(&rules, &relative, is_directory)? {
                    continue;
                }
            }
            if is_directory {
                pending.push((path, depth + 1, Rc::clone(&rules)));
                continue;
            }
            let search_relative = relative_slash_path(&path, root).ok_or(ScopeUnproven)?;
            if filter.searches(&search_relative) && sensitive_scope_file(&path) {
                return Err(ScopeUnproven);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "search_scope_tests.rs"]
mod tests;

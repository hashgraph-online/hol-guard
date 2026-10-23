//! Native search-scope proof for Claude Code's structured `Grep` tool.
//!
//! Claude's `Grep` searches hidden files, honors ignore files, and skips
//! `.git`. A directory search is allowed only after a bounded metadata walk
//! shows that no sensitive file is reachable. Contents are read only for a
//! tracked, sensitive-named file (see `search_scope_tracked`); otherwise only
//! ignore files are parsed. Any ambiguity falls back to normal review.
//!
//! This file resolves each host's search root and the ignore rules that apply
//! to it; `search_scope_walk` owns the walk itself.

use super::search_pattern_clearance::PatternClearance;
use super::search_scope_filter::SearchFilter;
use super::search_scope_walk::{walk_scope, walk_scope_cleared, walk_scope_with, Ignores};
use serde_json::{Map, Value};
use std::cell::Cell;
use std::path::{Path, PathBuf};

/// Links into the main checkout one names-only walk may follow and prove.
const MAX_CHECKOUT_LINK_WALKS: usize = 8;

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
    !super::read_paths::inside_agent_state_tree(&root, home_dir)
        && walk_scope(&root, &filter, Ignores::Ripgrep, false, home_dir, &mut None).is_ok()
}

/// Shell `rg` with `-g` inclusions the name screen cannot clear, such as
/// `*.md` or `README*`: true when below each directory root no sensitive
/// file matches one of them. ripgrep searches such a file even when it is
/// hidden or ignored, and the walk inspects every one. The other globs were
/// screened already and can only add safe files or remove some. A root that
/// is a regular file was screened as a path, and ripgrep reads it whatever
/// the globs say.
pub(super) fn rg_glob_scope_proven(
    roots: &[&str],
    globs: &[&str],
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    let Some(filter) = SearchFilter::from_rg_inclusions(globs) else {
        return false;
    };
    roots.iter().all(
        |target| match verified_directory_root(target, home_dir, cwd) {
            Some(root) => {
                // ripgrep matches a path-shaped glob against the path from
                // its match base, the working directory. Only a walk that
                // starts there renders the same path, so a search target of
                // its own leaves such a glob unmodeled.
                (!filter.is_path_shaped()
                    || working_directory_root(home_dir, cwd).as_deref() == Some(root.as_path()))
                    && !super::read_paths::inside_agent_state_tree(&root, home_dir)
                    && walk_scope(&root, &filter, Ignores::Ripgrep, false, home_dir, &mut None)
                        .is_ok()
            }
            None => cwd.is_some_and(|cwd| {
                std::fs::symlink_metadata(Path::new(cwd).join(target))
                    .is_ok_and(|metadata| metadata.is_file())
            }),
        },
    )
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

/// Content search (`grep`) variant of the unfiltered proof. Inside agent-state
/// trees (`~/.agent/skills`, `~/.agent/artifacts`) the per-file rules that
/// deny direct reads do not apply to a directory walk, so the walk must reach
/// only documents a direct read would allow.
pub(super) fn content_search_scope_proven(
    target: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    unfiltered_directory_root(target, home_dir, cwd).is_some_and(|root| {
        (!super::read_paths::inside_agent_state_tree(&root, home_dir)
            || super::read_paths::agent_state_tree_holds_only_documents(&root, home_dir))
            && unfiltered_walk_proven(&root, home_dir)
    })
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
    unfiltered_directory_root(target, home_dir, cwd)
        .is_some_and(|root| unfiltered_walk_proven(&root, home_dir))
}

/// The first sensitive file an unfiltered content search of `target` would
/// reach, relative to the searched folder, when that file is why the search
/// is unproven. Only names are inspected; no candidate file is opened.
pub(super) fn content_search_blocker(
    target: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
    clearance: Option<&PatternClearance>,
) -> Option<PathBuf> {
    let root = unfiltered_directory_root(target, home_dir, cwd)?;
    let filter = SearchFilter::from_input(&Map::new())?;
    let mut blocker = None;
    walk_scope_cleared(
        &root,
        &filter,
        Ignores::None,
        clearance,
        home_dir,
        &mut blocker,
    )
    .err()?;
    blocker.and_then(|path| path.strip_prefix(&root).ok().map(Path::to_path_buf))
}

fn unfiltered_walk_proven(root: &Path, home: Option<&str>) -> bool {
    unfiltered_walk_cleared(root, None, home)
}

/// [`unfiltered_walk_proven`], where a sensitive file the `clearance` pattern
/// provably cannot match does not fail the proof.
fn unfiltered_walk_cleared(
    root: &Path,
    clearance: Option<&PatternClearance>,
    home: Option<&str>,
) -> bool {
    SearchFilter::from_input(&Map::new()).is_some_and(|filter| {
        walk_scope_cleared(root, &filter, Ignores::None, clearance, home, &mut None).is_ok()
    })
}

/// Oh My Pi `glob` walks below its fixed prefix and returns names only. Below
/// a workspace cwd (not the home directory or an ancestor of it), or in a
/// linked worktree of a repository inside it, that is the listing `find`
/// already gets; anywhere else no sensitive file may be
/// reachable below the prefix. Either way no link may lead the walk out of it.
pub(super) fn omp_glob_scope_proven(
    target: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
    gitignore: bool,
) -> bool {
    let Some(root) = unfiltered_directory_root(target, home_dir, cwd) else {
        return false;
    };
    let workspace = cwd.zip(home_dir).and_then(|(cwd, home)| {
        let cwd = std::fs::canonicalize(cwd).ok()?;
        let home = std::fs::canonicalize(home).ok()?;
        (!home.starts_with(&cwd)).then_some(cwd)
    });
    let names_walk = |ignores, outside_link: &dyn Fn(&Path) -> bool| {
        SearchFilter::from_input(&Map::new()).is_some_and(|filter| {
            walk_scope_with(
                &root,
                &filter,
                ignores,
                true,
                outside_link,
                home_dir,
                &mut None,
            )
            .is_ok()
        })
    };
    // A linked worktree of a repository inside the workspace holds the same
    // checkout, so its names are the workspace's too.
    let in_workspace = workspace.is_some_and(|cwd| {
        root.starts_with(&cwd)
            || super::worktree_writes::linked_worktree_common_dir(&root)
                .and_then(|common| common.parent().map(Path::to_path_buf))
                .is_some_and(|checkout| checkout.starts_with(&cwd))
    });
    if !in_workspace {
        return unfiltered_walk_proven(&root, home_dir) && names_walk(Ignores::None, &|_| false);
    }
    // A linked worktree often borrows its gitignored dependencies through a
    // link into the main checkout. Without ignore rules the host may list
    // through it, so that target is held to the rules for a walk outside the
    // workspace. Any other link out of the root still fails the proof.
    let checkout = super::worktree_writes::linked_worktree_common_dir(&root)
        .and_then(|common| common.parent().map(Path::to_path_buf));
    let home = home_dir.and_then(|home| std::fs::canonicalize(home).ok());
    let walks = Cell::new(0_usize);
    let checkout_link = |target: &Path| {
        walks.set(walks.get() + 1);
        walks.get() <= MAX_CHECKOUT_LINK_WALKS
            && checkout
                .as_deref()
                .zip(home.as_deref())
                .is_some_and(|(checkout, home)| {
                    target != checkout
                        && target.starts_with(checkout)
                        && !home.starts_with(checkout)
                })
            && target.to_str().is_some_and(|target| {
                super::safe_reads::bounded_omp_directory_read_target(target, home_dir, cwd)
            })
            && unfiltered_walk_proven(target, home_dir)
            && SearchFilter::from_input(&Map::new()).is_some_and(|filter| {
                walk_scope(target, &filter, Ignores::None, true, home_dir, &mut None).is_ok()
            })
    };
    // Without ignore rules the walk covers every entry the host can reach,
    // so it still proves the scope when a `.ignore` file stops the first.
    gitignore && names_walk(Ignores::Gitignore, &|_| false)
        || names_walk(Ignores::None, &checkout_link)
}

/// Oh My Pi `grep` variant of [`content_search_scope_proven`]. The host
/// searches hidden files and, unless `gitignore` is false, skips what the
/// repository's `.gitignore` files exclude. Only those files narrow the walk,
/// so a gitignored `.env` stays out of scope while a tracked one fails it.
///
/// A plain-text `clearance` pattern lets the search through when every
/// sensitive file in reach is one the pattern cannot match: the host prints
/// only matching lines, so such a file adds nothing to its output.
pub(super) fn omp_grep_scope_proven(
    target: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
    gitignore: bool,
    clearance: Option<&PatternClearance>,
) -> bool {
    unfiltered_directory_root(target, home_dir, cwd).is_some_and(|root| {
        (!super::read_paths::inside_agent_state_tree(&root, home_dir)
            || super::read_paths::agent_state_tree_holds_only_documents(&root, home_dir))
            && if gitignore {
                SearchFilter::from_input(&Map::new()).is_some_and(|filter| {
                    walk_scope_cleared(
                        &root,
                        &filter,
                        Ignores::Gitignore,
                        clearance,
                        home_dir,
                        &mut None,
                    )
                    .is_ok()
                })
            } else {
                unfiltered_walk_cleared(&root, clearance, home_dir)
            }
    })
}

/// Canonical directory an unfiltered search walks, with `~/` expanded the
/// way the host does. Both the walk and the agent-state gate use this root.
fn unfiltered_directory_root(
    target: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> Option<PathBuf> {
    if !super::safe_reads::bounded_omp_directory_read_target(target, home_dir, cwd) {
        return None;
    }
    let candidate = if Path::new(target).is_absolute() {
        PathBuf::from(target)
    } else if let Some(stripped) = target.strip_prefix("~/") {
        Path::new(home_dir?).join(stripped)
    } else if target == "~" {
        return None;
    } else {
        Path::new(cwd?).join(target)
    };
    if guard_secure_fs::contains_symlink_component(&candidate) {
        return None;
    }
    std::fs::canonicalize(candidate)
        .ok()
        .filter(|root| root.is_dir())
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
    // A recursive search through `..` reaches a sibling tree whose ignore
    // rules were never inspected.
    if target.split(['/', '\\']).any(|part| part == "..")
        || !super::safe_reads::bounded_read_target(target, home_dir, cwd, true)
    {
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

/// The directory ripgrep matches a path-shaped glob against.
fn working_directory_root(home_dir: Option<&str>, cwd: Option<&str>) -> Option<PathBuf> {
    verified_directory_root(".", home_dir, cwd)
}

#[cfg(test)]
#[path = "search_scope_tests.rs"]
mod tests;

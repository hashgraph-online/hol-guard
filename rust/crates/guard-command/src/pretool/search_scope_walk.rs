//! The bounded metadata walk behind every search-scope proof.
//!
//! A proof in `search_scope` resolves the root and the host's ignore rules,
//! then hands both to the walk here. The walk models what the searching host
//! would reach: it reads entry metadata, parses ignore files, and never opens
//! a candidate secret. A sensitive file in reach fails the proof and names
//! itself as the blocker; a walk that cannot be bounded fails it outright.

use super::search_pattern_clearance::PatternClearance;
use super::search_scope_filter::{Override, SearchFilter};
use super::search_scope_ignore::{
    holds_custom_ignore_file, is_ignored, link_ignored, load_custom_rules, load_ignore_file,
    slash_path, IgnoreRule, IgnoreTiers, ScopeUnproven,
};
use super::search_scope_tracked::TrackedFiles;
use std::path::{Path, PathBuf};
use std::rc::Rc;

const MAX_SCOPE_ENTRIES: usize = 20_000;
/// A names-only walk checks only entry metadata and links, never contents,
/// so it may cover an ordinary mid-size repository in full.
const MAX_NAME_SCOPE_ENTRIES: usize = 100_000;

/// Which ignore files a walk honors, matching the host that searches.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Ignores {
    /// Every reachable entry counts.
    None,
    /// ripgrep: repository excludes, `.gitignore`, `.ignore` and `.rgignore`,
    /// and `.git` itself is skipped.
    Ripgrep,
    /// Only `.gitignore` files at or below the search root, inside a
    /// repository. Ancestor files, repository excludes and a global file rank
    /// below them and can only hide more, so leaving them out keeps the
    /// modeled scope at least as wide as the host's. A higher-ranked
    /// `.ignore` or `.rgignore` could re-include a gitignored file, so any
    /// such file in reach fails the proof.
    Gitignore,
}
const MAX_SCOPE_DEPTH: usize = 64;
const MAX_ANCESTORS: usize = 64;
/// Nested repositories (such as linked worktrees) one walk may enter.
const MAX_NESTED_REPOSITORIES: usize = 8;

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

/// Whether a name the walk reaches marks credential material.
///
/// A repository keeps its sign-in and token code in `src/lib/auth`,
/// `app/api/auth` or `packages/token`, which the credential-path screen reads
/// as a store. A direct read of a document in one is already admitted as the
/// feature code it is, so a search that reaches the same file is held for
/// nothing: every checkout with a sign-in feature loses `grep` over its own
/// tree. The exemption is the read path's own, with its repository root and
/// its refusal to exempt anything below a home directory that is itself a
/// work tree, so the walk admits exactly what a read of that file would. It
/// relaxes the credential-name screen alone; the sensitive-family screen
/// still runs on every name.
fn sensitive_scope_file(path: &Path, home: Option<&str>) -> bool {
    guard_secure_fs::sensitive_path_family(path).is_some()
        || (guard_secure_fs::credential_named_path(path)
            && !super::read_paths::feature_directories::feature_only_credential_name(path, home))
}

/// Whether a link out of the walked root can only ever contribute its own
/// name to a names-only listing.
///
/// A listing names paths it reaches, so a link to a directory is what lets one
/// out: walking it would spell out entries that live outside the root. A link
/// whose target is a regular file reaches no entries at all, so the only name
/// it can produce is the link's own, which is inside the root already. Every
/// Python project has one: `.venv/bin/python` points at the base interpreter,
/// and refusing it would review a recursive listing in any such checkout.
///
/// The target's own name is still held to the sensitive screens, so a link
/// that stands in for a credential file keeps the review.
fn single_outside_name(path: &Path, target: Option<&Path>, home: Option<&str>) -> bool {
    target.is_some_and(|target| {
        target.is_file() && !sensitive_scope_file(path, home) && !sensitive_scope_file(target, home)
    })
}

struct PendingDirectory {
    path: PathBuf,
    /// The directory's path from the search root, empty at the root. A
    /// path-shaped inclusion matches against it.
    relative: String,
    depth: usize,
    tiers: Rc<IgnoreTiers>,
}

/// Walks the modeled search scope. With `names`, the walk models a names-only
/// listing: sensitive names are fine, but every link it walks must resolve
/// inside `root`. When a sensitive file fails the proof, `blocker` names it.
pub(super) fn walk_scope(
    root: &Path,
    filter: &SearchFilter,
    ignores: Ignores,
    names: bool,
    home: Option<&str>,
    blocker: &mut Option<PathBuf>,
) -> Result<(), ScopeUnproven> {
    walk_scope_with(root, filter, ignores, names, &|_| false, home, blocker)
}

/// A content walk where a sensitive file `clearance` proves the pattern
/// cannot match is not a blocker.
pub(super) fn walk_scope_cleared(
    root: &Path,
    filter: &SearchFilter,
    ignores: Ignores,
    clearance: Option<&PatternClearance>,
    home: Option<&str>,
    blocker: &mut Option<PathBuf>,
) -> Result<(), ScopeUnproven> {
    walk_scope_inner(
        root,
        filter,
        ignores,
        false,
        &|_| false,
        clearance,
        home,
        blocker,
    )
}

/// [`walk_scope`], where a names-only walk also accepts a link out of `root`
/// whose canonical target `outside_link` proves.
pub(super) fn walk_scope_with(
    root: &Path,
    filter: &SearchFilter,
    ignores: Ignores,
    names: bool,
    outside_link: &dyn Fn(&Path) -> bool,
    home: Option<&str>,
    blocker: &mut Option<PathBuf>,
) -> Result<(), ScopeUnproven> {
    walk_scope_inner(
        root,
        filter,
        ignores,
        names,
        outside_link,
        None,
        home,
        blocker,
    )
}

#[allow(clippy::too_many_arguments)]
fn walk_scope_inner(
    root: &Path,
    filter: &SearchFilter,
    ignores: Ignores,
    names: bool,
    outside_link: &dyn Fn(&Path) -> bool,
    clearance: Option<&PatternClearance>,
    home: Option<&str>,
    blocker: &mut Option<PathBuf>,
) -> Result<(), ScopeUnproven> {
    let repository = repository_root(root).filter(|_| ignores != Ignores::None);
    let mut tiers = IgnoreTiers::default();
    if ignores == Ignores::Ripgrep {
        if let Some(repository) = &repository {
            tiers.git = ancestor_git_rules(root, repository)?;
        }
        ancestor_custom_rules(root, &mut tiers)?;
    }
    if ignores == Ignores::Gitignore
        && root
            .ancestors()
            .take(MAX_ANCESTORS)
            .any(holds_custom_ignore_file)
    {
        return Err(ScopeUnproven);
    }
    let mut pending = vec![PendingDirectory {
        path: root.to_path_buf(),
        relative: String::new(),
        depth: 0,
        tiers: Rc::new(tiers),
    }];
    let mut inspected = 0_usize;
    let mut tracked = TrackedFiles::default();
    let mut nested_repositories = 0_usize;
    let mut entry_limit = if names {
        MAX_NAME_SCOPE_ENTRIES
    } else {
        MAX_SCOPE_ENTRIES
    };
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
                // The host walks a nested checkout too, so it stays in the
                // proof; each one brings its own entry budget, a few at most.
                nested_repositories += 1;
                if nested_repositories > MAX_NESTED_REPOSITORIES {
                    return Err(ScopeUnproven);
                }
                entry_limit += if names {
                    MAX_NAME_SCOPE_ENTRIES
                } else {
                    MAX_SCOPE_ENTRIES
                };
            }
            load_ignore_file(&directory.path.join(".gitignore"), &base, &mut tiers.git)?;
        }
        if ignores == Ignores::Gitignore && holds_custom_ignore_file(&directory.path) {
            return Err(ScopeUnproven);
        }
        if ignores == Ignores::Ripgrep {
            load_custom_rules(&directory.path, &mut tiers)?;
        }
        let tiers = Rc::new(tiers);
        let entries = std::fs::read_dir(&directory.path).map_err(|_| ScopeUnproven)?;
        for entry in entries {
            let entry = entry.map_err(|_| ScopeUnproven)?;
            inspected += 1;
            if inspected > entry_limit {
                return Err(ScopeUnproven);
            }
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_str().ok_or(ScopeUnproven)?;
            // Metadata only: never follow links or open a candidate secret.
            let metadata = std::fs::symlink_metadata(&path).map_err(|_| ScopeUnproven)?;
            let relative = if directory.relative.is_empty() {
                name.to_string()
            } else {
                format!("{}/{name}", directory.relative)
            };
            if name == ".git" {
                // Ripgrep's walk passes over .git unless an inclusion selects
                // it, a names walk all but a link; a content walk inspects it.
                if !filter.selects_git(name, &relative)
                    && (ignores == Ignores::Ripgrep || (names && !metadata.is_symlink()))
                {
                    continue;
                }
                // A content walk prints what the entry holds, and the screen
                // below is name-shaped: `.git/config` is an ordinary name, so
                // a remote URL carrying a token, or an `http.extraHeader`,
                // would pass it. The recursive-grep check reads those files,
                // and a path-shaped inclusion must not win what `grep -r`
                // over the same checkout is refused. A link is not walked
                // here, so the symlink screen below decides it.
                if !names
                    && !metadata.is_symlink()
                    && !super::search::safe_git_entry(&path, &metadata)
                {
                    return Err(ScopeUnproven);
                }
            }
            if metadata.file_type().is_symlink() {
                // Claude's Grep does not follow links. Still refuse a link
                // whose name or file target is sensitive, in case it would.
                let target = std::fs::canonicalize(&path).ok();
                let escapes = !target.as_deref().is_some_and(|t| t.starts_with(root));
                if names {
                    // A link the ignore rules skip is never walked.
                    let skipped =
                        ignores != Ignores::None && link_ignored(&tiers, &path, target.as_deref())?;
                    if escapes
                        && !skipped
                        && !single_outside_name(&path, target.as_deref(), home)
                        && !target.as_deref().is_some_and(outside_link)
                    {
                        return Err(ScopeUnproven);
                    }
                } else if sensitive_scope_file(&path, home)
                    || target.as_deref().is_some_and(|target| {
                        target.is_file() && sensitive_scope_file(target, home)
                    })
                {
                    return Err(ScopeUnproven);
                }
                continue;
            }
            let is_directory = metadata.is_dir();
            if !is_directory && !metadata.is_file() {
                // A socket or pipe has no names to list and no text to search.
                if names {
                    continue;
                }
                return Err(ScopeUnproven);
            }
            let searched = match filter.override_for(name, &relative, is_directory) {
                Override::Skipped => continue,
                Override::Searched => true,
                Override::Undecided => {
                    let rendered = slash_path(&path).ok_or(ScopeUnproven)?;
                    if ignores != Ignores::None && is_ignored(&tiers, &rendered, is_directory)? {
                        continue;
                    }
                    is_directory || filter.type_allows(name)
                }
            };
            if is_directory {
                pending.push(PendingDirectory {
                    path,
                    relative,
                    depth: directory.depth + 1,
                    tiers: Rc::clone(&tiers),
                });
            } else if searched
                && !names
                && sensitive_scope_file(&path, home)
                && !tracked.non_secret(&path)
                && !clearance.is_some_and(|clearance| clearance.clears(&path))
            {
                *blocker = Some(path);
                return Err(ScopeUnproven);
            }
        }
    }
    Ok(())
}

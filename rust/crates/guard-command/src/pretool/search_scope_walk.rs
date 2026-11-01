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
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

const MAX_SCOPE_ENTRIES: usize = 20_000;
/// A names-only walk checks only entry metadata and links, never contents,
/// so it may cover an ordinary mid-size repository in full.
const MAX_NAME_SCOPE_ENTRIES: usize = 100_000;
/// The entries an include walk may inspect.
///
/// Every other reading of a recursive search answers before this one and
/// walks the tree to do it, so an include walk spends what is left of a
/// single evaluation's budget. A directory an include selects from -- the
/// documentation or source tree the globs name -- fits well inside this
/// count, and a larger tree leaves the reading unproven instead of spending
/// the evaluation on it. Withholding it only returns the answer the readings
/// above already reached.
const MAX_INCLUDE_SCOPE_ENTRIES: usize = 2_000;
/// The wall clock every include walk in one evaluation may spend between
/// them.
///
/// The whole native evaluation runs inside half a second, and the entry count
/// above does not bound the time those entries take: a directory read costs
/// what the host's filesystem charges for it, which on a loaded machine is
/// not what it costs on an idle one. Spending the evaluation's remaining
/// budget there fails the evaluation, and a failed evaluation blocks, so this
/// walk stops on the clock as well.
///
/// One evaluation asks this question once per recursive root, and a command
/// is read again for every spelling a rewrite reaches, so a clock started
/// afresh for each walk would bound no single evaluation. The clock below is
/// started once where the evaluation begins and shared by every include walk
/// inside it, which is what the evaluation's own budget can afford. The
/// repeated spellings pay nothing, because a root and glob set already
/// walked is answered from [`INCLUDE_SCOPE_ANSWERS`] rather than walked
/// again, so the clock bounds the distinct trees a submission names.
/// Expiring only withholds the narrowing and leaves the answer the readings
/// above already reached.
const INCLUDE_SCOPE_BUDGET: Duration = Duration::from_millis(75);

thread_local! {
    /// When the include walks of the evaluation running on this thread have
    /// to stop. Unset outside an evaluation -- a test driving the walk
    /// directly -- where each walk gets the budget to itself.
    static INCLUDE_SCOPE_CLOCK: std::cell::Cell<Option<Instant>> =
        const { std::cell::Cell::new(None) };
    /// What the include walks of this evaluation have already answered.
    ///
    /// A rewrite hands the same command back under several spellings, and
    /// each of them resolves the same operand to the same directory and the
    /// same globs. Without this the evaluation pays for that tree once per
    /// spelling and runs the shared clock out on work it has already done.
    static INCLUDE_SCOPE_ANSWERS: std::cell::RefCell<HashMap<IncludeScopeKey, bool>> =
        std::cell::RefCell::new(HashMap::new());
    /// How many evaluations are open on this thread.
    ///
    /// One submission reaches the evaluation entry point many times over: the
    /// command itself, then the envelope it is read inside once per
    /// projection -- a git-config isolation, a virtualenv activation, an
    /// environment prefix, each inner command of a process substitution, a
    /// redirect rewrite. Those are not separate submissions and must not get
    /// budgets of their own, so only the outermost starts the clock.
    static INCLUDE_SCOPE_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// What an include walk is decided by: the directory it starts at, the globs
/// that select the files below it, and the home the sensitive-path readings
/// are relative to. Two walks that agree on all three inspect the same
/// entries and reach the same answer.
type IncludeScopeKey = (PathBuf, String, Option<String>);

/// Start the shared include-walk clock for the submission beginning now.
///
/// The returned guard ends the submission where it is dropped. A nested
/// evaluation of the same submission takes a guard too, and that guard
/// neither restarts the clock nor ends the submission: the outermost one
/// does both, which is what makes the clock the submission's own.
///
/// The answers of the previous submission are dropped with it, because a
/// tree is read again when the next one asks: what is in it may have changed
/// since.
#[must_use]
pub(crate) fn begin_include_scope_budget() -> IncludeScopeBudget {
    let depth = INCLUDE_SCOPE_DEPTH.with(|depth| {
        let entered = depth.get() + 1;
        depth.set(entered);
        entered
    });
    if depth == 1 {
        INCLUDE_SCOPE_CLOCK.with(|clock| clock.set(Some(Instant::now() + INCLUDE_SCOPE_BUDGET)));
        INCLUDE_SCOPE_ANSWERS.with(|answers| answers.borrow_mut().clear());
    }
    IncludeScopeBudget
}

/// The open submission, which ends where this is dropped.
pub(crate) struct IncludeScopeBudget;

impl Drop for IncludeScopeBudget {
    fn drop(&mut self) {
        let left = INCLUDE_SCOPE_DEPTH.with(|depth| {
            let left = depth.get().saturating_sub(1);
            depth.set(left);
            left
        });
        if left == 0 {
            INCLUDE_SCOPE_CLOCK.with(|clock| clock.set(None));
            INCLUDE_SCOPE_ANSWERS.with(|answers| answers.borrow_mut().clear());
        }
    }
}

/// Put the thread back where it is outside an evaluation, for a test that
/// reads the unstarted clock on a thread an earlier test may have used.
#[cfg(test)]
fn clear_include_scope_budget() {
    INCLUDE_SCOPE_DEPTH.with(|depth| depth.set(0));
    INCLUDE_SCOPE_CLOCK.with(|clock| clock.set(None));
    INCLUDE_SCOPE_ANSWERS.with(|answers| answers.borrow_mut().clear());
}

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

/// When an include walk starting now has to stop: the evaluation's shared
/// clock, or a budget of its own outside one.
pub(super) fn include_scope_deadline() -> Instant {
    INCLUDE_SCOPE_CLOCK
        .with(std::cell::Cell::get)
        .unwrap_or_else(|| Instant::now() + INCLUDE_SCOPE_BUDGET)
}

/// [`walk_scope`] for a grep include, under the entry count and the wall
/// clock such a reading is allowed. Nothing is ignored: `grep` reads no
/// ignore file.
pub(super) fn walk_include_scope(
    root: &Path,
    filter: &SearchFilter,
    home: Option<&str>,
    budget: Instant,
) -> Result<(), ScopeUnproven> {
    walk_scope_inner(
        root,
        filter,
        Ignores::None,
        false,
        &|_| false,
        None,
        home,
        &mut None,
        Some(MAX_INCLUDE_SCOPE_ENTRIES),
        Some(budget),
    )
}

/// [`walk_include_scope`], answered once per evaluation for a given root,
/// glob set and home.
///
/// `globs` names the same files the caller built `filter` from; it is the
/// spelling this evaluation remembers the answer under.
pub(super) fn include_scope_proven(
    root: &Path,
    globs: &[&str],
    filter: &SearchFilter,
    home: Option<&str>,
) -> bool {
    let key: IncludeScopeKey = (
        root.to_path_buf(),
        globs.join("\u{0}"),
        home.map(str::to_owned),
    );
    if let Some(answer) = INCLUDE_SCOPE_ANSWERS.with(|answers| answers.borrow().get(&key).copied())
    {
        return answer;
    }
    let answer = walk_include_scope(root, filter, home, include_scope_deadline()).is_ok();
    INCLUDE_SCOPE_ANSWERS.with(|answers| {
        answers.borrow_mut().insert(key, answer);
    });
    answer
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
        None,
        None,
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
        None,
        None,
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
    entries: Option<usize>,
    budget: Option<Instant>,
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
    let scope_entries = entries.unwrap_or(if names {
        MAX_NAME_SCOPE_ENTRIES
    } else {
        MAX_SCOPE_ENTRIES
    });
    let mut entry_limit = scope_entries;
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
                entry_limit += scope_entries;
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
            if inspected > entry_limit || budget.is_some_and(|limit| Instant::now() >= limit) {
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

#[cfg(test)]
#[path = "search_scope_walk_tests.rs"]
mod tests;

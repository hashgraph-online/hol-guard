//! Native search-scope proof for Claude Code's structured `Grep` tool.
//!
//! Claude's `Grep` searches hidden files, honors ignore files, and skips
//! `.git`. A directory search is allowed only after a bounded metadata walk
//! shows that no sensitive file is reachable. Contents are read only for a
//! tracked, sensitive-named file (see `search_scope_tracked`); otherwise only
//! ignore files are parsed. Any ambiguity falls back to normal review.

use super::search_pattern_clearance::PatternClearance;
use super::search_scope_filter::{Override, SearchFilter};
use super::search_scope_ignore::{
    holds_custom_ignore_file, is_ignored, link_ignored, load_custom_rules, load_ignore_file,
    slash_path, IgnoreRule, IgnoreTiers, ScopeUnproven,
};
use super::search_scope_tracked::TrackedFiles;
use serde_json::{Map, Value};
use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

const MAX_SCOPE_ENTRIES: usize = 20_000;
/// A names-only walk checks only entry metadata and links, never contents,
/// so it may cover an ordinary mid-size repository in full.
const MAX_NAME_SCOPE_ENTRIES: usize = 100_000;
/// Links into the main checkout one names-only walk may follow and prove.
const MAX_CHECKOUT_LINK_WALKS: usize = 8;

/// Which ignore files a walk honors, matching the host that searches.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ignores {
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
                !super::read_paths::inside_agent_state_tree(&root, home_dir)
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
    depth: usize,
    tiers: Rc<IgnoreTiers>,
}

/// Walks the modeled search scope. With `names`, the walk models a names-only
/// listing: sensitive names are fine, but every link it walks must resolve
/// inside `root`. When a sensitive file fails the proof, `blocker` names it.
fn walk_scope(
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
fn walk_scope_cleared(
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
fn walk_scope_with(
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
            // Ripgrep's walk skips .git, a names walk all but a link; a content walk inspects it.
            if name == ".git" && (ignores == Ignores::Ripgrep || (names && !metadata.is_symlink()))
            {
                continue;
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
            let searched = match filter.override_for(name, is_directory) {
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
#[path = "search_scope_tests.rs"]
mod tests;

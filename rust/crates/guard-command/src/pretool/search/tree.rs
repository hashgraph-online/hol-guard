//! Bounded metadata walks for recursive readers (`grep -r`, `ls -R`).
//!
//! `rg` skips hidden and ignored entries by default, so a lexical operand
//! check is enough for it. `grep -r` and `ls -R` visit every entry, so the
//! walk classifies each descendant by metadata only: it never follows links
//! and never opens a file to decide.
//!
//! Descendants are judged by what the program can emit, not by shell syntax.
//! A name containing `[` or `]` is data the program reads itself, not a glob,
//! so framework route directories such as `[slug]` are fine. A hidden entry
//! must be on a short benign list, because recursion would otherwise reach
//! `.env`, `.ssh` or `.git`. A credential-named file is refused unless it is
//! source code, matching `credential_named_path`, or test data below a
//! test-data directory inside the walk; the name is judged on the
//! path below the walk root so a credential-named ancestor of the operand does
//! not poison it, but a credential-named directory inside the tree still
//! blocks its non-source files.
use super::ReadContext;
use crate::pretool::search_pattern_clearance::PatternClearance;
use glob_expand::expand_glob_matches;
use std::path::{Path, PathBuf};
#[path = "glob_expand.rs"]
mod glob_expand;

#[path = "literal_bracket.rs"]
mod literal_bracket;

use literal_bracket::inert_bracket_class;
pub(in crate::pretool) use literal_bracket::{
    safe_literal_bracket_read_target, safe_literal_bracket_search_target, safe_literal_bracket_tree,
};

/// An ordinary repository is already past ten thousand entries — this one
/// counts 11,217 below its own root — so a lower bound decided every search
/// named at a whole tree rather than bounding an unusual one. Refusing to
/// finish looking is not a safety margin: the walk returns false and the
/// search goes to review with nothing proven either way. The walk reads each
/// entry's kind from the listing, so the raised bound costs a `lstat` only
/// where the filesystem leaves that kind unknown.
const MAX_WALK_ENTRIES: usize = 100_000;
const MAX_WALK_DEPTH: usize = 64;
const MAX_GLOB_MATCHES: usize = 256;
const MAX_GLOB_ENTRIES: usize = 20_000;

/// Hidden names that carry no credentials and are common in source trees.
/// Hidden names that hold project metadata, never credentials. Descendants of
/// the listed directories still clear every per-entry screen.
const BENIGN_HIDDEN_NAMES: &[&str] = &[
    ".ds_store",
    ".well-known",
    ".gitignore",
    ".gitkeep",
    ".keep",
    ".gitattributes",
    ".nvmrc",
    ".node-version",
    ".python-version",
    ".editorconfig",
    ".prettierrc",
    ".prettierignore",
    ".eslintignore",
    ".dockerignore",
    ".github",
    ".vscode",
    ".husky",
    ".changeset",
];

/// Key and certificate containers whose names carry no credential word.
pub(in crate::pretool) const SECRET_EXTENSIONS: &[&str] = &[
    "pem", "p12", "pfx", "jks", "keystore", "asc", "gpg", "kdbx", "ppk",
];

/// Names-only recursive listing (`ls -R`).
pub(in crate::pretool) fn safe_recursive_target(value: &str, context: ReadContext<'_>) -> bool {
    safe_walk_target(value, context, &[], &[], false, false, None)
        || super::agent_root::agent_root_listing(value, context, true)
}

/// Recursive content search (`grep -r`, `rg`). Oh My Pi agent-state trees are
/// excluded: the per-file exclusions that deny direct reads there do not
/// apply to a walk, so a search could return a file a direct read denies.
pub(in crate::pretool) fn safe_recursive_search_target(
    value: &str,
    context: ReadContext<'_>,
) -> bool {
    safe_recursive_target_excluding(value, context, &[], &[], false, false)
}

/// A walk whose proof has to cover what the links point at, not only what the
/// walk lists. Two commands need it for different reasons. `diff -r` reads
/// through a link it meets while descending unless it is told not to, so the
/// target's contents reach the output. `cp -r` does not read the target, but
/// it reproduces the link at a new path, and that new name is one no screen
/// has seen; a later read of it would reach whatever the original pointed at.
pub(in crate::pretool) fn safe_recursive_target_through_links(
    value: &str,
    context: ReadContext<'_>,
) -> bool {
    safe_recursive_target_excluding(value, context, &[], &[], false, true)
}

/// `git_metadata` lets a `grep -r` walk read a screened `.git` entry.
/// `follow_links` is `grep -R`, which reads through every link it finds and so
/// must prove what they point at; plain `-r` only follows a link named as an
/// operand.
pub(super) fn safe_recursive_target_excluding(
    value: &str,
    context: ReadContext<'_>,
    excluded_files: &[&str],
    excluded_directories: &[&str],
    git_metadata: bool,
    follow_links: bool,
) -> bool {
    if expanded_operand(value, context).is_some_and(|root| inside_agent_state(&root, context)) {
        return false;
    }
    safe_walk_target(
        value,
        context,
        excluded_files,
        excluded_directories,
        git_metadata,
        follow_links,
        None,
    )
}

/// [`safe_recursive_target_excluding`] where a sensitive-named file the
/// pattern cannot match does not fail the proof.
pub(super) fn safe_recursive_target_cleared(
    value: &str,
    context: ReadContext<'_>,
    excluded_files: &[&str],
    excluded_directories: &[&str],
    follow_links: bool,
    clearance: &PatternClearance,
) -> bool {
    !expanded_operand(value, context).is_some_and(|root| inside_agent_state(&root, context))
        && safe_walk_target(
            value,
            context,
            excluded_files,
            excluded_directories,
            true,
            follow_links,
            Some(clearance),
        )
}

pub(in crate::pretool) use super::roots::{listing_root_below_home, rg_root_inside_cwd};

pub(super) fn inside_agent_state(path: &std::path::Path, context: ReadContext<'_>) -> bool {
    std::fs::canonicalize(path).is_ok_and(|canonical| {
        super::super::read_paths::inside_agent_state_tree(&canonical, context.home_dir)
    })
}

fn safe_walk_target(
    value: &str,
    context: ReadContext<'_>,
    excluded_files: &[&str],
    excluded_directories: &[&str],
    git_metadata: bool,
    follow_links: bool,
    clearance: Option<&PatternClearance>,
) -> bool {
    // A recursive walk through `..` reaches a sibling tree whose ignore rules
    // were never inspected; only the sibling-repository proof admits that.
    if parent_component(value) {
        return false;
    }
    if !super::super::safe_reads::bounded_read_target(value, context.home_dir, context.cwd, true) {
        return false;
    }
    let Some(root) = expanded_operand(value, context) else {
        return false;
    };
    // A clearance depends on the pattern, so its walk is never memoized.
    match clearance {
        Some(clearance) => walk_uncached(
            root,
            excluded_files,
            excluded_directories,
            git_metadata,
            follow_links,
            Some(clearance),
            false,
        ),
        None => walk(
            root,
            excluded_files,
            excluded_directories,
            git_metadata,
            follow_links,
        ),
    }
}

/// A glob operand that is expanded here, component by component. Every
/// match must be a non-hidden directory entry that clears the same screens as
/// a literal operand, and recursive listings walk each matched directory.
pub(in crate::pretool) fn safe_glob_operand(
    value: &str,
    context: ReadContext<'_>,
    recursive: bool,
) -> bool {
    let Some(matches) = expand_glob(value, context) else {
        return false;
    };
    // With globstar a final `**` also expands to every nested entry, so the
    // matched directories must be proven like a recursive read.
    let final_globstar = value
        .rsplit('/')
        .find(|part| !part.is_empty())
        .is_some_and(|part| part.len() > 1 && part.bytes().all(|byte| byte == b'*'));
    matches.into_iter().all(|path| {
        if recursive || final_globstar {
            walk(path, &[], &[], false, false)
        } else {
            true
        }
    })
}

/// An unquoted bracket operand that matches nothing. Bash passes such a word
/// through literally, so `ls app/[slug]` lists the Next.js route directory
/// named `[slug]`; zsh's `nomatch` fails the command instead. The literal
/// directory must clear the quoted-literal screens. A class that could match
/// a leading dot under `dotglob` does not qualify, nor does one holding a
/// range, whose ends the shell compares in the locale's collating sequence,
/// nor syntax this matcher would close at the wrong `]`.
///
/// A `*` or `?` operand qualifies when the strict expansion proves that it
/// matches nothing under any shell option: the program then receives either
/// the literal word, which names no file, or no operand under `nullglob`. So
/// `ls ~/code/app/vite.config.*` probes for an optional file.
pub(in crate::pretool) fn safe_unmatched_glob_operand(
    value: &str,
    context: ReadContext<'_>,
    recursive: bool,
) -> bool {
    if !value.contains('[') {
        // Only the last component may be a pattern, inside a real directory.
        let directory = value
            .rsplit_once('/')
            .map_or(".", |(directory, _)| directory);
        let directory = if directory.is_empty() { "/" } else { directory };
        return !directory.contains(['*', '?'])
            && expanded_operand(directory, context)
                .and_then(|path| std::fs::symlink_metadata(path).ok())
                .is_some_and(|metadata| metadata.is_dir())
            && glob_expand::expand_glob_matches_strict(value, context)
                .is_some_and(|matches| matches.is_empty());
    }
    inert_bracket_class(value, context) && safe_literal_bracket_tree(value, context, recursive)
}

/// Content-search glob operand: every match is walked, and matches inside an
/// Oh My Pi agent-state tree are refused as for a literal search root.
pub(in crate::pretool) fn safe_glob_search_operand(value: &str, context: ReadContext<'_>) -> bool {
    expand_glob(value, context).is_some_and(|matches| {
        matches
            .into_iter()
            .all(|path| !inside_agent_state(&path, context) && walk(path, &[], &[], false, false))
    })
}

pub(super) fn home_relative(value: &str, home: Option<&str>) -> Option<PathBuf> {
    if value == "~" || value.starts_with("~/") {
        Some(Path::new(home?).join(value.strip_prefix("~/").unwrap_or("")))
    } else {
        Some(PathBuf::from(value))
    }
}

pub(super) fn expanded_operand(value: &str, context: ReadContext<'_>) -> Option<PathBuf> {
    let expanded = if value == "~" || value.starts_with("~/") {
        home_relative(value, context.home_dir)?
    } else if Path::new(value).is_absolute() {
        PathBuf::from(value)
    } else {
        home_relative(context.cwd?, context.home_dir)?.join(value)
    };
    // Remove trailing separators so symlink_metadata cannot follow a directory link.
    Some(expanded.components().collect())
}

/// Characters that make a word mean more than one literal path.
pub(super) const HAZARDS: [char; 11] = ['$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '\\'];

/// A relative, quoted operand naming an existing real directory.
fn checked_directory(value: &str, context: ReadContext<'_>) -> Option<PathBuf> {
    if value.is_empty()
        || value.len() > 4096
        || value.contains(HAZARDS)
        || value.contains(['{', '}', '*', '?'])
        || value.starts_with(['/', '~', '-'])
        || value.split('/').any(|part| part == "..")
        || !super::super::safe_reads::verified_path_context(context.home_dir, context.cwd)
    {
        return None;
    }
    let path = expanded_operand(value, context)?;
    real_allowed_directory(&path, context)
}

fn real_allowed_directory(path: &Path, context: ReadContext<'_>) -> Option<PathBuf> {
    if !std::fs::symlink_metadata(path).ok()?.is_dir() {
        return None;
    }
    let canonical = std::fs::canonicalize(path).ok()?;
    super::super::read_paths::resolved_path_allowed(&canonical, context.home_dir, context.cwd)
        .then(|| path.to_path_buf())
}

pub(super) fn hidden_allowed(name: &str) -> bool {
    BENIGN_HIDDEN_NAMES.contains(&name.to_ascii_lowercase().as_str())
}

/// `node_modules/.bin` holds a package manager's executable shims. The name is
/// hidden, but the directory is part of every install, and what it holds is
/// links into packages this walk screens entry by entry. Refusing it on the
/// name alone sends every recursive search of an installed checkout to review.
fn package_store_bin(path: &Path, name: &str) -> bool {
    name == ".bin"
        && path
            .parent()
            .and_then(|parent| parent.file_name())
            .and_then(|parent| parent.to_str())
            .is_some_and(|parent| parent == "node_modules")
}

pub(super) fn descendant_allowed(path: &Path, root: &Path, is_file: bool) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if (name.starts_with('.') && !hidden_allowed(name) && !package_store_bin(path, name))
        || guard_secure_fs::sensitive_path_family(path).is_some()
    {
        return false;
    }
    if !is_file {
        return true;
    }
    let relative = path.strip_prefix(root).unwrap_or(path);
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    !SECRET_EXTENSIONS.contains(&extension.as_str())
        && (!guard_secure_fs::credential_named_path(relative)
            || path
                .strip_prefix(root)
                .is_ok_and(|relative| synthetic_fixture(root, relative)))
}

/// Directories that hold a project's test data.
const FIXTURE_DIRECTORIES: &[&str] = &[
    "testdata",
    "test-data",
    "test_data",
    "fixtures",
    "fixture",
    "__fixtures__",
    "tests",
    "test",
    "__tests__",
];

/// Test trees name their vectors for what they exercise
/// (`testdata/secrets_cli/vectors.json`, `tests/fixtures/tokens.json`), so a
/// credential name at or below a test-data directory inside the walk marks
/// data a test reads, not a store. A test directory inside a credential
/// directory (`secrets/tests/prod.json`), or a walk rooted in one, is still a
/// store. Key containers, hidden names and the sensitive families (`.env`,
/// `*.key`, `.npmrc`) are refused before this is asked.
fn synthetic_fixture(root: &Path, relative: &Path) -> bool {
    let Some(parent) = relative.parent() else {
        return false;
    };
    let mut above = root.to_path_buf();
    for part in parent.components() {
        let std::path::Component::Normal(name) = part else {
            return false;
        };
        if name
            .to_str()
            .is_some_and(|name| FIXTURE_DIRECTORIES.contains(&name.to_ascii_lowercase().as_str()))
        {
            // Every directory above the test directory is checked as a
            // directory, below a neutral entry name.
            return !guard_secure_fs::credential_named_path(&above.join("entry"));
        }
        above.push(name);
    }
    false
}

pub(super) fn walk(
    root: PathBuf,
    excluded_files: &[&str],
    excluded_directories: &[&str],
    git_metadata: bool,
    follow_links: bool,
) -> bool {
    super::walk_memo::memoized(
        &root,
        excluded_files,
        excluded_directories,
        git_metadata,
        follow_links,
        false,
        || {
            walk_uncached(
                root.clone(),
                excluded_files,
                excluded_directories,
                git_metadata,
                follow_links,
                None,
                false,
            )
        },
    )
}

/// `skip_hidden` is for a lister that never descends into a hidden entry, so
/// no hidden name below the root reaches its output and none of them holds
/// the proof. Every visible entry is screened as it is for a walk that reads.
pub(super) fn walk_uncached(
    root: PathBuf,
    excluded_files: &[&str],
    excluded_directories: &[&str],
    git_metadata: bool,
    follow_links: bool,
    clearance: Option<&PatternClearance>,
    skip_hidden: bool,
) -> bool {
    // The third field marks an entry below a directory that only the clearance
    // admitted: its files have ordinary names, so nothing but their content
    // says the pattern cannot match them. The fourth carries the kind the
    // directory listing already reported for the entry.
    let mut pending = vec![(root.clone(), 0_usize, false, None::<std::fs::FileType>)];
    let mut inspected = 0_usize;
    // Inspect metadata only. Never follow links or read a secret to classify it.
    while let Some((path, depth, admitted_below, listed)) = pending.pop() {
        let mut below = admitted_below;
        inspected += 1;
        if inspected > MAX_WALK_ENTRIES || depth > MAX_WALK_DEPTH {
            return false;
        }
        // The directory listing already carried this entry's kind, so reading
        // it there spares a `lstat` per entry. It answers about the link
        // itself, as `symlink_metadata` does, so a symlink is still neither a
        // directory nor a file and still refuses the proof below.
        let kind = match listed {
            Some(kind) => kind,
            None => match std::fs::symlink_metadata(&path) {
                Ok(metadata) => metadata.file_type(),
                Err(_) => return false,
            },
        };
        // Only descendants are excluded: explicit operands and links still
        // require proof. Exact basenames avoid approximating grep's glob rules.
        if depth > 0 {
            let basename = path.file_name().and_then(|name| name.to_str());
            if skip_hidden && basename.is_some_and(|name| name.starts_with('.')) {
                continue;
            }
            if basename.is_some_and(|name| {
                (kind.is_dir() && excluded_directories.contains(&name))
                    || (kind.is_file() && excluded_files.contains(&name))
            }) {
                continue;
            }
            if git_metadata && basename == Some(".git") {
                // A repository's own metadata directory is screened entry by
                // entry, which needs the rest of what `lstat` answers.
                let Ok(metadata) = std::fs::symlink_metadata(&path) else {
                    return false;
                };
                match super::git_metadata::safe_git_entry(&path, &metadata) {
                    true => continue,
                    false => return false,
                }
            }
            if !descendant_allowed(&path, &root, kind.is_file()) {
                // The name alone holds the search; a clearance may admit it.
                // Only a name the screen refused reaches here, so reading the
                // rest of its metadata leaves the ordinary entry as it was.
                let Ok(metadata) = std::fs::symlink_metadata(&path) else {
                    return false;
                };
                if !clearance.is_some_and(|clearance| clearance.admits(&path, &metadata)) {
                    return false;
                }
                if metadata.is_file() {
                    continue;
                }
                below = true;
            } else if admitted_below && kind.is_file() {
                // Below an admitted directory every file clears on its own.
                if !clearance.is_some_and(|clearance| clearance.clears(&path)) {
                    return false;
                }
                continue;
            }
        }
        if kind.is_dir() {
            let Ok(entries) = std::fs::read_dir(&path) else {
                return false;
            };
            for entry in entries {
                let Ok(entry) = entry else { return false };
                if pending.len() + inspected >= MAX_WALK_ENTRIES {
                    return false;
                }
                let Ok(entry_kind) = entry.file_type() else {
                    return false;
                };
                pending.push((entry.path(), depth + 1, below, Some(entry_kind)));
            }
        } else if !kind.is_file() {
            // A recursive tool lists a link without reading through it unless
            // it was asked to dereference one. The name was screened above;
            // the target belongs to whatever tree owns it, which this walk has
            // not proven. An operand named on the command line is followed by
            // every such tool, so it still needs proof of its own.
            //
            // Only a link is listed rather than read. A FIFO, socket or device
            // is an entry a search can be told to read in place, and what comes
            // back is not a file this walk could have proven, so it refuses.
            if follow_links || depth == 0 || !kind.is_symlink() {
                return false;
            }
        }
    }
    true
}

/// [`glob_expand::expand_glob_matches`] with at least one match.
fn expand_glob(value: &str, context: ReadContext<'_>) -> Option<Vec<PathBuf>> {
    expand_glob_matches(value, context).filter(|matches| !matches.is_empty())
}

pub(super) fn parent_component(value: &str) -> bool {
    value.split(['/', '\\']).any(|part| part == "..")
}

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
use std::path::PathBuf;
#[path = "glob_expand.rs"]
mod glob_expand;

#[path = "descendant.rs"]
mod descendant;
#[path = "literal_bracket.rs"]
mod literal_bracket;
#[path = "operand.rs"]
mod operand;

use literal_bracket::inert_bracket_class;

pub(in crate::pretool) use descendant::SECRET_EXTENSIONS;
pub(super) use descendant::{descendant_allowed, hidden_allowed};
pub(in crate::pretool) use literal_bracket::{
    safe_literal_bracket_read_target, safe_literal_bracket_search_target, safe_literal_bracket_tree,
};
use operand::checked_directory;
pub(super) use operand::{expanded_operand, home_relative, real_allowed_directory, HAZARDS};

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

/// Names-only recursive listing (`ls -R`). `lists_hidden` is the `-a`/`-A`
/// flag. Without it the lister prints no hidden name and descends into no
/// hidden directory, so a hidden entry below the root is not part of what the
/// command can emit. Screening one anyway refused every `ls -R` run inside a
/// repository, because `.git` is hidden and carries no benign-name exemption.
pub(in crate::pretool) fn safe_recursive_listing_target(
    value: &str,
    context: ReadContext<'_>,
    lists_hidden: bool,
) -> bool {
    safe_walk_target(
        value,
        context,
        &[],
        &[],
        WalkReach {
            skip_hidden: !lists_hidden,
            ..WalkReach::default()
        },
        None,
    ) || super::agent_root::agent_root_listing(value, context, true)
}

/// Names-only recursive listing that reaches every entry, as `du` does.
pub(in crate::pretool) fn safe_recursive_target(value: &str, context: ReadContext<'_>) -> bool {
    safe_recursive_listing_target(value, context, true)
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
        WalkReach {
            git_metadata,
            follow_links,
            skip_hidden: false,
        },
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
            WalkReach {
                git_metadata: true,
                follow_links,
                skip_hidden: false,
            },
            Some(clearance),
        )
}

pub(in crate::pretool) use super::roots::{listing_root_below_home, rg_root_inside_cwd};

pub(super) fn inside_agent_state(path: &std::path::Path, context: ReadContext<'_>) -> bool {
    std::fs::canonicalize(path).is_ok_and(|canonical| {
        super::super::read_paths::inside_agent_state_tree(&canonical, context.home_dir)
    })
}

/// What a walk is allowed to cross: git metadata, symbolic links, and
/// whether a hidden entry is part of what the command can emit at all.
#[derive(Clone, Copy, Default)]
struct WalkReach {
    git_metadata: bool,
    follow_links: bool,
    skip_hidden: bool,
}

fn safe_walk_target(
    value: &str,
    context: ReadContext<'_>,
    excluded_files: &[&str],
    excluded_directories: &[&str],
    reach: WalkReach,
    clearance: Option<&PatternClearance>,
) -> bool {
    let WalkReach {
        git_metadata,
        follow_links,
        skip_hidden,
    } = reach;
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
    match (clearance, skip_hidden) {
        (Some(clearance), _) => walk_uncached(
            root,
            excluded_files,
            excluded_directories,
            git_metadata,
            follow_links,
            Some(clearance),
            skip_hidden,
        ),
        (None, true) => walk_skipping_hidden(
            root,
            excluded_files,
            excluded_directories,
            git_metadata,
            follow_links,
        ),
        (None, false) => walk(
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
    let Some(matches) = expand_listing_glob(value, context) else {
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

/// No shell option can make `value` match anything, so a program handed the
/// word receives only the literal text or, under `nullglob`, nothing at all.
pub(in crate::pretool) fn glob_matches_nothing(value: &str, context: ReadContext<'_>) -> bool {
    glob_expand::expand_glob_matches_strict(value, context)
        .is_some_and(|matches| matches.is_empty())
}

/// Content-search glob operand: every match is walked, and matches inside an
/// Oh My Pi agent-state tree are refused as for a literal search root.
///
/// A glob the expansion refuses, such as `src/*.ts` in a directory with more
/// files than it lists, is proven by walking the literal directory it
/// expands below: the search then reads no more than a recursive search of
/// that directory, which the same walk admits.
pub(in crate::pretool) fn safe_glob_search_operand(value: &str, context: ReadContext<'_>) -> bool {
    let searched =
        |path: PathBuf| !inside_agent_state(&path, context) && walk(path, &[], &[], false, false);
    match expand_glob_matches(value, context) {
        Some(matches) => !matches.is_empty() && matches.into_iter().all(searched),
        None => glob_expand::search_glob_directory(value, context).is_some_and(searched),
    }
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

/// [`walk`] for a lister that never descends into a hidden entry.
fn walk_skipping_hidden(
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
        true,
        || {
            walk_uncached(
                root.clone(),
                excluded_files,
                excluded_directories,
                git_metadata,
                follow_links,
                None,
                true,
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
    let _documents = crate::pretool::search_scope_tracked::names::document_walk();
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

/// [`glob_expand::expand_glob_matches_listing`] with at least one match.
fn expand_listing_glob(value: &str, context: ReadContext<'_>) -> Option<Vec<PathBuf>> {
    glob_expand::expand_glob_matches_listing(value, context).filter(|matches| !matches.is_empty())
}

pub(super) fn parent_component(value: &str) -> bool {
    value.split(['/', '\\']).any(|part| part == "..")
}

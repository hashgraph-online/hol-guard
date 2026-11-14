//! Why a recursive `grep` stays under review when a sensitive file is in
//! reach. The generic reason ("could not be confirmed read-only") left agents
//! guessing which operand held the search. This names the file the walk
//! stopped at, in the words the Oh My Pi `grep` review uses, and the shell
//! ways around it. Names are inspected, and a sensitive file the pattern
//! clearance considers is read locally, as the proof reads it, so a file the
//! pattern cannot match is never the one named. A file no `--include` glob
//! selects is never named either: grep does not open it. No content is
//! returned.
//!
//! An include search over more entries than the include proof may inspect
//! names nothing it did not select. Naming whatever hidden file the walk met
//! first sent agents after an `--exclude-dir` that could not shorten the
//! proof, so the reason says the tree is too large instead.

use super::{scan_arguments, tree, AbsentOperands, ReadContext};
use crate::pretool::search_pattern_clearance::PatternClearance;

const MAX_ENTRIES: usize = 10_000;

/// The entries the include proof may inspect. Past this many, an include
/// search is reviewed for its size whatever the globs select.
const INCLUDE_PROOF_ENTRIES: usize = crate::pretool::search_scope_walk::MAX_INCLUDE_SCOPE_ENTRIES;

/// A review reason for a command that is one recursive `grep` plus filters of
/// its output, when a sensitive-named entry under one of its roots is what
/// holds it. `None` for every other command.
pub(in crate::pretool) fn sensitive_reach_reason(
    model: &crate::CanonicalCommandV1,
    context: ReadContext<'_>,
) -> Option<String> {
    if model.confidence != "exact" || model.path_overridden || !model.wrapper_chain.is_empty() {
        return None;
    }
    let mut grep = None;
    for segment in &model.segments {
        let is_grep = segment
            .executable
            .as_deref()
            .is_some_and(|name| crate::pretool::executable_basename(name) == "grep");
        if is_grep && grep.is_none() {
            grep = Some(segment);
        } else if !crate::pretool::segment_proof::stdin_filter_segment(segment) {
            return None;
        }
    }
    let segment = grep.filter(|segment| segment.environment_names.is_empty())?;
    let absent = AbsentOperands {
        plain: true,
        recursive: true,
    };
    let (proven, scan) = scan_arguments(&segment.arguments, context, false, absent, false);
    if proven || !scan.recursive {
        return None;
    }
    // Any `--exclude` next to `--include` keeps the review, so advice to
    // exclude a file would not release the search.
    if scan.include_beside_exclusion {
        return None;
    }
    let clearance = scan.clearance();
    let mut inspected = 0_usize;
    let shown = scan.targets.iter().find_map(|target| {
        let entry =
            first_sensitive_entry(target, context, &scan, clearance.as_ref(), &mut inspected)?;
        let folder = target.trim_end_matches('/');
        let shown = if matches!(folder, "" | ".") {
            entry
        } else {
            format!("{folder}/{entry}")
        };
        (shown.len() <= 512 && !shown.contains('`') && !shown.chars().any(char::is_control))
            .then_some(shown)
    });
    let Some(shown) = shown else {
        // Only the include proof's limit is known to be below this walk's;
        // a plain recursive search past this walk's limit stays unexplained.
        let too_large = !scan.included.is_empty() && inspected > INCLUDE_PROOF_ENTRIES;
        return too_large.then(|| {
            "HOL Guard requires review because the search covers more files than Guard can check before it runs. Name the folders you need instead of the whole tree, for example `grep -rn PATTERN src app`.".to_owned()
        });
    };
    Some(format!(
        "HOL Guard requires review because the search would reach `{shown}`, which Guard treats as sensitive. Leave out the folder that holds it, for example by naming the folders you need instead of the whole tree, or skip it with `--exclude=<file>` or `--exclude-dir=<folder>`."
    ))
}

/// The first entry below `value`, in name order, that the recursive screens
/// refuse by name and the pattern clearance does not admit, relative to
/// `value`. A walk that does not finish names nothing. Every entry it
/// inspects is added to `inspected`.
fn first_sensitive_entry(
    value: &str,
    context: ReadContext<'_>,
    scan: &super::Scan,
    clearance: Option<&PatternClearance>,
    inspected: &mut usize,
) -> Option<String> {
    if value.split(['/', '\\']).any(|part| part == "..")
        || !crate::pretool::safe_reads::bounded_read_target(
            value,
            context.home_dir,
            context.cwd,
            true,
        )
    {
        return None;
    }
    let root = tree::expanded_operand(value, context)?;
    // The flag marks an entry below a directory that only the clearance
    // admitted, whose files must each clear on their own content.
    let mut pending = vec![(root.clone(), false)];
    let mut walked = 0_usize;
    while let Some((path, admitted_below)) = pending.pop() {
        let mut below = admitted_below;
        walked += 1;
        *inspected += 1;
        if walked > MAX_ENTRIES {
            return None;
        }
        let metadata = std::fs::symlink_metadata(&path).ok()?;
        if path != root {
            let name = path.file_name().and_then(|name| name.to_str())?;
            let excluded = if metadata.is_dir() {
                &scan.excluded_directories
            } else {
                &scan.excluded_files
            };
            if name == ".git" || excluded.iter().any(|excluded| excluded == name) {
                continue;
            }
            // An include list is the whole of what grep opens below a root.
            if !metadata.is_dir() && !included(&scan.included, name) {
                continue;
            }
            if !tree::descendant_allowed(&path, &root, metadata.is_file()) {
                // The name alone holds the search; a clearance may admit it.
                if !clearance.is_some_and(|clearance| clearance.admits(&path, &metadata)) {
                    return shell_relative(&path, &root);
                }
                if metadata.is_file() {
                    continue;
                }
                below = true;
            } else if admitted_below && metadata.is_file() {
                if clearance.is_some_and(|clearance| clearance.clears(&path)) {
                    continue;
                }
                return shell_relative(&path, &root);
            }
        }
        if metadata.is_dir() {
            let mut entries: Vec<_> = std::fs::read_dir(&path)
                .ok()?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<Result<Vec<_>, _>>()
                .ok()?;
            entries.sort();
            // The stack pops the last entry first.
            pending.extend(entries.into_iter().rev().map(|entry| (entry, below)));
        }
    }
    None
}

/// Whether grep opens a file of this name: GNU grep matches an include
/// against the name. BSD grep also tries the whole path, which can only add
/// files, so the reason may skip a file BSD grep would open; it is advice and
/// grants nothing.
fn included(globs: &[String], name: &str) -> bool {
    globs.is_empty()
        || globs
            .iter()
            .any(|glob| crate::codex_output_fnmatch::fnmatchcase(name, glob))
}

/// `path` below `root`, spelled with `/` as the command line spells it. The
/// name is joined to the operand the agent typed, so a Windows separator here
/// would leave a path mixed from both.
fn shell_relative(path: &std::path::Path, root: &std::path::Path) -> Option<String> {
    let parts = path
        .strip_prefix(root)
        .ok()?
        .components()
        .map(|part| part.as_os_str().to_str())
        .collect::<Option<Vec<_>>>()?;
    Some(parts.join("/"))
}

#[cfg(test)]
#[path = "reach_tests.rs"]
mod tests;

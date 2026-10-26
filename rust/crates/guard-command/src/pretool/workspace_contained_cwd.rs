//! Possible shell working directories for literal command segments.

use crate::CanonicalCommandV1;
use std::path::{Path, PathBuf};

const MAX_STATES: usize = 64;

/// Whether this segment is the shell builtin that moves the shell itself.
///
/// Only the bare spelling counts. `cd` and `pushd` change the directory of the
/// shell that reads them, which is why a proven descent may spend a `..` step
/// later in the same command; a program at `./tools/cd` or `/usr/local/bin/cd`
/// is an ordinary child process that cannot move its parent, so reading it by
/// basename would credit the walk with a descent the real shell never made and
/// let the next `..` leave the workspace.
fn moves_the_shell(executable: Option<&str>) -> bool {
    matches!(executable, Some("cd") | Some("pushd"))
}

pub(super) fn locations(model: &CanonicalCommandV1, workspace: &Path) -> Option<Vec<Vec<PathBuf>>> {
    let mut states = vec![(workspace.to_path_buf(), true)];
    let mut result = Vec::new();
    for (index, segment) in model.segments.iter().enumerate() {
        let connector: String = if index == 0 {
            String::new()
        } else {
            let before = &model.segments[index - 1];
            model
                .normalized_text
                .chars()
                .skip(before.span.end)
                .take(segment.span.start.checked_sub(before.span.end)?)
                .collect()
        };
        let connector = connector.trim();
        if !matches!(connector, "" | "&&" | "||" | ";" | "|" | "\n") {
            return None;
        }
        let name = segment.executable.as_deref()?;
        let mut executing = Vec::new();
        let mut next = Vec::new();
        for (cwd, succeeded) in states {
            if (connector == "&&" && !succeeded) || (connector == "||" && succeeded) {
                next.push((cwd, succeeded));
                continue;
            }
            executing.push(cwd.clone());
            if moves_the_shell(Some(name)) {
                let [target] = segment.arguments.as_slice() else {
                    return None;
                };
                if target.starts_with(['-', '~', '+']) {
                    return None;
                }
                // A pipeline's cd runs in a child shell and never moves its parent.
                let in_pipeline = model
                    .segments
                    .iter()
                    .filter(|other| other.execution_context == segment.execution_context)
                    .count()
                    > 1;
                if in_pipeline {
                    next.extend([(cwd.clone(), true), (cwd, false)]);
                } else {
                    let supplied = cwd.join(target);
                    // The sandbox hands the run no CDPATH to search, and
                    // `cd::sets_search_path` refuses the shape of a run that
                    // sets one itself, so a name that exists here is where the
                    // run lands. A name that does not exist has nowhere to
                    // land at all, so don't invent a cwd the real shell never
                    // reaches.
                    if !supplied.is_dir() {
                        return None;
                    }
                    let moved = supplied.canonicalize().ok()?;
                    if !moved.starts_with(workspace) {
                        return None;
                    }
                    // A failed cd leaves the old cwd. &&/|| choose the corresponding
                    // state; a later semicolon resumes both, rather than guessing.
                    next.extend([(moved, true), (cwd, false)]);
                }
            } else if name == "popd" {
                return None;
            } else {
                next.extend([(cwd.clone(), true), (cwd, false)]);
            }
        }
        next.sort();
        next.dedup();
        if next.len() > MAX_STATES {
            return None;
        }
        executing.sort();
        executing.dedup();
        result.push(executing);
        states = next;
    }
    Some(result)
}

/// How many directories below `workspace` every shell that could run each
/// segment stands, segment by segment. A segment that runs one directory down
/// resolves one leading `..` back inside the workspace, so the reach checks
/// may spend that many parent steps before a path leaves. Where the walk
/// cannot prove the directory — an unmodelled connector, a `popd`, a `cd`
/// whose target is not there yet — every segment keeps the root's zero, which
/// is what the checks assumed before.
pub(super) fn depths(model: &CanonicalCommandV1, workspace: &Path) -> Vec<usize> {
    let zeros = vec![0usize; model.segments.len()];
    // A command with no `cd` and no parent step cannot spend one, and the walk
    // reads the file system, so it is worth skipping.
    if !model.normalized_text.contains("..")
        // A `CDPATH` the command sets sends a bare relative `cd` wherever that
        // search finds the name first, which is not the directory `locations`
        // joins it onto, so no segment may spend a step. zsh ties the same
        // search to a lowercase `cdpath` array, and `export cdpath=...` in a
        // zsh harness sets both, so the name is matched without case.
        || model
            .normalized_text
            .to_ascii_lowercase()
            .contains("cdpath")
        || !model
            .segments
            .iter()
            .any(|segment| moves_the_shell(segment.executable.as_deref()))
    {
        return zeros;
    }
    let Some(locations) = locations(model, workspace) else {
        return zeros;
    };
    locations
        .iter()
        .map(|roots| {
            // The shallowest possible directory decides: a `;` after a `cd`
            // leaves both the moved and the unmoved shell, and only the steps
            // both can spend stay inside.
            roots
                .iter()
                .map(|root| {
                    root.strip_prefix(workspace)
                        .map_or(0, |rest| rest.components().count())
                })
                .min()
                .unwrap_or(0)
        })
        .collect()
}

// The tests spell the workspace path inside POSIX shell text, which a
// Windows `\\?\C:\...` path cannot be written in.
#[cfg(all(test, unix))]
#[path = "workspace_contained_cwd_tests.rs"]
mod tests;

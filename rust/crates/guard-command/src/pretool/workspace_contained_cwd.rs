//! Possible shell working directories for literal command segments.

use crate::CanonicalCommandV1;
use std::path::{Path, PathBuf};

const MAX_STATES: usize = 64;

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
        let name = crate::pretool::executable_basename(segment.executable.as_deref()?);
        let mut executing = Vec::new();
        let mut next = Vec::new();
        for (cwd, succeeded) in states {
            if (connector == "&&" && !succeeded) || (connector == "||" && succeeded) {
                next.push((cwd, succeeded));
                continue;
            }
            executing.push(cwd.clone());
            if matches!(name, "cd" | "pushd") {
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
                    // Missing relative names may resolve through CDPATH; don't
                    // invent a successful cwd that the real shell won't use.
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

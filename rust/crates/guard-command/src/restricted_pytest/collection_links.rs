use super::*;
use std::collections::{BTreeSet, VecDeque};

/// Directories pytest leaves out of collection by default (`norecursedirs`).
/// Entries inside them are never stat'd, so their links need no metadata.
const COLLECTION_SKIPPED_DIRECTORIES: &[&str] = &[
    "_darcs",
    "build",
    "CVS",
    "dist",
    "node_modules",
    "venv",
    "{arch}",
];
/// At most this many directory entries are examined across the whole walk.
const COLLECTION_ENTRY_BUDGET: usize = 20_000;
const COLLECTION_DEPTH_LIMIT: usize = 16;

fn collection_skips(name: &str) -> bool {
    name.starts_with('.')
        || name.ends_with(".egg")
        || COLLECTION_SKIPPED_DIRECTORIES.contains(&name)
}

/// Collection calls `is_file()` on every entry of each directory it walks,
/// which follows a link to its target. A link to a path outside the sandbox,
/// such as a worktree's `node_modules` borrowed from the main checkout, then
/// stops collection with `PermissionError` unless its target's metadata is
/// readable. This walks the same directories pytest does by default and
/// returns those targets; their contents stay unreadable.
pub(super) fn collection_link_metadata(
    input: &Input,
) -> Result<Vec<PathBuf>, RestrictedPytestError> {
    walk(input, COLLECTION_ENTRY_BUDGET)
}

/// A directory named on the command line is collected even when its name is
/// one pytest skips by default (`pytest build/tests`), so each argument that
/// resolves to a directory inside the workspace is walked as a root too.
fn selected_directories(input: &Input) -> Vec<PathBuf> {
    let Ok(workspace) = input.workspace.canonicalize() else {
        return vec![];
    };
    input
        .command
        .iter()
        .skip(1)
        .filter(|argument| !argument.starts_with('-'))
        .filter_map(|argument| {
            let path = argument.split("::").next().unwrap_or(argument);
            input.cwd.join(path).canonicalize().ok()
        })
        .filter(|path| path.is_dir() && path.starts_with(&workspace))
        .collect()
}

/// The walk is breadth-first and always lists the workspace and cwd in full,
/// so the budget only limits how far it descends. Links at either root keep
/// their grants however large the tree below them is.
pub(super) fn walk(
    input: &Input,
    mut budget: usize,
) -> Result<Vec<PathBuf>, RestrictedPytestError> {
    let unavailable = || {
        RestrictedPytestError::new(
            PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
            "Collection metadata is unavailable.",
        )
    };
    let patterns: Vec<Regex> = patterns().iter().map(|p| Regex::new(p).unwrap()).collect();
    let mut targets = BTreeSet::new();
    let mut roots = BTreeSet::from([input.workspace.clone(), input.cwd.clone()]);
    roots.extend(selected_directories(input));
    let mut pending: VecDeque<(PathBuf, usize, bool)> = roots
        .into_iter()
        .map(|directory| (directory, 0, true))
        .collect();
    let mut visited = BTreeSet::new();
    while let Some((directory, depth, required)) = pending.pop_front() {
        if !visited.insert(directory.clone()) {
            continue;
        }
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(_) if required => return Err(unavailable()),
            Err(_) => continue,
        };
        for entry in entries {
            if required {
                budget = budget.saturating_sub(1);
            } else if budget == 0 {
                return Ok(targets.into_iter().collect());
            } else {
                budget -= 1;
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) if required => return Err(unavailable()),
                Err(_) => continue,
            };
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_symlink() {
                if let Ok(target) = entry.path().canonicalize() {
                    if !patterns
                        .iter()
                        .any(|p| p.is_match(&target.to_string_lossy()))
                    {
                        targets.insert(target);
                    }
                }
            } else if kind.is_dir()
                && depth < COLLECTION_DEPTH_LIMIT
                && !collection_skips(&entry.file_name().to_string_lossy())
            {
                pending.push_back((entry.path(), depth + 1, false));
            }
        }
    }
    Ok(targets.into_iter().collect())
}

use std::path::{Component, Path};

/// Scratch folder names a script or agent writes its own output into.
/// Writes to them are already proven (`plain_dot_scratch_target`).
const SCRATCH_FOLDERS: &[&str] = &[".scratch", ".temp", ".tmp"];

/// A file or folder below a scratch folder at the top of the session folder,
/// such as `.tmp/report/cohorts.jsonl` that a report script just wrote. The
/// scratch folder must be the only hidden part, so this never opens other
/// hidden state, and the session folder must not be the home or above it,
/// where `~/.tmp` would be a home dot folder. `canonical` is already fully
/// resolved, so a scratch link out of the session folder does not qualify,
/// and the caller has already refused credential names and sensitive
/// families.
pub(in crate::pretool) fn workspace_scratch_read(
    canonical: &Path,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    let (Some(home), Some(root)) = (
        home_dir.and_then(|home| std::fs::canonicalize(home).ok()),
        cwd.and_then(|cwd| std::fs::canonicalize(cwd).ok()),
    ) else {
        return false;
    };
    if home.starts_with(&root) {
        return false;
    }
    let Ok(relative) = canonical.strip_prefix(&root) else {
        return false;
    };
    let mut names = relative.components().map(|component| match component {
        Component::Normal(name) => name.to_str(),
        _ => None,
    });
    names
        .next()
        .flatten()
        .is_some_and(|first| SCRATCH_FOLDERS.contains(&first))
        && names.all(|name| name.is_some_and(|name| !name.starts_with('.')))
}

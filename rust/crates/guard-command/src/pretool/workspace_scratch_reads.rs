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

/// A scratch folder, or an entry below one, in a directory the session made
/// in the private temporary directory.
///
/// Work stages its own output there — `mktemp -d` for a comparison checkout,
/// a report script writing `.tmp/rows.jsonl` beside it — and reads it back.
/// Every other file in that directory already reads, because the private
/// temporary directory is the session's own space; only the scratch folder's
/// leading dot held `ls .../.tmp` for review while `ls .../node_modules`
/// beside it continued. The folder must be named for scratch and must be the
/// path's only hidden part, so a `.ssh` or a `.env` staged in the same
/// directory keeps its screen, a part the host does not spell in UTF-8 refuses
/// the read outright, and `canonical` is already resolved, so a link
/// out of the temporary directory does not qualify.
pub(in crate::pretool) fn private_temporary_scratch_read(
    canonical: &Path,
    home_dir: Option<&str>,
) -> bool {
    if !super::private_temporary::inside_private_temporary_directory(canonical, home_dir) {
        return false;
    }
    let mut hidden = Vec::new();
    for component in canonical.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        // A name the host does not spell in UTF-8 cannot be read for a leading
        // dot, so it cannot be shown to be anything but hidden state.
        let Some(name) = name.to_str() else {
            return false;
        };
        if name.starts_with('.') {
            hidden.push(name);
        }
    }
    matches!(hidden.as_slice(), [only] if SCRATCH_FOLDERS.contains(only))
}

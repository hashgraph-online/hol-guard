//! The descendant walk below a sibling repository root, as `rg` and `fd`
//! search it by default.
//!
//! `excluded` holds names an `rg -g '!NAME'` override leaves out. An override
//! outranks every ignore file, so `rg` neither reads an excluded file nor
//! enters an excluded directory, whatever a `.gitignore` negation re-includes
//! below it. Ignore files are still read wherever `rg` reads them, so an
//! `.ignore` or `.rgignore` stops the walk even under an excluded name's
//! parent.
use super::{tree, Ignored, MAX_DEPTH, MAX_ENTRIES};
use std::path::{Path, PathBuf};

/// Why a walk did not prove its tree.
pub(super) enum Refused {
    /// The descendant screen refused this entry by its name or place.
    Sensitive(PathBuf),
    /// Anything else: an ignore file, a link, an unreadable entry, a limit.
    Other,
}

pub(super) fn walk(
    root: &Path,
    operand: &Path,
    ignored: &mut Ignored,
    whitelisting: &[&str],
    excluded: &[String],
) -> Result<(), Refused> {
    let mut pending: Vec<(PathBuf, usize)> = vec![(operand.to_path_buf(), 0)];
    let mut inspected = 0_usize;
    let _documents = crate::pretool::search_scope_tracked::names::document_walk();
    while let Some((directory, depth)) = pending.pop() {
        if depth > MAX_DEPTH {
            return Err(Refused::Other);
        }
        // The directory's own `.gitignore` applies to its entries, so its
        // negations are admitted before any entry is screened.
        if directory != root && !ignored.admit_ignore_file(&directory) {
            return Err(Refused::Other);
        }
        let Ok(entries) = std::fs::read_dir(&directory) else {
            return Err(Refused::Other);
        };
        // Sorted, so the entry a refusal names is the same on every run.
        let mut entries = entries
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Refused::Other)?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        let mut below = Vec::new();
        for entry in entries {
            inspected += 1;
            if inspected > MAX_ENTRIES {
                return Err(Refused::Other);
            }
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                return Err(Refused::Other);
            };
            if whitelisting.contains(&name) {
                return Err(Refused::Other);
            }
            // `rg` skips hidden entries unless a negated pattern re-includes
            // them; ignore files themselves were read above.
            if name == ".gitignore" || (name.starts_with('.') && !ignored.whitelists(&path)) {
                continue;
            }
            if ignored.prunes(name, directory == root) || excluded.iter().any(|left| left == name) {
                continue;
            }
            // The listing already carries each entry's kind here, so this reads
            // it instead of spending an `lstat` per entry, falling back to one
            // only where the filesystem leaves the kind unknown. Like `lstat`,
            // it describes a link itself, so a symlink is neither a directory
            // nor a file and still refuses the proof below.
            let Ok(kind) = entry.file_type() else {
                return Err(Refused::Other);
            };
            if !tree::descendant_allowed(&path, root, kind.is_file()) {
                return Err(Refused::Sensitive(path));
            }
            if kind.is_dir() {
                below.push((path, depth + 1));
            } else if !kind.is_file() {
                return Err(Refused::Other);
            }
        }
        // The stack pops the last entry first.
        pending.extend(below.into_iter().rev());
    }
    Ok(())
}

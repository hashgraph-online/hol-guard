//! Hidden entries a repository commits as documents.
//!
//! A recursive search refuses a hidden name that is not on its short benign
//! list, because recursion would otherwise reach `.env`, `.ssh` or a tool's
//! login state. Projects also commit dot-folders of their own documents, such
//! as a design tool's `.impeccable/design.json` or a linter's
//! `.markdownlint.json`. Refusing those sends every search of the folder that
//! holds them to review.
//!
//! Such an entry is walked when the repository tracks every file it holds,
//! each file is a small document the tracked-file proof finds free of secrets,
//! and no name on the way is a harness directory, a credential store, an
//! environment file or `.git`. Links, sockets and untracked files keep the
//! review, and so does a folder too large or too deep to prove.
use guard_secure_fs::credential_store_names::{
    lowered_names, names_hold_credential_store, HARNESS_DIRECTORIES,
};
use std::path::Path;

/// Entries, files and folders alike, a hidden folder may hold before the
/// proof gives up.
const MAX_ENTRIES: usize = 32;
/// Folder levels the proof descends below the hidden folder.
const MAX_DEPTH: usize = 3;

/// Whether `path`, a hidden file or folder a recursive walk reached, holds
/// only documents the repository commits.
pub(super) fn committed_hidden(path: &Path, is_file: bool) -> bool {
    if !path.is_absolute()
        || !lowered_names(path)
            .last()
            .is_some_and(|name| screened(name))
    {
        return false;
    }
    if names_hold_credential_store(&lowered_names(path)) {
        return false;
    }
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if is_file {
        return metadata.is_file() && committed(path);
    }
    let mut walk = Walk::default();
    metadata.is_dir() && documents_only(path, 0, &mut walk) && walk.files > 0
}

/// What the proof has visited so far, shared across every level.
#[derive(Default)]
struct Walk {
    entries: usize,
    files: usize,
}

/// A name that is neither `.git`, a harness folder, a credential store nor
/// an environment file.
fn screened(name: &str) -> bool {
    name != ".git" && !harness_owned(name) && !names_hold_credential_store(&[name.to_owned()])
}

/// Whether a harness owns the folder: its own directory, or one named after
/// it, such as the `.claude-plugin` folder that holds a plugin manifest.
/// A search that reaches those reads how the agent itself is configured, so
/// the proof leaves them to review even when the repository commits them.
fn harness_owned(name: &str) -> bool {
    HARNESS_DIRECTORIES.iter().any(|harness| {
        name == *harness
            || name
                .strip_prefix(harness)
                .is_some_and(|rest| rest.starts_with('-') || rest.starts_with('.'))
    })
}

fn committed(path: &Path) -> bool {
    crate::pretool::search_scope_tracked::names::committed_document(path)
}

fn documents_only(directory: &Path, depth: usize, walk: &mut Walk) -> bool {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return false;
    };
    for entry in entries {
        let Ok(entry) = entry else {
            return false;
        };
        // `file_type` does not follow links, so a link is neither a file nor
        // a folder here and keeps the review.
        let Ok(kind) = entry.file_type() else {
            return false;
        };
        walk.entries += 1;
        if walk.entries > MAX_ENTRIES
            || !screened(&entry.file_name().to_string_lossy().to_ascii_lowercase())
        {
            return false;
        }
        let path = entry.path();
        let proven = if kind.is_dir() {
            depth + 1 < MAX_DEPTH && documents_only(&path, depth + 1, walk)
        } else if kind.is_file() {
            walk.files += 1;
            committed(&path)
        } else {
            false
        };
        if !proven {
            return false;
        }
    }
    true
}

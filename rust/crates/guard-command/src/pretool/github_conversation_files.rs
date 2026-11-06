//! The `--body-file` of a review-conversation write: one plain, bounded
//! UTF-8 file in the work tree or in an owned temporary directory.

use std::io::Read;
use std::path::Path;

/// Longest body file read, in bytes.
const MAX_FILE_BYTES: u64 = 64 * 1024;

/// The text of the body file `value` names, or `None` when it is standard
/// input, a link, a special or oversized file, sensitive, outside the work
/// tree `root` (or inside its `.git`) and every owned temporary directory,
/// or not UTF-8 text. The caller scans the text for credentials.
pub(super) fn body_file_text(
    value: &str,
    context: super::super::PathContext<'_>,
    root: &Path,
) -> Option<String> {
    if value.is_empty() || value == "-" || value.starts_with('~') || value.len() > 4096 {
        return None;
    }
    let path = Path::new(value);
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        Path::new(context.cwd?).join(path)
    };
    let metadata = std::fs::symlink_metadata(&candidate).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES || !single_link(&metadata) {
        return None;
    }
    let canonical = std::fs::canonicalize(&candidate).ok()?;
    let in_work_tree = canonical.strip_prefix(root).is_ok_and(|relative| {
        !relative
            .components()
            .any(|part| part.as_os_str().eq_ignore_ascii_case(".git"))
    });
    // System roots, another user's home, credential families and
    // credential-named files stay out even inside the work tree.
    if !(in_work_tree || private_temporary(&canonical, context))
        || !super::super::read_paths::resolved_location_allowed(
            &canonical,
            context.home_dir,
            context.cwd,
            false,
        )
    {
        return None;
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&canonical)
        .ok()?
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_FILE_BYTES || bytes.contains(&0) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// A second hard link could name a credential file outside the workspace.
#[cfg(unix)]
fn single_link(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.nlink() == 1
}

#[cfg(not(unix))]
fn single_link(_metadata: &std::fs::Metadata) -> bool {
    true
}

/// A file in a directory below `/tmp` that the home owner owns and no one
/// else can write, down from `/tmp`.
fn private_temporary(canonical: &Path, context: super::super::PathContext<'_>) -> bool {
    canonical
        .parent()
        .is_some_and(|parent| super::super::git_routes::owned_temporary_directory(parent, context))
}

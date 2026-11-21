//! A script outside the workspace that the sandbox may read, and only it.
//!
//! Agents routinely write a scratch script to a temporary directory and run
//! it. Such a launch is workspace work once its source is read and found to
//! need neither the network nor a credential store: the sandbox still bounds
//! every effect, and it is granted read access to that one file. The grant is
//! never a directory, never a symbolic link, and never a path the secret-path
//! screen names or that sits below a hidden directory.

use crate::CommandSegmentV1;
use std::path::{Component, Path, PathBuf};

use super::super::script_content::{self, Language};

/// Scripts this large are not read whole, so they are not granted.
const MAX_SCRIPT_BYTES: u64 = 256 * 1024;

/// The operand and canonical file of the script `segment` launches when it
/// lies outside `workspace` and qualifies for a bounded read grant.
pub(super) fn outside_script(
    segment: &CommandSegmentV1,
    workspace: &Path,
) -> Option<(String, PathBuf)> {
    let (language, operand) = script_content::launched_script(segment)?;
    let canonical = grantable(language, operand, workspace)?;
    script_content::standalone_clean(language, &canonical).then(|| (operand.to_owned(), canonical))
}

fn grantable(language: Language, operand: &str, workspace: &Path) -> Option<PathBuf> {
    if operand.contains(['$', '~', '`', '*', '?', '[', '\\', '\n']) {
        return None;
    }
    let lexical = Path::new(operand);
    if !lexical.is_absolute()
        || lexical.starts_with(workspace)
        || lexical.components().any(|component| match component {
            Component::ParentDir | Component::CurDir => true,
            Component::Normal(name) => name.to_str().is_none_or(|name| name.starts_with('.')),
            _ => false,
        })
    {
        return None;
    }
    let extension = lexical.extension()?.to_str()?;
    if language == Language::Python && extension != "py" {
        return None;
    }
    // The leaf itself may not be a link: a swap after the check would point
    // the grant's name at another file.
    let metadata = std::fs::symlink_metadata(lexical).ok()?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_SCRIPT_BYTES {
        return None;
    }
    let canonical = std::fs::canonicalize(lexical).ok()?;
    if canonical.starts_with(workspace)
        || !same_location(lexical, &canonical)
        || crate::secret_path_probe::is_request_secret_path(operand, Some(workspace), None)
        || crate::secret_path_probe::is_request_secret_path(
            canonical.to_str()?,
            Some(workspace),
            None,
        )
    {
        return None;
    }
    Some(canonical)
}

/// The lexical path names the canonical file directly, or through the one
/// root link macOS keeps for `/tmp`, `/var` and `/etc`. Any other redirected
/// directory could send the script's name somewhere the grant does not cover.
fn same_location(lexical: &Path, canonical: &Path) -> bool {
    lexical == canonical
        || Path::new("/private").join(lexical.strip_prefix("/").unwrap_or(lexical)) == canonical
}

#[cfg(all(test, unix))]
#[path = "workspace_contained_script_tests.rs"]
mod tests;

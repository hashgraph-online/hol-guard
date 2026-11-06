//! How a hook spells the paths it carries, read where the runtime decides.
//!
//! The daemon used to settle these in Python before it asked about trust:
//! the server's `_normalized_hook_workspace_string` and
//! `_runtime_hook_exec_command_workdir` turned a harness spelling into a
//! workspace or into "no workspace", and `hook_request_parsing`'s
//! `_safe_reference_path` decided whether an out-of-band payload file was
//! one Guard had written. A spelling is part of the verdict, so the rules
//! live with the runtime that answers the call.
//!
//! `hook_direct_workspace.rs` keeps its own copy of the workspace rules
//! rather than calling these. It answers for the resident's direct lane,
//! where the temporary root is this process's `std::env::temp_dir()` and a
//! spelling whose verdict that root would decide defers instead of being
//! answered; the daemon's rules here take the temporary root from the
//! request, because the verdict is the daemon's own `gettempdir()` to make.

use crate::guard_paths::{self, PathError};
use std::path::{Path, PathBuf};

/// The directory an out-of-band hook payload has to sit in, named by the
/// writer that creates it.
const PAYLOAD_REFERENCE_DIR_PREFIX: &str = "hol-guard-hook-payload-";

/// The spellings a harness sends for "this request has no workspace".
fn is_absent_spelling(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    lowered == "none" || lowered == "null"
}

fn is_separator(character: char) -> bool {
    character == '/' || (cfg!(windows) && character == '\\')
}

/// `os.path.split`: the directory and the last component, keeping a root
/// that is nothing but separators.
fn split_path(value: &str) -> (&str, &str) {
    let Some(index) = value.rfind(is_separator) else {
        return ("", value);
    };
    let (head, tail) = value.split_at(index + 1);
    if !head.is_empty() && !head.chars().all(is_separator) {
        return (head.trim_end_matches(is_separator), tail);
    }
    (head, tail)
}

/// `_normalized_hook_workspace_string`: the workspace a hook named, or
/// `None` where it named none.
pub(crate) fn normalized_hook_workspace(
    value: &str,
    home_dir: &str,
    temp_dir: &Path,
) -> Result<Option<String>, PathError> {
    let Some(stripped) = guard_paths::python_strip(value)? else {
        return Ok(None);
    };
    if is_absent_spelling(stripped) {
        return Ok(None);
    }
    let expanded = guard_paths::expanduser(stripped, home_dir)?;
    // Mirror the CLI hook contract until runtime callers stop emitting
    // `/None` as the explicit "no workspace" sentinel.
    let (parent, last) = split_path(&expanded);
    let candidate = if last == "None" {
        if guard_paths::python_strip(parent)?.is_none() {
            return Ok(None);
        }
        parent
    } else {
        expanded.as_str()
    };
    let normalized = guard_paths::normpath(candidate)?;
    Ok(without_bare_temporary_root(&normalized, temp_dir))
}

/// `_runtime_hook_exec_command_workdir`'s path half: the directory an
/// `exec_command` call asked to run in. It carries no `/None` sentinel,
/// because the tool input either holds a `workdir` or does not.
pub(crate) fn normalized_exec_workdir(
    value: &str,
    home_dir: &str,
    temp_dir: &Path,
) -> Result<Option<String>, PathError> {
    let Some(stripped) = guard_paths::python_strip(value)? else {
        return Ok(None);
    };
    if is_absent_spelling(stripped) {
        return Ok(None);
    }
    let expanded = guard_paths::expanduser(stripped, home_dir)?;
    let normalized = guard_paths::normpath(&expanded)?;
    Ok(without_bare_temporary_root(&normalized, temp_dir))
}

/// A shared temporary root is where a harness puts a process that has no
/// workspace of its own, so naming the root itself names no workspace.
fn without_bare_temporary_root(candidate: &str, temp_dir: &Path) -> Option<String> {
    let path = Path::new(candidate);
    // Python resolves strictly here and reads `OSError` as "no root".
    let root = guard_paths::trusted_temporary_root_for_path(path, temp_dir)
        .ok()
        .flatten();
    if let Some(root) = root {
        let resolved = guard_paths::python_realpath_lax(path).ok();
        let resolved_root = guard_paths::python_realpath_lax(&root).ok();
        if resolved.is_some() && resolved == resolved_root {
            return None;
        }
    }
    Some(candidate.to_owned())
}

/// `_safe_reference_path`: the file an out-of-band hook payload reference
/// names, when Guard's own writer is the only thing that could have put it
/// there. Anything else is not a payload this runtime reads.
pub(crate) fn trusted_payload_reference(value: &str, temp_dir: &Path) -> Option<PathBuf> {
    let path = Path::new(value);
    // Python resolves a relative reference against the daemon's working
    // directory. This process has its own, so a reference that does not say
    // where it is, is not one that can be trusted here.
    if !path.is_absolute() {
        return None;
    }
    let resolved = guard_paths::python_realpath(path).ok().flatten()?;
    let root = guard_paths::trusted_temporary_root_for_path(&resolved, temp_dir)
        .ok()
        .flatten()?;
    let parent = resolved.parent()?;
    if parent.parent() != Some(root.as_path()) {
        return None;
    }
    if !parent
        .file_name()?
        .to_str()?
        .starts_with(PAYLOAD_REFERENCE_DIR_PREFIX)
    {
        return None;
    }
    if !std::fs::metadata(&resolved).ok()?.is_file() {
        return None;
    }
    Some(resolved)
}

#[cfg(all(test, unix))]
#[path = "hook_path_rules_tests.rs"]
mod tests;

//! `stat` and `file` of a program a tool installed below the home directory.
//!
//! The content screen keeps `~/.cargo/bin/cargo` and
//! `~/.nvm/versions/node/v24.0.0/bin/node` in review: their bytes are a
//! program, and `cat` or `xxd` of one has no place in a task. `stat` and
//! `file` hand the agent none of those bytes. `stat` prints the size, owner
//! and dates; `file` prints a one-line type such as `Mach-O 64-bit
//! executable arm64`. An agent asks both when it checks which build of a tool
//! is installed, the question `ls -la` of the same path already answers
//! without a review.
//!
//! So a metadata operand passes where the content screen would pass, and also
//! where the only thing the content screen held against it is the program
//! directory, per `hidden_program_metadata_allowed`. A directory passes where
//! a listing of it would. A link is screened twice, as spelled and as
//! resolved: `stat` and `file` report the link itself, while `stat -L` and
//! `file -L` report what it points at. Both must sit below home and clear the
//! screen, so a link cannot dress `~/.ssh/id_ed25519` as a program. A `~`
//! spelling passes only while the shell's HOME is the home screened here.

use crate::credential_store_names::{
    clears_store_screen, hidden_content_read_allowed, hidden_program_metadata_allowed,
    lowered_names,
};
use std::path::{Path, PathBuf};

pub(super) fn home_program_metadata(value: &str, context: super::PathContext<'_>) -> bool {
    let (Some(home), Some(cwd)) = (context.home_dir, context.cwd) else {
        return false;
    };
    if value.starts_with('-')
        || (value.contains('\\') && !cfg!(windows))
        || !super::read_paths::bounded_path_spelling(value)
        || !super::read_paths::verified_path_context(context.home_dir, context.cwd)
    {
        return false;
    }
    // `~` is the shell's HOME. When the stamped shell HOME is not the home
    // this check reads, `~/.cargo/bin/tool` names a different file for Bash
    // than the one screened here.
    if (value == "~" || value.starts_with("~/")) && !context.shell_home_matches {
        return false;
    }
    let Some(spelled) = spelled_path(value, home, cwd) else {
        return false;
    };
    let (Ok(home_canonical), Ok(canonical)) =
        (std::fs::canonicalize(home), std::fs::canonicalize(&spelled))
    else {
        return false;
    };
    let Ok(spelled_relative) = spelled
        .strip_prefix(home)
        .or_else(|_| spelled.strip_prefix(&home_canonical))
    else {
        return false;
    };
    let Ok(resolved_relative) = canonical.strip_prefix(&home_canonical) else {
        return false;
    };
    let directory = canonical.is_dir();
    (directory || canonical.is_file())
        && metadata_screen(spelled_relative, directory)
        && metadata_screen(resolved_relative, directory)
        && super::read_paths::resolved_location_allowed(
            &canonical,
            context.home_dir,
            Some(cwd),
            false,
        )
}

/// The absolute spelling of `value`, with `.` components dropped and links
/// left in place. `..` never reaches here.
fn spelled_path(value: &str, home: &str, cwd: &str) -> Option<PathBuf> {
    let path = if value == "~" || value.starts_with("~/") {
        PathBuf::from(super::read_paths::expand_home_read_path(value, Some(home))?)
    } else if Path::new(value).is_absolute() {
        PathBuf::from(value)
    } else {
        let root = super::read_paths::expand_home_read_path(cwd, Some(home))
            .unwrap_or_else(|| cwd.to_owned());
        Path::new(&root).join(value)
    };
    Some(path.components().collect())
}

/// The screen for one home-relative path. A directory takes the listing
/// screen: one hidden directory directly below home, nothing hidden deeper
/// and no credential store. A file takes the content screen or, failing
/// that, the program-directory relaxation of it.
fn metadata_screen(relative: &Path, directory: bool) -> bool {
    let lowered = lowered_names(relative);
    if !directory {
        return hidden_content_read_allowed(&lowered) || hidden_program_metadata_allowed(&lowered);
    }
    lowered.first().is_some_and(|first| first.starts_with('.'))
        && !lowered.iter().skip(1).any(|name| name.starts_with('.'))
        && clears_store_screen(relative)
}

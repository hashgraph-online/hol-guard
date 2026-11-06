//! A path-spelled executable that names an installed program's own entry.
//!
//! The exact-safe floor refuses an executable written with a directory in it.
//! A bare name is looked up on `PATH`, so the basename the command is judged
//! by names a program the session's own environment designates; a path names
//! whatever file it points at, and the agent writes files. Refusing every
//! path spelling costs the read-only admissions their whole subject: the user
//! who runs `~/google-cloud-sdk/bin/kubectl get pods` because that is where
//! the installer put it gets a review, while `kubectl get pods` is silent.
//!
//! This proves one narrower thing: the word names an installed program's own
//! launcher directory, and it names the same program the basename claims.
//! Four properties hold together, and any one alone is a hole:
//!
//! * The directory the word points into is a launcher directory — `bin` or
//!   `sbin` by its own canonical name, not a directory that merely holds a
//!   file of that name.
//! * That directory is one only the home owner or root can write, from the
//!   directory up (see [`super::trusted_location::trusted_program_directory`]).
//!   A directory another user can write is a directory another user can plant
//!   a program in.
//! * The file resolves to a regular executable file outside the checkout the
//!   command runs in. The agent writes the workspace, so a `bin` it wrote
//!   there proves nothing about what the program is.
//! * A home spelling is the shell's own, not one this screen supplies: the
//!   shell's HOME is the declared one, and the `~` is unquoted, so the word
//!   the program is looked up by is the home path this proof resolved. A
//!   quoted `~` stays a literal relative name under the working directory,
//!   which is the one place the agent writes.
//! * The resolved file still carries the basename the command spelled. An
//!   installer's `bin` entry is routinely a link into the version it unpacked,
//!   and that link keeps the program's name; a link that renames some other
//!   program into `kubectl` does not.
//!
//! This proves only which file the word names. The basename still decides
//! what the command may do with it, exactly as it does for a bare name.
use std::path::Path;

pub(super) fn installed_program(
    segment: &crate::CommandSegmentV1,
    executable: &str,
    context: super::PathContext<'_>,
) -> bool {
    if !super::read_paths::verified_path_context(context.home_dir, context.cwd)
        || !super::read_paths::bounded_path_spelling(executable)
    {
        return false;
    }
    // The expansion below reads `~` as the declared home, which is the shell's
    // answer only when its own HOME is that directory and the word reaches it
    // unquoted. Windows has no such expansion to read.
    if executable.starts_with('~')
        && (cfg!(windows)
            || !context.shell_home_matches
            || !super::directory_targets::home_executable_unquoted(segment))
    {
        return false;
    }
    let (Some(home), Some(cwd)) = (context.home_dir, context.cwd) else {
        return false;
    };
    let Ok(candidate) =
        guard_secure_fs::resolve_candidate(executable, Some(Path::new(cwd)), Path::new(home))
    else {
        return false;
    };
    let (Some(parent), Some(program)) = (candidate.parent(), candidate.file_name()) else {
        return false;
    };
    let Ok(binaries) = std::fs::canonicalize(parent) else {
        return false;
    };
    if !binaries
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .is_some_and(|name| name == "bin" || name == "sbin")
    {
        return false;
    }
    if !super::trusted_location::trusted_program_directory(
        &binaries,
        Path::new(home),
        Path::new(cwd),
    ) {
        return false;
    }
    let named = binaries.join(program);
    if !super::read_paths::resolved_location_allowed(&named, context.home_dir, context.cwd, false) {
        return false;
    }
    let Ok(resolved) = std::fs::canonicalize(&named) else {
        return false;
    };
    if !executable_file(&resolved) || resolved.file_name() != Some(program) {
        return false;
    }
    if !super::read_paths::resolved_location_allowed(
        &resolved,
        context.home_dir,
        context.cwd,
        false,
    ) {
        return false;
    }
    let Ok(cwd) = std::fs::canonicalize(cwd) else {
        return false;
    };
    let workspace = nearest_checkout(&cwd).unwrap_or(cwd);
    !binaries.starts_with(&workspace) && !resolved.starts_with(&workspace)
}

/// The checkout the command runs in, so a `bin` the session wrote beside its
/// own work is not read as an installation.
fn nearest_checkout(cwd: &Path) -> Option<std::path::PathBuf> {
    cwd.ancestors()
        .find(|directory| directory.join(".git").symlink_metadata().is_ok())
        .map(Path::to_path_buf)
}

#[cfg(unix)]
fn executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn executable_file(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
#[path = "installed_program_path_tests.rs"]
mod tests;

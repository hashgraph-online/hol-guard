//! Listing operands in a temporary directory agents keep scratch work in.
//!
//! A path below a temporary directory only the home owner can create an
//! entry in - the owner's private temporary root, or an owned directory below
//! the shared one - answers two listing shapes the home tree answers
//! differently: a name that is not there, whatever it spells, and a pattern
//! below that directory. Neither reads anything the owner did not put there,
//! and a home that itself lives below the temporary root - every test
//! fixture, some sandboxes - keeps the home screens' own answers.

/// Whether `ancestor` is a temporary directory only the home owner can
/// create an entry in. Below one, a name that is not there prints the same
/// error whatever it spells: the listing reads nothing, and nobody else can
/// put content behind that name, so a scratch probe
/// (`ls /tmp/tmp.ab12/build/.cache`) needs no visible spelling. The home
/// tree keeps its own answer, where a hidden name is the secrets boundary.
pub(super) fn private_temporary_ancestor(
    ancestor: &std::path::Path,
    context: super::PathContext<'_>,
) -> bool {
    std::fs::canonicalize(ancestor).is_ok_and(|canonical| outside_home(&canonical, context))
}

/// Whether a glob's literal directory is a temporary directory only the home
/// owner can create an entry in: the owner's private temporary root, or an
/// owned directory below a shared one. The listing names the matches, not
/// the directory holding them, and every match is screened on its own. The
/// shared root itself (`/tmp`) is not one: the shell expands the pattern
/// after the screen, and any local user can plant a matching link there in
/// between, so a pattern directly below it keeps its review.
pub(super) fn temporary_glob_directory(
    base: &std::path::Path,
    context: super::PathContext<'_>,
) -> bool {
    std::fs::canonicalize(base).is_ok_and(|canonical| outside_home(&canonical, context))
}

/// Whether `directory` is world-writable, as the shared temporary roots are.
/// Any local user can add an entry there at any moment.
#[cfg(unix)]
pub(super) fn writable_by_anyone(directory: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(directory).is_ok_and(|metadata| metadata.permissions().mode() & 0o002 != 0)
}

#[cfg(not(unix))]
pub(super) fn writable_by_anyone(_directory: &std::path::Path) -> bool {
    false
}

/// Whether canonical `path` is a temporary directory only the home owner can
/// create an entry in, and lies outside the home tree.
fn outside_home(path: &std::path::Path, context: super::PathContext<'_>) -> bool {
    let inside_home = context
        .home_dir
        .and_then(|home| std::fs::canonicalize(home).ok())
        .is_some_and(|home| path.starts_with(&home));
    !inside_home && super::git_routes::private_temporary_parent(path, context)
}

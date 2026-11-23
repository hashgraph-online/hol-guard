//! A shell lookup of a name that is not a program stays at review.
//!
//! `type NAME`, `which NAME` in zsh, `whence NAME` and `command -v NAME` answer
//! from the caller's live shell: its functions and aliases as well as PATH.
//! The workspace sandbox runs a fresh shell with none of the session's
//! definitions, so for a name no PATH directory holds it reports "not found"
//! where the session would print a function body or an alias. That is a wrong
//! answer, not a safe one, and the review the lookup earned is the honest
//! response. A name PATH does resolve gets the same answer in the sandbox.

use std::path::Path;

/// Whether a segment is a lookup that may print a definition and names
/// something no directory on `path` holds as a program. The bounded forms
/// (`type -t`, `whence -p`) are proved read-only elsewhere.
pub(super) fn looks_up_session_definitions(
    model: &crate::CanonicalCommandV1,
    path: Option<&str>,
) -> bool {
    model.segments.iter().any(|segment| {
        let Some(executable) = segment.executable.as_deref() else {
            return false;
        };
        let name = executable.rsplit('/').next().unwrap_or(executable);
        let lookup = match name {
            "type" | "which" | "whence" | "where" => {
                !crate::pretool::lookup_reads::safe_path_lookup(name, &segment.arguments)
            }
            "command" => segment
                .arguments
                .iter()
                .take_while(|argument| argument.starts_with('-') && *argument != "--")
                .any(|flag| flag[1..].contains(['v', 'V'])),
            _ => false,
        };
        lookup
            && segment
                .arguments
                .iter()
                .filter(|argument| !argument.starts_with('-'))
                .any(|operand| !on_path(operand, path))
    })
}

fn on_path(name: &str, path: Option<&str>) -> bool {
    if name.contains('/') {
        return Path::new(name).is_file();
    }
    let inherited = std::env::var("PATH").ok();
    let Some(path) = path.or(inherited.as_deref()) else {
        return false;
    };
    std::env::split_paths(path).any(|dir| executable(&dir.join(name)))
}

#[cfg(unix)]
fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn executable(path: &Path) -> bool {
    path.is_file()
        || ["exe", "cmd", "bat"]
            .iter()
            .any(|ext| path.with_extension(ext).is_file())
}

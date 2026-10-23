//! Whether the workspace sandbox could run the programs a command launches.
//!
//! The sandbox executes only from the workspace, the system directories and
//! the toolchain roots `workspace_exec_roots` accepts, and it searches only
//! the PATH entries it accepted. A program the agent's shell would find
//! elsewhere, or whose script interpreter lives elsewhere, cannot run inside
//! it, so containing that command would only trade a review for a failure.
use super::launch_shebang::{shebang, Shebang};
use super::workspace_linked::admissible_checkout;
use super::*;
use crate::pretool::workspace_git_config::linked_git_dirs;

/// What looking a program up came to.
pub(super) enum Lookup {
    Found(PathBuf),
    /// Nothing to run: a builtin, a function or a name the shell expands.
    Missing,
    /// The answer depends on a directory the caller does not know.
    Unresolved,
}

/// Whether any launch, resolved the way the agent's shell resolves it on
/// `search_path`, is something the workspace sandbox could not execute. Each
/// launch carries every directory the shell may stand in when it starts, with
/// `None` for one that cannot be named. A bare name the shell cannot find is
/// left to the shell (a builtin or a function), a program that resolves to
/// another file inside the sandbox than outside it counts as unreachable, and
/// so does one whose lookup depends on a directory that is not known.
pub(crate) fn launches_outside_exec_roots<'a>(
    launches: impl IntoIterator<Item = (&'a str, Vec<Option<PathBuf>>)>,
    search_path: &str,
    home: Option<&Path>,
    workspace: &Path,
) -> bool {
    // Reachability, not a grant: this asks whether the sandbox could run what
    // the command launches, so the Go module cache, the Cargo caches and the
    // Maven repository stay in view and such a run is not judged unreachable
    // before the plan decides whether to grant them.
    let (roots, sandbox_path) =
        workspace_exec_roots(search_path, home, workspace, true, true, true);
    let mut executable = executable_roots(workspace, roots);
    executable.extend(linked_checkout(workspace, home));
    let reaches = |path: &Path| path_is_within_any(path, &executable);
    launches.into_iter().any(|(program, places)| {
        places.iter().any(|place| {
            unreachable_from(
                program,
                place.as_deref(),
                (search_path, sandbox_path.as_str()),
                &reaches,
            )
        })
    })
}

/// Whether `program`, started from `place`, is one the sandbox could not run.
/// `paths` are the session `PATH` and the one the sandbox accepted.
fn unreachable_from(
    program: &str,
    place: Option<&Path>,
    paths: (&str, &str),
    reaches: &impl Fn(&Path) -> bool,
) -> bool {
    let (search_path, sandbox_path) = paths;
    let found = match locate(program, search_path, place) {
        Lookup::Found(path) => path,
        Lookup::Missing => return false,
        Lookup::Unresolved => return true,
    };
    let Ok(canonical) = found.canonicalize() else {
        return true;
    };
    if !reaches(&canonical) {
        return true;
    }
    if !program.contains('/') {
        let inside = match locate(program, sandbox_path, place) {
            Lookup::Found(path) => path.canonicalize().ok(),
            Lookup::Missing | Lookup::Unresolved => None,
        };
        if inside.as_deref() != Some(canonical.as_path()) {
            return true;
        }
    }
    match shebang(&canonical) {
        Shebang::Absent => false,
        Shebang::Unclear => true,
        Shebang::Runs(programs) => {
            programs
                .iter()
                .any(|name| match locate(name, sandbox_path, place) {
                    Lookup::Found(path) => !path.canonicalize().is_ok_and(|path| reaches(&path)),
                    Lookup::Missing | Lookup::Unresolved => true,
                })
        }
    }
}

/// The macOS system directories that hold programs, named one by one because
/// `/usr` cannot be taken whole: `/usr/local` is writable by any admin user,
/// so a subpath of `/usr` would let a command run something it had just
/// placed there. The sealed directories beside `/usr/bin` carry the tools a
/// session reads its own machine with - `sysctl`, `ioreg`, `system_profiler`,
/// `scutil`, `netstat`, `ifconfig`, `ping`, `diskutil list` - and leaving
/// them out meant a command as ordinary as `sysctl -n hw.ncpu` could not be
/// contained and was reviewed instead. Linux already executes all of `/usr`
/// and `/sbin`, so this is the same posture spelled out for a platform where
/// the parent directory is not uniformly system-owned. The names that change
/// the machine are refused individually by the profile's privilege denials,
/// as they already are in `/usr/bin`.
pub(super) const MAC_PROGRAM_ROOTS: &[&str] = &["/bin", "/usr/bin", "/usr/sbin", "/sbin"];

/// The canonical form of a session `PATH` entry that is one of the system
/// program directories above, which the sandbox executes from on every
/// platform. The toolchain roots the sandbox PATH otherwise accepts leave out
/// `/usr/sbin` and `/sbin`, so a bare `sysctl` resolved there for the agent's
/// shell but not inside the sandbox, and the command went to review.
pub(super) fn system_program_directory(entry: &Path) -> Option<PathBuf> {
    let canonical = entry.canonicalize().ok()?;
    MAC_PROGRAM_ROOTS
        .iter()
        .any(|root| {
            Path::new(root)
                .canonicalize()
                .is_ok_and(|root| root == canonical)
        })
        .then_some(canonical)
}

/// Directories the sandbox may execute from on this platform.
pub(super) fn executable_roots(workspace: &Path, exec_roots: Vec<PathBuf>) -> Vec<PathBuf> {
    let system: &[&str] = if cfg!(target_os = "macos") {
        MAC_PROGRAM_ROOTS
    } else {
        &["/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64"]
    };
    let mut roots = vec![workspace.to_path_buf()];
    roots.extend(
        system
            .iter()
            .map(PathBuf::from)
            .filter(|root| root.exists()),
    );
    roots.extend(exec_roots);
    roots
}

/// The main checkout of a linked worktree workspace. The sandbox reads and
/// executes it, as it does the workspace, so a dependency directory linked
/// into it still runs; one that is not an admissible root gets no plan at all.
fn linked_checkout(workspace: &Path, home: Option<&Path>) -> Option<PathBuf> {
    let (common, _) = linked_git_dirs(workspace, home)?;
    if !admissible_checkout(&common, home) {
        return None;
    }
    common.parent().map(Path::to_path_buf)
}

/// The file `program` names when started from `place`: a path relative to
/// `place`, or a bare name on `search_path`, where an empty or relative entry
/// is a directory below `place` too. Names a shell would expand are not
/// resolved.
pub(super) fn locate(program: &str, search_path: &str, place: Option<&Path>) -> Lookup {
    if program.is_empty() || program.contains(['$', '~', '`', '*', '?', '[', '\\', '\n']) {
        return Lookup::Missing;
    }
    let candidate = if program.contains('/') {
        match (Path::new(program).is_absolute(), place) {
            (true, _) => PathBuf::from(program),
            (false, Some(directory)) => directory.join(program),
            (false, None) => return Lookup::Unresolved,
        }
    } else {
        for entry in search_path.split(':') {
            let directory = match (Path::new(entry).is_absolute(), place) {
                (true, _) => PathBuf::from(entry),
                (false, Some(directory)) => directory.join(entry),
                (false, None) => return Lookup::Unresolved,
            };
            let candidate = directory.join(program);
            if executable_file(&candidate) {
                return Lookup::Found(candidate);
            }
        }
        return Lookup::Missing;
    };
    if executable_file(&candidate) {
        Lookup::Found(candidate)
    } else {
        Lookup::Missing
    }
}

#[cfg(test)]
#[path = "launch_roots_tests.rs"]
mod tests;

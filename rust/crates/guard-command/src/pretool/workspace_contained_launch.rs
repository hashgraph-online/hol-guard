//! Programs the workspace sandbox could not run.
use super::PathContext;
use crate::CanonicalCommandV1;
use guard_contracts::GuardExecutionEnvironmentV1;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;

/// Whether the sandbox could not run a program the command launches, as the
/// agent's shell would resolve it from the session `PATH`. Without that
/// `PATH` the launch cannot be compared, and the sandbox decides.
#[cfg(unix)]
pub(super) fn outside(
    model: &CanonicalCommandV1,
    workspace: &Path,
    context: PathContext<'_>,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> bool {
    let (Some(environment), Some(cwd)) = (execution_environment, context.cwd) else {
        return false;
    };
    crate::restricted_pytest::launches_outside_exec_roots(
        launches(model, Path::new(cwd), context.cdpath_unset),
        &environment.path,
        context.home_dir.map(Path::new),
        workspace,
    )
}

#[cfg(not(unix))]
pub(super) fn outside(
    _model: &CanonicalCommandV1,
    _workspace: &Path,
    _context: PathContext<'_>,
    _execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> bool {
    false
}

/// Most directories tracked at once before the position counts as unknown.
#[cfg(unix)]
const MOST_PLACES: usize = 16;

/// Commands the shell runs itself, without looking a program up on `PATH`. A
/// `PATH` directory that happens to hold a file of the same name, such as a
/// GNU coreutils directory, is never what runs.
#[cfg(unix)]
const SHELL_BUILTINS: &[&str] = &[
    ":", "[", "alias", "break", "continue", "echo", "exit", "export", "false", "getopts", "jobs",
    "kill", "printf", "pwd", "read", "readonly", "return", "set", "shift", "test", "trap", "true",
    "type", "umask", "unalias", "unset", "wait",
];

/// A program a command starts, and where the shell may stand when it does.
#[cfg(unix)]
type Launch<'a> = (&'a str, Vec<Option<PathBuf>>);

/// Each program the command starts, with the directories the shell may stand
/// in when it starts. A later program resolves a relative path, or a relative
/// `PATH` entry, from where an earlier `cd` left the shell, not from where the
/// command began. A `cd` can fail, or run in a pipeline or the background and
/// leave the shell in place, so the directories before it stay possible.
#[cfg(unix)]
fn launches<'a>(model: &'a CanonicalCommandV1, cwd: &Path, cdpath_unset: bool) -> Vec<Launch<'a>> {
    let mut places = vec![Some(cwd.to_path_buf())];
    let mut launches = Vec::new();
    for segment in &model.segments {
        let Some(executable) = segment.executable.as_deref() else {
            continue;
        };
        match executable {
            "cd" | "pushd" => {
                places = after_cd(&places, &segment.arguments, cdpath_unset);
            }
            "popd" => places = vec![None],
            builtin if SHELL_BUILTINS.contains(&builtin) => {}
            _ => launches.push((executable, places.clone())),
        }
    }
    launches
}

/// The directories possible after a `cd` or `pushd` that may or may not run.
#[cfg(unix)]
fn after_cd(
    places: &[Option<PathBuf>],
    arguments: &[String],
    cdpath_unset: bool,
) -> Vec<Option<PathBuf>> {
    let mut next = places.to_vec();
    for place in places {
        let entered = match arguments {
            [target] => enter(place.as_deref(), target, cdpath_unset),
            _ => None,
        };
        if !next.contains(&entered) {
            next.push(entered);
        }
    }
    if next.len() > MOST_PLACES {
        return vec![None];
    }
    next
}

/// The directory `cd target` reaches from `place`, when a literal path says.
#[cfg(unix)]
fn enter(place: Option<&Path>, target: &str, cdpath_unset: bool) -> Option<PathBuf> {
    let path = Path::new(target);
    if target.is_empty()
        || target.starts_with(['~', '-'])
        || target.contains(['$', '`', '*', '?', '[', '\\', '\n'])
        || crate::pretool::generic::chain_literals::inert::temp_cd::private_directory(target)
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return None;
    }
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    // A search path can send a relative `cd` anywhere.
    place
        .filter(|_| cdpath_unset)
        .map(|directory| directory.join(path))
}

#[cfg(all(test, unix))]
#[path = "workspace_contained_launch_tests.rs"]
mod tests;

//! A workspace file written beside local Git writes in one chain:
//! `echo x > notes.txt && git add -A && git commit -m init`.
//!
//! The projection refuses most chains that write a file, because an earlier
//! step could change directory or swap the target for a symlink before the
//! shell opens it, and because a later step was proven before the write
//! landed. This form admits a chain only when neither can matter:
//!
//! * every target is a relative, non-hidden path below the working directory
//!   with no symlink on the way, which the projection's target check proves;
//!   hidden paths cover `.git`, `.gitattributes`, `.gitmodules`, `.envrc` and
//!   hook managers such as `.husky`;
//! * every other step is a print or read that changes no directory, renames
//!   nothing and creates no link, or a Git step that leaves the checked-out
//!   tree alone, so nothing can retarget a write;
//! * the command without its redirects earns the local Git write proof,
//!   which also proves each of those other steps a read on its own; a push
//!   or any publishing step is not that proof;
//! * the file written is neither in the hooks directory Git resolves, which
//!   `core.hooksPath` can point into the workspace, nor a configuration file
//!   an include would load, so the write cannot add a program the proof's
//!   probe did not see.

use crate::pretool::git_session_probe::Probe;
use crate::pretool::PathContext;
use crate::CanonicalCommandV1;
use guard_contracts::{GuardExecutionEnvironmentV1, PreToolResultV1};
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

/// Steps that print or read. None changes directory, renames a file or
/// creates a link.
const PEERS: &[&str] = &[
    "cat", "echo", "grep", "head", "ls", "printf", "rg", "tail", "true", "wc",
];

/// Git commands that leave the checked-out tree as it is. Each still has to
/// pass the local Git write proof as a write form or a read.
const KEEPS_TREE: &[&str] = &[
    "add",
    "branch",
    "commit",
    "diff",
    "log",
    "ls-files",
    "rev-parse",
    "rm",
    "show",
    "status",
];

/// Whether the projected chain has the shape above, with every redirect
/// target relative to the working directory.
pub(super) fn admits(model: &CanonicalCommandV1, targets: &[String]) -> bool {
    targets.iter().all(|target| relative(target))
        && model
            .segments
            .iter()
            .any(|segment| segment.executable.as_deref() == Some("git"))
        && model.segments.iter().all(|segment| {
            segment.wrapper_chain.is_empty()
                && !segment.path_overridden
                && match segment.executable.as_deref() {
                    Some("git") => keeps_tree(&segment.arguments),
                    Some(executable) => PEERS.contains(&executable),
                    None => false,
                }
        })
}

/// A target the shell resolves against the working directory: no root, no
/// drive, no Windows separator and no hidden part. The projection admits a
/// scratch path such as `.tmp/log.txt`, which this form does not need.
fn relative(target: &str) -> bool {
    !target.is_empty()
        && !target.starts_with('/')
        && !target.contains([':', '\\'])
        && !target
            .split('/')
            .any(|part| part.starts_with('.') && part != ".")
}

/// A leading option such as `-C`, `-c core.hooksPath=...` or `--git-dir`
/// is refused. A new branch at `HEAD` keeps the tree; a checkout or switch
/// to anything else, a stash, a reset or a restore does not.
fn keeps_tree(arguments: &[String]) -> bool {
    match arguments {
        [command, flag, _]
            if matches!(
                (command.as_str(), flag.as_str()),
                ("switch", "-c" | "--create") | ("checkout", "-b")
            ) =>
        {
            true
        }
        [command, ..] => KEEPS_TREE.contains(&command.as_str()),
        [] => false,
    }
}

/// Whether the projected command earned the local Git write proof and no
/// written file is a hook or an included configuration file.
pub(in crate::pretool) fn settled(
    projected: &PreToolResultV1,
    targets: &[String],
    context: PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> bool {
    if projected.reason_code != crate::pretool::git_local_writes::REASON
        || projected.minimum_action != "allow"
        || projected.action.sensitive_target
    {
        return false;
    }
    let Some(probe) = Probe::new("git", &[], context, deadline, execution_environment) else {
        return false;
    };
    let Some((effective, repository)) = probe.config() else {
        return false;
    };
    // A repository include may name a workspace file by a relative path, and
    // any include inside the working directory could be the file written.
    let includes = effective.iter().any(|(key, values)| {
        (key == "include.path" || (key.starts_with("includeif.") && key.ends_with(".path")))
            && (repository.contains_key(key)
                || values
                    .iter()
                    .any(|value| include_reaches(value, &probe.home, &probe.cwd)))
    });
    if includes {
        return false;
    }
    let Some(hooks) = probe.text(&["rev-parse", "--path-format=absolute", "--git-path", "hooks"])
    else {
        return false;
    };
    let hooks = Path::new(&hooks);
    hooks.is_absolute()
        && !targets
            .iter()
            .any(|target| inside(&probe.cwd.join(target), hooks))
}

/// Whether a global include could load a file in the working directory. A
/// relative value resolves against the global configuration's directory,
/// which is approximated by home; one that climbs with `..` is refused.
fn include_reaches(value: &str, home: &Path, cwd: &Path) -> bool {
    let path = match value.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None if Path::new(value).is_absolute() => PathBuf::from(value),
        None if value.starts_with('~') => return true,
        None => home.join(value),
    };
    path.components()
        .any(|component| component == Component::ParentDir)
        || inside(&path, cwd)
}

/// Whether `path` is `base` or below it, compared without ASCII case so a
/// case-insensitive file system cannot hide a match.
fn inside(path: &Path, base: &Path) -> bool {
    let (path, base) = (resolved(path), resolved(base));
    let mut components = path.components();
    base.components().all(|part| {
        components
            .next()
            .is_some_and(|other| other.as_os_str().eq_ignore_ascii_case(part.as_os_str()))
    })
}

/// The canonical path, or the canonical parent joined with the name when the
/// file does not exist yet, or the path as given.
fn resolved(path: &Path) -> PathBuf {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return canonical;
    }
    path.parent()
        .zip(path.file_name())
        .and_then(|(parent, name)| Some(std::fs::canonicalize(parent).ok()?.join(name)))
        .unwrap_or_else(|| path.to_path_buf())
}

#[cfg(test)]
#[path = "redirect_git_chain_tests.rs"]
mod tests;

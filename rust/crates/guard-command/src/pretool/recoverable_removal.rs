//! A recursive `rm` whose every target Git can bring back.
//!
//! A recursive removal asks for approval because it can take uncommitted
//! work with it. Inside the session's own Git work tree, a target that holds
//! only committed, unmodified files loses nothing: `git restore` returns
//! them. Such a removal needs no approval. An untracked, ignored or modified
//! file, a staged change, an index entry marked assume-unchanged or
//! skip-worktree, a nested repository, a dirty submodule, the work tree
//! itself or its `.git` directory keeps the approval, as does any target Git
//! was not asked about. Ignored files count because Git cannot restore them:
//! they may be secrets, local data or another repository.

use super::git_session_probe::Probe;
use super::PathContext;
use crate::{CanonicalCommandV1, CommandSegmentV1};
use guard_contracts::GuardExecutionEnvironmentV1;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

const MAX_OPERANDS: usize = 16;

/// The operands of a plain `rm -r`, or `None` for any other program, option,
/// shell expansion or operand spelling Git could read as a pathspec.
fn operands(segment: &CommandSegmentV1) -> Option<Vec<&str>> {
    if segment.executable.as_deref() != Some("rm")
        || segment.path_overridden
        || segment.pipeline_index != 0
        || !segment.wrapper_chain.is_empty()
        || !segment.environment_names.is_empty()
        || segment.text.contains([
            '>', '<', '$', '`', '|', '&', ';', '\n', '\r', '~', '*', '?', '[', '{',
        ])
    {
        return None;
    }
    let (mut recursive, mut options, mut operands) = (false, true, Vec::new());
    for argument in &segment.arguments {
        let argument = argument.as_str();
        if options && argument == "--" {
            options = false;
        } else if options && argument.starts_with("--") {
            match argument {
                "--recursive" => recursive = true,
                "--force" | "--verbose" => {}
                _ => return None,
            }
        } else if options && argument.len() > 1 && argument.starts_with('-') {
            for flag in argument[1..].chars() {
                match flag {
                    'r' | 'R' => recursive = true,
                    'f' | 'v' => {}
                    _ => return None,
                }
            }
        } else if argument.is_empty() || argument.starts_with(':') {
            return None;
        } else {
            operands.push(argument);
        }
    }
    (recursive && (1..=MAX_OPERANDS).contains(&operands.len())).then_some(operands)
}

/// `operand` from `cwd`, spelled with plain names after an optional `./`,
/// strictly inside `root` and outside every `.git`, its parent directory
/// already in canonical form so the removal lands where it is named. A link
/// is not followed here; the link proof answers for those.
fn target(operand: &str, cwd: &Path, root: &Path) -> Option<PathBuf> {
    let path = Path::new(operand);
    let mut target = if path.is_absolute() {
        PathBuf::new()
    } else {
        cwd.to_path_buf()
    };
    for component in path.components() {
        match component {
            Component::RootDir => target.push("/"),
            Component::CurDir => {}
            // The volume may ignore case, so `.GIT` is `.git` there.
            Component::Normal(name)
                if !name
                    .to_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case(".git")) =>
            {
                target.push(name);
            }
            _ => return None,
        }
    }
    let relative = target.strip_prefix(root).ok()?;
    if relative.as_os_str().is_empty() {
        return None;
    }
    let parent = target.parent()?;
    if std::fs::canonicalize(parent).ok()? != parent {
        return None;
    }
    match std::fs::symlink_metadata(&target) {
        Ok(metadata) if metadata.file_type().is_symlink() => None,
        Ok(_) => Some(target),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(target),
        Err(_) => None,
    }
}

/// Git reports nothing under `target` that is not committed: no untracked,
/// ignored, modified, staged or deleted file and no dirty submodule. An
/// ignored directory is reported whole, whatever it holds.
fn committed(probe: &Probe, target: &Path) -> bool {
    let Some(target) = target.to_str() else {
        return false;
    };
    trusted_index(probe, target)
        && probe
            .output(&[
                "--literal-pathspecs",
                "--no-optional-locks",
                "--no-pager",
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignored=traditional",
                "--ignore-submodules=none",
                "--",
                target,
            ])
            .is_some_and(|report| report.is_empty())
}

/// No index entry under `target` tells Git to skip its working file, so the
/// status report covers every tracked file. `ls-files -v` tags an
/// assume-unchanged entry in lower case and a skip-worktree entry `S`.
fn trusted_index(probe: &Probe, target: &str) -> bool {
    probe
        .output(&[
            "--literal-pathspecs",
            "--no-optional-locks",
            "ls-files",
            "-v",
            "-z",
            "--",
            target,
        ])
        .is_some_and(|listing| {
            listing
                .split(|byte| *byte == 0)
                .filter(|entry| !entry.is_empty())
                .all(|entry| entry.first() == Some(&b'H'))
        })
}

/// Whether `segment` is a recursive `rm` of targets Git can restore, in the
/// work tree the session runs in, whose configuration starts nothing.
fn proven_segment(
    segment: &CommandSegmentV1,
    context: PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> bool {
    let Some(operands) = operands(segment) else {
        return false;
    };
    let Some(probe) = Probe::new("git", &[], context, deadline, execution_environment) else {
        return false;
    };
    let inert = probe.config().is_some_and(|(effective, repository)| {
        super::git_local_writes::inert(&effective, &repository)
    });
    let root = probe
        .text(&["rev-parse", "--show-toplevel"])
        .and_then(|root| std::fs::canonicalize(root).ok());
    let Some(root) = root.filter(|_| inert) else {
        return false;
    };
    // A work tree at or above the home would make every dotfile a workspace
    // file.
    !probe.home.starts_with(&root)
        && probe.cwd.starts_with(&root)
        && operands.iter().all(|operand| {
            target(operand, &probe.cwd, &root).is_some_and(|target| committed(&probe, &target))
        })
}

/// The whole command is one such removal. In a chain an earlier step could
/// change the directory, or create or move what the removal names, so the
/// answer below would describe the wrong tree.
pub(crate) fn exact_safe_command(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> bool {
    model.confidence == "exact"
        && !model.path_overridden
        && model.wrapper_chain.is_empty()
        && matches!(model.segments.as_slice(), [segment]
            if proven_segment(segment, context, deadline, execution_environment))
}

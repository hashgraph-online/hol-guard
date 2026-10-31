//! File removal and in-place edits inside the workspace sandbox.
//!
//! The destructive-shell rule matches every `rm`, `dd`, `truncate` and in-place
//! edit, and marks each match uncertain because the rule alone cannot prove a
//! target is safe to lose. A plain `rm` or `rmdir` in the workspace is ordinary
//! cleanup, and `sed -i` is the same file edit an agent's own edit tool makes:
//! the sandbox keeps both off the network, credentials, the home directory and
//! `.git`, so this module accepts that uncertainty for those programs only.
//! A sed script cannot reach past the sandbox either, so it is not parsed. A
//! recursive removal could still take uncommitted work with it, so each of its
//! targets must be missing or ignored by Git, and it must run before any other
//! command could create or move what it names.
use super::super::git_session_probe::Probe;
use super::PathContext;
use crate::CanonicalCommandV1;
use guard_contracts::{
    GuardExecutionEnvironmentV1, NativeCommandObservationV1, NativeCommandObservationsV1,
    PreToolResultV1,
};
use std::path::Path;

pub(super) const SHELL_DESTRUCTION: &str = "command.shell-mutations.destructive-shell";

fn segment_indexes(observation: &NativeCommandObservationV1) -> impl Iterator<Item = usize> + '_ {
    observation
        .matcher_evidence
        .iter()
        .map(|evidence| evidence.segment_index)
        .chain(observation.effective_segment_indexes.iter().copied())
}

/// The operands of a plain `rm` or `rmdir` segment and whether it recurses,
/// no operands for an in-place `sed` edit, or `None` for any other program,
/// option or shell expansion.
fn removal(model: &CanonicalCommandV1, index: usize) -> Option<(bool, Vec<&str>)> {
    let segment = model.segments.get(index)?;
    let program = segment.executable.as_deref()?;
    if !matches!(program, "rm" | "rmdir" | "sed")
        || segment.path_overridden
        || !segment.wrapper_chain.is_empty()
        || !segment.environment_names.is_empty()
    {
        return None;
    }
    if program == "sed" {
        return in_place_edit(&segment.arguments).then(|| (false, Vec::new()));
    }
    let (mut recursive, mut options, mut operands) = (false, true, Vec::new());
    for argument in &segment.arguments {
        if options && argument == "--" {
            options = false;
        } else if options && argument.starts_with("--") {
            match argument.as_str() {
                "--recursive" => recursive = true,
                "--force" | "--verbose" | "--dir" => {}
                _ => return None,
            }
        } else if options && argument.len() > 1 && argument.starts_with('-') {
            for flag in argument[1..].chars() {
                match flag {
                    'r' | 'R' => recursive = true,
                    'f' | 'i' | 'I' | 'v' | 'd' => {}
                    _ => return None,
                }
            }
        } else if argument.is_empty() || argument.contains(['$', '`', '~']) {
            return None;
        } else {
            operands.push(argument.as_str());
        }
    }
    (program == "rm" || !recursive).then_some((recursive, operands))
}

/// Whether `sed` runs with `-i` (GNU or BSD spelling) and only the options
/// both document. The script and file operands are left as they are.
fn in_place_edit(arguments: &[String]) -> bool {
    let mut in_place = false;
    let mut words = arguments.iter();
    while let Some(argument) = words.next() {
        let argument = argument.as_str();
        if argument == "--" {
            break;
        }
        if let Some(long) = argument.strip_prefix("--") {
            let (name, value) = long
                .split_once('=')
                .map_or((long, None), |(name, value)| (name, Some(value)));
            match name {
                "in-place" => in_place = true,
                "expression" | "file" | "line-length" => {
                    if value.is_none() && words.next().is_none() {
                        return false;
                    }
                }
                "regexp-extended" | "quiet" | "silent" | "separate" | "null-data" | "posix"
                | "sandbox" | "unbuffered" | "debug" | "zero-terminated"
                    if value.is_none() => {}
                _ => return false,
            }
            continue;
        }
        let Some(flags) = argument.strip_prefix('-').filter(|flags| !flags.is_empty()) else {
            continue;
        };
        for (position, flag) in flags.char_indices() {
            match flag {
                // The rest of the word is a backup suffix.
                'i' => {
                    in_place = true;
                    break;
                }
                // The rest of the word, or the next word, is the value.
                'e' | 'f' | 'l' => {
                    if position + 1 == flags.len() && words.next().is_none() {
                        return false;
                    }
                    break;
                }
                'E' | 'r' | 'n' | 's' | 'u' | 'z' => {}
                _ => return false,
            }
        }
    }
    in_place
}

/// Whether `observation` is the destructive-shell match on plain removals and
/// in-place edits.
pub(super) fn accepted(
    observation: &NativeCommandObservationV1,
    model: &CanonicalCommandV1,
) -> bool {
    let mut indexes = segment_indexes(observation).peekable();
    observation.rule_id == SHELL_DESTRUCTION
        && observation.uncertainty_reasons == ["matcher-failure"]
        && indexes.peek().is_some()
        && indexes.all(|index| removal(model, index).is_some())
}

/// The uncertainty the binding may carry: one per accepted removal match.
pub(super) fn accepted_uncertainty(
    extensions: &NativeCommandObservationsV1,
    model: &CanonicalCommandV1,
) -> usize {
    extensions
        .observations
        .iter()
        .filter(|observation| {
            !observation.uncertainty_reasons.is_empty() && accepted(observation, model)
        })
        .count()
}

/// Whether a recursive removal could take work Git does not already ignore.
pub(super) fn loses_work(
    result: &PreToolResultV1,
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> bool {
    let (Some(extensions), Some(cwd)) = (result.command_extensions.as_ref(), context.cwd) else {
        return true;
    };
    let cwd = Path::new(cwd);
    let removals: Vec<(usize, Vec<&str>)> = extensions
        .observations
        .iter()
        .filter(|observation| observation.rule_id == SHELL_DESTRUCTION)
        .flat_map(segment_indexes)
        .filter_map(|index| match removal(model, index) {
            Some((true, operands)) => Some((index, operands)),
            _ => None,
        })
        .collect();
    if removals.is_empty() {
        return false;
    }
    // An earlier command could create or move what the removal names, so the
    // check below would describe the wrong tree.
    let first_other = model
        .segments
        .iter()
        .enumerate()
        .position(|(index, _)| removal(model, index).is_none())
        .unwrap_or(model.segments.len());
    if removals.iter().any(|(index, _)| *index > first_other) {
        return true;
    }
    let mut ignore = IgnoreProbe::new(context, execution_environment);
    removals
        .iter()
        .flat_map(|(_, operands)| operands)
        .any(|operand| {
            if operand.contains(['*', '?', '[', '{']) {
                return true;
            }
            if std::fs::symlink_metadata(cwd.join(operand)).is_err() {
                return false;
            }
            !ignore.ignores(operand)
        })
}

/// Whether a local `rsync` copy could replace a destination Git does not
/// ignore. Overwriting uncommitted files loses work the sandbox cannot
/// restore, the same loss a recursive removal is held to.
pub(super) fn rsync_replaces_work(
    model: &CanonicalCommandV1,
    command_text: Option<&str>,
    context: PathContext<'_>,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> bool {
    let mut ignore = IgnoreProbe::new(context, execution_environment);
    super::super::rsync_local::replaces_work(
        &model.segments,
        Some(command_text.unwrap_or(&model.normalized_text)),
        context.cwd.map(Path::new),
        &mut |operand| ignore.ignores(operand),
    )
}

/// Git's answer to whether a path is ignored. The repository is asked only
/// when a path exists, and only after its configuration proves inert.
struct IgnoreProbe<'a> {
    context: PathContext<'a>,
    execution_environment: Option<&'a GuardExecutionEnvironmentV1>,
    probe: Option<Option<Probe>>,
}

impl<'a> IgnoreProbe<'a> {
    fn new(
        context: PathContext<'a>,
        execution_environment: Option<&'a GuardExecutionEnvironmentV1>,
    ) -> Self {
        Self {
            context,
            execution_environment,
            probe: None,
        }
    }

    fn ignores(&mut self, operand: &str) -> bool {
        let (context, environment) = (self.context, self.execution_environment);
        self.probe
            .get_or_insert_with(|| {
                let probe = Probe::new("git", &[], context, None, environment)?;
                let (effective, repository) = probe.config()?;
                super::super::git_local_writes::inert(&effective, &repository).then_some(probe)
            })
            .as_ref()
            .and_then(|probe| probe.text(&["check-ignore", "--", operand]))
            .is_some()
    }
}

/// Whether a destructive argument names the whole workspace, an ancestor of
/// it, or every entry at its root. Deleting build output stays contained;
/// wiping the workspace loses uncommitted work like `git reset --hard`.
///
/// `below` is how many directories under the workspace root the segment's
/// shell stands, so a relative operand is resolved from there: after
/// `cd build`, `rm -f ../*` names every entry at the root, not at its parent.
fn broad_target(argument: &str, workspace: &Path, below: usize) -> bool {
    use std::path::Component;
    // BSD `sed -i ''` passes an empty backup suffix, not a path.
    if argument.is_empty() || argument.starts_with('-') {
        return false;
    }
    if argument.starts_with('~') || argument.contains('$') {
        return true;
    }
    let path = Path::new(argument);
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        // The names of the directories the shell descended through do not
        // matter: a `..` pops whatever stands above it, so a placeholder per
        // level resolves the operand at the right depth.
        let mut base = workspace.to_path_buf();
        for _ in 0..below {
            base.push("_");
        }
        base.join(path)
    };
    let mut normal = std::path::PathBuf::new();
    for component in joined.components() {
        match component {
            Component::ParentDir => {
                normal.pop();
            }
            Component::CurDir => {}
            other => normal.push(other),
        }
    }
    let root_glob = normal
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            // Brackets and braces can spell any name, so only a literal
            // stem or suffix such as `*.pyc` keeps a root glob narrow.
            name.chars().all(|c| matches!(c, '*' | '.' | '?')) || name.contains(['[', '{', '\\'])
        });
    // The volume may be case-insensitive, so `/Users/me/Proj` can name the
    // workspace `/Users/me/proj`.
    let fold = |path: &Path| std::path::PathBuf::from(path.to_string_lossy().to_ascii_lowercase());
    let (normal, workspace) = (fold(&normal), fold(workspace));
    workspace.starts_with(&normal) || (root_glob && normal.parent() == Some(workspace.as_path()))
}

pub(super) fn destroys_workspace(
    result: &PreToolResultV1,
    model: &CanonicalCommandV1,
    workspace: &Path,
) -> bool {
    let Some(extensions) = result.command_extensions.as_ref() else {
        return true;
    };
    let below = super::cwd::depths(model, workspace);
    extensions
        .observations
        .iter()
        .filter(|observation| observation.rule_id == SHELL_DESTRUCTION)
        .flat_map(segment_indexes)
        .any(|index| {
            model.segments.get(index).is_none_or(|segment| {
                let below = below.get(index).copied().unwrap_or(0);
                segment
                    .arguments
                    .iter()
                    .any(|argument| broad_target(argument, workspace, below))
            })
        })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    /// A destructive operand is resolved from the directory its segment runs
    /// in. `cd build && rm -f ../*` names every entry at the workspace root,
    /// which is the loss this screen refuses, even though the same operand
    /// read from the root would point at the root's parent.
    #[test]
    fn a_parent_glob_after_a_descent_names_the_workspace_root() {
        let workspace = Path::new("/synthetic/workspace");
        assert!(super::broad_target("../*", workspace, 1));
        assert!(super::broad_target("..", workspace, 1));
        assert!(super::broad_target("../../*", workspace, 2));
        // Without a proven descent the same operand leaves the workspace, and
        // the reach checks refuse it before this one is asked.
        assert!(!super::broad_target("../*", workspace, 0));
        // A named entry one level down is ordinary build output.
        assert!(!super::broad_target("../target", workspace, 1));
        assert!(!super::broad_target("out", workspace, 1));
    }
}

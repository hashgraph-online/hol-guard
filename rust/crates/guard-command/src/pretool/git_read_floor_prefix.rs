use super::*;

/// The command from its only `cd` onward, when everything before the `cd` is
/// a Git read proven helper-free in the reported directory, or a read the
/// plain read prefix also accepts: such a read writes no configuration, ref
/// or hook the later reads could pick up. Anything else stays judged whole.
pub(super) fn after_git_read_prefix(
    model: &CanonicalCommandV1,
    context: super::super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<CanonicalCommandV1> {
    after_prefix(model, |prefix, index| {
        let segment = &prefix.segments[index];
        let git = segment
            .executable
            .as_deref()
            .is_some_and(|executable| super::super::executable_basename(executable) == "git");
        if git {
            super::super::git_remote_ops::proven_read(
                prefix,
                index,
                context,
                deadline,
                execution_environment,
            )
        } else {
            super::super::segment_proof::cwd_read_executable(segment.executable.as_deref())
                && super::super::segment_proof::exact_safe_segment_with_context(
                    prefix, segment, false, context,
                )
        }
    })
}

/// The command from its only `cd` onward when everything before the `cd` is
/// a read the plain segment proofs accept, Git reads included. The allow path
/// uses this lexical split; `requires_review` still insists that each Git
/// read in the prefix is proven helper-free before it trusts the split.
pub(super) fn after_safe_git_read_prefix(
    model: &CanonicalCommandV1,
    allow_git_helper_context: bool,
    context: super::super::PathContext<'_>,
) -> Option<CanonicalCommandV1> {
    after_prefix(model, |prefix, index| {
        let segment = &prefix.segments[index];
        super::super::segment_proof::cwd_read_executable(segment.executable.as_deref())
            && super::super::segment_proof::exact_safe_segment_with_context(
                prefix,
                segment,
                allow_git_helper_context,
                context,
            )
    })
}

fn after_prefix(
    model: &CanonicalCommandV1,
    proven_segment: impl Fn(&CanonicalCommandV1, usize) -> bool,
) -> Option<CanonicalCommandV1> {
    if model.confidence != "exact" || model.path_overridden || !model.wrapper_chain.is_empty() {
        return None;
    }
    let mut changes = model
        .segments
        .iter()
        .enumerate()
        .filter(|(_, segment)| segment.executable.as_deref() == Some("cd"));
    let (start, _) = changes.next()?;
    if start == 0 || changes.next().is_some() {
        return None;
    }
    for index in 1..=start {
        let separator = super::super::worktree_add::separator_between(model, index - 1, index)?;
        let expected: &[&str] = if index == start {
            &["&&"]
        } else {
            &["&&", "|"]
        };
        if !expected.contains(&separator.trim()) {
            return None;
        }
    }
    let mut prefix = model.clone();
    prefix.segments.truncate(start);
    let proven = (0..start).all(|index| {
        let segment = &prefix.segments[index];
        segment.environment_names.is_empty()
            && segment.wrapper_chain.is_empty()
            && !segment.path_overridden
            && proven_segment(&prefix, index)
    });
    if !proven {
        return None;
    }
    let mut rest = model.clone();
    rest.segments = model.segments[start..].to_vec();
    Some(rest)
}

/// Whether a Git inspection runs after a `cd` that is not the command's first
/// segment. Other Git operations keep their own native permission floors,
/// which judge the moved directory themselves.
pub(super) fn git_after_later_cd(model: &CanonicalCommandV1) -> bool {
    let mut moved = false;
    model.segments.iter().enumerate().any(|(index, segment)| {
        let basename = segment
            .executable
            .as_deref()
            .map(super::super::executable_basename);
        if index > 0 && basename == Some("cd") {
            moved = true;
        }
        moved && basename == Some("git") && may_inspect(&segment.arguments)
    })
}

/// Whether Git arguments may name an inspection operation. Global options that
/// relocate or reconfigure Git count as inspections, so they stay reviewed.
fn may_inspect(arguments: &[String]) -> bool {
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        match argument.as_str() {
            "-C" => index += 2,
            "--no-pager" | "-P" | "--no-replace-objects" | "--literal-pathspecs" => index += 1,
            option if option.starts_with('-') => return true,
            operation => {
                return matches!(
                    operation,
                    "status"
                        | "diff"
                        | "log"
                        | "show"
                        | "grep"
                        | "branch"
                        | "hash-object"
                        | "config"
                        | "merge-base"
                        | "ls-tree"
                        | "cat-file"
                        | "show-ref"
                        | "for-each-ref"
                        | "rev-list"
                        | "stash"
                        | "submodule"
                )
            }
        }
    }
    true
}

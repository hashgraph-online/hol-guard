use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::path::{Path, PathBuf};
use std::time::Instant;

struct WorktreeAdd<'a> {
    leading: &'a [String],
    branch: &'a str,
    destination: &'a str,
    reference: Option<&'a str>,
}

const MAX_GIT_NAME_BYTES: usize = 256;
const MAX_DESTINATION_BYTES: usize = 4096;

pub(super) fn exact_safe_command(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    if model.confidence != "exact"
        || model.path_overridden
        || model.segments.is_empty()
        || !model.wrapper_chain.is_empty()
    {
        return false;
    }
    let cwd_proof = model
        .segments
        .iter()
        .position(|segment| segment.executable.as_deref() == Some("cd"))
        .and_then(|cd_index| verified_worktree_cwd_context(model, cd_index, context));
    let proof_context = super::PathContext {
        home_dir: context.home_dir,
        cwd: cwd_proof
            .as_ref()
            .map(|proof| proof.cwd.as_str())
            .or(context.cwd),
    };
    let mut worktree_seen = false;
    for (index, segment) in model.segments.iter().enumerate() {
        let is_cd = segment.executable.as_deref() == Some("cd");
        if is_cd {
            if cwd_proof
                .as_ref()
                .is_none_or(|proof| proof.cd_index != index)
            {
                return false;
            }
            continue;
        }
        let is_worktree = segment
            .executable
            .as_deref()
            .is_some_and(|value| super::executable_basename(value) == "git")
            && parse(segment).is_some();
        if is_worktree {
            if worktree_seen
                || segment.pipeline_index != 0
                || !safe_segment(
                    model,
                    segment,
                    proof_context,
                    deadline,
                    execution_environment,
                )
            {
                return false;
            }
            worktree_seen = true;
            continue;
        }
        if segment.pipeline_index > 0 {
            let is_tail = segment
                .executable
                .as_deref()
                .is_some_and(|value| super::executable_basename(value) == "tail");
            if !is_tail || !super::safe_reads::safe_head_tail_stdin_arguments(&segment.arguments) {
                return false;
            }
        }
        if segment
            .executable
            .as_deref()
            .is_some_and(|value| super::executable_basename(value) == "tail")
            && !super::git_worktree::trusted_pipeline_command(
                "tail",
                proof_context,
                execution_environment,
            )
        {
            return false;
        }
        if !super::segment_proof::exact_safe_segment_with_context(
            model,
            segment,
            false,
            proof_context,
        ) {
            return false;
        }
    }
    worktree_seen
}

struct WorktreeCwdProof {
    cd_index: usize,
    cwd: String,
}

fn verified_worktree_cwd_context(
    model: &CanonicalCommandV1,
    cd_index: usize,
    context: super::PathContext<'_>,
) -> Option<WorktreeCwdProof> {
    if cd_index > 0 {
        for index in 0..cd_index {
            let segment = model.segments.get(index)?;
            if segment.executable.as_deref() != Some("sleep")
                || segment.pipeline_index != 0
                || !segment.environment_names.is_empty()
                || !segment.wrapper_chain.is_empty()
                || segment.path_overridden
                || !super::safe_reads::safe_sleep_arguments(&segment.arguments)
                || !separator_between(model, index, index + 1)
                    .is_some_and(|separator| matches!(separator.trim(), ";" | "&&"))
            {
                return None;
            }
        }
    }

    // Keep the original spans and normalized text so the existing compound
    // proof checks the separator immediately following the guarded `cd`.
    let mut cwd_model = model.clone();
    cwd_model.segments = model.segments.get(cd_index..)?.to_vec();
    let cwd = super::segment_proof::verified_cwd_compound_context(&cwd_model, context)?;
    Some(WorktreeCwdProof { cd_index, cwd })
}

fn separator_between(model: &CanonicalCommandV1, left: usize, right: usize) -> Option<String> {
    let left_segment = model.segments.get(left)?;
    let right_segment = model.segments.get(right)?;
    let length = right_segment
        .span
        .start
        .checked_sub(left_segment.span.end)?;
    Some(
        model
            .normalized_text
            .chars()
            .skip(left_segment.span.end)
            .take(length)
            .collect(),
    )
}

fn safe_segment(
    _model: &CanonicalCommandV1,
    segment: &CommandSegmentV1,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    if !segment.environment_names.is_empty() {
        return false;
    }
    let Some(spec) = parse(segment) else {
        return false;
    };
    let Some(destination) = fresh_destination(spec.destination, context) else {
        return false;
    };
    let result = super::git_worktree::worktree_add_execution_free(
        segment.executable.as_deref().unwrap_or("git"),
        spec.leading,
        &destination,
        spec.branch,
        spec.reference,
        context,
        deadline,
        execution_environment,
    )
    .unwrap_or(false);
    result
}

fn parse(segment: &CommandSegmentV1) -> Option<WorktreeAdd<'_>> {
    let arguments = if segment
        .arguments
        .last()
        .is_some_and(|argument| argument == "2>&1")
    {
        &segment.arguments[..segment.arguments.len() - 1]
    } else {
        &segment.arguments
    };
    let mut index = 0;
    while matches!(
        arguments.get(index).map(String::as_str),
        Some("-P" | "--no-pager" | "--no-optional-locks")
    ) {
        index += 1;
    }
    if arguments.get(index).map(String::as_str) != Some("worktree") {
        return None;
    }
    let leading = &arguments[..index];
    index += 1;
    if arguments.get(index).map(String::as_str) != Some("add") {
        return None;
    }
    index += 1;
    let mut branch = None;
    let mut destination = None;
    let mut reference = None;
    while let Some(argument) = arguments.get(index) {
        match argument.as_str() {
            "-q" | "--quiet" => index += 1,
            "-b" if branch.is_none() && reference.is_none() => {
                branch = arguments.get(index + 1).map(String::as_str);
                index += 2;
            }
            _ if argument.starts_with('-') => return None,
            _ if destination.is_none() => {
                destination = Some(argument.as_str());
                index += 1;
            }
            _ if reference.is_none() => {
                reference = Some(argument.as_str());
                index += 1;
            }
            _ => return None,
        }
    }
    let branch = branch.filter(|value| valid_branch_name(value))?;
    let destination = destination.filter(|value| valid_path_text(value))?;
    if reference.is_some_and(|value| !valid_local_reference(value)) {
        return None;
    }
    Some(WorktreeAdd {
        leading,
        branch,
        destination,
        reference,
    })
}

fn valid_branch_name(value: &str) -> bool {
    valid_ref_component(value)
        && !value.starts_with('-')
        && !value.ends_with('.')
        && !value.ends_with('/')
        && !value.contains("..")
        && !value.contains("@{")
        && !value.ends_with(".lock")
}

fn valid_local_reference(value: &str) -> bool {
    value == "HEAD"
        || (value
            .strip_prefix("refs/heads/")
            .or_else(|| value.strip_prefix("refs/tags/"))
            .or_else(|| value.strip_prefix("refs/remotes/"))
            .or_else(|| value.strip_prefix("origin/"))
            .is_some_and(valid_ref_component))
}

fn valid_ref_component(value: &str) -> bool {
    value.len() <= MAX_GIT_NAME_BYTES
        && !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
        && !value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        && !value.contains("..")
        && !value.contains("@{")
        && !value.ends_with('.')
        && !value.ends_with('/')
        && !value.ends_with(".lock")
}

fn valid_path_text(value: &str) -> bool {
    let components = value.strip_prefix('/').unwrap_or(value);
    value.len() <= MAX_DESTINATION_BYTES
        && !components.is_empty()
        && value.trim() == value
        && !value.starts_with('~')
        && !value.contains([
            '$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '*', '?', '[', ']', '{', '}', '\\',
        ])
        && !components
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
}

fn fresh_destination(value: &str, context: super::PathContext<'_>) -> Option<PathBuf> {
    let home = std::fs::canonicalize(Path::new(context.home_dir?)).ok()?;
    let cwd = std::fs::canonicalize(Path::new(context.cwd?)).ok()?;
    if !home.is_dir() || !home.is_absolute() || !cwd.is_dir() || !cwd.is_absolute() {
        return None;
    }
    let supplied = Path::new(value);
    let target = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else {
        cwd.join(supplied)
    };
    let parent = target.parent()?;
    match std::fs::symlink_metadata(&target) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return None,
    }
    let parent_metadata = std::fs::symlink_metadata(parent).ok()?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return None;
    }
    let canonical_parent = std::fs::canonicalize(parent).ok()?;
    if !canonical_parent.starts_with(&home) {
        return None;
    }
    let leaf = target.file_name()?.to_str()?;
    if leaf.starts_with('.') {
        return None;
    }
    let destination = canonical_parent.join(leaf);
    if protected_worktree_destination(&destination)
        || !super::safe_writes::bounded_native_file_write_target(
            destination.to_str()?,
            context.home_dir,
            context.cwd,
        )
    {
        return None;
    }
    Some(destination)
}

fn protected_worktree_destination(path: &Path) -> bool {
    let parts: Vec<String> = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => {
                Some(value.to_string_lossy().to_ascii_lowercase())
            }
            _ => None,
        })
        .collect();
    parts
        .windows(2)
        .any(|pair| pair == [".github", "workflows"])
}

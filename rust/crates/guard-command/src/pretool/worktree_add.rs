use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[path = "worktree_add_chain.rs"]
pub(super) mod chain;
pub(crate) use chain::new_checkout_route;
#[path = "worktree_add_destination.rs"]
mod destination;
#[path = "worktree_add_names.rs"]
mod names;

pub(in crate::pretool) use destination::fresh_destination;
use destination::resolve_chdir;

pub(in crate::pretool) use names::{valid_branch_name, valid_destination_text};
use names::{valid_local_reference, valid_path_text};

struct WorktreeAdd<'a> {
    leading: Vec<String>,
    /// The single `-C <dir>` value, applied by changing the proof's cwd
    /// (as Git does) instead of being passed on to the probes.
    chdir: Option<&'a str>,
    /// `None` for the detached form, which creates no branch.
    branch: Option<&'a str>,
    destination: &'a str,
    reference: Option<&'a str>,
    /// Neither `-b` nor `--detach`: Git checks out the local branch the
    /// reference names when one exists, and detaches otherwise.
    attach: bool,
}

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
    if chain::proven(model, context, deadline, execution_environment) {
        return true;
    }
    let cwd_proof = model
        .segments
        .iter()
        .position(|segment| segment.executable.as_deref() == Some("cd"))
        .and_then(|cd_index| verified_worktree_cwd_context(model, cd_index, context));
    let proof_context = super::PathContext {
        home_dir: context.home_dir,
        cdpath_unset: context.cdpath_unset,
        rustup_override_absent: context.rustup_override_absent,
        npm_config_inert: context.npm_config_inert,
        pip_config_inert: context.pip_config_inert,
        shell_home_matches: context.shell_home_matches,
        ripgrep_config_absent: context.ripgrep_config_absent,
        psql_environment: context.psql_environment,
        cwd: cwd_proof
            .as_ref()
            .map(|proof| proof.cwd.as_str())
            .or(context.cwd),
    };
    let mut worktree_seen = false;
    let mut fetch_before = false;
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
                || proven_checkout(
                    segment,
                    fetch_before,
                    proof_context,
                    deadline,
                    execution_environment,
                )
                .is_none()
            {
                return false;
            }
            worktree_seen = true;
            continue;
        }
        // `git fetch origin main; git worktree add ... origin/main` refreshes
        // the base first. A proven fetch writes only refs and objects, never
        // the configuration or hooks the worktree proof reads.
        if segment.pipeline_index == 0
            && super::git_remote_ops::proven_fetch(
                segment,
                proof_context,
                deadline,
                execution_environment,
            )
        {
            fetch_before |= !worktree_seen;
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

/// Whether segment `index` is a `git worktree add` the single-command proof
/// admits on its own. Such an add writes the new checkout, its
/// administrative files, a branch and that branch's upstream; it never
/// writes configuration or hooks a later Git read in the same command uses.
pub(super) fn proven_alone(
    model: &CanonicalCommandV1,
    index: usize,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let Some(segment) = model.segments.get(index) else {
        return false;
    };
    if segment.pipeline_index != 0
        || model
            .segments
            .get(index + 1)
            .is_some_and(|next| next.pipeline_index != 0)
        || parse(segment).is_none()
    {
        return false;
    }
    let mut alone = model.clone();
    alone.segments = vec![segment.clone()];
    exact_safe_command(&alone, context, deadline, execution_environment)
}

/// A review reason for a lone `git worktree add` whose new checkout would sit
/// outside home and the temporary directories, where the proof above never
/// admits it. Agents told only that
/// the command "could not be confirmed read-only" tend to copy the repository
/// by hand instead; naming the home-directory bound lets them pick a
/// destination the proof accepts. `None` for every other command.
pub(super) fn outside_home_reason(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
) -> Option<String> {
    let [segment] = model.segments.as_slice() else {
        return None;
    };
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        || !segment.environment_names.is_empty()
        || super::executable_basename(segment.executable.as_deref()?) != "git"
    {
        return None;
    }
    let spec = parse(segment)?;
    // `~/<path>` already names a checkout below home.
    if spec.destination.starts_with('~') {
        return None;
    }
    let home = std::fs::canonicalize(Path::new(context.home_dir?)).ok()?;
    let supplied = Path::new(spec.destination);
    let target = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else {
        let base = match spec.chdir {
            Some(directory) => resolve_chdir(directory, context)?,
            None => context.cwd?.to_owned(),
        };
        Path::new(&base).join(supplied)
    };
    let parent = std::fs::canonicalize(target.parent()?).ok()?;
    if parent.starts_with(&home) || super::git_routes::temporary_checkout_parent(&parent, context) {
        return None;
    }
    Some(
        "HOL Guard requires review because `git worktree add` runs without review only when the new checkout's parent directory is inside your home directory or a temporary directory such as `/tmp`. Repeat it with a destination under one of those, such as a sibling of the repository or a new directory in `/tmp`, or ask the user to approve it in the HOL Guard inbox.".to_owned(),
    )
}

/// The index of a leading `cd` and the directory it provably enters, so the
/// compatibility layer can look up proofs made where later segments run.
pub(crate) fn verified_leading_cd(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
) -> Option<(usize, String)> {
    let cd_index = model
        .segments
        .iter()
        .position(|segment| segment.executable.as_deref() == Some("cd"))?;
    verified_worktree_cwd_context(model, cd_index, context).map(|proof| (proof.cd_index, proof.cwd))
}

pub(super) struct WorktreeCwdProof {
    pub(super) cd_index: usize,
    pub(super) cwd: String,
}

/// The cwd a leading `cd` proves, allowing only bounded `sleep` before it.
pub(super) fn verified_worktree_cwd_context(
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

pub(super) fn separator_between(
    model: &CanonicalCommandV1,
    left: usize,
    right: usize,
) -> Option<String> {
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

/// The checkout a proven `git worktree add` segment creates, and the `-C`
/// directory it runs in when one is given.
fn proven_checkout(
    segment: &CommandSegmentV1,
    reference_may_move: bool,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<(PathBuf, Option<String>)> {
    let (spec, destination, chdir_cwd) = planned_checkout(segment, context)?;
    let context = super::PathContext {
        cwd: chdir_cwd.as_deref().or(context.cwd),
        ..context
    };
    super::git_worktree::worktree_add_execution_free(
        segment.executable.as_deref().unwrap_or("git"),
        &spec.leading,
        &destination,
        spec.branch,
        spec.reference,
        spec.attach,
        reference_may_move,
        context,
        deadline,
        execution_environment,
    )
    .unwrap_or(false)
    .then_some((destination, chdir_cwd))
}

/// The checkout `git worktree add` would create, with the directory its
/// own `-C` enters, before any probe of the repository.
fn planned_checkout<'a>(
    segment: &'a CommandSegmentV1,
    context: super::PathContext<'_>,
) -> Option<(WorktreeAdd<'a>, PathBuf, Option<String>)> {
    if !segment.environment_names.is_empty() {
        return None;
    }
    let spec = parse(segment)?;
    let chdir_cwd = match spec.chdir {
        Some(directory) => Some(resolve_chdir(directory, context)?),
        None => None,
    };
    let destination = fresh_destination(
        spec.destination,
        super::PathContext {
            cwd: chdir_cwd.as_deref().or(context.cwd),
            ..context
        },
    )?;
    Some((spec, destination, chdir_cwd))
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
    let mut leading = Vec::new();
    let mut chdir = None;
    loop {
        match arguments.get(index).map(String::as_str) {
            Some(flag @ ("-P" | "--no-pager" | "--no-optional-locks")) => {
                leading.push(flag.to_owned());
                index += 1;
            }
            Some("-C") if chdir.is_none() => {
                let value = arguments.get(index + 1)?.as_str();
                if value.is_empty()
                    || value.starts_with('-')
                    || value.contains(['\0', '\n', '\r'])
                    || value.len() > MAX_DESTINATION_BYTES
                {
                    return None;
                }
                chdir = Some(value);
                index += 2;
            }
            _ => break,
        }
    }
    if arguments.get(index).map(String::as_str) != Some("worktree") {
        return None;
    }
    index += 1;
    if arguments.get(index).map(String::as_str) != Some("add") {
        return None;
    }
    index += 1;
    let mut branch = None;
    let mut detach = false;
    let mut destination = None;
    let mut reference = None;
    while let Some(argument) = arguments.get(index) {
        match argument.as_str() {
            "-q" | "--quiet" => index += 1,
            "-d" | "--detach" => {
                detach = true;
                index += 1;
            }
            "-b" if branch.is_none() && reference.is_none() => {
                branch = Some(arguments.get(index + 1)?.as_str());
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
    // With neither a reference nor `--detach` Git would create a branch
    // named after the destination, which stays reviewed.
    match branch {
        Some(value) if detach || !valid_branch_name(value) => return None,
        None if !detach && reference.is_none() => return None,
        _ => {}
    }
    let destination = destination.filter(|value| valid_destination_text(value))?;
    // A quoted or escaped `~` stays a literal directory name.
    if destination.starts_with('~') && !super::directory_targets::home_targets_unquoted(segment) {
        return None;
    }
    // A bare name such as `main` or `feat/x` is accepted in every form.
    // Without `-b` and `--detach` Git checks out the existing branch of that
    // name (or detaches at what the name resolves to); with either flag it
    // starts from the commit the name resolves to, exactly as the probe's
    // `rev-parse` resolves it. The tree proven is the tree checked out.
    let attach = branch.is_none() && !detach;
    if reference.is_some_and(|value| !(valid_local_reference(value) || valid_branch_name(value))) {
        return None;
    }
    Some(WorktreeAdd {
        leading,
        chdir,
        branch,
        destination,
        reference,
        attach,
    })
}

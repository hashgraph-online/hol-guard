//! The verified directory of a `cd <dir> && ...` list, which the steps after
//! the `cd` are proven against.

use super::super::{directory_targets, executable_basename, safe_reads, PathContext};
use super::exact_safe_segment_with_context;
use crate::CanonicalCommandV1;

pub(in crate::pretool) fn verified_cwd_compound_context(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
) -> Option<String> {
    verified_cwd_list_context(model, context, false)
}

/// Like [`verified_cwd_compound_context`], but `sequence_after_cd` also admits
/// `cd <dir>; ...`. Only a caller whose executor resolves the directory itself
/// and runs nothing when it is gone may pass it: there a failed `cd` cannot
/// leave the rest running in the old directory as the shell would.
pub(in crate::pretool) fn verified_cwd_list_context(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
    sequence_after_cd: bool,
) -> Option<String> {
    let first = model.segments.first()?;
    if model.segments.len() < 2
        || first.executable.as_deref() != Some("cd")
        || !first.environment_names.is_empty()
        || first.pipeline_index != 0
        || !directory_targets::drive_targets_quoted(first)
        || !directory_targets::home_targets_unquoted(first)
        || model.segments[1..]
            .iter()
            .any(|segment| segment.executable.as_deref() == Some("cd"))
    {
        return None;
    }
    let [target] = first.arguments.as_slice() else {
        return None;
    };
    let cwd = safe_reads::verified_cwd_target(target, context)?;
    for (index, pair) in model.segments.windows(2).enumerate() {
        // Parser spans count Unicode characters, not UTF-8 byte offsets.
        let length = pair[1].span.start.checked_sub(pair[0].span.end)?;
        let separator: String = model
            .normalized_text
            .chars()
            .skip(pair[0].span.end)
            .take(length)
            .collect();
        let separator = separator.trim();
        let allowed = if index == 0 {
            separator == "&&" || (sequence_after_cd && separator == ";")
        } else {
            matches!(separator, "&&" | "|")
        };
        if !allowed {
            return None;
        }
    }
    Some(cwd)
}

pub(in crate::pretool) fn exact_safe_cwd_compound(
    model: &CanonicalCommandV1,
    allow_git_helper_context: bool,
    context: PathContext<'_>,
) -> bool {
    let Some(cwd) = verified_cwd_compound_context(model, context) else {
        return false;
    };
    if model.segments.len() == 2
        && matches!(
            model.segments[1].executable.as_deref(),
            Some("cp" | "mkdir" | "touch" | "mv" | "ln" | "rm")
        )
    {
        // `rm` and `ln` delete or publish a path. Re-anchoring them is safe
        // only inside the original workspace or a linked worktree of it.
        // `cd ~` and `cd /tmp` must not become the new write boundary.
        if matches!(model.segments[1].executable.as_deref(), Some("ln" | "rm"))
            && !mutation_directory_stays_in_workspace(&cwd, context)
        {
            return false;
        }
        // A verified successful cd has no filesystem side effects. Reuse the
        // standalone mutation proof without admitting a later write chain.
        let mut operation = model.clone();
        operation.segments = vec![model.segments[1].clone()];
        return exact_safe_segment_with_context(
            &operation,
            &operation.segments[0],
            false,
            crate::pretool::PathContext {
                home_dir: context.home_dir,
                cdpath_unset: context.cdpath_unset,
                rustup_override_absent: context.rustup_override_absent,
                npm_config_inert: context.npm_config_inert,
                pip_config_inert: context.pip_config_inert,
                shell_home_matches: context.shell_home_matches,
                ripgrep_config_absent: context.ripgrep_config_absent,
                psql_environment: context.psql_environment,
                cwd: Some(&cwd),
                creates_nothing: false,
            },
        );
    }
    model.segments[1..].iter().all(|segment| {
        !cwd_effectful_segment(segment)
            && exact_safe_segment_with_context(
                model,
                segment,
                allow_git_helper_context,
                crate::pretool::PathContext {
                    home_dir: context.home_dir,
                    cdpath_unset: context.cdpath_unset,
                    rustup_override_absent: context.rustup_override_absent,
                    npm_config_inert: context.npm_config_inert,
                    pip_config_inert: context.pip_config_inert,
                    shell_home_matches: context.shell_home_matches,
                    ripgrep_config_absent: context.ripgrep_config_absent,
                    psql_environment: context.psql_environment,
                    cwd: Some(&cwd),
                    creates_nothing: false,
                },
            )
    })
}

/// Whether `segment` carries an effect the generic branch must not admit:
/// its executable is one of the effectful names below, or its own proof is
/// one of the few that authorize an effect for a program whose other shapes
/// only read.
fn cwd_effectful_segment(segment: &crate::CommandSegmentV1) -> bool {
    if cwd_effectful_executable(segment.executable.as_deref()) {
        return true;
    }
    let words: Vec<&str> = segment.arguments.iter().map(String::as_str).collect();
    match segment.executable.as_deref() {
        // `docker ps` and the other listings read; `docker start` and
        // `docker container start` run an existing container again.
        Some("docker") => super::super::docker_start::start_shaped(&words),
        // `hol-guard dashboard` starts Guard's daemon and opens a browser.
        Some("hol-guard") => words.contains(&"dashboard"),
        _ => false,
    }
}

/// Executables a verified `cd` compound keeps out of its generic branch.
///
/// Every later step of the compound is proven again against the verified
/// directory, so a program the proof admits there has already been read as
/// safe in that directory. Naming the readers a second time only meant that a
/// reader this module had not listed - `pip list`, `npm ls`, `docker ps`,
/// `awk`, `file`, `realpath` - lost a proof it had standalone and became an
/// approval row. The names below are the ones whose own proofs can authorize
/// an effect rather than a read: a path written, a process stopped, a server
/// started, or a shell variable the later steps inherit. Mutations keep the
/// narrower two-segment handling above, which bounds the write to the
/// workspace; they must not ride the generic branch.
fn cwd_effectful_executable(executable: Option<&str>) -> bool {
    matches!(
        executable,
        Some(
            "cd" | "cp"
                | "mktemp"
                | "mkdir"
                | "touch"
                | "mv"
                | "ln"
                | "rm"
                | "dd"
                | "rustfmt"
                | "pkill"
                | "pg_ctl"
                | "export"
                | "set"
                | "unset"
                // `--output`, `--remote-name` and `--dump-header` write what
                // curl fetched into the directory the `cd` named.
                | "curl"
        )
    )
}

/// Executables a verified `cd` compound may run after the directory change.
pub(in crate::pretool) fn cwd_read_executable(executable: Option<&str>) -> bool {
    if executable.is_some_and(super::super::digest_reads::digest_program) {
        return true;
    }
    matches!(
        executable,
        Some(
            "pwd"
                | "true"
                | "echo"
                | "printf"
                | "which"
                | "whoami"
                | "uname"
                | "date"
                | "sleep"
                | "uptime"
                | "pgrep"
                | "ps"
                | "lsof"
                | "pg_isready"
                | "psql"
                | "ls"
                | "cat"
                | "base64"
                | "stat"
                | "test"
                | "find"
                | "head"
                | "tail"
                | "git"
                | "gh"
                | "jq"
                | "wc"
                | "od"
                | "rg"
                | "grep"
                | "sed"
                | "sort"
                | "uniq"
                | "cut"
                | "tr"
                | "du"
                | "df"
                | "diff"
        )
    )
}

/// The command from its only `cd` onward, when everything before that `cd`
/// is a proven read that neither depends on nor changes the directory or Git
/// state the rest reads. `ls /tmp/a && cd /tmp/a/app && git status` then gets
/// the same decision as `cd /tmp/a/app && git status`. The prefix keeps its
/// own proof against the original directory; Git segments stay out of it so
/// the Git execution floor always sees every Git read with its directory.
pub(in crate::pretool) fn after_read_prefix(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
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
    for (index, pair) in model.segments[..=start].windows(2).enumerate() {
        let length = pair[1].span.start.checked_sub(pair[0].span.end)?;
        let separator: String = model
            .normalized_text
            .chars()
            .skip(pair[0].span.end)
            .take(length)
            .collect();
        let last = index + 2 == start + 1;
        if (last && separator.trim() != "&&") || !matches!(separator.trim(), "&&" | "|") {
            return None;
        }
    }
    let proven = model.segments[..start].iter().all(|segment| {
        segment.environment_names.is_empty()
            && segment.wrapper_chain.is_empty()
            && !segment.path_overridden
            && segment
                .executable
                .as_deref()
                .is_some_and(|executable| executable_basename(executable) != "git")
            && cwd_read_executable(segment.executable.as_deref())
            && exact_safe_segment_with_context(model, segment, false, context)
    });
    if !proven {
        return None;
    }
    let mut rest = model.clone();
    rest.segments = model.segments[start..].to_vec();
    Some(rest)
}

/// `ln` and `rm` may follow `cd` only when the new directory is the original
/// workspace, a directory inside it, or a linked worktree of the same
/// repository. A session whose directory is the home, or a directory that
/// contains the home, has no workspace boundary. `cd ~` and `cd /tmp` must
/// not become the new write boundary.
fn mutation_directory_stays_in_workspace(cwd: &str, context: PathContext<'_>) -> bool {
    let Some(original) = context
        .cwd
        .and_then(|root| std::fs::canonicalize(root).ok())
    else {
        return false;
    };
    let target = std::path::Path::new(cwd);
    let home = context
        .home_dir
        .and_then(|home| std::fs::canonicalize(home).ok());
    let Some(home) = home else {
        return false;
    };
    if home.starts_with(target) || home.starts_with(&original) {
        return false;
    }
    target.starts_with(&original)
        || super::super::worktree_writes::same_repository_worktree(&original, target)
}

use crate::{CanonicalCommandV1, CommandSegmentV1};

#[path = "package_directory_flags.rs"]
pub(super) mod package_dir;

#[path = "contained_output_filters.rs"]
mod output_filters;

/// The package-directory route keeps its single `| tail -N`/`| head -N` filter.
fn output_filter(segment: &CommandSegmentV1) -> bool {
    segment.environment_names.is_empty()
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
        && segment.pipeline_index == 1
        && matches!(segment.executable.as_deref(), Some("tail" | "head"))
        && output_filters::head_tail_arguments(&segment.arguments)
}

/// How many segments after `core` form the sink's output filter chain: each a
/// later stage of the same pipeline, joined by a plain `|`. `None` when any
/// segment after `core` is something else.
fn filter_chain(model: &CanonicalCommandV1, segments: &[CommandSegmentV1]) -> Option<usize> {
    let (core, filters) = segments.split_first()?;
    if filters.len() > output_filters::MAX_FILTERS {
        return None;
    }
    let mut previous = core;
    for (offset, filter) in filters.iter().enumerate() {
        if filter.pipeline_index != core.pipeline_index + offset + 1
            || text(model, previous.span.end, filter.span.start)? != "|"
            || !output_filters::filter_stage(
                filter,
                &text(model, filter.span.start, filter.span.end)?,
            )
        {
            return None;
        }
        previous = filter;
    }
    Some(filters.len())
}

/// A final `; echo "exit=$?"`: the sink prints the label and status itself.
///
/// The shell prints a single-quoted or backslash-escaped `$?` literally, and
/// the Python sink cannot peel those forms. Accept only the source syntax the
/// sink peels, so those commands stay on the normal review path.
fn status_echo(model: &CanonicalCommandV1, segment: &CommandSegmentV1) -> bool {
    segment.environment_names.is_empty()
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
        && segment.pipeline_index == 0
        && segment.executable.as_deref() == Some("echo")
        && segment.arguments.len() == 1
        && text(model, segment.span.start, segment.span.end)
            .is_some_and(|source| status_echo_syntax(&source))
}

fn status_echo_syntax(source: &str) -> bool {
    let Some(rest) = source.trim().strip_prefix("echo") else {
        return false;
    };
    if !rest.starts_with([' ', '\t']) {
        return false;
    }
    let argument = rest.trim();
    let (label, quoted) = if let Some(inner) = argument
        .strip_prefix('"')
        .and_then(|body| body.strip_suffix('"'))
    {
        (inner, true)
    } else if argument.contains(['\'', '\\', '"']) {
        return false;
    } else {
        (argument, false)
    };
    let Some(label) = label.strip_suffix("$?") else {
        return false;
    };
    label.len() <= 32
        && label.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'=' | b':' | b'-')
                || (quoted && byte == b' ')
        })
}

// Parser spans count Unicode characters, not UTF-8 byte offsets.
fn text(model: &CanonicalCommandV1, start: usize, end: usize) -> Option<String> {
    let length = end.checked_sub(start)?;
    let text: String = model
        .normalized_text
        .chars()
        .skip(start)
        .take(length)
        .collect();
    Some(text.trim().to_owned())
}

/// The repository holding a `cd` target outside the hook workspace: the
/// nearest ancestor with a `.git` entry, strictly below home or the system
/// temporary directory, and owned by the agent's user. Agents step into a
/// sibling checkout or worktree this way; the execution sink rebases its
/// approved root to the same directory, so the run is contained to that
/// repository exactly as it would be from a session started there.
#[cfg(unix)]
pub(super) fn sibling_project_root(
    target: &std::path::Path,
    home: &str,
) -> Option<std::path::PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let uid = nix::unistd::getuid().as_raw();
    [std::path::Path::new(home), std::path::Path::new("/tmp")]
        .iter()
        .filter_map(|base| std::fs::canonicalize(base).ok())
        .find(|base| target.starts_with(base) && target != base.as_path())
        .and_then(|base| {
            target
                .ancestors()
                .take_while(|directory| *directory != base)
                .find(|directory| directory.join(".git").symlink_metadata().is_ok())
                .filter(|root| std::fs::metadata(root).is_ok_and(|meta| meta.uid() == uid))
                .map(std::path::Path::to_path_buf)
        })
}

/// Whether the verified cd `target` lies in the canonical `root`. Windows
/// reports the target in the harness's drive spelling, which the directory
/// proof checked exactly; compare its canonical (`\\?\`) form there.
fn within(target: &std::path::Path, root: &std::path::Path) -> bool {
    if cfg!(windows) {
        return std::fs::canonicalize(target).is_ok_and(|target| target.starts_with(root));
    }
    target.starts_with(root)
}

/// Whether the sink peels a relative leading `cd` into the workspace: only on
/// Windows, and only when `&&` joins it to the next command
/// (`peel_contained_wrapper`).
fn relative_inside_peeled(model: &CanonicalCommandV1, segments: &[CommandSegmentV1]) -> bool {
    cfg!(windows)
        && matches!(segments, [cd, next, ..]
            if text(model, cd.span.end, next.span.start).as_deref() == Some("&&"))
}

#[cfg(not(unix))]
pub(super) fn sibling_project_root(
    _target: &std::path::Path,
    _home: &str,
) -> Option<std::path::PathBuf> {
    None
}

/// Whether the execution sink can peel the leading `cd` of a command that
/// `contained_core` accepted. The sink resolves a relative operand only when it
/// names a sibling repository root outside the workspace, and runs a
/// `;`-sequenced `cd` only into a sibling root, so a relative or sequenced cd
/// inside the workspace classifies but cannot be peeled there.
pub(super) fn sink_peels_leading_cd(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
) -> bool {
    let Some(first) = model.segments.first() else {
        return true;
    };
    if first.executable.as_deref() != Some("cd") {
        return true;
    }
    let (Some(target), Some(cwd), Some(home)) = (
        super::segment_proof::verified_cwd_compound_context(model, context),
        context.cwd.and_then(|cwd| std::fs::canonicalize(cwd).ok()),
        context.home_dir,
    ) else {
        return false;
    };
    let target = std::path::PathBuf::from(target);
    let inside = within(&target, &cwd);
    let operand = first.arguments.first().map_or("", String::as_str);
    let relative = !operand.starts_with(['/', '~']);
    let sequenced = model.segments.get(1).is_some_and(|next| {
        text(model, first.span.end, next.span.start).is_some_and(|between| between == ";")
    });
    if inside {
        return (!relative || relative_inside_peeled(model, &model.segments)) && !sequenced;
    }
    let sibling = sibling_project_root(&target, home).is_some_and(|root| root == target);
    !relative || sibling
}

/// Peel a verified `cd <workspace or sibling repository dir> &&` prefix
/// spelled as the sink peels it, a
/// trailing `2>&1`, a chain of bounded `| tail -N`/`| head -N` and
/// standard-input `| grep` filters and a final `; echo "<label>$?"`,
/// returning the sole core invocation.
/// Classification only: the execution sink peels the same shape and
/// re-authorizes the core in the resolved directory before running it.
pub(super) fn contained_core(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
) -> Option<CanonicalCommandV1> {
    // `bun --cwd <dir> run build` is checked as `cd <dir> && bun run build`.
    if let Some(projected) = package_dir::as_cd_list(model, context) {
        return contained_core(&projected.model, context);
    }
    if model.confidence != "exact" || model.path_overridden || !model.wrapper_chain.is_empty() {
        return None;
    }
    let mut segments = model.segments.as_slice();
    let mut start = 0;
    if segments.first()?.executable.as_deref() == Some("cd") {
        let target = super::segment_proof::verified_cwd_compound_context(model, context)?;
        let workspace = std::fs::canonicalize(context.cwd?).ok()?;
        let target = std::path::Path::new(&target);
        let inside = within(target, &workspace);
        let sibling = sibling_project_root(target, context.home_dir?);
        if !inside && sibling.is_none() {
            return None;
        }
        // The sink peels a relative target only when it names a sibling
        // repository root outside the workspace (`peel_contained_wrapper`).
        // Any other relative target is left to the workspace sandbox, which
        // runs the text whole, instead of a receipt the sink cannot redeem.
        // Windows has no workspace sandbox, so there the sink also peels an
        // `&&`-joined relative cd into the workspace.
        let [spelled] = segments[0].arguments.as_slice() else {
            return None;
        };
        let anchored = spelled.starts_with('~') || std::path::Path::new(spelled).is_absolute();
        let peeled_inside = inside && relative_inside_peeled(model, segments);
        if !anchored && !peeled_inside && (inside || sibling.as_deref() != Some(target)) {
            return None;
        }
        start = 1;
    }
    let status = segments.len() >= start + 2
        && segments
            .last()
            .is_some_and(|segment| status_echo(model, segment))
        && text(
            model,
            segments[segments.len() - 2].span.end,
            segments[segments.len() - 1].span.start,
        )? == ";";
    if status {
        segments = &segments[..segments.len() - 1];
    }
    let filtered = filter_chain(model, segments.get(start..)?)? > 0;
    let mut core = segments[start].clone();
    let merged = core
        .arguments
        .last()
        .is_some_and(|argument| argument == "2>&1");
    if (start == 0 && !filtered && !status && !merged)
        || core.pipeline_index != 0
        || core.executable.as_deref() == Some("cd")
    {
        return None;
    }
    if merged {
        core.arguments.pop();
    }
    let producer = text(model, core.span.start, core.span.end)?;
    let producer = producer.strip_suffix("2>&1").unwrap_or(&producer);
    if producer.contains(['<', '>']) {
        return None;
    }
    if core
        .arguments
        .iter()
        .any(|argument| argument.contains(['<', '>', '|', '&', ';']))
    {
        return None;
    }
    let mut peeled = model.clone();
    peeled.segments = vec![core];
    Some(peeled)
}

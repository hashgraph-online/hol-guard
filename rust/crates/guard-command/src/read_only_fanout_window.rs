//! Which producer an `xargs` reads its names from: the stage right before
//! it, or the stage before one `head`/`tail` line window.

use crate::CommandSegmentV1;

/// Whether the `xargs` at `pipeline_index`, with `arguments`, fans out over
/// names a read-only producer walked: fed directly (`find`, a rooted search
/// listing, a rooted `fd` walk, object names) or through one line window.
pub(crate) fn xargs_reads_names(
    segments: &[CommandSegmentV1],
    pipeline_index: usize,
    execution_context: &str,
    arguments: &[String],
) -> bool {
    let lists_names = |producer: &CommandSegmentV1, at: usize| {
        super::xargs_follows_find(producer, at, execution_context, arguments)
            || super::listing::xargs_follows(producer, at, execution_context, arguments)
            || super::fd::xargs_follows(producer, at, execution_context, arguments)
    };
    segments.last().is_some_and(|previous| {
        lists_names(previous, pipeline_index)
            || super::xargs_follows_object_names(
                previous,
                pipeline_index,
                execution_context,
                arguments,
            )
    }) || through_line_window(segments, pipeline_index, execution_context)
        .is_some_and(|(producer, window_index)| lists_names(producer, window_index))
}

/// `head` or `tail` keeping a count of whole lines from the pipe:
/// `head -20`, `head -n 20`, `tail -1`, `tail -n +2`.
///
/// Agents trim a long file list before fanning out over it (`grep -rl X src
/// | head -20 | xargs grep -l Y`). Whole lines of a producer's output are
/// still names that producer printed, each carrying its root as a prefix, so
/// the window passes the producer's reading through unchanged. A byte count
/// (`-c`) is refused: `tail -c` can start a word in the middle of a name, past
/// the root that kept it from beginning with a dash. A file operand is refused
/// too, because the window would then print that file instead of the pipe.
pub(crate) fn line_window(segment: &CommandSegmentV1) -> bool {
    let tail = match segment.executable.as_deref() {
        Some("head") => false,
        Some("tail") => true,
        _ => return false,
    };
    let count = |value: &str| {
        let digits = if tail {
            value.strip_prefix('+').unwrap_or(value)
        } else {
            value
        };
        !digits.is_empty() && digits.len() <= 6 && digits.bytes().all(|byte| byte.is_ascii_digit())
    };
    segment.environment_names.is_empty()
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
        && match super::without_stderr_merge(&segment.arguments) {
            [] => true,
            [only] => only
                .strip_prefix("--lines=")
                .or_else(|| only.strip_prefix("-n"))
                .or_else(|| only.strip_prefix('-'))
                .is_some_and(count),
            [option, value] => matches!(option.as_str(), "-n" | "--lines") && count(value),
            _ => false,
        }
}

/// The producer an `xargs` at `pipeline_index` reads through one line window:
/// `PRODUCER | head -N | xargs ...`. The caller still asks whether that
/// producer feeds the `xargs`, at the window's own place in the pipeline.
pub(crate) fn through_line_window<'a>(
    segments: &'a [CommandSegmentV1],
    pipeline_index: usize,
    execution_context: &str,
) -> Option<(&'a CommandSegmentV1, usize)> {
    let [.., producer, window] = segments else {
        return None;
    };
    (window.pipeline_index + 1 == pipeline_index
        && window.execution_context == execution_context
        && producer.execution_context == execution_context
        && line_window(window))
    .then_some((producer, window.pipeline_index))
}

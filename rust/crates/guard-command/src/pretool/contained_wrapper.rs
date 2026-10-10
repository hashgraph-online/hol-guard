use crate::{CanonicalCommandV1, CommandSegmentV1};

fn bounded_count(value: &str) -> bool {
    !value.is_empty() && value.len() <= 6 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn output_filter(segment: &CommandSegmentV1) -> bool {
    segment.environment_names.is_empty()
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
        && segment.pipeline_index == 1
        && matches!(segment.executable.as_deref(), Some("tail" | "head"))
        && match segment.arguments.as_slice() {
            [count] => count.strip_prefix('-').is_some_and(bounded_count),
            [flag, count] => flag == "-n" && bounded_count(count),
            _ => false,
        }
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

/// Peel a verified `cd <workspace dir> &&` prefix and a final bounded
/// `| tail -N`/`| head -N` filter, returning the sole core invocation.
/// Classification only: the execution sink peels the same shape and
/// re-authorizes the core in the resolved directory before running it.
pub(super) fn contained_core(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
) -> Option<CanonicalCommandV1> {
    if model.confidence != "exact" || model.path_overridden || !model.wrapper_chain.is_empty() {
        return None;
    }
    let segments = model.segments.as_slice();
    let mut start = 0;
    if segments.first()?.executable.as_deref() == Some("cd") {
        let target = super::segment_proof::verified_cwd_compound_context(model, context)?;
        let workspace = std::fs::canonicalize(context.cwd?).ok()?;
        if !std::path::Path::new(&target).starts_with(&workspace) {
            return None;
        }
        start = 1;
    }
    let filtered = segments.len() == start + 2 && output_filter(&segments[start + 1]);
    if filtered
        && text(
            model,
            segments[start].span.end,
            segments[start + 1].span.start,
        )? != "|"
    {
        return None;
    }
    if (start == 0 && !filtered) || segments.len() != start + 1 + usize::from(filtered) {
        return None;
    }
    let mut core = segments[start].clone();
    if core.pipeline_index != 0 || core.executable.as_deref() == Some("cd") {
        return None;
    }
    if filtered
        && core
            .arguments
            .last()
            .is_some_and(|argument| argument == "2>&1")
    {
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

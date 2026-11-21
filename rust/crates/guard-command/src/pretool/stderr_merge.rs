//! Trailing `2>&1` redirects inside a command segment.

/// Trailing `2>&1` redirects only join stderr to the segment's own stdout, so
/// the proof applies to the command without them. Every eligible redirect is
/// removed in one copy. The parser admits that redirect only at a token
/// boundary; a quoted or escaped `2>&1` operand is still the last argument but
/// leaves a quote or backslash in the text, so it stays.
fn stderr_merge_tail(segment: &crate::CommandSegmentV1) -> bool {
    segment.arguments.last().map(String::as_str) == Some("2>&1")
        && segment.tokens.last().map(String::as_str) == Some("2>&1")
}

pub(crate) fn without_stderr_merge(
    segment: &crate::CommandSegmentV1,
) -> Option<crate::CommandSegmentV1> {
    if !stderr_merge_tail(segment) {
        return None;
    }
    let mut merged = segment.clone();
    while stderr_merge_tail(&merged) {
        let Some(text) = merged.text.strip_suffix("2>&1") else {
            break;
        };
        let command = text.trim_end();
        if command.len() == text.len() || command.ends_with('\\') {
            break;
        }
        merged.arguments.pop();
        merged.tokens.pop();
        merged.text = command.to_owned();
    }
    Some(merged)
}

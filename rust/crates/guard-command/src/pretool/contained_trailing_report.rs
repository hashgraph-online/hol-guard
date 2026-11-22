//! The trailing report an agent closes a run with.
//!
//! A run that ends in `; echo "exit=$?"`, `; echo <label>`, `&& echo <label>`,
//! `|| echo <label>` or `&& echo <label> || echo <label>` says how it went and
//! nothing more. The sink prints the report itself, so the run behind it keeps
//! the containment it would have had alone. This module reads that shape; the
//! sink's own peel of the same text lives in `sink_peel`.

use crate::{CanonicalCommandV1, CommandSegmentV1};

use super::text;

/// How many trailing segments say how the run went rather than doing work.
///
/// An agent closes a run with a report of its own: `; echo "exit=$?"`, which
/// the sink has always printed itself, `; echo <label>`, which prints however
/// the run ends, `&& echo <label>` or `|| echo <label>`, which print on one
/// outcome, and `&& echo <label> || echo <label>`, which prints one of two.
/// Each reads nothing and writes only its own label, so the sink prints it
/// and the run behind it keeps the containment it would have had alone. A
/// `$?` label counts only after `;`, because after `&&` or `||` the status it
/// would read is the echo's own.
pub(in crate::pretool) fn trailing_report_steps(
    model: &CanonicalCommandV1,
    segments: &[CommandSegmentV1],
    start: usize,
) -> usize {
    let separator = |index: usize| -> Option<String> {
        text(
            model,
            segments[index - 1].span.end,
            segments[index].span.start,
        )
    };
    let last = segments
        .len()
        .checked_sub(1)
        .filter(|_| segments.len() >= start + 2);
    let Some(last) = last else {
        return 0;
    };
    let Some((_, status)) = echo_report(model, &segments[last]) else {
        return 0;
    };
    let Some(joined) = separator(last) else {
        return 0;
    };
    if status {
        return usize::from(joined == ";");
    }
    if joined == "||"
        && segments.len() >= start + 3
        && matches!(echo_report(model, &segments[last - 1]), Some((_, false)))
        && separator(last - 1).as_deref() == Some("&&")
    {
        // `&& echo <label> || echo <label>`: one arm or the other runs.
        return 2;
    }
    if joined == ";" || joined == "&&" || joined == "||" {
        return 1;
    }
    0
}

/// One `echo <label>` step of a trailing report: the label it prints, and
/// whether that label ends in the `$?` the shell expands to a status.
fn echo_report(model: &CanonicalCommandV1, segment: &CommandSegmentV1) -> Option<(String, bool)> {
    if !(segment.environment_names.is_empty()
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
        && segment.pipeline_index == 0
        && segment.executable.as_deref() == Some("echo")
        && segment.arguments.len() == 1)
    {
        return None;
    }
    echo_report_syntax(&text(model, segment.span.start, segment.span.end)?)
}

fn echo_report_syntax(source: &str) -> Option<(String, bool)> {
    let rest = source.trim().strip_prefix("echo")?;
    if !rest.starts_with([' ', '\t']) {
        return None;
    }
    let argument = rest.trim();
    let (label, quoted) = if let Some(inner) = argument
        .strip_prefix('"')
        .and_then(|body| body.strip_suffix('"'))
    {
        (inner, true)
    } else if argument.contains(['\'', '\\', '"']) {
        return None;
    } else {
        (argument, false)
    };
    let (label, status) = match strip_status_expansion(label) {
        Some((label, _)) => (label, true),
        // An `echo` with nothing to print is not a report.
        None if label.is_empty() => return None,
        None => (label, false),
    };
    // `echo -n`, `-e` and `-E` are options to the shell's own echo, which
    // prints nothing for them. A label the sink would print instead is not
    // the text the command produces, so it is not a report.
    if label.starts_with('-') {
        return None;
    }
    let printable = label.len() <= 32
        && label.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'=' | b':' | b'-')
                || (quoted && byte == b' ')
        });
    printable.then(|| (label.to_owned(), status))
}

/// The status expansion a report label ends in, and whether it names the
/// first stage of a pipeline rather than whatever the shell last ran.
///
/// `$?` is the shell's own status. `${PIPESTATUS[0]}` is bash's status of the
/// first command in the pipeline it just ran, which is the core itself: an
/// agent that pipes a run into `grep` and `head` writes it to read past those
/// filters. The sink knows the core's status, so it prints that label too.
pub(in crate::pretool) fn strip_status_expansion(label: &str) -> Option<(&str, bool)> {
    if let Some(rest) = label.strip_suffix("$?") {
        return Some((rest, false));
    }
    label
        .strip_suffix("${PIPESTATUS[0]}")
        .map(|rest| (rest, true))
}

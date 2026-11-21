//! The sink's own read of a trailing report.
//!
//! `peel` truncates a wrapped command at the line that only says how the run
//! went, and records what each arm of that line prints. The classifier reads
//! the same shape off the parsed segments in `contained_trailing_report`;
//! this is the text-level twin the sink itself runs.

use super::{literal, require_blanks, skip_blanks, STATUS_LABEL_LIMIT};

/// What a trailing report prints, and when.
#[derive(Debug, Clone, Default, PartialEq)]
pub(super) struct TrailingReport {
    /// A `; echo "<label>$?"`, which prints the label and the status itself.
    pub(super) status: Option<String>,
    /// What the report prints when the command the shell tested succeeded.
    pub(super) success: Option<String>,
    /// What it prints when that command failed.
    pub(super) failure: Option<String>,
}

/// The report an agent appends to a run to say how it went: where it starts,
/// and what it prints. One of
///
/// - `; echo "<label>$?"`, the status the sink has always printed itself;
/// - `; echo <label>`, printed however the run ends;
/// - `&& echo <label>`, printed only after a run that succeeded;
/// - `|| echo <label>`, printed only after one that failed;
/// - `&& echo <label> || echo <label>`, one of the two.
///
/// A label with spaces must be double-quoted. Nothing else may follow, so the
/// report is the whole of what the shell would run after the command.
pub(super) fn trailing_report(characters: &[char]) -> Option<(usize, TrailingReport)> {
    unquoted_indices(characters).into_iter().find_map(|index| {
        let separator = report_separator(characters, index)?;
        report_at(characters, index + separator.len(), separator).map(|report| (index, report))
    })
}

/// The positions the shell reads as syntax rather than as text: an operator
/// inside quotes is an argument, and truncating there would cut a word in
/// half.
fn unquoted_indices(characters: &[char]) -> Vec<usize> {
    let mut open: Option<char> = None;
    let mut escaped = false;
    let mut indices = Vec::new();
    for (index, character) in characters.iter().copied().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match (open, character) {
            (None, '\\') => escaped = true,
            (Some('"'), '\\') => escaped = true,
            (None, '\'' | '"') => open = Some(character),
            (Some(quote), _) if quote == character => open = None,
            (None, _) => indices.push(index),
            _ => {}
        }
    }
    indices
}

/// The operator at `index`, when it is one a report can hang from.
fn report_separator(characters: &[char], index: usize) -> Option<&'static str> {
    match characters.get(index)? {
        ';' => Some(";"),
        '&' if characters.get(index + 1) == Some(&'&') => Some("&&"),
        '|' if characters.get(index + 1) == Some(&'|') => Some("||"),
        _ => None,
    }
}

/// The report that runs after `separator`, when the rest of the text is one.
fn report_at(characters: &[char], start: usize, separator: &str) -> Option<TrailingReport> {
    let (index, label, status) = echo_clause(characters, start)?;
    if status {
        // `$?` reads the status of whatever the shell last ran, which is the
        // echo itself after `&&` or `||`. Only the sequenced spelling names
        // the command's own status.
        return (separator == ";" && skip_blanks(characters, index) == characters.len()).then(
            || TrailingReport {
                status: Some(label),
                ..TrailingReport::default()
            },
        );
    }
    let after = skip_blanks(characters, index);
    if after != characters.len() {
        // The one shape that continues is the `||` arm of `&& echo … || echo …`.
        if separator != "&&" || report_separator(characters, after) != Some("||") {
            return None;
        }
        let (index, failure, status) = echo_clause(characters, after + 2)?;
        if status || skip_blanks(characters, index) != characters.len() {
            return None;
        }
        return Some(TrailingReport {
            status: None,
            success: Some(label),
            failure: Some(failure),
        });
    }
    Some(match separator {
        // A sequenced report prints however the command ended.
        ";" => TrailingReport {
            status: None,
            success: Some(label.clone()),
            failure: Some(label),
        },
        "&&" => TrailingReport {
            status: None,
            success: Some(label),
            failure: None,
        },
        _ => TrailingReport {
            status: None,
            failure: Some(label),
            success: None,
        },
    })
}

/// One `echo <label>` clause: where it ends, the label, and whether the label
/// ended in the `$?` the shell expands to a status.
fn echo_clause(characters: &[char], start: usize) -> Option<(usize, String, bool)> {
    let mut index = skip_blanks(characters, start);
    index = literal(characters, index, "echo")?;
    index = require_blanks(characters, index)?;
    let quoted = characters.get(index) == Some(&'"');
    if quoted {
        index += 1;
    }
    let mut label = String::new();
    while label.len() < STATUS_LABEL_LIMIT
        && characters.get(index).copied().is_some_and(|character| {
            character.is_ascii_alphanumeric()
                || "_=:-".contains(character)
                || (quoted && character == ' ')
        })
    {
        label.push(characters[index]);
        index += 1;
    }
    let status = match literal(characters, index, "$?") {
        Some(past) => {
            index = past;
            true
        }
        None => false,
    };
    if quoted {
        if characters.get(index) != Some(&'"') {
            return None;
        }
        index += 1;
    }
    // An empty label is `echo` with nothing to print, and a label that opens
    // with `-` is an option word the shell's echo consumes rather than
    // prints. Neither is a report.
    if label.starts_with('-') {
        return None;
    }
    (status || !label.is_empty()).then_some((index, label, status))
}

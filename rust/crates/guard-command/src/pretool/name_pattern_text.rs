//! Text a command matches against names it already lists or collects: the
//! pattern of a `find` name test and the expression of `pytest -k`.
//!
//! `find examples -name "*password*"` prints the names the walk visits that
//! match the pattern, and `pytest -k password` selects which collected tests
//! run. Neither opens a file the pattern names, so a credential word there is
//! not a secret read. The rest of the command still meets every screen.
//!
//! The names `find` prints can still be handed to a program that opens them,
//! as in `find . -name "*password*" | xargs cat`. The patterns are therefore
//! set aside only when every later stage of the pipeline reads nothing but
//! its standard input: `head`, `tail` or `wc` with no operand, or a `grep` or
//! `rg` filter. A `find` expression with an action such as `-exec` or
//! `-fprint` keeps its patterns in view.

use crate::{CanonicalCommandV1, CommandSegmentV1};

/// `find` tests whose value is a pattern compared against each visited name.
const FIND_NAME_TESTS: &[&str] = &[
    "-name",
    "-iname",
    "-path",
    "-ipath",
    "-wholename",
    "-iwholename",
];

/// Shell text that makes a word do more than carry its pattern: a redirect
/// opens a file and a substitution brings in text no screen has seen.
const UNSAFE: [char; 7] = ['<', '>', '$', '`', ';', '&', '|'];

/// The segment's text with its name patterns left out, or `None` when the
/// segment is not a `find` listing or `pytest` run whose patterns may be set
/// aside.
pub(super) fn segment_without_patterns(model: &CanonicalCommandV1, index: usize) -> Option<String> {
    let segment = model.segments.get(index)?;
    let executable = super::executable_basename(segment.executable.as_deref()?);
    if segment.pipeline_index != 0
        || !segment.environment_names.is_empty()
        || !segment.wrapper_chain.is_empty()
        || segment.path_overridden
        || segment.tokens.len() != segment.arguments.len() + 1
        || !later_stages_read_stdin_only(model, index)
    {
        return None;
    }
    let masked = match executable {
        "find" => find_patterns(&segment.arguments)?,
        _ => pytest_keyword_values(executable, &segment.arguments)?,
    };
    if masked.is_empty()
        || masked
            .iter()
            .any(|&position| segment.tokens[position + 1].contains(UNSAFE))
    {
        return None;
    }
    Some(
        segment
            .tokens
            .iter()
            .enumerate()
            .filter(|(position, _)| *position == 0 || !masked.contains(&(position - 1)))
            .map(|(_, token)| token.as_str())
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// The argument positions holding a name test's pattern, when the whole
/// expression only matches and prints names.
fn find_patterns(arguments: &[String]) -> Option<Vec<usize>> {
    if !super::find_reads::prints_names_only(arguments) {
        return None;
    }
    Some(
        arguments
            .iter()
            .enumerate()
            .filter(|(_, argument)| FIND_NAME_TESTS.contains(&argument.as_str()))
            .map(|(position, _)| position + 1)
            .filter(|position| *position < arguments.len())
            .collect(),
    )
}

/// The argument positions holding a `-k` expression of `pytest` or
/// `python -m pytest`. pytest reads every `-k` before a `--` as its own
/// option, so a value-taking option before it cannot swallow it.
fn pytest_keyword_values(executable: &str, arguments: &[String]) -> Option<Vec<usize>> {
    let start = match executable {
        "pytest" | "py.test" => 0,
        name if python(name) => (arguments.get(..2)? == ["-m", "pytest"]).then_some(2)?,
        _ => return None,
    };
    let end = arguments
        .iter()
        .position(|argument| argument == "--")
        .unwrap_or(arguments.len());
    Some(
        (start..end)
            .filter(|&position| arguments[position] == "-k")
            .map(|position| position + 1)
            .filter(|&position| position < end)
            .collect(),
    )
}

fn python(name: &str) -> bool {
    name == "python"
        || name.strip_prefix("python3").is_some_and(|version| {
            version.is_empty()
                || version.strip_prefix('.').is_some_and(|minor| {
                    !minor.is_empty() && minor.bytes().all(|b| b.is_ascii_digit())
                })
        })
}

/// Whether every stage after `index` in its pipeline reads only its standard
/// input: a pipeline filter whose patterns may be masked, or `head`, `tail`
/// or `wc` with options and counts but no operand.
fn later_stages_read_stdin_only(model: &CanonicalCommandV1, index: usize) -> bool {
    model.segments[index + 1..]
        .iter()
        .take_while(|segment| segment.pipeline_index > 0)
        .all(|segment| {
            super::filter_pattern_text::segment_without_patterns(segment).is_some()
                || trimmer(segment)
        })
}

fn trimmer(segment: &CommandSegmentV1) -> bool {
    super::filter_pattern_text::maskable_filter_segment(segment)
        && segment.executable.as_deref().is_some_and(|executable| {
            matches!(
                super::executable_basename(executable),
                "head" | "tail" | "wc"
            )
        })
        && segment
            .arguments
            .iter()
            .enumerate()
            .all(|(position, argument)| {
                argument.bytes().all(|byte| byte.is_ascii_digit())
                    && position > 0
                    && matches!(segment.arguments[position - 1].as_str(), "-n" | "-c")
                    || (argument.starts_with('-')
                        && argument.len() > 1
                        && argument[1..]
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || b"nclwmL".contains(&byte)))
            })
}

#[cfg(test)]
#[path = "name_pattern_text_tests.rs"]
mod tests;

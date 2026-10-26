use super::*;

#[path = "parser_ansi_c.rs"]
mod ansi_c;

#[path = "parser_shell_tokens.rs"]
mod tokens;

pub(crate) use tokens::{shell_tokens, shell_tokens_preserving_redirects};

#[path = "parser_segment_shapes.rs"]
mod shapes;

use shapes::sole_command_group;
pub(super) use shapes::{is_stderr_to_null_redirect, is_stderr_to_stdout_redirect};
// Only the redirect tests in `command_compatibility` read the sink directly.
#[cfg(test)]
pub(super) use shapes::stderr_null_sink_is_inert;

pub(super) fn split_execution_segments(
    command: &str,
    preserve_unquoted_backslash: bool,
) -> Result<Vec<RawSegment>, &'static str> {
    split_execution_segments_inner(command, preserve_unquoted_backslash, false)
}

/// Like [`split_execution_segments`], but a background `&` separates commands
/// the way `;` does. Pipe checks use this so `curl … | sh &` is still the
/// pipe, not an unparsed background job.
pub(super) fn split_pipelines_including_background(
    command: &str,
    preserve_unquoted_backslash: bool,
) -> Result<Vec<RawSegment>, &'static str> {
    split_execution_segments_inner(command, preserve_unquoted_backslash, true)
}

fn split_execution_segments_inner(
    command: &str,
    preserve_unquoted_backslash: bool,
    allow_background: bool,
) -> Result<Vec<RawSegment>, &'static str> {
    let chars: Vec<char> = command.chars().collect();
    // A whole command the shell runs as one group: `(cd src && npm test)` and
    // `{ cd src && npm test; }`. The group itself names no program, so the
    // list inside it owns everything the command can run, and reading it as
    // that list is what proves it. The offsets stay the caller's, so a segment
    // still points at the text it came from.
    if let Some(inside) = sole_command_group(&chars) {
        let inner: String = chars[inside.clone()].iter().collect();
        let mut segments =
            split_execution_segments_inner(&inner, preserve_unquoted_backslash, allow_background)?;
        for segment in &mut segments {
            segment.start += inside.start;
            segment.end += inside.start;
        }
        return Ok(segments);
    }
    let mut quote = Quote::None;
    let mut escaped = false;
    let mut segments = Vec::new();
    let mut segment_start = 0usize;
    let mut group_index = 0usize;
    let mut pipeline_index = 0usize;
    let mut index = 0usize;

    while index < chars.len() {
        let current = chars[index];
        if escaped {
            escaped = false;
            index += 1;
            continue;
        }
        match quote {
            Quote::Single => {
                if current == '\'' {
                    quote = Quote::None;
                }
                index += 1;
                continue;
            }
            Quote::Double => {
                if current == '"' {
                    quote = Quote::None;
                } else if current == '\\' {
                    escaped = true;
                } else if current == '$' && chars.get(index + 1) == Some(&'(') {
                    // Arithmetic runs no command, inside a double quote as
                    // much as outside it: the text spells a number, so the
                    // word carries on past where it closes.
                    match arithmetic_close(&chars, index) {
                        Some(close) => {
                            index = close + 1;
                            continue;
                        }
                        None => return Err("command_substitution_not_yet_supported"),
                    }
                } else if current == '`'
                    || (current == '$'
                        && chars.get(index + 1) == Some(&'{')
                        && chars
                            .get(index + 2)
                            .copied()
                            .is_some_and(crate::parser_brace_command::opens_brace_command))
                {
                    return Err("command_substitution_not_yet_supported");
                }
                index += 1;
                continue;
            }
            Quote::None => {}
        }

        match current {
            '\'' => quote = Quote::Single,
            '"' => quote = Quote::Double,
            // The escape that survives `preserve_unquoted_backslash`: an
            // operator that ends the command belongs to the word, so it never
            // separates commands.
            '\\' if preserve_unquoted_backslash => {
                if crate::command_tokens::backslash_escapes_operator(&chars, index) {
                    escaped = true;
                }
            }
            '\\' => escaped = true,
            '`' => return Err("command_substitution_not_yet_supported"),
            '$' if chars.get(index + 1) == Some(&'(') => {
                // `$(( … ))` evaluates arithmetic; nothing in it runs.
                match arithmetic_close(&chars, index) {
                    Some(close) => {
                        index = close + 1;
                        continue;
                    }
                    None => return Err("command_substitution_not_yet_supported"),
                }
            }
            '$' if chars.get(index + 1) == Some(&'{') => {
                return Err("parameter_expansion_not_yet_supported");
            }
            // Each `$` pairs off with the next one: `$$` is the shell's own
            // process id, so the word beside it opens where this pair ends.
            '$' if chars.get(index + 1) == Some(&'$') => {
                index += 2;
                continue;
            }
            // The word runs nothing, so carry on past the text it spells.
            '$' if chars.get(index + 1) == Some(&'\'') => {
                index = ansi_c::word(&chars, index, preserve_unquoted_backslash)?.1 + 1;
                continue;
            }
            '$' if chars.get(index + 1) == Some(&'"') => {
                return Err("non_posix_quoting_not_yet_supported");
            }
            '<' | '>'
                if is_stderr_to_stdout_redirect(&chars, index, preserve_unquoted_backslash) => {}
            '>' if index.checked_sub(1).is_some_and(|start| {
                is_stderr_to_null_redirect(&chars, start, preserve_unquoted_backslash)
            }) => {}
            '<' | '>' => return Err("command_redirect_not_yet_supported"),
            '(' | ')' => return Err("compound_shell_not_yet_supported"),
            '{' | '}'
                if (index == 0
                    || is_shell_token_whitespace(chars[index - 1])
                    || matches!(chars[index - 1], ';' | '&' | '|'))
                    && chars.get(index + 1).is_none_or(|value| {
                        is_shell_token_whitespace(*value) || matches!(*value, ';' | '&' | '|')
                    }) =>
            {
                return Err("compound_shell_not_yet_supported");
            }
            '&' => {
                if is_stderr_to_stdout_redirect(&chars, index, preserve_unquoted_backslash) {
                    index += 1;
                    continue;
                }
                if chars.get(index + 1) != Some(&'&') {
                    if !allow_background {
                        return Err("background_job_not_yet_supported");
                    }
                    push_segment(
                        &chars,
                        segment_start,
                        index,
                        group_index,
                        pipeline_index,
                        &mut segments,
                    )?;
                    let rest_blank = chars[index + 1..].iter().all(|value| value.is_whitespace());
                    if rest_blank {
                        return if segments.is_empty() {
                            Err("background_job_not_yet_supported")
                        } else {
                            Ok(segments)
                        };
                    }
                    segment_start = index + 1;
                    group_index += 1;
                    pipeline_index = 0;
                } else {
                    push_segment(
                        &chars,
                        segment_start,
                        index,
                        group_index,
                        pipeline_index,
                        &mut segments,
                    )?;
                    index += 1;
                    segment_start = index + 1;
                    group_index += 1;
                    pipeline_index = 0;
                }
            }
            '|' => {
                let logical_or = chars.get(index + 1) == Some(&'|');
                // `a |& b` sends a's standard error down the pipe with its
                // standard output: the `&` belongs to the pipe, not to a job
                // behind it. Reading it as a background `&` left `make |& tee
                // build.log` unmodelled, while the `make 2>&1 | tee build.log`
                // it spells modelled as the two commands it names. A trailing
                // `|&` with nothing behind it is ksh's coprocess rather than a
                // pipe, so the `&` is left where it is.
                let merges_stderr = !logical_or
                    && chars.get(index + 1) == Some(&'&')
                    && chars[index + 2..]
                        .iter()
                        .any(|value| !value.is_whitespace());
                push_segment(
                    &chars,
                    segment_start,
                    index,
                    group_index,
                    pipeline_index,
                    &mut segments,
                )?;
                if logical_or {
                    index += 1;
                    group_index += 1;
                    pipeline_index = 0;
                } else {
                    if merges_stderr {
                        index += 1;
                    }
                    pipeline_index += 1;
                }
                segment_start = index + 1;
            }
            ';' | '\n' => {
                push_segment(
                    &chars,
                    segment_start,
                    index,
                    group_index,
                    pipeline_index,
                    &mut segments,
                )?;
                segment_start = index + 1;
                group_index += 1;
                pipeline_index = 0;
            }
            _ => {}
        }
        index += 1;
    }

    if quote != Quote::None || escaped {
        return Err("malformed_shell_quoting");
    }
    // `ls;` is `ls`: one `;` or newline may end the command. A dangling `&&`,
    // `||` or `|` still continues it, and `ls; ;` still fails.
    let terminated = segment_start > 0
        && matches!(chars[segment_start - 1], ';' | '\n')
        && chars[segment_start..]
            .iter()
            .all(|value| value.is_whitespace());
    if terminated && !segments.is_empty() {
        return Ok(segments);
    }
    push_segment(
        &chars,
        segment_start,
        chars.len(),
        group_index,
        pipeline_index,
        &mut segments,
    )?;
    if segments.is_empty() {
        return Err("empty_command_segment");
    }
    Ok(segments)
}

pub(super) fn contained_compile_check_segments(command: &str) -> Option<Vec<RawSegment>> {
    let chars: Vec<char> = command.chars().collect();
    let and_index = chars.windows(2).position(|window| window == ['&', '&'])?;
    if chars[and_index + 2..]
        .windows(2)
        .any(|window| window == ['&', '&'])
    {
        return None;
    }
    let (cd_start, cd_end) = trimmed_bounds(&chars, 0, and_index)?;
    let (find_start, find_end) = trimmed_bounds(&chars, and_index + 2, chars.len())?;
    let cd: String = chars[cd_start..cd_end].iter().collect();
    let find: String = chars[find_start..find_end].iter().collect();
    let cd_tokens = shell_tokens(&cd, false).ok()?;
    let find_tokens = shell_tokens(&find, false).ok()?;
    if cd_tokens.len() != 2
        || cd_tokens.first().map(String::as_str) != Some("cd")
        || !is_plain_cd_target(&cd_tokens[1])
        || find_tokens.first().map(String::as_str) != Some("find")
        || !is_contained_compile_check_arguments(&find_tokens[1..])
    {
        return None;
    }
    Some(vec![
        RawSegment {
            group_index: 0,
            pipeline_index: 0,
            start: cd_start,
            end: cd_end,
        },
        RawSegment {
            group_index: 1,
            pipeline_index: 0,
            start: find_start,
            end: find_end,
        },
    ])
}

pub(super) fn trimmed_bounds(chars: &[char], start: usize, end: usize) -> Option<(usize, usize)> {
    let mut left = start;
    let mut right = end;
    while left < right && chars[left].is_whitespace() {
        left += 1;
    }
    while right > left && chars[right - 1].is_whitespace() {
        right -= 1;
    }
    (left < right).then_some((left, right))
}

pub(super) fn starts_at_shell_token_boundary(
    chars: &[char],
    start: usize,
    preserve_backslash: bool,
) -> bool {
    start == 0
        || (is_shell_token_whitespace(chars[start - 1])
            && (preserve_backslash
                || chars[..start - 1]
                    .iter()
                    .rev()
                    .take_while(|value| **value == '\\')
                    .count()
                    % 2
                    == 0))
}

pub(super) fn is_plain_cd_target(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.chars().any(|value| {
            matches!(
                value,
                '$' | '`' | '<' | '>' | '|' | ';' | '&' | '(' | ')' | '{' | '}' | '\0'
            )
        })
}

pub(super) fn push_segment(
    chars: &[char],
    start: usize,
    end: usize,
    group_index: usize,
    pipeline_index: usize,
    output: &mut Vec<RawSegment>,
) -> Result<(), &'static str> {
    let mut left = start;
    let mut right = end;
    while left < right && chars[left].is_whitespace() {
        left += 1;
    }
    while right > left && chars[right - 1].is_whitespace() {
        right -= 1;
    }
    if left == right {
        return Err("empty_command_segment");
    }
    output.push(RawSegment {
        group_index,
        pipeline_index,
        start: left,
        end: right,
    });
    Ok(())
}

/// The value an arithmetic expansion stands for once the parser has read it.
/// Arithmetic only ever spells a number, so the word it sits in carries one.
/// It is the count every program accepts: `-j0` and `-n 0` are errors to the
/// programs that take them, and a stand-in must not read as one.
pub(crate) const ARITHMETIC_VALUE: &str = "1";

/// The second `)` of the `))` that closes the arithmetic expansion opening at
/// `start`, the `$` of a `$((`, or `None` when the shell would read the text as
/// a substitution around a subshell instead.
///
/// `$((` opens arithmetic when the body closes on two parentheses of its own:
/// `$(( (a + b) * c ))` is a number in every shell, and `$((a))` is one even
/// when `a` is a word arithmetic cannot read, because the shell fails the
/// expansion rather than running anything. When the first close lands anywhere
/// else the shell has closed a subshell instead, so `$((cat id) | sh)` runs
/// `cat` and `sh` in bash and zsh and is a syntax error in dash; either way it
/// is not arithmetic. A nested substitution or a backtick inside the body runs
/// a command of its own, so it is not read here.
///
/// The body is not scanned as ordinary shell text. The shell expands it as if
/// it were double-quoted, so a `'` inside it quotes nothing: bash 5.2 runs the
/// substitution in `echo $(( '$(echo SQ >&2)' 1 ))`. Tracking quotes here
/// would hide that `$(` from the check below and hide a `)` from the depth
/// count, so a quote, a backslash or a backtick anywhere in the body ends the
/// read instead. Arithmetic needs none of them, and refusing them leaves the
/// expansion unmodelled, which is where it was before it was read at all.
pub(crate) fn arithmetic_close(chars: &[char], start: usize) -> Option<usize> {
    if chars.get(start + 1) != Some(&'(') || chars.get(start + 2) != Some(&'(') {
        return None;
    }
    let mut depth = 1usize;
    for (index, &character) in chars.iter().enumerate().skip(start + 3) {
        match character {
            '\\' | '\'' | '"' | '`' => return None,
            // `$(cmd)`, and the ksh `${ cmd; }` and `${| cmd; }` forms, each
            // run a command inside what would otherwise read as a number.
            // `${name}` is an ordinary parameter and stays.
            '$' if chars.get(index + 1) == Some(&'(') => return None,
            '$' if chars.get(index + 1) == Some(&'{')
                && chars
                    .get(index + 2)
                    .is_some_and(|next| next.is_whitespace() || *next == '|') =>
            {
                return None;
            }
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return (chars.get(index + 1) == Some(&')')).then_some(index + 1);
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
#[path = "parser_segments_ansi_c_tests.rs"]
mod ansi_c_tests;

#[cfg(test)]
#[path = "parser_segments_arithmetic_tests.rs"]
mod arithmetic_tests;

#[cfg(test)]
#[path = "parser_segments_pipe_tests.rs"]
mod pipe_tests;

#[cfg(test)]
#[path = "parser_segments_windows_escape_tests.rs"]
mod windows_escape_tests;

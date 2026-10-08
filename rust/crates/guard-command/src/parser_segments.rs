use super::*;

pub(super) fn split_execution_segments(
    command: &str,
    preserve_unquoted_backslash: bool,
) -> Result<Vec<RawSegment>, &'static str> {
    let chars: Vec<char> = command.chars().collect();
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
                } else if current == '`' || (current == '$' && chars.get(index + 1) == Some(&'(')) {
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
            '\\' if preserve_unquoted_backslash => {}
            '\\' => escaped = true,
            '`' => return Err("command_substitution_not_yet_supported"),
            '$' if chars.get(index + 1) == Some(&'(') => {
                return Err("command_substitution_not_yet_supported");
            }
            '$' if chars.get(index + 1) == Some(&'{') => {
                return Err("parameter_expansion_not_yet_supported");
            }
            '$' if chars
                .get(index + 1)
                .is_some_and(|next| *next == '\'' || *next == '"') =>
            {
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
                index += 1;
                segment_start = index + 1;
                group_index += 1;
                pipeline_index = 0;
            }
            '|' => {
                let logical_or = chars.get(index + 1) == Some(&'|');
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

pub(super) fn is_stderr_to_stdout_redirect(
    chars: &[char],
    index: usize,
    preserve_backslash: bool,
) -> bool {
    let start = match chars.get(index) {
        Some('&') => index.checked_sub(2),
        Some('>') => index.checked_sub(1),
        _ => None,
    };
    let Some(start) = start else {
        return false;
    };
    let Some(redirect) = chars.get(start..start.saturating_add(4)) else {
        return false;
    };
    redirect == ['2', '>', '&', '1']
        && starts_at_shell_token_boundary(chars, start, preserve_backslash)
        && chars.get(start + 4).is_none_or(|value| {
            is_shell_token_whitespace(*value) || matches!(*value, '|' | '&' | ';')
        })
}

pub(super) fn is_stderr_to_null_redirect(
    chars: &[char],
    start: usize,
    preserve_backslash: bool,
) -> bool {
    // Only Unix's fixed stderr sink is inert; arbitrary paths and descriptors
    // must still pass through the unsupported-redirection guard.
    cfg!(unix)
        && chars.get(start..start.saturating_add(11))
            == Some(&['2', '>', '/', 'd', 'e', 'v', '/', 'n', 'u', 'l', 'l'])
        && starts_at_shell_token_boundary(chars, start, preserve_backslash)
        && chars.get(start + 11).is_none_or(|value| {
            is_shell_token_whitespace(*value) || matches!(*value, '|' | '&' | ';')
        })
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

pub(crate) fn shell_tokens(
    command: &str,
    preserve_backslash: bool,
) -> Result<Vec<String>, &'static str> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut token_started = false;
    let mut quote = Quote::None;
    let mut escaped = false;

    let chars: Vec<char> = command.chars().collect();
    let mut characters = chars.iter().copied().enumerate();
    while let Some((index, current)) = characters.next() {
        if escaped {
            if quote == Quote::Double && current != '"' && current != '\\' {
                token.push('\\');
            }
            token.push(current);
            token_started = true;
            escaped = false;
            continue;
        }
        match quote {
            Quote::Single => {
                if current == '\'' {
                    quote = Quote::None;
                } else {
                    token.push(current);
                    token_started = true;
                }
            }
            Quote::Double => {
                if current == '"' {
                    quote = Quote::None;
                } else if current == '\\' {
                    escaped = true;
                    token_started = true;
                } else {
                    token.push(current);
                    token_started = true;
                }
            }
            Quote::None => match current {
                '2' if !token_started
                    && is_stderr_to_null_redirect(&chars, index, preserve_backslash) =>
                {
                    // A shell redirection is not an argv operand. Preserve it
                    // in segment.text/spans, but exclude it from argument proofs.
                    for _ in 0..10 {
                        characters.next();
                    }
                }
                '\'' => {
                    quote = Quote::Single;
                    token_started = true;
                }
                '"' => {
                    quote = Quote::Double;
                    token_started = true;
                }
                '\\' if preserve_backslash => {
                    token.push('\\');
                    token_started = true;
                }
                '\\' => {
                    escaped = true;
                    token_started = true;
                }
                value if is_shell_token_whitespace(value) => {
                    if token_started {
                        tokens.push(std::mem::take(&mut token));
                        token_started = false;
                    }
                }
                value => {
                    token.push(value);
                    token_started = true;
                }
            },
        }
    }
    if quote != Quote::None || escaped {
        return Err("malformed_shell_quoting");
    }
    if token_started {
        tokens.push(token);
    }
    Ok(tokens)
}

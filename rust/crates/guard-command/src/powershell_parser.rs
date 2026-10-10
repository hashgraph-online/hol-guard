//! Bounded PowerShell tokenizer for the `powershell-subset-v1` profile.
//!
//! Only literal strings, plain barewords, `-Param` switches, `|` pipelines,
//! `;` statements and `[Type]::Method(literal, ...)` calls are understood.
//! Everything else is rejected with a specific reason so the caller can stay
//! uncertain and fail closed.

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PsArg {
    pub value: String,
    pub quoted: bool,
    /// Unquoted bareword starting with `-`.
    pub param: bool,
    /// Value written as `-Param:value`.
    pub attached: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PsCall {
    Command {
        name: String,
        args: Vec<PsArg>,
    },
    Static {
        type_name: String,
        method: String,
        args: Vec<String>,
        /// A trailing text-encoding argument from the fixed list below.
        encoding: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PsStatement {
    pub start: usize,
    pub end: usize,
    pub group_index: usize,
    pub pipeline_index: usize,
    pub call: PsCall,
}

type Reason = &'static str;

pub(crate) fn parse_statements(chars: &[char]) -> Result<Vec<PsStatement>, Reason> {
    let mut statements = Vec::new();
    let (mut index, mut group, mut pipeline) = (0usize, 0usize, 0usize);
    let mut after_pipe = false;
    loop {
        skip_blanks(chars, &mut index);
        match chars.get(index) {
            None => break,
            Some(';' | '\n') if !after_pipe => {
                index += 1;
                group += 1;
                pipeline = 0;
                continue;
            }
            Some('|') if !after_pipe => {
                // An empty first command before `|` is not a command.
                return Err("empty_command_segment");
            }
            _ => {}
        }
        let (start, end, call) = parse_segment(chars, &mut index)?;
        statements.push(PsStatement {
            start,
            end,
            group_index: group,
            pipeline_index: pipeline,
            call,
        });
        after_pipe = false;
        skip_blanks(chars, &mut index);
        match chars.get(index) {
            Some('|') => {
                if chars.get(index + 1) == Some(&'|') {
                    return Err("powershell_logical_operator_not_supported");
                }
                index += 1;
                pipeline += 1;
                after_pipe = true;
            }
            Some(';' | '\n') => {
                index += 1;
                group += 1;
                pipeline = 0;
            }
            _ => {}
        }
    }
    if after_pipe || statements.is_empty() {
        return Err("empty_command_segment");
    }
    Ok(statements)
}

fn skip_blanks(chars: &[char], index: &mut usize) {
    while chars
        .get(*index)
        .is_some_and(|c| matches!(c, ' ' | '\t' | '\r'))
    {
        *index += 1;
    }
}

fn is_terminator(value: Option<&char>) -> bool {
    matches!(value, None | Some(' ' | '\t' | '\r' | '\n' | ';' | '|'))
}

fn parse_segment(chars: &[char], index: &mut usize) -> Result<(usize, usize, PsCall), Reason> {
    let start = *index;
    if chars[start] == '[' {
        let call = parse_static_call(chars, index)?;
        skip_blanks(chars, index);
        if !is_terminator(chars.get(*index)) {
            return Err("powershell_static_call_trailer_not_supported");
        }
        return Ok((start, trimmed_end(chars, start, *index), call));
    }
    let mut tokens: Vec<PsArg> = Vec::new();
    loop {
        skip_blanks(chars, index);
        if is_terminator(chars.get(*index)) {
            break;
        }
        let first = tokens.is_empty();
        read_arg(chars, index, false, &mut tokens)?;
        if first {
            let head = &tokens[0];
            if head.quoted || head.param {
                return Err("powershell_quoted_command_not_supported");
            }
        }
    }
    let end = trimmed_end(chars, start, *index);
    let mut tokens = tokens.into_iter();
    let name = tokens.next().map(|arg| arg.value).unwrap_or_default();
    if name == "." {
        return Err("powershell_dot_source_not_supported");
    }
    Ok((
        start,
        end,
        PsCall::Command {
            name,
            args: tokens.collect(),
        },
    ))
}

fn trimmed_end(chars: &[char], start: usize, mut end: usize) -> usize {
    while end > start && chars[end - 1].is_whitespace() {
        end -= 1;
    }
    end
}

fn parse_static_call(chars: &[char], index: &mut usize) -> Result<PsCall, Reason> {
    *index += 1;
    let type_start = *index;
    while chars
        .get(*index)
        .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_'))
    {
        *index += 1;
    }
    let type_name: String = chars[type_start..*index].iter().collect();
    if type_name.is_empty() || chars.get(*index) != Some(&']') {
        return Err("powershell_type_expression_not_supported");
    }
    *index += 1;
    if chars.get(*index) != Some(&':') || chars.get(*index + 1) != Some(&':') {
        return Err("powershell_type_expression_not_supported");
    }
    *index += 2;
    let method_start = *index;
    while chars
        .get(*index)
        .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
    {
        *index += 1;
    }
    let method: String = chars[method_start..*index].iter().collect();
    if method.is_empty() || chars.get(*index) != Some(&'(') {
        return Err("powershell_type_expression_not_supported");
    }
    *index += 1;
    let mut args: Vec<String> = Vec::new();
    let mut encoding = false;
    let mut after_comma = false;
    loop {
        skip_blanks(chars, index);
        if encoding && chars.get(*index) != Some(&')') {
            return Err("powershell_static_call_argument_not_supported");
        }
        if chars.get(*index) == Some(&')') {
            if after_comma {
                return Err("powershell_array_not_supported");
            }
            *index += 1;
            break;
        }
        if !args.is_empty() {
            if let Some(length) = encoding_argument(&chars[*index..]) {
                *index += length;
                encoding = true;
                after_comma = false;
                continue;
            }
        }
        let mut parsed = Vec::new();
        read_arg(chars, index, true, &mut parsed)?;
        if parsed.len() != 1 {
            return Err("powershell_static_call_argument_not_supported");
        }
        args.push(parsed.remove(0).value);
        skip_blanks(chars, index);
        after_comma = false;
        match chars.get(*index) {
            Some(',') => {
                *index += 1;
                after_comma = true;
            }
            Some(')') => {}
            Some(other) => return Err(reject_reason(*other)),
            None => return Err("malformed_shell_quoting"),
        }
    }
    Ok(PsCall::Static {
        type_name,
        method,
        args,
        encoding,
    })
}

/// Length of a text-encoding argument such as `[Text.UTF8Encoding]::new($false)`.
/// Only these constant forms are accepted; any other expression is rejected.
fn encoding_argument(chars: &[char]) -> Option<usize> {
    const FORMS: &[&str] = &[
        "[text.utf8encoding]::new($false)",
        "[text.utf8encoding]::new($true)",
        "[text.utf8encoding]::new()",
        "[text.encoding]::utf8",
        "[text.encoding]::ascii",
        "[text.encoding]::unicode",
        "[text.encoding]::default",
    ];
    let text: String = chars
        .iter()
        .take(48)
        .collect::<String>()
        .to_ascii_lowercase();
    let (prefix, text) = match text.strip_prefix("[system.") {
        Some(rest) => (7, format!("[{rest}")),
        None => (0, text),
    };
    FORMS.iter().find_map(|form| {
        let rest = text.strip_prefix(form)?;
        let next = rest.chars().next();
        next.is_none_or(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '(')))
            .then_some(prefix + form.chars().count())
    })
}

/// Reads one argument (two when `-Param:value`) into `output`.
fn read_arg(
    chars: &[char],
    index: &mut usize,
    in_call: bool,
    output: &mut Vec<PsArg>,
) -> Result<(), Reason> {
    let Some(&current) = chars.get(*index) else {
        return Err("malformed_shell_quoting");
    };
    match current {
        '\'' | '"' => {
            let value = read_string(chars, index)?;
            output.push(PsArg {
                value,
                quoted: true,
                param: false,
                attached: false,
            });
        }
        _ if is_bareword_start(current) => {
            let param = current == '-' && !in_call;
            let value = read_bareword(chars, index, param, in_call)?;
            output.push(PsArg {
                value,
                quoted: false,
                param,
                attached: false,
            });
            if param && chars.get(*index) == Some(&':') {
                *index += 1;
                match chars.get(*index) {
                    Some(&next) if next == '\'' || next == '"' || is_bareword_start(next) => {
                        let mut attached = Vec::new();
                        read_arg(chars, index, false, &mut attached)?;
                        if let [value] = attached.as_mut_slice() {
                            value.attached = true;
                            value.param = false;
                        }
                        output.extend(attached);
                    }
                    Some(&other) => return Err(reject_reason(other)),
                    None => return Err("powershell_unsupported_syntax"),
                }
                return Ok(());
            }
        }
        other => return Err(reject_reason(other)),
    }
    match chars.get(*index) {
        None => Ok(()),
        Some(next) if is_terminator(Some(next)) => Ok(()),
        Some(',' | ')') if in_call => Ok(()),
        Some(next) => Err(reject_reason(*next)),
    }
}

fn is_bareword_start(value: char) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, '.' | '_' | '/' | '\\' | '-' | '~')
}

fn read_bareword(
    chars: &[char],
    index: &mut usize,
    param: bool,
    in_call: bool,
) -> Result<String, Reason> {
    let start = *index;
    while let Some(&current) = chars.get(*index) {
        let offset = *index - start;
        let allowed = current.is_ascii_alphanumeric()
            || matches!(current, '.' | '_' | '/' | '\\' | '-')
            || (current == '~' && offset == 0);
        if allowed {
            *index += 1;
            continue;
        }
        if current == ':' {
            if param {
                break;
            }
            let prefix = &chars[start..*index];
            let drive = offset == 1
                && prefix[0].is_ascii_alphabetic()
                && chars
                    .get(*index + 1)
                    .is_none_or(|next| matches!(next, '/' | '\\') || is_terminator(Some(next)))
                && !in_call;
            let scheme = offset >= 2
                && prefix.iter().all(char::is_ascii_alphabetic)
                && chars.get(*index + 1) == Some(&'/')
                && chars.get(*index + 2) == Some(&'/');
            if drive || scheme {
                *index += 1;
                continue;
            }
            return Err("powershell_colon_syntax_not_supported");
        }
        break;
    }
    Ok(chars[start..*index].iter().collect())
}

fn is_unicode_quote(value: char) -> bool {
    matches!(value, '\u{2018}'..='\u{201E}' | '\u{0}')
}

fn read_string(chars: &[char], index: &mut usize) -> Result<String, Reason> {
    let quote = chars[*index];
    *index += 1;
    let mut value = String::new();
    while let Some(&current) = chars.get(*index) {
        *index += 1;
        if is_unicode_quote(current) {
            return Err("powershell_unicode_quote_not_supported");
        }
        if current == quote {
            if quote == '\'' && chars.get(*index) == Some(&'\'') {
                value.push('\'');
                *index += 1;
                continue;
            }
            return Ok(value);
        }
        if quote == '\'' {
            value.push(current);
            continue;
        }
        match current {
            '$' => {
                return Err(if chars.get(*index) == Some(&'(') {
                    "powershell_subexpression_not_supported"
                } else {
                    "powershell_variable_not_supported"
                });
            }
            '`' => {
                let Some(&escaped) = chars.get(*index) else {
                    return Err("malformed_shell_quoting");
                };
                *index += 1;
                value.push(match escaped {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    '0' => '\0',
                    '"' => '"',
                    '`' => '`',
                    _ => return Err("powershell_escape_not_supported"),
                });
            }
            _ => value.push(current),
        }
    }
    Err("malformed_shell_quoting")
}

fn reject_reason(value: char) -> Reason {
    match value {
        '$' => "powershell_variable_not_supported",
        '@' => "powershell_splat_or_array_not_supported",
        '{' | '}' => "powershell_script_block_not_supported",
        '(' | ')' => "powershell_nested_expression_not_supported",
        '<' | '>' => "powershell_redirect_not_supported",
        '&' => "powershell_invocation_not_supported",
        ',' => "powershell_array_not_supported",
        '`' => "powershell_backtick_continuation_not_supported",
        '#' => "powershell_comment_not_supported",
        '\'' | '"' => "powershell_adjacent_token_not_supported",
        '\u{2018}'..='\u{201E}' => "powershell_unicode_quote_not_supported",
        _ => "powershell_unsupported_syntax",
    }
}

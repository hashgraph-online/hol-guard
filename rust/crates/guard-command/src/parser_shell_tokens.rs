//! The shell's word splitting, read one character at a time.
//!
//! A word ends where the shell ends it: on unquoted whitespace. Quoting,
//! escapes, `$'…'` and `$$` are read here so the tokens hold the text the
//! shell would hand the command, not the spelling it was typed with.

use super::*;

pub(crate) fn shell_tokens(
    command: &str,
    preserve_backslash: bool,
) -> Result<Vec<String>, &'static str> {
    shell_tokens_mode(command, preserve_backslash, true)
}

pub(crate) fn shell_tokens_preserving_redirects(
    command: &str,
) -> Result<Vec<String>, &'static str> {
    shell_tokens_mode(command, false, false)
}

fn shell_tokens_mode(
    command: &str,
    preserve_backslash: bool,
    exclude_stderr_redirect: bool,
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
                '2' if exclude_stderr_redirect
                    && !token_started
                    && is_stderr_to_null_redirect(&chars, index, preserve_backslash) =>
                {
                    // A shell redirection is not an argv operand. Preserve it
                    // in segment.text/spans, but exclude it from argument proofs.
                    for _ in 0..10 {
                        characters.next();
                    }
                }
                '$' if chars.get(index + 1) == Some(&'$') => {
                    token.push_str("$$");
                    token_started = true;
                    characters.next();
                }
                '$' if chars.get(index + 1) == Some(&'\'') => {
                    let (literal, end) = super::ansi_c::word(&chars, index, preserve_backslash)?;
                    token.push_str(&literal);
                    token_started = true;
                    for _ in index..end {
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
                    // An escaped operator that ends the command is part of
                    // the word it ends, the way `find … -exec cat {} \;`
                    // ends its body.
                    if crate::command_tokens::backslash_escapes_operator(&chars, index) {
                        escaped = true;
                    } else {
                        token.push('\\');
                    }
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

//! Shell tokenisation used by the cloud text scrub
//! (`local_request_snapshots.py` `_shell_tokens`, `shlex.split`,
//! `shlex.quote`). Positions are `char` indices, like Python string indices.

#[derive(Clone, Debug)]
pub(crate) struct ShellToken {
    pub value: String,
    pub start: usize,
    pub end: usize,
    pub is_control: bool,
}

pub(crate) use crate::codex_output_py::{is_py_space as py_isspace, shlex_split};
pub(crate) use crate::command_launcher_floors::shlex_quote;

fn is_control_char(c: char) -> bool {
    matches!(c, '|' | ';' | '&' | '<' | '>')
}

/// `_shell_tokens`; `None` when the text is not tokenisable.
pub(crate) fn shell_tokens(value: &[char]) -> Option<Vec<ShellToken>> {
    let mut tokens = Vec::new();
    let length = value.len();
    let mut index = 0usize;
    while index < length {
        while index < length && py_isspace(value[index]) {
            index += 1;
        }
        if index >= length {
            break;
        }
        let start = index;
        if is_control_char(value[index]) {
            let pair_len = if index + 1 < length {
                let pair = [value[index], value[index + 1]];
                matches!(pair, ['&', '&'] | ['|', '|'] | ['>', '>'] | ['<', '<'])
            } else {
                false
            };
            index += if pair_len { 2 } else { 1 };
            tokens.push(ShellToken {
                value: value[start..index].iter().collect(),
                start,
                end: index,
                is_control: true,
            });
            continue;
        }
        let mut quote: Option<char> = None;
        while index < length {
            let character = value[index];
            if let Some(open) = quote {
                if open == '"' && character == '\\' {
                    index += 2;
                    continue;
                }
                if character == open {
                    quote = None;
                }
                index += 1;
                continue;
            }
            if character == '\'' || character == '"' {
                quote = Some(character);
                index += 1;
                continue;
            }
            if character == '\\' {
                index += 2;
                continue;
            }
            if py_isspace(character) || is_control_char(character) {
                break;
            }
            index += 1;
        }
        if quote.is_some() {
            return None;
        }
        let end = index.min(length);
        let raw: String = value[start..end].iter().collect();
        let parsed = shlex_split(&raw)?;
        if parsed.len() != 1 {
            return None;
        }
        tokens.push(ShellToken {
            value: parsed.into_iter().next().unwrap_or_default(),
            start,
            end: index,
            is_control: false,
        });
    }
    Some(tokens)
}

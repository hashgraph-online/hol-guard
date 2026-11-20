//! The `cd` operand screen and the contained compile check that reads it.
//!
//! Both answer the same question from different directions: whether the text
//! before `&&` is a plain `cd` into a directory the shell hands over as typed.

use super::*;

/// Whether a `cd` operand is a directory word the shell hands over as typed.
///
/// `(` and `)` are not on the list. They carry no expansion meaning inside a
/// shell word, and an unquoted one never reaches this function through the
/// segment parser: it opens a subshell, and the model comes back `uncertain`
/// with `compound_shell_not_yet_supported` long before a `cd` operand is read.
/// A parenthesis in an exact token is therefore part of the directory's own
/// name -- a route group such as `app/(group)` is an ordinary directory --
/// and refusing it only turned reads below it into reviews. `{` and `}` stay
/// refused because brace expansion rewrites an unquoted word the tokenizer
/// still hands over whole.
///
/// `contained_compile_check_segments` tokenizes its own text rather than
/// taking the parser's segments, so it screens for an unquoted parenthesis
/// itself.
pub(crate) fn is_plain_cd_target(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.chars().any(|value| {
            matches!(
                value,
                '$' | '`' | '<' | '>' | '|' | ';' | '&' | '{' | '}' | '\0'
            )
        })
}

/// Whether the text spells a parenthesis the shell would read as syntax.
///
/// A parenthesis inside quotes, or behind a backslash, is a character in a
/// word. Anywhere else it opens or closes a subshell.
fn unquoted_parenthesis(text: &str) -> bool {
    let mut quote = None;
    let mut escaped = false;
    for character in text.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match (quote, character) {
            (None, '\\') | (Some('"'), '\\') => escaped = true,
            (None, '\'' | '"') => quote = Some(character),
            (Some(open), _) if open == character => quote = None,
            (None, '(' | ')') => return true,
            _ => {}
        }
    }
    false
}

pub(crate) fn contained_compile_check_segments(command: &str) -> Option<Vec<RawSegment>> {
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
        || unquoted_parenthesis(&cd)
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

//! A subshell group `( ... )` that ends a command list runs its commands in a
//! child shell. Because nothing follows the group, a `cd` or assignment inside
//! it cannot change how a later command resolves, and the group inherits every
//! effect of the commands before it. Its commands are therefore the same as the
//! ungrouped list, so the ordinary proofs can decide them. Anything this
//! recognizer does not fully understand returns `None`, which keeps the
//! existing review behavior.

const MAX_COMMAND_BYTES: usize = 8192;

/// The command text with its trailing subshell group's parentheses replaced by
/// spaces, or `None` unless the command has exactly one unquoted `(` and one
/// unquoted `)` that open a group at the start of the command or after `&&`,
/// `||`, `;` or a newline and close it as the last non-blank character.
pub(super) fn unwrap(command: &str) -> Option<String> {
    let command = command.trim();
    if command.len() > MAX_COMMAND_BYTES
        || command.contains("<<")
        || command.contains("$'")
        || command.contains("$\"")
        || command
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        return None;
    }
    let chars: Vec<char> = command.chars().collect();
    let (open, close) = unquoted_parentheses(&chars)?;
    if close + 1 != chars.len() || !opens_list_element(&chars, open) {
        return None;
    }
    if chars[open + 1..close].iter().all(|c| c.is_whitespace()) {
        return None;
    }
    let mut ungrouped = chars;
    ungrouped[open] = ' ';
    ungrouped[close] = ' ';
    Some(ungrouped.into_iter().collect::<String>().trim().to_owned())
}

/// The positions of the only unquoted `(` and `)`, in that order.
fn unquoted_parentheses(chars: &[char]) -> Option<(usize, usize)> {
    let mut open = None;
    let mut close = None;
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    for (index, &c) in chars.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if single {
            single = c != '\'';
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' => double = !double,
            '\'' if !double => single = true,
            '(' | ')' if !double => {
                let slot = if c == '(' { &mut open } else { &mut close };
                if slot.replace(index).is_some() {
                    return None;
                }
            }
            _ => {}
        }
    }
    if single || double || escaped {
        return None;
    }
    let (open, close) = (open?, close?);
    (open < close).then_some((open, close))
}

/// Whether the `(` at `open` begins a new element of the command list.
fn opens_list_element(chars: &[char], open: usize) -> bool {
    let before: Vec<char> = chars[..open]
        .iter()
        .rev()
        .skip_while(|c| matches!(c, ' ' | '\t'))
        .take(3)
        .copied()
        .collect();
    let unescaped =
        |rest: &[char], op: char| !matches!(rest.first(), Some(&c) if c == op || c == '\\');
    match before.as_slice() {
        [] => true,
        ['\n', rest @ ..] => rest.first() != Some(&'\\'),
        [';', rest @ ..] => unescaped(rest, ';'),
        ['&', '&', rest @ ..] => unescaped(rest, '&'),
        ['|', '|', rest @ ..] => unescaped(rest, '|'),
        _ => false,
    }
}

#[cfg(test)]
#[path = "trailing_group_tests.rs"]
mod tests;

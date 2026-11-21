//! A subshell group `( ... )` that ends a command list runs its commands in a
//! child shell. Because nothing follows the group, a `cd` or assignment inside
//! it cannot change how a later command resolves, and the group inherits every
//! effect of the commands before it. Its commands are therefore the same as the
//! ungrouped list, so the ordinary proofs can decide them. Anything this
//! recognizer does not fully understand returns `None`, which keeps the
//! existing review behavior.
//!
//! A group that is an element of a pipeline is the other place the group's
//! own text may be blanked. Every element of a pipeline already runs in a
//! child shell, so `( cd web ) | wc -l` confines its `cd` exactly as
//! `cd web | wc -l` does, and the two spellings run the same work. That
//! holds only while the group's body is a single command: blanking
//! `( a; b ) | c` would leave `a; b | c`, which pipes `b` alone.

const MAX_COMMAND_BYTES: usize = 8192;

/// The command text with its trailing subshell group's parentheses replaced by
/// spaces, or `None` unless the command has exactly one unquoted `(` and one
/// unquoted `)` that open a group at the start of the command or after `&&`,
/// `||`, `;` or a newline and close it as the last non-blank character.
pub(crate) fn unwrap(command: &str) -> Option<String> {
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
    let piped_into = follows_a_pipe(&chars, open);
    if !opens_list_element(&chars, open) && !piped_into {
        return None;
    }
    let piped_on = pipes_onward(&chars, close);
    // Only a pipeline may follow the group. A redirection or a conditional
    // after it would keep the group's child shell while the blanked text
    // loses it, so `( cd web ) > log && npm ci` would run `npm ci` somewhere
    // the submitted command never reaches.
    if close + 1 != chars.len() && !piped_on {
        return None;
    }
    let inner = &chars[open + 1..close];
    if inner.iter().all(|c| c.is_whitespace()) {
        return None;
    }
    if (piped_into || piped_on) && super::brace_group::holds_a_list_operator(inner) {
        return None;
    }
    let mut ungrouped = chars;
    ungrouped[open] = ' ';
    ungrouped[close] = ' ';
    Some(ungrouped.into_iter().collect::<String>().trim().to_owned())
}

/// The positions of the only unquoted `(` and `)`, in that order.
/// The trailing group's command list when running that list in place of the
/// group runs exactly the same commands, or `None`. A decision may read
/// `false && (touch a; touch b)` as its flattened list, since that list runs
/// every command the group can; a sink that executes the text cannot, because
/// the flattened `touch b` no longer waits on `false`. A group behind `&&` or
/// `||` therefore keeps its parentheses here when it holds a list, as a brace
/// group does in `brace_group::unwrap`.
pub(crate) fn unwrap_for_execution(command: &str) -> Option<String> {
    let ungrouped = unwrap(command)?;
    let chars: Vec<char> = command.trim().chars().collect();
    let (open, close) = unquoted_parentheses(&chars)?;
    if super::brace_group::follows_a_conditional(&chars, open)
        && super::brace_group::holds_a_list_operator(&chars[open + 1..close])
    {
        return None;
    }
    Some(ungrouped)
}

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

/// Whether the group at `open` is the element of a pipeline that another
/// element feeds. A single unquoted `|` separates pipeline elements; `||` is
/// the conditional operator `opens_list_element` already reads.
pub(super) fn follows_a_pipe(chars: &[char], open: usize) -> bool {
    let before: Vec<char> = chars[..open]
        .iter()
        .rev()
        .skip_while(|c| matches!(c, ' ' | '\t' | '\n'))
        .take(2)
        .copied()
        .collect();
    matches!(before.as_slice(), ['|', rest @ ..] if !matches!(rest.first(), Some('|' | '\\')))
}

/// Whether the group closing at `close` feeds the next element of a pipeline,
/// which is the one thing that may follow it.
fn pipes_onward(chars: &[char], close: usize) -> bool {
    let mut after = chars[close + 1..]
        .iter()
        .skip_while(|c| matches!(c, ' ' | '\t'));
    after.next() == Some(&'|') && after.next() != Some(&'|')
}

/// Whether the group opened at `open` begins a new element of the command
/// list. Shared with the brace group recognizer, which opens the same way.
pub(super) fn opens_list_element(chars: &[char], open: usize) -> bool {
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

//! A brace group `{ ...; }` that ends a command list groups its commands
//! without a child shell, so the words inside it are exactly the words the
//! shell runs. Nothing follows the group, so a `cd` or assignment inside it
//! changes no later command of this request, and the group inherits every
//! effect of the commands before it. Its commands are therefore the same as
//! the ungrouped list, and the ordinary proofs can decide them instead of
//! sending an unmodeled string to the user: `{ npm run build; npm test; }`
//! reached review while `npm run build && npm test` ran in the workspace
//! sandbox.
//!
//! `{` is a reserved word only at the start of a command and only when a blank
//! follows it, and the list inside has to end with the `;` or newline that
//! separates it from `}`. Both are checked here, so brace expansion
//! (`echo {a,b}`) and parameter expansion (`${HOME}`) are never read as a
//! group. Anything this recognizer does not fully understand returns `None`,
//! which keeps the existing review behavior.

const MAX_COMMAND_BYTES: usize = 8192;

/// The command text with its trailing brace group's braces and list terminator
/// replaced by spaces, or `None` unless the command has exactly one unquoted
/// `{` and one unquoted `}` that open a group at the start of the command or
/// after `&&`, `||`, `;` or a newline, hold a terminated command list, and
/// close as the last non-blank character.
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
    let (open, close) = unquoted_braces(&chars)?;
    if close + 1 != chars.len() || !super::trailing_group::opens_list_element(&chars, open) {
        return None;
    }
    // The reserved word is `{` followed by a blank; `{a,b}` is one word.
    if !matches!(chars.get(open + 1), Some(c) if c.is_whitespace()) {
        return None;
    }
    let inner = &chars[open + 1..close];
    let last = inner.iter().rposition(|c| !c.is_whitespace())?;
    // `}` is a reserved word only after a `;` or a newline, so a list that
    // runs straight into the brace is not one this recognizer understands.
    let terminator = if inner[last] == ';' {
        Some(open + 1 + last)
    } else if inner[last + 1..].contains(&'\n') {
        None
    } else {
        return None;
    };
    // `cd web && { npm ci; npm test; }` runs `npm test` only when `cd web`
    // succeeded, and the braces are the whole of that: blanking them leaves a
    // text that runs it either way, and that text is what the decision and the
    // sandbox shape are bound to. A list behind `&&` or `||` therefore keeps
    // its group. A group that opens the command, or holds a single command
    // behind one of those operators, means the same either way.
    let first = inner.iter().position(|c| !c.is_whitespace())?;
    if follows_a_conditional(&chars, open) && holds_a_list_operator(&inner[first..last]) {
        return None;
    }
    let mut ungrouped = chars;
    ungrouped[open] = ' ';
    ungrouped[close] = ' ';
    if let Some(index) = terminator {
        ungrouped[index] = ' ';
    }
    let ungrouped: String = ungrouped.into_iter().collect();
    let ungrouped = ungrouped.trim();
    (!ungrouped.is_empty()).then(|| ungrouped.to_owned())
}

/// The positions of the only unquoted `{` and `}`, in that order.
///
/// A `#` where a word could start comments out the rest of its line, so the
/// braces it covers are not braces at all: `{ echo hi # ; }` is an unterminated
/// group the shell refuses, and reading the commented `}` as the group's end
/// would hand `echo hi #` a decision for a command that never runs.
fn unquoted_braces(chars: &[char]) -> Option<(usize, usize)> {
    let mut open = None;
    let mut close = None;
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    let mut comment = false;
    let mut in_word = false;
    for (index, &c) in chars.iter().enumerate() {
        if comment {
            comment = c != '\n';
            continue;
        }
        if escaped {
            escaped = false;
            in_word = true;
            continue;
        }
        if single {
            single = c != '\'';
            in_word = true;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' => double = !double,
            '\'' if !double => single = true,
            '#' if !double && !in_word => {
                comment = true;
                continue;
            }
            '{' | '}' if !double => {
                let slot = if c == '{' { &mut open } else { &mut close };
                if slot.replace(index).is_some() {
                    return None;
                }
            }
            _ => {}
        }
        in_word = double || !starts_a_word_position(c);
    }
    if single || double || escaped {
        return None;
    }
    let (open, close) = (open?, close?);
    (open < close).then_some((open, close))
}

/// Whether a word could start after this character: `#` opens a comment only
/// there, and `echo a#b` keeps its `#` as part of the word.
fn starts_a_word_position(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | ';' | '&' | '|' | '(' | ')')
}

/// Whether the group may stand behind a `&&` or a `||`, the operators that
/// make what follows conditional. The opening brace has already been placed at
/// the start of a list element, so an operator character there is one of those
/// two.
///
/// A newline is skipped with the other blanks: the shell reads `make ||` and
/// the group on the next line as one conditional list, and stopping at the
/// newline would have called that list unconditional and flattened it. A
/// newline that is the separator itself lands this scan on the end of the
/// command before it, which is not an operator.
///
/// A `#` anywhere before the brace hides whatever it comments out, including
/// the operator this scan is looking for, so the group keeps its review rather
/// than being flattened on a reading this scan cannot make.
fn follows_a_conditional(chars: &[char], open: usize) -> bool {
    if chars[..open].contains(&'#') {
        return true;
    }
    matches!(
        chars[..open]
            .iter()
            .rev()
            .copied()
            .find(|c| !matches!(c, ' ' | '\t' | '\n')),
        Some('&' | '|')
    )
}

/// Whether the body is itself a list rather than one command: a `;`, a newline
/// or an unquoted `&` or `|` the shell would act on.
fn holds_a_list_operator(inner: &[char]) -> bool {
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    let mut comment = false;
    let mut in_word = false;
    for &c in inner {
        if comment {
            // The line the comment ends is itself a separator.
            if c == '\n' {
                return true;
            }
            continue;
        }
        if escaped {
            escaped = false;
            in_word = true;
            continue;
        }
        if single {
            single = c != '\'';
            in_word = true;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' => double = !double,
            '\'' if !double => single = true,
            '#' if !double && !in_word => {
                comment = true;
                continue;
            }
            ';' | '\n' | '&' | '|' if !double => return true,
            _ => {}
        }
        in_word = double || !starts_a_word_position(c);
    }
    false
}

#[cfg(test)]
#[path = "brace_group_tests.rs"]
mod tests;

//! The redirect shapes and the single command group that segment splitting
//! reads out of a command's own text.

use super::*;

pub(crate) fn is_stderr_to_stdout_redirect(
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

pub(crate) fn is_stderr_to_null_redirect(
    chars: &[char],
    start: usize,
    preserve_backslash: bool,
) -> bool {
    // Only a fixed stderr sink known to be inert is dropped; arbitrary paths
    // and descriptors must still pass through the unsupported-redirection
    // guard.
    stderr_null_sink_is_inert()
        && chars.get(start..start.saturating_add(11))
            == Some(&['2', '>', '/', 'd', 'e', 'v', '/', 'n', 'u', 'l', 'l'])
        && starts_at_shell_token_boundary(chars, start, preserve_backslash)
        && chars.get(start + 11).is_none_or(|value| {
            is_shell_token_whitespace(*value) || matches!(*value, '|' | '&' | ';')
        })
}

/// `/dev/null` is the null device on Unix. On Windows, Git Bash (the shell
/// harnesses run POSIX commands in) maps it to the null device too, while
/// PowerShell and cmd open `\dev\null` on the shell's current drive. That
/// open fails without writing anything while the drive has no `\dev`. The
/// shell may have changed drive since Guard started, or earlier in the same
/// command, so the sink is inert only while no drive letter has a `\dev`.
pub(crate) fn stderr_null_sink_is_inert() -> bool {
    cfg!(unix)
        || (cfg!(windows)
            && (b'A'..=b'Z').all(|drive| {
                std::fs::symlink_metadata(format!("{}:\\dev", drive as char)).is_err_and(|error| {
                    // Not found, no such drive, or no media in the drive.
                    error.kind() == std::io::ErrorKind::NotFound
                        || matches!(error.raw_os_error(), Some(15 | 21))
                })
            }))
}

/// The span inside a command that is nothing but one group: a `( list )`
/// subshell or a `{ list; }` brace group, with no second bracket of its own
/// kind anywhere in the text.
///
/// Requiring the group to be the whole command, and to be the only one, is
/// what makes stripping it sound. A bracket left over would mean a nesting,
/// an expansion such as `$(` or `${`, or a glob this pass has not read, and a
/// redirect, a pipe or a background `&` after the closing bracket would leave
/// text outside the group that the list inside it does not account for.
///
/// A subshell runs its list in a child, so the directory, environment and
/// options it sets do not outlive it; reading the list as though they did can
/// only widen what the command is taken to own, never narrow it.
pub(super) fn sole_command_group(chars: &[char]) -> Option<std::ops::Range<usize>> {
    let open = chars.iter().position(|value| !value.is_whitespace())?;
    let close = chars.iter().rposition(|value| !value.is_whitespace())?;
    let (opener, closer) = match (chars[open], chars[close]) {
        ('(', ')') => ('(', ')'),
        ('{', '}') => ('{', '}'),
        _ => return None,
    };
    if close <= open + 1 {
        return None;
    }
    let brackets = chars
        .iter()
        .filter(|value| **value == opener || **value == closer)
        .count();
    if brackets != 2 {
        return None;
    }
    // `{` is a word unless whitespace separates it from the list, so `{ls; }`
    // runs a program named `{ls`. The list itself has to be terminated, which
    // is what keeps `}` a bracket rather than the list's last word.
    if opener == '{'
        && !(is_shell_token_whitespace(chars[open + 1]) && list_is_closed(chars, open, close))
    {
        return None;
    }
    Some(open + 1..close)
}

/// Whether the list of a brace group running from `open` to `close` ends with
/// a terminator of its own. A `;` or a `&` ends a list, and so does the
/// newline that ends a line, which is why `{ cat one.txt` and `}` on two
/// lines is the same group as `{ cat one.txt; }`. Only spaces and tabs may
/// follow that terminator, because a newline the list does not reach would be
/// the separator of a list this check never saw.
fn list_is_closed(chars: &[char], open: usize, close: usize) -> bool {
    chars[open + 1..close]
        .iter()
        .rposition(|value| !matches!(*value, ' ' | '\t' | '\r'))
        .is_some_and(|last| matches!(chars[open + 1 + last], ';' | '&' | '\n'))
}

/// The command with the parentheses of every top-level subshell group replaced
/// by spaces, or `None` unless every unquoted parenthesis in the text belongs
/// to such a group.
///
/// A subshell group that starts a list element and ends one runs its list in a
/// child shell. Reading the list in place of the group therefore keeps every
/// command the group can run, and the directory, environment and options the
/// child sets are the only thing the reading adds to the commands after it.
/// That can only widen what the command is taken to own, never narrow it,
/// which is the same argument [`sole_command_group`] rests on. The effective
/// directory each command runs in is read from the command's own text by the
/// shell execution context, which tracks the group brackets itself, so
/// blanking them here does not move a command into a directory it never ran
/// in.
///
/// Everything this pass does not fully read returns `None`, which leaves the
/// splitter's own error to describe the text: a nested group, a parenthesis in
/// an assignment or a `case` pattern, an expansion, or a group with a redirect
/// or a background `&` after it.
pub(super) fn blank_top_level_groups(chars: &[char]) -> Option<Vec<char>> {
    let mut blanked = chars.to_vec();
    let mut index = 0usize;
    let mut last_significant: Option<usize> = None;
    let mut found = false;
    while index < chars.len() {
        match chars[index] {
            '\\' => {
                index += 2;
                continue;
            }
            '\'' | '"' => {
                index = quoted_word_end(chars, index)? + 1;
                last_significant = Some(index - 1);
                continue;
            }
            // An expansion, a redirect or a substitution owns the bracket
            // beside it, so this pass reads none of them.
            '`' | '<' | '>' | '$' => return None,
            '(' => {
                if !opens_a_list_element(chars, last_significant) {
                    return None;
                }
                let close = group_close(chars, index)?;
                if !ends_a_list_element(chars, close) {
                    return None;
                }
                blanked[index] = ' ';
                blanked[close] = ' ';
                found = true;
                // `group_close` read the list inside the group already, so
                // the scan carries on after the bracket it closed. The
                // bracket is what the scan last saw, and `ends_a_list_element`
                // has already required the next element's operator to follow
                // it, so that operator is what a later group reads.
                last_significant = Some(close);
                index = close + 1;
                continue;
            }
            ')' => return None,
            '{' => {
                let Some(close) = brace_group_close(chars, index, last_significant) else {
                    if !chars[index].is_whitespace() {
                        last_significant = Some(index);
                    }
                    index += 1;
                    continue;
                };
                let terminator = brace_list_terminator(chars, index, close)?;
                if !ends_a_list_element(chars, close) {
                    return None;
                }
                blanked[index] = ' ';
                blanked[terminator] = ' ';
                blanked[close] = ' ';
                found = true;
                last_significant = Some(close);
                index = close + 1;
                continue;
            }
            value => {
                if !value.is_whitespace() || value == '\n' {
                    last_significant = Some(index);
                }
            }
        }
        index += 1;
    }
    found.then_some(blanked)
}

/// Whether a group opening after the last significant character starts a list
/// element. A list element starts the command or follows the operator that
/// ended the one before it. A single `|` is not one of those, and neither is
/// `|&`: the group is then an element of a pipeline, and the list inside it
/// would feed the next stage on its own once the brackets were gone.
fn opens_a_list_element(chars: &[char], last_significant: Option<usize>) -> bool {
    let Some(last) = last_significant else {
        return true;
    };
    match chars[last] {
        ';' | '\n' => true,
        // `|&` is a pipe that merges stderr, not a background `&` or `&&`.
        '&' => last
            .checked_sub(1)
            .is_none_or(|before| chars[before] != '|'),
        '|' => last
            .checked_sub(1)
            .is_some_and(|before| chars[before] == '|'),
        _ => false,
    }
}

/// Whether the group closing at `close` ends a list element: nothing follows
/// it, or the operator that starts the next element does. A single `|` or `&`
/// after the group keeps the child shell the blanked text loses, so the list
/// inside would pipe or background only its own last command.
fn ends_a_list_element(chars: &[char], close: usize) -> bool {
    let rest = &chars[close + 1..];
    let Some(offset) = rest.iter().position(|value| !matches!(*value, ' ' | '\t')) else {
        return true;
    };
    match rest[offset] {
        ';' | '\n' => true,
        '&' | '|' => rest.get(offset + 1) == Some(&rest[offset]),
        _ => false,
    }
}

/// The index of the `)` that closes the group opened at `open`, or `None` when
/// the group holds a bracket of its own or never closes.
fn group_close(chars: &[char], open: usize) -> Option<usize> {
    let mut index = open + 1;
    while index < chars.len() {
        match chars[index] {
            '\\' => index += 1,
            '\'' | '"' => index = quoted_word_end(chars, index)?,
            '`' | '<' | '>' | '$' | '(' => return None,
            ')' => return Some(index),
            _ => {}
        }
        index += 1;
    }
    None
}

/// The index of the `}` closing the brace group opened at `open`, or `None`
/// unless the text there is a brace group this pass reads. `{` is a word
/// unless whitespace separates it from the list, so `{ls; }` runs a program
/// named `{ls` and `a{1,2}.txt` is one word: neither opens a group. A group
/// holding a bracket of its own, an expansion, a redirect or a substitution is
/// left to the splitter's own error, and so is one that never closes.
fn brace_group_close(
    chars: &[char],
    open: usize,
    last_significant: Option<usize>,
) -> Option<usize> {
    if !opens_a_list_element(chars, last_significant) {
        return None;
    }
    if !is_shell_token_whitespace(*chars.get(open + 1)?) {
        return None;
    }
    let mut index = open + 2;
    while index < chars.len() {
        match chars[index] {
            '\\' => index += 1,
            '\'' | '"' => index = quoted_word_end(chars, index)?,
            '`' | '<' | '>' | '$' | '(' | ')' | '{' => return None,
            '}' => return Some(index),
            _ => {}
        }
        index += 1;
    }
    None
}

/// The index of the `;` that ends the list of the brace group running from
/// `open` to `close`. A brace group runs its list in the current shell, so the
/// list it holds is what the text after the group already builds on, and
/// blanking the brackets leaves every command pointing at the text it came
/// from. The terminator goes with them, because `{ ls; } && pwd` blanked
/// without it would leave a `;` where the `&&` belongs.
///
/// Only `;` is read. A list a newline ends would leave that newline between
/// the list and the operator after the group, and a list `&` ends backgrounds
/// its last command rather than the group, which is the child the blanked
/// text no longer has.
fn brace_list_terminator(chars: &[char], open: usize, close: usize) -> Option<usize> {
    let last = chars[open + 1..close]
        .iter()
        .rposition(|value| !matches!(*value, ' ' | '\t' | '\r'))?;
    let terminator = open + 1 + last;
    (chars[terminator] == ';').then_some(terminator)
}

/// The index of the quote that closes the word opened at `open`.
fn quoted_word_end(chars: &[char], open: usize) -> Option<usize> {
    let quote = chars[open];
    let mut index = open + 1;
    while index < chars.len() {
        if quote == '"' && chars[index] == '\\' {
            index += 2;
            continue;
        }
        if chars[index] == quote {
            return Some(index);
        }
        index += 1;
    }
    None
}

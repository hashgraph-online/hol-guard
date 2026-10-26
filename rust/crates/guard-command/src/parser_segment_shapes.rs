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

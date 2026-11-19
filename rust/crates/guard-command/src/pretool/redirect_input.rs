//! Plain `< path` input redirects.
//!
//! `cmd < file` reads `file` and hands its bytes to `cmd` on standard input,
//! which is what `cat file | cmd` does. The projection models it that way,
//! in the place of the command that carries the redirect, so the read keeps
//! the proof `cat` gets and `cmd` stays an operand-free filter.

use super::trailing_word;

/// Where the command a later input redirect belongs to starts in the
/// projected text.
///
/// While every separator so far is `;`, `&&`, `||` or a newline, each
/// command runs on its own after the one before it, so the redirect belongs
/// to the command since the last separator. A pipe, a background `&`, a
/// group or a substitution makes that placement unclear, and the redirect
/// keeps the fail-closed path.
pub(super) struct InputSite {
    list_only: bool,
    segment_start: usize,
}

impl InputSite {
    pub(super) fn new() -> Self {
        Self {
            list_only: true,
            segment_start: 0,
        }
    }

    /// Note the separator at `index`, before it is pushed onto `out`.
    pub(super) fn separator(&mut self, chars: &[char], index: usize, out: &str) {
        if list_separator(chars, index) {
            self.segment_start = out.len() + chars[index].len_utf8();
        } else {
            self.list_only = false;
        }
    }

    /// Note text whose placement this does not follow, such as a
    /// substitution inside quotes.
    pub(super) fn opaque(&mut self) {
        self.list_only = false;
    }

    /// The offset a redirect seen now belongs at, or `None` when it cannot
    /// be placed. Literal standard input already fed to an earlier command
    /// leaves which command reads what unclear, so it is refused too.
    fn start(&self, separated: bool, saw_stdin_data: bool) -> Option<usize> {
        if !separated {
            Some(0)
        } else {
            (self.list_only && !saw_stdin_data).then_some(self.segment_start)
        }
    }
}

/// `;`, a newline, or either half of `&&` or `||`.
fn list_separator(chars: &[char], index: usize) -> bool {
    let current = chars[index];
    let previous = index.checked_sub(1).and_then(|at| chars.get(at));
    let next = chars.get(index + 1);
    match current {
        // `;;` and `;&` end a `case` arm.
        ';' => previous != Some(&';') && !matches!(next, Some(';' | '&')),
        '\n' => true,
        // An escaped twin is a literal character, so `\||` is a word and a
        // pipe, not `||`.
        '&' | '|' => {
            (previous == Some(&current) && !escaped(chars, index - 1)) || next == Some(&current)
        }
        _ => false,
    }
}

/// Whether an odd run of backslashes right before `index` escapes it.
fn escaped(chars: &[char], index: usize) -> bool {
    chars[..index]
        .iter()
        .rev()
        .take_while(|character| **character == '\\')
        .count()
        % 2
        == 1
}

/// Remove a plain `< path` input redirect, recording the file it reads and
/// where the command it feeds starts.
///
/// `<<`, `<<<`, `<&` and `<>` are other forms and keep the fail-closed path,
/// as does a second redirect, a target the shell would expand, or a
/// redirect [`InputSite`] cannot place.
pub(super) fn remove(
    chars: &[char],
    start: usize,
    out: &str,
    site: (&InputSite, bool, bool),
    input_source: &mut Option<(String, usize)>,
) -> Option<usize> {
    let (site, separated, saw_stdin_data) = site;
    let at = site.start(separated, saw_stdin_data)?;
    if input_source.is_some()
        || matches!(chars.get(start + 1), Some('&' | '>'))
        || !trailing_word(out).is_empty()
    {
        return None;
    }
    let mut index = start + 1;
    while matches!(chars.get(index), Some(' ' | '\t')) {
        index += 1;
    }
    let target_start = index;
    while chars
        .get(index)
        .is_some_and(|value| !value.is_whitespace() && !matches!(value, ';' | '|' | '&' | ')'))
    {
        index += 1;
    }
    let target: String = chars[target_start..index].iter().collect();
    if target.is_empty()
        || target.len() > 4096
        || target.starts_with('-')
        || !target
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || "._-/+@%,=:~".contains(value))
    {
        return None;
    }
    // The guard above leaves `out` empty or ended by its own separator, so
    // the removed redirect needs none of its own.
    *input_source = Some((target, at));
    Some(index)
}

/// `command` with the reader of `source` spliced in front of the command
/// that starts at `at` in `out`.
///
/// The first command keeps its trimmed text, where an empty command already
/// stands for the no-op. A later command has to be there, or the splice would
/// leave a dangling pipe.
pub(super) fn splice(out: &str, command: String, source: &str, at: usize) -> Option<String> {
    if at == 0 {
        return Some(format!("cat {source} | {command}"));
    }
    let before = out.get(..at)?;
    let rest = out.get(at..)?.trim_start();
    if rest.is_empty() || rest.starts_with([';', '&', '|']) {
        return None;
    }
    Some(format!("{before} cat {source} | {rest}").trim().to_owned())
}

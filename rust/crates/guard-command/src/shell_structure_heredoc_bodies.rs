//! Heredoc bodies are text, not shell syntax. A quote or parenthesis in one
//! cannot open or close anything around it. An apostrophe in a commit message
//! written as `git commit -m "$(cat <<'MSG' ... it's ... MSG\n)"` used to open
//! a quote that never closed, so the substitution ran to the end of the
//! command and every line of the message was read as a command.

use super::{
    extract_heredocs, find_heredoc_closing_line, heredoc_declaration, HeredocDecl, ShellHeredoc,
};

/// `_extract_parenthesized` (:243-266), reading the bodies of heredocs
/// declared inside the `$(` as text, at any depth of grouping such as
/// `$( (cat <<'EOF' ...) )`. Inside arithmetic, `$((` or `((`, a `<<` is a
/// shift and declares nothing. A word-start `#` opens a comment that runs to
/// the end of its line: a quote, parenthesis or `<<` there is text.
pub(super) fn extract_parenthesized(chars: &[char], start: usize) -> (String, usize) {
    let n = chars.len();
    let mut depth = 1;
    // The depth at which arithmetic opened, while the scan is inside it.
    let mut arithmetic = (chars.get(start) == Some(&'(')).then_some(1);
    let mut index = start;
    let mut quote: Option<char> = None;
    let mut bodies = PendingBodies::default();
    let mut comment = false;
    // The index after the last escaped character. A `#` there continues the
    // word the escape belongs to, so it opens no comment.
    let mut escape_end = None;
    while index < n {
        let ch = chars[index];
        if comment && ch != '\n' {
            index += 1;
            continue;
        }
        if ch == '\\' {
            index += 2;
            escape_end = Some(index);
            continue;
        }
        if quote.is_none() && ch == '\n' {
            comment = false;
            if let Some(next) = bodies.skip(chars, index) {
                index = next;
                continue;
            }
        }
        if quote.is_none()
            && ch == '#'
            && escape_end != Some(index)
            && word_start(chars, start, index)
        {
            comment = true;
            index += 1;
            continue;
        }
        if quote.is_none() && arithmetic.is_none() && ch == '<' {
            if let Some(end) = bodies.declare(chars, index) {
                index = end;
                continue;
            }
        }
        if ch == '\'' || ch == '"' {
            if quote.is_none() {
                quote = Some(ch);
            } else if quote == Some(ch) {
                quote = None;
            }
            index += 1;
            continue;
        }
        if quote.is_none() && ch == '(' {
            let opens_arithmetic = chars.get(index + 1) == Some(&'(')
                && (index > start && chars[index - 1] == '$'
                    || word_start(chars, start, index)
                    || after_keyword(chars, start, index));
            if arithmetic.is_none() && opens_arithmetic {
                arithmetic = Some(depth + 1);
            }
            depth += 1;
        } else if quote.is_none() && ch == ')' {
            depth -= 1;
            if arithmetic.is_some_and(|opened| depth < opened) {
                arithmetic = None;
            }
            if depth == 0 {
                return (chars[start..index].iter().collect(), index);
            }
        }
        index += 1;
    }
    (chars[start..].iter().collect(), n)
}

/// Whether `index` starts a word, so a `#` there opens a comment.
/// Whether `index` directly follows a keyword that bash lets open `((`
/// with no space, as in `for((i=0;i<n;i++))` or `while((x<<2))`.
fn after_keyword(chars: &[char], start: usize, index: usize) -> bool {
    ["for", "while", "until", "if", "elif"]
        .iter()
        .any(|keyword| {
            let length = keyword.len();
            index >= start + length
                && chars[index - length..index]
                    .iter()
                    .copied()
                    .eq(keyword.chars())
                && word_start(chars, start, index - length)
        })
}

fn word_start(chars: &[char], start: usize, index: usize) -> bool {
    index == start
        || chars[index - 1].is_whitespace()
        || matches!(chars[index - 1], ';' | '&' | '|' | '(' | ')')
}

/// Whether every heredoc found in `command` has its closing line. Bash also
/// ends a heredoc inside `$(...)` at a line such as `EOF)`, which the body
/// scan does not model, so an unclosed body must not hide what follows it.
fn heredocs_closed(command: &str, heredocs: &[ShellHeredoc]) -> bool {
    let n = command.chars().count();
    heredocs.iter().all(|heredoc| heredoc.body_end < n)
}

/// `command` with its heredoc bodies blanked, or unchanged when one of them
/// never closes: blanking that body would blank every command after it.
pub fn mask_closed_heredoc_bodies(command: &str, heredocs: &[ShellHeredoc]) -> String {
    if heredocs_closed(command, heredocs) {
        super::mask_heredoc_bodies(command, heredocs)
    } else {
        command.to_owned()
    }
}

/// Heredocs declared on the current line of a `$(` body, whose bodies start
/// after the line ends.
#[derive(Default)]
pub(super) struct PendingBodies(Vec<HeredocDecl>);

impl PendingBodies {
    /// Records a `<<` declaration that starts at `index` and returns where the
    /// declaration ends, or `None` when no delimiter parses there.
    pub(super) fn declare(&mut self, chars: &[char], index: usize) -> Option<usize> {
        if chars.get(index + 1) != Some(&'<') || chars.get(index.wrapping_sub(1)) == Some(&'<') {
            return None;
        }
        let operator_end = index + 2;
        let declaration = if chars.get(operator_end) == Some(&'-') {
            heredoc_declaration(chars, index, operator_end + 1, true)
                .or_else(|| heredoc_declaration(chars, index, operator_end, false))
        } else {
            heredoc_declaration(chars, index, operator_end, false)
        }?;
        let end = declaration.end;
        self.0.push(declaration);
        Some(end)
    }

    /// At an unquoted newline, returns the index after the bodies declared on
    /// the line it ends, or `None` when that line declared none. When a body
    /// has no closing line, nothing is skipped and the scan reads on as
    /// before: bash may end that body at a line such as `EOF)`.
    pub(super) fn skip(&mut self, chars: &[char], newline: usize) -> Option<usize> {
        if self.0.is_empty() {
            return None;
        }
        let mut cursor = newline + 1;
        for declaration in std::mem::take(&mut self.0) {
            let (closing, end) = find_heredoc_closing_line(
                chars,
                cursor,
                &declaration.delimiter,
                declaration.strip_tabs,
            );
            if closing == chars.len() {
                return None;
            }
            cursor = end;
        }
        Some(cursor)
    }
}

/// Closed heredoc bodies as `(start, end)`. A body is text, not shell
/// syntax, so the substitution scan must not let `it's` there open a quote
/// that hides what follows. The scan still looks for `$(...)` and backticks in
/// every body: an unquoted delimiter runs them in this shell, and a quoted
/// body fed to `sh`, `ssh` or `kubectl exec` runs them in the next one. A body
/// with no closing line is left out: bash may end it at a line such as
/// `EOF)`, which the body scan does not model.
pub(super) fn text_bodies(command: &str) -> Vec<(usize, usize)> {
    if !command.contains("<<") {
        return Vec::new();
    }
    let n = command.chars().count();
    extract_heredocs(command)
        .into_iter()
        .filter(|heredoc| heredoc.body_end < n)
        .map(|heredoc| (heredoc.body_start, heredoc.body_end))
        .collect()
}

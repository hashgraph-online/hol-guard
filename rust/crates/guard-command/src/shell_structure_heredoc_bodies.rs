//! Heredoc bodies are text, not shell syntax. A quote or parenthesis in one
//! cannot open or close anything around it. An apostrophe in a commit message
//! written as `git commit -m "$(cat <<'MSG' ... it's ... MSG\n)"` used to open
//! a quote that never closed, so the substitution ran to the end of the
//! command and every line of the message was read as a command.

use super::{extract_heredocs, find_heredoc_closing_line, heredoc_declaration, HeredocDecl};

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
    /// the line it ends, or `None` when that line declared none. A body with
    /// no closing line runs to the end of the text.
    pub(super) fn skip(&mut self, chars: &[char], newline: usize) -> Option<usize> {
        if self.0.is_empty() {
            return None;
        }
        let mut cursor = newline + 1;
        for declaration in self.0.drain(..) {
            let (_, end) = find_heredoc_closing_line(
                chars,
                cursor,
                &declaration.delimiter,
                declaration.strip_tabs,
            );
            cursor = end;
        }
        Some(cursor)
    }
}

/// Bodies of heredocs with an unquoted delimiter. The shell still expands
/// `$(...)` and backticks in them, but quotes there are literal characters,
/// so the substitution scan must not let `it's` hide what follows.
pub(super) fn expanding_bodies(command: &str) -> Vec<(usize, usize)> {
    if !command.contains("<<") {
        return Vec::new();
    }
    extract_heredocs(command)
        .into_iter()
        .filter(|heredoc| !heredoc.quoted)
        .map(|heredoc| (heredoc.body_start, heredoc.body_end))
        .collect()
}

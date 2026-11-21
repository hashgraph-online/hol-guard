//! A quoted heredoc fed to a bare `cat` is file content, never a command or a
//! path the shell reads. Words in that content, such as `process.env` in a
//! generated source file, are not a sensitive access. The declaring line stays
//! in the text, so a sensitive redirect target is still seen.

use crate::shell_structure::{extract_heredocs, mask_heredoc_bodies, ShellHeredoc};

/// `text` with the body of each data heredoc blanked, or `text` unchanged when
/// it has none.
pub(super) fn without_data_bodies(text: &str) -> String {
    if !text.contains("<<") {
        return text.to_owned();
    }
    let heredocs = extract_heredocs(text);
    if heredocs.is_empty() {
        return text.to_owned();
    }
    let chars: Vec<char> = text.chars().collect();
    // Quotes inside any heredoc body are body text, not shell syntax.
    let outline: Vec<char> = mask_heredoc_bodies(text, &heredocs).chars().collect();
    let data: Vec<ShellHeredoc> = heredocs
        .into_iter()
        .filter(|heredoc| heredoc.quoted && declared_by_bare_cat(&chars, &outline, heredoc))
        .collect();
    mask_heredoc_bodies(text, &data)
}

/// The heredoc's declaring line is `cat`, an optional literal output redirect
/// and the heredoc operator, and nothing else.
fn declared_by_bare_cat(chars: &[char], outline: &[char], heredoc: &ShellHeredoc) -> bool {
    let Some(newline) = heredoc.body_start.checked_sub(1) else {
        return false;
    };
    if chars.get(newline) != Some(&'\n') {
        return false;
    }
    let line_start = chars[..newline]
        .iter()
        .rposition(|character| *character == '\n')
        .map_or(0, |position| position + 1);
    // The shell may continue this line from the one before it, or an earlier
    // quote, substitution or group may still be open, so only a clean line
    // start is trusted.
    if !clean_line_start(&outline[..line_start]) {
        return false;
    }
    let command: String = chars[line_start..newline].iter().collect();
    // The declaring line holds this one command: a chain separator leaves
    // open which command owns the heredoc.
    if command.contains(['&', ';', '|']) {
        return false;
    }
    let mut heredocs = 0;
    let mut cats = 0;
    let mut expecting_target = false;
    for token in command.split_whitespace() {
        if expecting_target {
            if !literal_word(token) {
                return false;
            }
            expecting_target = false;
        } else if token == "cat" {
            cats += 1;
        } else if matches!(token, ">" | ">>") {
            expecting_target = true;
        } else if let Some(target) = token
            .strip_prefix(">>")
            .or_else(|| token.strip_prefix('>'))
            .filter(|target| !target.is_empty())
        {
            if !literal_word(target) {
                return false;
            }
        } else if let Some(delimiter) = token
            .strip_prefix("<<-")
            .or_else(|| token.strip_prefix("<<"))
            .filter(|delimiter| !delimiter.is_empty())
        {
            if !delimiter.starts_with(['\'', '"']) {
                return false;
            }
            heredocs += 1;
        } else {
            return false;
        }
    }
    cats == 1 && heredocs == 1 && !expecting_target
}

/// `before` ends outside every quote, escape, backquote and parenthesis.
fn clean_line_start(before: &[char]) -> bool {
    let (mut single, mut double) = (false, false);
    let (mut depth, mut backquotes) = (0i32, 0usize);
    let mut index = 0;
    while index < before.len() {
        match before[index] {
            '\\' if !single => index += 1,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '`' if !single => backquotes += 1,
            '(' if !single => depth += 1,
            ')' if !single => depth -= 1,
            _ => {}
        }
        index += 1;
    }
    // A backslash before the line break continues the command.
    let continued = before.len() >= 2 && before[before.len() - 2] == '\\';
    !(single || double || continued) && depth == 0 && backquotes % 2 == 0
}

fn literal_word(word: &str) -> bool {
    !word.is_empty()
        && !word.starts_with(['&', '-', '<', '>'])
        && !word.contains([
            '$', '`', '(', ')', '|', '&', ';', '<', '>', '\'', '"', '\\', '*', '?',
        ])
}

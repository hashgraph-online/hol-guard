//! Source-faithful shell heredoc and command-substitution structures
//! (`runtime/shell_structure.py`).

/// `ShellHeredoc` (:10-23).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellHeredoc {
    pub delimiter: String,
    pub body: String,
    pub operator_start: usize,
    pub declaration_end: usize,
    pub body_start: usize,
    pub body_end: usize,
    pub end: usize,
    pub quoted: bool,
    pub strip_tabs: bool,
}

/// `ShellCommandSubstitution` (:25-34).
#[derive(Clone, Debug, serde::Serialize)]
#[allow(dead_code)]
pub struct ShellCommandSubstitution {
    pub kind: &'static str, // "dollar" | "backtick"
    pub body: String,
    pub start: usize,
    pub body_start: usize,
    pub body_end: usize,
    pub end: usize,
}

/// `extract_heredocs` (:43-88). Bounded POSIX heredocs without interpreting
/// contents; offsets index Unicode scalar values.
pub fn extract_heredocs(command: &str) -> Vec<ShellHeredoc> {
    if command.is_empty() {
        return Vec::new();
    }
    let chars: Vec<char> = command.chars().collect();
    let n = chars.len();
    let mut results = Vec::new();
    let mut scan_cursor = 0usize;
    // A quote opened on one line stays open on the next, so the scan state
    // spans declaration lines. Heredoc bodies are not shell syntax, and the
    // cursor jumps past them, so they never advance it.
    let mut state = ShellScanState::new();
    // A line ending in an unquoted backslash continues the current word onto
    // the next line, so the word boundary spans lines as well.
    let mut word_start = true;
    while scan_cursor < n {
        let mut line_end = find_newline(&chars, scan_cursor).unwrap_or(n);
        let pending =
            heredoc_declarations(&chars[scan_cursor..line_end], &mut state, &mut word_start);
        if pending.is_empty() {
            if line_end == n {
                break;
            }
            scan_cursor = line_end + 1;
            continue;
        }
        if line_end == n {
            break;
        }
        let mut body_cursor = line_end + 1;
        for m in pending {
            let delimiter = &m.delimiter;
            let strip_tabs = m.strip_tabs;
            let body_start = body_cursor;
            let (closing_start, closing_end) =
                find_heredoc_closing_line(&chars, body_start, delimiter, strip_tabs);
            results.push(ShellHeredoc {
                delimiter: m.delimiter,
                body: chars[body_start..closing_start].iter().collect(),
                operator_start: scan_cursor + m.start,
                declaration_end: scan_cursor + m.end,
                body_start,
                body_end: closing_start,
                end: closing_end,
                quoted: m.quoted,
                strip_tabs,
            });
            body_cursor = closing_end;
        }
        scan_cursor = body_cursor;
        // The line after a closing delimiter starts a fresh command.
        word_start = true;
        line_end = n;
        let _ = line_end;
    }
    results
}

/// Top-level `<<` operators, the same places `extract_heredocs` looks. A
/// quoted `<<`, as in `echo '<<'`, is text.
pub(crate) fn heredoc_operators(text: &str) -> usize {
    let chars: Vec<char> = text.chars().collect();
    let mut state = ShellScanState::new();
    let mut index = 0;
    let mut operators = 0;
    while index < chars.len() {
        // Declarations are read one line at a time, with a fresh state. A
        // quote still open at a newline is a different `<<` than the next
        // line's, so the two counts are not the same operator.
        if chars[index] == '\n' {
            if !state.is_top_level() {
                return usize::MAX;
            }
            state = ShellScanState::new();
        }
        if state.is_top_level()
            && chars.get(index) == Some(&'<')
            && chars.get(index + 1) == Some(&'<')
            && chars.get(index.wrapping_sub(1)) != Some(&'<')
            && chars.get(index + 2) != Some(&'<')
        {
            operators += 1;
        }
        let next = state.advance(&chars, index);
        index = if next > index { next } else { index + 1 };
    }
    operators
}

struct HeredocDecl {
    start: usize,
    end: usize,
    delimiter: String,
    quoted: bool,
    strip_tabs: bool,
}

/// `_heredoc_declarations` (:91-107).
fn heredoc_declarations(
    line: &[char],
    state: &mut ShellScanState,
    carried_word_start: &mut bool,
) -> Vec<HeredocDecl> {
    let mut matches = Vec::new();
    let mut index = 0usize;
    // `#` opens a comment only at the start of a word, so the rest of the line
    // is not shell syntax and cannot declare a heredoc. Quoting state is
    // unchanged by a comment, so the next line resumes from the break point.
    //
    // Word starts are tracked from the scan's own steps rather than from the
    // preceding character, because `advance` consumes an escape pair or a
    // quoted span in one step: bash reads `echo a\ #` as the single word
    // `a #`, where the `#` is not a comment at all.
    let mut word_start = *carried_word_start;
    // Anything but a line continuation ends the command at the newline, so the
    // next line starts a word.
    *carried_word_start = true;
    while index < line.len() {
        // A trailing unquoted backslash joins this line to the next before bash
        // looks for comments, so the word boundary has to survive the join.
        // `advance` cannot report this on its own: it clamps the escape pair to
        // the end of the line, which is indistinguishable from an ordinary
        // single-character step. A backslash inside single quotes is literal and
        // joins nothing.
        let literal_backslash = state.quote == Some('\'') && !state.in_backtick;
        let escapes_newline = line[index] == '\\' && index + 1 == line.len() && !literal_backslash;
        let next_index = state.advance(line, index);
        if escapes_newline {
            *carried_word_start = word_start;
            index = next_index;
            continue;
        }
        if next_index != index + 1 {
            word_start = false;
            index = next_index;
            continue;
        }
        if state.is_top_level() && line[index] == '#' && word_start {
            return matches;
        }
        let next_word_start = state.is_top_level()
            && matches!(
                line[index],
                ' ' | '\t' | ';' | '&' | '|' | '(' | ')' | '<' | '>'
            );
        if state.is_top_level()
            && line[index] == '<'
            && line.get(index + 1) == Some(&'<')
            && (index == 0 || line[index - 1] != '<')
        {
            let operator_end = index + 2;
            let declaration = if line.get(operator_end) == Some(&'-') {
                // Bash reads `<<-` greedily, so `<<--END` strips tabs and closes
                // at `-END`. Only fall back to `<<` when no `<<-` delimiter parses.
                heredoc_declaration(line, index, operator_end + 1, true)
                    .or_else(|| heredoc_declaration(line, index, operator_end, false))
            } else {
                heredoc_declaration(line, index, operator_end, false)
            };
            if let Some(declaration) = declaration {
                index = declaration.end;
                word_start = false;
                matches.push(declaration);
                continue;
            }
        }
        word_start = next_word_start;
        index += 1;
    }
    matches
}

fn heredoc_declaration(
    line: &[char],
    operator_start: usize,
    mut cursor: usize,
    strip_tabs: bool,
) -> Option<HeredocDecl> {
    while matches!(line.get(cursor), Some(' ' | '\t')) {
        cursor += 1;
    }
    let quote = line
        .get(cursor)
        .copied()
        .filter(|ch| matches!(ch, '\'' | '"'));
    if quote.is_some() {
        cursor += 1;
    }
    let delimiter_start = cursor;
    let allow_hyphen = match line.get(cursor).copied()? {
        ch if ch.is_ascii_alphabetic() || ch == '_' => {
            cursor += 1;
            false
        }
        '-' if line.get(cursor + 1) == Some(&'-')
            && line
                .get(cursor + 2)
                .is_some_and(|ch| ch.is_ascii_alphanumeric()) =>
        {
            cursor += 3;
            true
        }
        // After the `<<-` operator a single leading hyphen belongs to the delimiter.
        '-' if strip_tabs
            && line
                .get(cursor + 1)
                .is_some_and(|ch| ch.is_ascii_alphanumeric()) =>
        {
            cursor += 2;
            true
        }
        _ => return None,
    };
    while line
        .get(cursor)
        .is_some_and(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || (allow_hyphen && *ch == '-'))
    {
        cursor += 1;
    }
    let delimiter_end = cursor;
    if let Some(quote) = quote {
        if line.get(cursor) != Some(&quote) {
            return None;
        }
        cursor += 1;
    }
    Some(HeredocDecl {
        start: operator_start,
        end: cursor,
        delimiter: line[delimiter_start..delimiter_end].iter().collect(),
        quoted: quote.is_some(),
        strip_tabs,
    })
}

/// `_find_heredoc_closing_line` (:110-129).
fn find_heredoc_closing_line(
    chars: &[char],
    body_start: usize,
    delimiter: &str,
    strip_tabs: bool,
) -> (usize, usize) {
    let n = chars.len();
    let mut cursor = body_start;
    while cursor <= n {
        let line_end = find_newline(chars, cursor).unwrap_or(n);
        let candidate: String = chars[cursor..line_end].iter().collect();
        let comparable = if strip_tabs {
            candidate.trim_start_matches('\t').to_owned()
        } else {
            candidate
        };
        if comparable == delimiter {
            return (cursor, line_end + if line_end < n { 1 } else { 0 });
        }
        if line_end == n {
            break;
        }
        cursor = line_end + 1;
    }
    (n, n)
}

/// `mask_heredoc_bodies` (:132-142).
pub fn mask_heredoc_bodies(command: &str, heredocs: &[ShellHeredoc]) -> String {
    if heredocs.is_empty() {
        return command.to_owned();
    }
    let mut characters: Vec<char> = command.chars().collect();
    for heredoc in heredocs {
        for character in characters
            .iter_mut()
            .take(heredoc.end)
            .skip(heredoc.body_start)
        {
            if *character != '\n' {
                *character = ' ';
            }
        }
    }
    characters.iter().collect()
}

/// `mask_complete_heredocs` (:145-153).
#[allow(dead_code)]
pub fn mask_complete_heredocs(command: &str, heredocs: &[ShellHeredoc]) -> String {
    let mut characters: Vec<char> = mask_heredoc_bodies(command, heredocs).chars().collect();
    for heredoc in heredocs {
        for character in characters
            .iter_mut()
            .take(heredoc.declaration_end)
            .skip(heredoc.operator_start)
        {
            if *character != '\n' {
                *character = ' ';
            }
        }
    }
    characters.iter().collect()
}

/// `extract_command_substitutions` (:156-159).
pub fn extract_command_substitutions(command: &str) -> Vec<String> {
    extract_command_substitution_spans(command)
        .into_iter()
        .map(|s| s.body)
        .collect()
}

/// `extract_command_substitution_spans` (:162-165).
pub fn extract_command_substitution_spans(command: &str) -> Vec<ShellCommandSubstitution> {
    extract_command_substitution_spans_impl(command, true)
}

/// `extract_expanded_heredoc_substitution_spans` (:168-171).
pub fn extract_expanded_heredoc_substitution_spans(command: &str) -> Vec<ShellCommandSubstitution> {
    extract_command_substitution_spans_impl(command, false)
}

/// `_extract_command_substitution_spans` (:174-240).
fn extract_command_substitution_spans_impl(
    command: &str,
    respect_quotes: bool,
) -> Vec<ShellCommandSubstitution> {
    let chars: Vec<char> = command.chars().collect();
    let n = chars.len();
    let mut substitutions = Vec::new();
    let mut index = 0usize;
    let mut quote: Option<char> = None;
    while index < n {
        let ch = chars[index];
        if ch == '\\' {
            index += 2;
            continue;
        }
        if respect_quotes && ch == '\'' && quote.is_none() {
            quote = Some('\'');
            index += 1;
            continue;
        }
        if respect_quotes && ch == '\'' && quote == Some('\'') {
            quote = None;
            index += 1;
            continue;
        }
        if respect_quotes && ch == '"' && quote.is_none() {
            quote = Some('"');
            index += 1;
            continue;
        }
        if respect_quotes && ch == '"' && quote == Some('"') {
            quote = None;
            index += 1;
            continue;
        }
        if quote != Some('\'') && starts_with(&chars, index, "$(") {
            let (extracted, end_index) = extract_parenthesized(&chars, index + 2);
            let whitespace = crate::command_option_parsing::python_is_whitespace;
            if !extracted.trim_matches(whitespace).is_empty() {
                let body_start = index + 2;
                let leading = extracted.chars().count()
                    - extracted.trim_start_matches(whitespace).chars().count();
                let trailing = extracted.trim_end_matches(whitespace).chars().count();
                substitutions.push(ShellCommandSubstitution {
                    kind: "dollar",
                    body: extracted.trim_matches(whitespace).to_owned(),
                    start: index,
                    body_start: body_start + leading,
                    body_end: body_start + trailing,
                    end: (n).min(end_index + 1),
                });
            }
            index = end_index + 1;
            continue;
        }
        if quote != Some('\'') && ch == '`' {
            let (extracted, end_index) = extract_backtick(&chars, index + 1);
            let whitespace = crate::command_option_parsing::python_is_whitespace;
            if !extracted.trim_matches(whitespace).is_empty() {
                let body_start = index + 1;
                let leading = extracted.chars().count()
                    - extracted.trim_start_matches(whitespace).chars().count();
                let trailing = extracted.trim_end_matches(whitespace).chars().count();
                substitutions.push(ShellCommandSubstitution {
                    kind: "backtick",
                    body: extracted.trim_matches(whitespace).to_owned(),
                    start: index,
                    body_start: body_start + leading,
                    body_end: body_start + trailing,
                    end: (n).min(end_index + 1),
                });
            }
            index = end_index + 1;
            continue;
        }
        index += 1;
    }
    substitutions
}

/// `_extract_parenthesized` (:243-266).
fn extract_parenthesized(chars: &[char], start: usize) -> (String, usize) {
    let n = chars.len();
    let mut depth = 1;
    let mut index = start;
    let mut quote: Option<char> = None;
    while index < n {
        let ch = chars[index];
        if ch == '\\' {
            index += 2;
            continue;
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
            depth += 1;
        } else if quote.is_none() && ch == ')' {
            depth -= 1;
            if depth == 0 {
                return (chars[start..index].iter().collect(), index);
            }
        }
        index += 1;
    }
    (chars[start..].iter().collect(), n)
}

/// `_extract_backtick` (:269-279).
fn extract_backtick(chars: &[char], start: usize) -> (String, usize) {
    let n = chars.len();
    let mut index = start;
    while index < n {
        let ch = chars[index];
        if ch == '\\' {
            index += 2;
            continue;
        }
        if ch == '`' {
            return (chars[start..index].iter().collect(), index);
        }
        index += 1;
    }
    (chars[start..].iter().collect(), n)
}

/// `ShellScanState` (:282-322).
pub struct ShellScanState {
    quote: Option<char>,
    subshell_depth: usize,
    in_backtick: bool,
}

impl ShellScanState {
    pub fn from_snapshot(value: &serde_json::Value) -> Result<Self, &'static str> {
        let v = value.as_array().ok_or("shell_helpers_invalid_state")?;
        if v.len() != 3 {
            return Err("shell_helpers_invalid_state");
        }
        let quote = match v[0].as_str() {
            Some("'") => Some('\''),
            Some("\"") => Some('"'),
            None if v[0].is_null() => None,
            _ => return Err("shell_helpers_invalid_state"),
        };
        let subshell_depth = usize::try_from(v[1].as_u64().ok_or("shell_helpers_invalid_state")?)
            .map_err(|_| "shell_helpers_invalid_state")?;
        if subshell_depth.checked_add(256 * 1024).is_none() {
            return Err("shell_helpers_invalid_state");
        }
        Ok(Self {
            quote,
            subshell_depth,
            in_backtick: v[2].as_bool().ok_or("shell_helpers_invalid_state")?,
        })
    }
    pub fn snapshot(&self) -> (Option<char>, usize, bool) {
        (self.quote, self.subshell_depth, self.in_backtick)
    }
    pub fn new() -> Self {
        ShellScanState {
            quote: None,
            subshell_depth: 0,
            in_backtick: false,
        }
    }

    pub fn is_top_level(&self) -> bool {
        self.quote.is_none() && self.subshell_depth == 0 && !self.in_backtick
    }

    /// `advance` (:296-322).
    pub fn advance(&mut self, chars: &[char], index: usize) -> usize {
        let n = chars.len();
        let ch = chars[index];
        // Inside single quotes bash takes every character literally, a
        // backslash included, so the escape below must not consume the closing
        // quote and leave the scan holding the opposite quote state to bash.
        if self.quote == Some('\'') && !self.in_backtick {
            if ch == '\'' {
                self.quote = None;
            }
            return index + 1;
        }
        if ch == '\\' {
            return (n).min(index + 2);
        }
        if ch == '`' && self.quote != Some('\'') {
            self.in_backtick = !self.in_backtick;
            return index + 1;
        }
        if self.in_backtick {
            return index + 1;
        }
        if ch == '\'' && self.quote.is_none() {
            self.quote = Some('\'');
            return index + 1;
        }
        if ch == '"' {
            if self.quote == Some('"') {
                self.quote = None;
            } else if self.quote.is_none() {
                self.quote = Some('"');
            }
            return index + 1;
        }
        if self.quote != Some('\'') && starts_with(chars, index, "$(") {
            let (_extracted, end_index) = extract_parenthesized(chars, index + 2);
            return (n).min(end_index + 1);
        }
        if self.quote.is_none() && ch == '(' {
            self.subshell_depth += 1;
        } else if self.quote.is_none() && ch == ')' && self.subshell_depth > 0 {
            self.subshell_depth -= 1;
        }
        index + 1
    }
}

fn starts_with(chars: &[char], index: usize, pat: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    index + p.len() <= chars.len() && chars[index..index + p.len()] == p[..]
}

fn find_newline(chars: &[char], from: usize) -> Option<usize> {
    chars[from..]
        .iter()
        .position(|&c| c == '\n')
        .map(|p| from + p)
}

#[cfg(test)]
#[path = "shell_structure_tests.rs"]
mod tests;

//! Source-faithful shell heredoc and command-substitution structures
//! (`runtime/shell_structure.py`, 323 lines — verbatim).

use regex::Regex;
use std::sync::OnceLock;

#[allow(clippy::invalid_regex)]
fn heredoc_operator_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?<!<)(?P<operator><<-?)[ \t]*(?P<quote>['"]?)(?P<delimiter>(?:[A-Za-z_][A-Za-z0-9_]*|--[A-Za-z0-9][A-Za-z0-9_-]*))(?P=quote)"#,
        )
        .unwrap()
    })
}

/// `ShellHeredoc` (:10-23).
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
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
/// contents; text is byte-offset exact.
pub fn extract_heredocs(command: &str) -> Vec<ShellHeredoc> {
    if command.is_empty() {
        return Vec::new();
    }
    let chars: Vec<char> = command.chars().collect();
    let n = chars.len();
    let mut results = Vec::new();
    let mut scan_cursor = 0usize;
    while scan_cursor < n {
        let mut line_end = find_newline(&chars, scan_cursor).unwrap_or(n);
        let pending = heredoc_declarations(&chars[scan_cursor..line_end]);
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
                delimiter: delimiter.clone(),
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
        line_end = n;
        let _ = line_end;
    }
    results
}

struct HeredocDecl {
    start: usize,
    end: usize,
    delimiter: String,
    quoted: bool,
    strip_tabs: bool,
}

/// `_heredoc_declarations` (:91-107).
fn heredoc_declarations(line: &[char]) -> Vec<HeredocDecl> {
    let mut matches = Vec::new();
    let mut state = ShellScanState::new();
    let mut index = 0usize;
    while index < line.len() {
        let next_index = state.advance(line, index);
        if next_index != index + 1 {
            index = next_index;
            continue;
        }
        if state.is_top_level() && starts_with(line, index, "<<") {
            // `pattern.match(line, index)` — anchored at index only.
            let tail: String = line[index..].iter().collect();
            if let Some(caps) = heredoc_operator_pattern().captures(&tail) {
                let whole = caps.get(0).unwrap();
                if whole.start() == 0 {
                    let byte_end = whole.end();
                    let delim = caps.name("delimiter").unwrap().as_str().to_owned();
                    let quoted = caps
                        .name("quote")
                        .map(|q| !q.as_str().is_empty())
                        .unwrap_or(false);
                    let strip_tabs = caps.name("operator").unwrap().as_str() == "<<-";
                    let char_end = tail[..byte_end].chars().count();
                    matches.push(HeredocDecl {
                        start: index,
                        end: index + char_end,
                        delimiter: delim,
                        quoted,
                        strip_tabs,
                    });
                    index += char_end;
                    continue;
                }
            }
        }
        index += 1;
    }
    matches
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
            if !extracted.trim().is_empty() {
                let body_start = index + 2;
                let leading = extracted.len() - extracted.trim_start().len();
                let trailing = extracted.trim_end().len();
                substitutions.push(ShellCommandSubstitution {
                    kind: "dollar",
                    body: extracted.trim().to_owned(),
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
            if !extracted.trim().is_empty() {
                let body_start = index + 1;
                let leading = extracted.len() - extracted.trim_start().len();
                let trailing = extracted.trim_end().len();
                substitutions.push(ShellCommandSubstitution {
                    kind: "backtick",
                    body: extracted.trim().to_owned(),
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
        if self.quote == Some('\'') {
            if ch == '\'' {
                self.quote = None;
            }
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

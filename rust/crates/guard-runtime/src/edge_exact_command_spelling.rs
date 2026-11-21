//! Other spellings of a shell command that run the command a rule names.
//!
//! A rule for one exact shell command is saved under the hash of its text.
//! Shells read many texts as the same program and arguments: extra spaces, a
//! trailing `;`, an environment prefix, a full path to the program, a group in
//! parentheses, `bash -c '…'`, or the command as one step of a longer line. A
//! rule that only matched its own text let every one of those run. This
//! module lists the texts a rule author would have written for each program
//! the line runs, so the rule applies to all of them.
//!
//! The list only ever adds texts to look up, each the program and arguments
//! of a step the shell runs. The command's byte limit bounds it; a length cap
//! let a line padded with harmless steps push the ruled step off the end.

use std::collections::HashSet;

use guard_command::{parse_command, CommandModelRequestV1, CommandSegmentV1, MAX_COMMAND_BYTES};

#[path = "edge_exact_command_spelling_words.rs"]
mod words;
use words::words;

/// Nesting followed through `bash -c` scripts and groups; deeper is not fully read.
const MAX_DEPTH: usize = 8;
const INLINE_SHELLS: &[&str] = &["bash", "sh", "zsh", "dash", "ash", "ksh"];
/// Words that start a step without being its program.
const LEADING_KEYWORDS: &[&str] = &[
    "{", "!", "then", "do", "else", "elif", "if", "while", "until", "time",
];

/// The texts a command spells, other than its own text.
#[derive(Debug, Default)]
pub(crate) struct Spellings {
    pub(crate) texts: Vec<String>,
    /// False when part of the line could not be read, so a rule may name a
    /// step that is missing from `texts`.
    pub(crate) complete: bool,
}

impl Spellings {
    /// Adds `text`, and `text` as Guard Cloud saves a command rule: every
    /// run of whitespace read as one space, quoted runs included. These rules
    /// only block or ask, so the wider match only adds a review.
    fn push(&mut self, seen: &mut HashSet<String>, text: String) {
        let cloud = text.split_whitespace().collect::<Vec<_>>().join(" ");
        for text in [text, cloud] {
            if !text.is_empty() && seen.insert(text.clone()) {
                self.texts.push(text);
            }
        }
    }
}

/// Texts that name a program the shell runs for `command`, other than the
/// command text itself.
pub(crate) fn spellings(command: &str) -> Spellings {
    let mut out = Spellings {
        texts: Vec::new(),
        complete: true,
    };
    if command.len() > MAX_COMMAND_BYTES {
        out.complete = false;
        return out;
    }
    let mut seen = HashSet::from([command.to_owned()]);
    out.push(&mut seen, collapse(command));
    visit(command, 0, &mut out, &mut seen);
    out
}

fn visit(text: &str, depth: usize, out: &mut Spellings, seen: &mut HashSet<String>) {
    if depth > MAX_DEPTH {
        out.complete = false;
        return;
    }
    let commented = guard_command::rich_command_model_api::mask_shell_comments(text) != text;
    let parsed = parse_command(&CommandModelRequestV1 {
        command: text.to_owned(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "guard-shell".into(),
    });
    match parsed {
        Ok(model) if model.confidence == "exact" && !model.segments.is_empty() => {
            // Comments off, bash runs `#` text line by line, even before a bad quote.
            let plain = commented.then(|| steps(text, true, false).0);
            for step in plain.iter().flatten().filter(|s| *s != text.trim()) {
                out.push(seen, collapse(step));
                visit(step, depth + 1, out, seen);
            }
            for segment in &model.segments {
                let cut =
                    words::comment_cut(&segment.text, &segment.arguments).unwrap_or_else(|()| {
                        out.complete = false;
                        None
                    });
                for end in [segment.arguments.len()].into_iter().chain(cut) {
                    for spelling in segment_spellings(segment, &segment.arguments[..end]) {
                        out.push(seen, spelling);
                    }
                }
                out.push(seen, collapse(&segment.text));
                out.push(seen, bare_step(&collapse(&segment.text)));
                if let Some(executable) = segment.executable.as_deref() {
                    match inline_script(executable, &segment.arguments) {
                        Inline::Script(script) => {
                            out.push(seen, collapse(script));
                            visit(script, depth + 1, out, seen);
                        }
                        Inline::Unread => out.complete = false,
                        Inline::No => {}
                    }
                }
            }
        }
        _ => {
            // The parser does not model groups such as `(npm publish)` or
            // heredocs. Each step outside quotes and heredoc bodies is read.
            let words = guard_command::rich_command_model_api::shell_tokens_without_redirects(
                text.trim(),
                0,
                &[],
            );
            if let Some((program, arguments)) = words.split_first() {
                match inline_script(program, arguments) {
                    Inline::Script(script) => {
                        out.push(seen, collapse(script));
                        visit(script, depth + 1, out, seen);
                        return;
                    }
                    Inline::Unread => {
                        out.complete = false;
                        return;
                    }
                    Inline::No => {}
                }
            }
            // Bash reads `((` as arithmetic only when it parses as one, and
            // runs `((npm publish); true)` as nested groups. Every reading,
            // with `#` comments and without, is listed; an extra text only
            // adds a match. The line is complete only when both close.
            let (mut found, closed) = steps(text, true, true);
            let (plain, plain_closed) = steps(text, true, false);
            out.complete &= closed && plain_closed;
            let mut readings = vec![plain];
            if text.contains("((") {
                readings.push(steps(text, false, true).0);
                readings.push(steps(text, false, false).0);
            }
            for step in readings.into_iter().flatten() {
                if !found.contains(&step) {
                    found.push(step);
                }
            }
            if found.len() == 1 && found[0] == text.trim() {
                return;
            }
            for step in found {
                out.push(seen, collapse(&step));
                // `(( i++ ))` read as groups lists itself; skip a repeat pass.
                if step != text.trim() {
                    visit(&step, depth + 1, out, seen);
                }
            }
        }
    }
}

/// `program arg …` with the program's file name, quoted the ways a person
/// writes a word that needs quotes. `Spellings::push` drops a repeat.
fn segment_spellings(segment: &CommandSegmentV1, arguments: &[String]) -> Vec<String> {
    let Some(executable) = segment.executable.as_deref() else {
        return Vec::new();
    };
    let program = executable.rsplit(['/', '\\']).next().unwrap_or(executable);
    if program.is_empty() {
        return Vec::new();
    }
    let join = |quote: fn(&str) -> String| {
        std::iter::once(program.to_owned())
            .chain(arguments.iter().map(|word| quote(word.as_str())))
            .collect::<Vec<_>>()
            .join(" ")
    };
    vec![join(single_quoted), join(double_quoted)]
}

/// What an inline shell runs from its arguments.
enum Inline<'a> {
    /// Not a shell given a script with `-c`.
    No,
    /// The script of `bash -c '…'` and the like.
    Script(&'a str),
    /// `-c` with no script word Guard could find.
    Unread,
}

/// The script of `bash -c '…'` and the like, when the parser kept the shell
/// as the program. Option operands such as `-o pipefail` and `--rcfile file`
/// are skipped, so `bash -euo pipefail -c '…'` reads its script.
fn inline_script<'a>(executable: &str, arguments: &'a [String]) -> Inline<'a> {
    let program = executable.rsplit(['/', '\\']).next().unwrap_or(executable);
    if !INLINE_SHELLS.contains(&program) {
        return Inline::No;
    }
    let mut command = false;
    let mut words = arguments.iter();
    while let Some(word) = words.next() {
        if word == "--" || word == "-" {
            break;
        }
        if let Some(long) = word.strip_prefix("--") {
            if matches!(long, "rcfile" | "init-file") {
                words.next();
            }
            continue;
        }
        let Some(cluster) = word.strip_prefix('-').or_else(|| word.strip_prefix('+')) else {
            return if command {
                Inline::Script(word)
            } else {
                Inline::No
            };
        };
        if word.starts_with('-') && cluster.contains('c') {
            command = true;
        }
        for _ in cluster.chars().filter(|&c| c == 'o' || c == 'O') {
            words.next();
        }
    }
    match (command, words.next()) {
        (true, Some(word)) => Inline::Script(word),
        (true, None) => Inline::Unread,
        _ => Inline::No,
    }
}

fn safe_word(word: &str) -> bool {
    !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c))
}

fn single_quoted(word: &str) -> String {
    if safe_word(word) {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

fn double_quoted(word: &str) -> String {
    if safe_word(word) || word.contains(['"', '$', '`', '\\', '!']) {
        single_quoted(word)
    } else {
        format!("\"{word}\"")
    }
}

/// The steps of `text` split at `;`, `&`, `|`, parentheses and line breaks
/// outside quotes, without the keyword or brace that opens each or its
/// redirections. Heredoc bodies are skipped to their closing line; a body that
/// never closes is read as steps, so nothing after an unclosed `<<` hides.
fn steps(text: &str, read_arithmetic: bool, read_comments: bool) -> (Vec<String>, bool) {
    let chars: Vec<char> = text.chars().collect();
    let mut steps = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    // `((` and `$((` hold arithmetic, where `<<` is a shift, not a heredoc.
    let mut arithmetic = 0usize;
    let mut heredocs: Vec<(String, bool)> = Vec::new();
    // A `#` that starts a word comments out the rest of the line, where
    // quotes and `<<` start nothing. Its text is still split into steps.
    let mut comment = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if comment && c != '\n' {
            if matches!(c, ';' | '&' | '|' | '(' | ')' | '\r' | '`') {
                steps.push(std::mem::take(&mut current));
            } else {
                current.push(c);
            }
            i += 1;
            continue;
        }
        match (quote, c) {
            (Some('\''), '\'') | (Some('"'), '"') => {
                quote = None;
                current.push(c);
            }
            (Some('"') | None, '\\') => {
                current.push(c);
                if let Some(next) = next {
                    current.push(next);
                    i += 1;
                }
            }
            (Some(_), _) => current.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                current.push(c);
            }
            (None, '#')
                if read_comments
                    && arithmetic == 0
                    && (current.is_empty() || current.ends_with([' ', '\t'])) =>
            {
                comment = true;
                current.push(c);
            }
            (None, '(') if read_arithmetic && next == Some('(') => {
                arithmetic += 1;
                current.push_str("((");
                i += 1;
            }
            (None, ')') if next == Some(')') && arithmetic > 0 => {
                arithmetic -= 1;
                current.push_str("))");
                i += 1;
            }
            (None, '<') if arithmetic == 0 && next == Some('<') => {
                if chars.get(i + 2) == Some(&'<') {
                    current.push_str("<<<");
                    i += 2;
                } else {
                    let (delimiter, strip_tabs, end) = heredoc_delimiter(&chars, i + 2);
                    if !delimiter.is_empty() {
                        heredocs.push((delimiter, strip_tabs));
                    }
                    i = end;
                    continue;
                }
            }
            (None, '\n') => {
                comment = false;
                steps.push(std::mem::take(&mut current));
                i = skip_heredoc_bodies(&chars, i + 1, &mut heredocs);
                continue;
            }
            (None, ';' | '&' | '|' | '(' | ')' | '\r' | '`') => {
                steps.push(std::mem::take(&mut current));
            }
            (None, _) => current.push(c),
        }
        i += 1;
    }
    steps.push(current);
    let steps = steps
        .into_iter()
        .map(|step| bare_step(&step))
        .filter(|step| !step.is_empty())
        .collect();
    (steps, quote.is_none())
}

/// The delimiter word after `<<` at `start`, whether `<<-` strips leading
/// tabs, and the index after the word.
fn heredoc_delimiter(chars: &[char], start: usize) -> (String, bool, usize) {
    let mut i = start;
    let strip_tabs = chars.get(i) == Some(&'-');
    if strip_tabs {
        i += 1;
    }
    while chars.get(i).is_some_and(|c| *c == ' ' || *c == '\t') {
        i += 1;
    }
    let mut delimiter = String::new();
    let mut quote: Option<char> = None;
    while let Some(&c) = chars.get(i) {
        match (quote, c) {
            (Some(open), c) if c == open => quote = None,
            (Some(_), c) => delimiter.push(c),
            (None, '\'' | '"') => quote = Some(c),
            (None, '\\') => {
                if let Some(&escaped) = chars.get(i + 1) {
                    delimiter.push(escaped);
                    i += 1;
                }
            }
            (None, c) if c.is_whitespace() || ";&|()<>".contains(c) => break,
            (None, c) => delimiter.push(c),
        }
        i += 1;
    }
    (delimiter, strip_tabs, i)
}

/// The index after the bodies of the pending heredocs that start at `start`.
/// A body without its closing line is not skipped.
fn skip_heredoc_bodies(chars: &[char], start: usize, heredocs: &mut Vec<(String, bool)>) -> usize {
    let mut i = start;
    for (delimiter, strip_tabs) in std::mem::take(heredocs) {
        let mut line_start = i;
        let closed = loop {
            if line_start >= chars.len() {
                break None;
            }
            let line_end = chars[line_start..]
                .iter()
                .position(|c| *c == '\n')
                .map_or(chars.len(), |offset| line_start + offset);
            let line: String = chars[line_start..line_end].iter().collect();
            let line = if strip_tabs {
                line.trim_start_matches('\t')
            } else {
                line.as_str()
            };
            if line.trim_end_matches('\r') == delimiter {
                break Some((line_end + 1).min(chars.len()));
            }
            line_start = line_end + 1;
        };
        match closed {
            Some(after) => i = after,
            None => return i,
        }
    }
    i
}

fn bare_step(step: &str) -> String {
    let mut words = words(step);
    while words
        .first()
        .is_some_and(|word| LEADING_KEYWORDS.contains(word))
    {
        words.remove(0);
    }
    if words.last() == Some(&"}") {
        words.pop();
    }
    let mut kept = Vec::with_capacity(words.len());
    let mut words = words.into_iter();
    while let Some(word) = words.next() {
        match redirection(word) {
            // `> out` names its target in the next word.
            Some("") => {
                words.next();
            }
            Some(_) => {}
            None => kept.push(word),
        }
    }
    kept.join(" ")
}

/// The target written in the same word as a redirection operator (empty when
/// the next word holds it), or `None` for a word that is not one.
fn redirection(word: &str) -> Option<&str> {
    let rest = word.trim_start_matches(|c: char| c.is_ascii_digit());
    ["<<<", "&>>", "&>", ">>", ">&", "<&", ">|", ">", "<"]
        .iter()
        .find_map(|operator| rest.strip_prefix(operator))
}

/// `text` with runs of spaces between words read as one and without the
/// separator that ends it. Spaces inside quotes are kept: they are part of an
/// argument.
fn collapse(text: &str) -> String {
    let mut collapsed = words(text).join(" ");
    loop {
        let trimmed = match collapsed.as_bytes() {
            [.., b'&', b'&'] => break,
            [.., b';' | b'&'] => collapsed[..collapsed.len() - 1].trim_end().to_owned(),
            _ => break,
        };
        collapsed = trimmed;
    }
    collapsed
}

#[cfg(test)]
#[path = "edge_exact_command_spelling_tests.rs"]
mod tests;

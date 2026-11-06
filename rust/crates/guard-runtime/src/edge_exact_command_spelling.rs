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
//! The list only ever adds texts to look up. Each one is the program and
//! arguments of a step the shell runs, so a rule can only match a step that
//! runs the command it names.

use guard_command::{parse_command, CommandModelRequestV1, CommandSegmentV1, MAX_COMMAND_BYTES};

/// Nesting followed through `bash -c` scripts and grouped steps.
const MAX_DEPTH: usize = 3;
/// Texts listed for one command; a longer line keeps the first ones.
const MAX_SPELLINGS: usize = 48;
const INLINE_SHELLS: &[&str] = &["bash", "sh", "zsh", "dash", "ash", "ksh"];
/// Words that start a step without being its program.
const LEADING_KEYWORDS: &[&str] = &[
    "{", "!", "then", "do", "else", "elif", "if", "while", "until", "time",
];

/// Texts that name a program the shell runs for `command`, other than the
/// command text itself.
pub(crate) fn spellings(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    if command.len() > MAX_COMMAND_BYTES {
        return out;
    }
    push(&mut out, collapse(command));
    visit(command, 0, &mut out);
    out.retain(|text| text != command);
    out
}

fn visit(text: &str, depth: usize, out: &mut Vec<String>) {
    if depth > MAX_DEPTH || out.len() >= MAX_SPELLINGS {
        return;
    }
    let parsed = parse_command(&CommandModelRequestV1 {
        command: text.to_owned(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "guard-shell".into(),
    });
    match parsed {
        Ok(model) if model.confidence == "exact" && !model.segments.is_empty() => {
            for segment in &model.segments {
                for spelling in segment_spellings(segment) {
                    push(out, spelling);
                }
                push(out, collapse(&segment.text));
                push(out, bare_step(&collapse(&segment.text)));
                if let Some(executable) = segment.executable.as_deref() {
                    if let Some(script) = inline_script(executable, &segment.arguments) {
                        push(out, collapse(script));
                        visit(script, depth + 1, out);
                    }
                }
            }
        }
        _ => {
            // The parser does not model groups such as `(npm publish)`. Each
            // step outside quotes is read on its own instead.
            if text.contains("<<") {
                return;
            }
            let words = guard_command::rich_command_model_api::shell_tokens_without_redirects(
                text.trim(),
                0,
                &[],
            );
            if let Some((program, arguments)) = words.split_first() {
                if let Some(script) = inline_script(program, arguments) {
                    push(out, collapse(script));
                    visit(script, depth + 1, out);
                    return;
                }
            }
            let steps = steps(text);
            if steps.len() == 1 && steps[0] == text.trim() {
                return;
            }
            for step in steps.into_iter().take(MAX_SPELLINGS) {
                push(out, collapse(&step));
                visit(&step, depth + 1, out);
            }
        }
    }
}

/// `program arg …` with the program's file name, quoted the ways a person
/// writes a word that needs quotes.
fn segment_spellings(segment: &CommandSegmentV1) -> Vec<String> {
    let Some(executable) = segment.executable.as_deref() else {
        return Vec::new();
    };
    let program = executable.rsplit(['/', '\\']).next().unwrap_or(executable);
    if program.is_empty() {
        return Vec::new();
    }
    let join = |quote: fn(&str) -> String| {
        std::iter::once(program.to_owned())
            .chain(segment.arguments.iter().map(|word| quote(word.as_str())))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let single = join(single_quoted);
    let double = join(double_quoted);
    if single == double {
        vec![single]
    } else {
        vec![single, double]
    }
}

/// The script of `bash -c '…'` and the like, when the parser kept the shell
/// as the program.
fn inline_script<'a>(executable: &str, arguments: &'a [String]) -> Option<&'a str> {
    let program = executable.rsplit('/').next().unwrap_or(executable);
    if !INLINE_SHELLS.contains(&program) {
        return None;
    }
    let flags = arguments
        .iter()
        .take_while(|word| word.starts_with('-'))
        .position(|word| !word.starts_with("--") && word.contains('c'))?;
    arguments.get(flags + 1).map(String::as_str)
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
/// outside quotes, each without the keyword or brace that opens it and
/// without its redirections.
fn steps(text: &str) -> Vec<String> {
    let mut steps = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some('\''), '\'') | (Some('"'), '"') => {
                quote = None;
                current.push(c);
            }
            (Some('"'), '\\') | (None, '\\') => {
                current.push(c);
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            (Some(_), _) => current.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                current.push(c);
            }
            (None, ';' | '&' | '|' | '(' | ')' | '\n' | '\r' | '`') => {
                steps.push(std::mem::take(&mut current));
            }
            (None, _) => current.push(c),
        }
    }
    steps.push(current);
    steps
        .into_iter()
        .map(|step| bare_step(&step))
        .filter(|step| !step.is_empty())
        .collect()
}

fn bare_step(step: &str) -> String {
    let mut words: Vec<&str> = step.split_whitespace().collect();
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
    ["&>>", "&>", ">>", ">&", "<&", ">|", ">", "<"]
        .iter()
        .find_map(|operator| rest.strip_prefix(operator))
}

/// `text` with runs of spaces read as one and without the separator that
/// ends it.
fn collapse(text: &str) -> String {
    let mut collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
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

fn push(out: &mut Vec<String>, text: String) {
    if !text.is_empty() && out.len() < MAX_SPELLINGS && !out.contains(&text) {
        out.push(text);
    }
}

#[cfg(test)]
#[path = "edge_exact_command_spelling_tests.rs"]
mod tests;

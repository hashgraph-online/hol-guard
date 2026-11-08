//! The words, quoted phrases and file names a typed prompt gives, which the
//! project file search looks for.
use crate::context_assistance_prompt_files::wanted_file;

pub(crate) const MAX_TERMS: usize = 32;
const MAX_PHRASES: usize = 4;
/// How far past an opening quote to look for its closing one, so a prompt
/// full of unmatched quotes is still scanned in one pass.
const MAX_PHRASE_SPAN: usize = 120;
/// Files the prompt names, such as `CHANGES.rst`, each standing for at most
/// `MAX_NAMED_MATCHES` files with that name.
pub(crate) const MAX_NAMED: usize = 4;
const TEST_WORDS: &[&str] = &["test", "tests", "spec", "e2e", "testing"];
const STOP_WORDS: &[&str] = &[
    "about", "add", "after", "again", "all", "already", "also", "and", "any", "are", "because",
    "been", "before", "being", "both", "build", "but", "can", "cannot", "change", "could",
    "create", "did", "does", "during", "each", "either", "every", "few", "fix", "for", "from",
    "further", "get", "had", "has", "have", "help", "here", "how", "into", "its", "itself", "just",
    "let", "like", "make", "might", "more", "most", "must", "need", "new", "not", "now", "once",
    "only", "other", "our", "over", "please", "put", "same", "should", "some", "still", "such",
    "than", "that", "the", "them", "then", "there", "these", "they", "this", "those", "though",
    "too", "until", "update", "use", "very", "want", "was", "were", "what", "when", "where",
    "whether", "which", "while", "who", "whose", "why", "will", "with", "without", "would", "you",
    "your",
];
/// Words that, written plainly, say what to do or how a task came about, not
/// which code it is about: "find the root cause after the last commit" names
/// no function `find`, `root` or `last`. Written like code they still count.
const TASK_WORDS: &[&str] = &[
    "actually",
    "alone",
    "answer",
    "behavior",
    "behaviour",
    "broke",
    "broken",
    "bug",
    "cause",
    "check",
    "code",
    "commit",
    "committed",
    "describe",
    "docstring",
    "doctest",
    "edit",
    "everywhere",
    "example",
    "expected",
    "explain",
    "fail",
    "failing",
    "find",
    "first",
    "implement",
    "implementation",
    "last",
    "leave",
    "library",
    "line",
    "lines",
    "look",
    "output",
    "pass",
    "passes",
    "passing",
    "push",
    "pushed",
    "question",
    "recently",
    "refactor",
    "remove",
    "rename",
    "reply",
    "review",
    "root",
    "run",
    "short",
    "something",
    "started",
    "sure",
    "teammate",
    "track",
    "usage",
    "write",
    "written",
];

/// Lowercase words from the prompt worth looking for in paths and code.
/// Words written like code come first, so a long prompt keeps the names it
/// is about (`case_sensitive`, `IntRange`) over the plain words around them.
#[cfg(test)]
pub(crate) fn terms(prompt: &str) -> Vec<String> {
    marked_terms(prompt)
        .into_iter()
        .map(|(term, _)| term)
        .collect()
}

/// The prompt's `terms`, each marked when the prompt wrote it whole as a
/// name (`case_sensitive`, `IntRange`), not as a plain word or a piece of a
/// name.
pub(crate) fn marked_terms(prompt: &str) -> Vec<(String, bool)> {
    let mut code: Vec<(String, bool)> = Vec::new();
    let mut plain: Vec<(String, bool)> = Vec::new();
    for (word, shaped) in words(prompt) {
        let joined = word.replace(['-', '_'], "").to_lowercase();
        let pieces = word
            .split(['-', '_'])
            .filter(|_| word.contains(['-', '_']))
            .map(|piece| (piece.to_lowercase(), false));
        for (part, whole) in std::iter::once((joined, true)).chain(pieces) {
            let term = singular(&part);
            if term.chars().count() >= 3
                && !STOP_WORDS.contains(&term.as_str())
                && (shaped || !TASK_WORDS.contains(&term.as_str()))
                && !term.chars().all(|c| c.is_ascii_digit())
            {
                if shaped {
                    code.push((term, whole));
                } else {
                    plain.push((term, false));
                }
            }
        }
    }
    let mut found: Vec<(String, bool)> = Vec::new();
    for (term, name) in code.into_iter().chain(plain) {
        if found.len() >= MAX_TERMS {
            break;
        }
        match found.iter_mut().find(|(seen, _)| *seen == term) {
            Some((_, seen_name)) => *seen_name |= name,
            None => found.push((term, name)),
        }
    }
    // A request for tests counts even when it comes late in a long prompt.
    if !found
        .iter()
        .any(|(term, _)| TEST_WORDS.contains(&term.as_str()))
        && prompt_mentions_tests(prompt)
    {
        found.truncate(MAX_TERMS - 1);
        found.push(("test".into(), false));
    }
    found
}

/// The prompt's words, each marked when it is written like code: inside
/// backticks, dotted (`click.Choice`), snake_case or camelCase. A file name
/// gives no words: `named` finds the file, and its folders and name
/// (`src/app/utils.py`) would map every definition that mentions them.
fn words(prompt: &str) -> Vec<(String, bool)> {
    let mut found = Vec::new();
    for (span, ticked) in spans(prompt) {
        for token in tokens(span) {
            let token = token.trim_matches(['.', '-', '/']);
            if file_name(token).is_some() {
                continue;
            }
            let shaped = ticked || token.contains(['.', '_']) || camel(token);
            for piece in token.split(['.', '/']).filter(|piece| !piece.is_empty()) {
                found.push((piece.to_owned(), shaped));
            }
        }
    }
    found
}

/// The prompt's text between backticks and outside them, each marked when it
/// was backticked. A fenced block (a pasted traceback or snippet) counts as
/// plain text. A backticked command line (`pytest -x tests`) says how to run
/// something, not what the request is about, so it is left out.
fn spans(prompt: &str) -> Vec<(&str, bool)> {
    let mut found = Vec::new();
    for (fence, block) in prompt.split("```").enumerate() {
        if fence % 2 == 1 {
            found.push((block, false));
            continue;
        }
        let parts: Vec<&str> = block.split('`').collect();
        let last = parts.len() - 1;
        for (index, span) in parts.into_iter().enumerate() {
            let ticked = index % 2 == 1 && index < last;
            if !(ticked && command(span)) {
                found.push((span, ticked));
            }
        }
    }
    found
}

/// True for a command line such as `pytest -x tests/test_cli.py`: a plain
/// program name followed by a flag or a path. Code with spaces in it, such as
/// `case_sensitive = False`, is not one.
fn command(span: &str) -> bool {
    let mut words = span.split_whitespace();
    let Some(program) = words.next() else {
        return false;
    };
    program
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && words
            .any(|word| word.starts_with('-') || word.contains('/') || file_name(word).is_some())
}

fn tokens(span: &str) -> impl Iterator<Item = &str> {
    span.split(|c: char| !(c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | '/')))
}

fn camel(word: &str) -> bool {
    word.chars()
        .zip(word.chars().skip(1))
        .any(|(a, b)| a.is_lowercase() && b.is_uppercase())
}

/// `(stem, extension)` when `token` is a file name this search reads.
fn file_name(token: &str) -> Option<(&str, &str)> {
    let (stem, extension) = token.rsplit_once('.')?;
    let base = stem.rsplit('/').next().unwrap_or(stem);
    (!base.is_empty() && wanted_file(token.rsplit('/').next().unwrap_or(token)))
        .then_some((stem, extension))
}

/// Files the prompt names, as typed (`CHANGES.rst`, `src/app/cli.py`).
pub(crate) fn named(prompt: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for token in spans(prompt).into_iter().flat_map(|(span, _)| tokens(span)) {
        if found.len() >= MAX_NAMED {
            break;
        }
        let name = token.trim_matches(['.', '/']);
        if !token.contains("..") && file_name(name).is_some() && !found.iter().any(|n| n == name) {
            found.push(name.to_owned());
        }
    }
    found
}

/// True when the search terms ask about tests.
pub(crate) fn asks_for_tests(terms: &[String]) -> bool {
    terms.iter().any(|term| TEST_WORDS.contains(&term.as_str()))
}

fn prompt_mentions_tests(prompt: &str) -> bool {
    prompt
        .split(|c: char| !c.is_alphanumeric())
        .any(|word| TEST_WORDS.contains(&singular(&word.to_lowercase()).as_str()))
}

/// Text the prompt quotes, such as a label to change, lowercased. A quote
/// opens only at the start of a word, so an apostrophe inside one ("dialog's")
/// never pairs with a later quote.
pub(crate) fn phrases(prompt: &str) -> Vec<String> {
    let chars: Vec<char> = prompt.chars().collect();
    let mut found: Vec<String> = Vec::new();
    let mut at = 0;
    while at < chars.len() && found.len() < MAX_PHRASES {
        if at > 0 && chars[at - 1].is_alphanumeric() {
            at += 1;
            continue;
        }
        let close = match chars[at] {
            '"' => '"',
            '\u{201c}' => '\u{201d}',
            '`' => '`',
            '\'' => '\'',
            _ => {
                at += 1;
                continue;
            }
        };
        let end = chars[at + 1..]
            .iter()
            .take(MAX_PHRASE_SPAN)
            .enumerate()
            .position(|(offset, &c)| {
                let next = chars.get(at + offset + 2);
                (c == close || (close == '\u{201d}' && c == '"'))
                    && (close != '\'' || next.is_none_or(|n| !n.is_alphanumeric()))
            });
        let Some(end) = end else {
            at += 1;
            continue;
        };
        let phrase: String = chars[at + 1..at + 1 + end].iter().collect();
        let phrase = phrase.trim().to_lowercase();
        if (3..=80).contains(&phrase.chars().count())
            && phrase.chars().any(char::is_alphanumeric)
            && !found.contains(&phrase)
        {
            found.push(phrase);
        }
        at += end + 2;
    }
    found
}

/// How `terms` spells `word`: lowercase, without `-` or `_`, singular.
pub(crate) fn term_form(word: &str) -> String {
    singular(&word.replace(['-', '_'], "").to_lowercase())
}

fn singular(word: &str) -> String {
    if word.len() > 4 && word.ends_with("ies") {
        return format!("{}y", &word[..word.len() - 3]);
    }
    if word.len() > 4 && word.ends_with('s') && !word.ends_with("ss") {
        return word[..word.len() - 1].into();
    }
    word.into()
}

#[cfg(test)]
#[path = "context_assistance_prompt_words_tests.rs"]
mod tests;

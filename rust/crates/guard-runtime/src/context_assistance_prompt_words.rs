//! The words, quoted phrases and file names a typed prompt gives, which the
//! project file search looks for.
use crate::context_assistance_prompt_files::wanted_file;
pub(crate) use no_change::asks_no_change;
use paths::without_paths;

#[path = "context_assistance_prompt_no_change.rs"]
mod no_change;
#[path = "context_assistance_prompt_paths.rs"]
mod paths;

pub(crate) const MAX_TERMS: usize = 32;
const MAX_PHRASES: usize = 4;
/// How far past an opening quote to look for its closing one, so a prompt
/// full of unmatched quotes is still scanned in one pass.
const MAX_PHRASE_SPAN: usize = 160;
/// The most of a quote searched for. A longer one, such as a whole docstring
/// sentence, is searched by its first words up to this length.
const MAX_PHRASE_CHARS: usize = 80;
/// Files the prompt names, such as `CHANGES.rst`, each standing for at most
/// `MAX_NAMED_MATCHES` files with that name.
pub(crate) const MAX_NAMED: usize = 4;
const TEST_WORDS: &[&str] = &["test", "tests", "spec", "e2e", "testing"];
pub(crate) const TEST_DIRS: &[&str] = &["test", "tests", "__tests__", "spec", "e2e"];
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
/// name. An absolute path such as `/tmp/run-1/out.log` gives none.
pub(crate) fn marked_terms(prompt: &str) -> Vec<(String, bool)> {
    let prompt = &without_paths(prompt);
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
                // `passes` is a task word whose singular form, `passe`, is not.
                && (shaped
                    || !(TASK_WORDS.contains(&term.as_str())
                        || TASK_WORDS.contains(&part.as_str())))
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
/// backticks, dotted (`click.Choice`), snake_case, camelCase or called
/// (`URL(...).normalize()`). A file name gives no words: `named` finds the
/// file, and its folders and name (`src/app/utils.py`) would map every
/// definition that mentions them.
fn words(prompt: &str) -> Vec<(String, bool)> {
    let mut found = Vec::new();
    for (span, ticked) in spans(prompt) {
        for written in tokens(span) {
            let token = written.trim_matches(['.', '-', '/']);
            if file_name(token).is_some() {
                continue;
            }
            let end = written.as_ptr() as usize - span.as_ptr() as usize + written.len();
            let called = span[end..].starts_with('(') && !span[end..].starts_with("(s)");
            let shaped = ticked
                || called
                || (written.starts_with('.') && !token.contains('/'))
                || token.contains(['.', '_'])
                || camel(token);
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

/// The names the prompt writes as code, spelled as written: `_batched`,
/// which `terms` reads as `batched`, and each dotted name whole as well
/// (`peekable.prepend`), which names a member. An absolute path gives none.
pub(crate) fn spellings(prompt: &str) -> Vec<String> {
    let prompt = &without_paths(prompt);
    let dotted = (spans(prompt).into_iter())
        .flat_map(|(span, _)| tokens(span))
        .map(|token| token.trim_matches(['.', '-', '/']))
        .filter(|token| token.contains('.') && !token.contains('/') && file_name(token).is_none())
        .map(str::to_owned);
    (words(prompt).into_iter())
        .filter(|(_, shaped)| *shaped)
        .map(|(word, _)| word)
        .chain(dotted)
        .collect()
}

/// What the prompt renames to what, both names written as code:
/// "rename `a` to `b`", "`a` -> `b`". A name written twice, or two names
/// side by side ("rename `a` and update `b`"), is no rename.
pub(crate) fn renames(prompt: &str) -> Vec<(String, String)> {
    let shaped = spellings(prompt);
    let spaced = prompt.replace('`', " ");
    let words: Vec<&str> = (spaced.split_whitespace())
        .map(|word| word.trim_matches([',', ';', ':', '"', '\'', '(', ')']))
        .map(|word| word.trim_end_matches('.'))
        .collect();
    (words.windows(3))
        .filter(|three| matches!(three[1].to_lowercase().as_str(), "to" | "into" | "->"))
        .filter(|three| {
            [three[0], three[2]]
                .iter()
                .all(|word| shaped.iter().any(|known| known == word))
        })
        .filter(|three| term_form(three[0]) != term_form(three[2]))
        .map(|three| (three[0].to_owned(), three[2].to_owned()))
        .collect()
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

/// A test or spec file by its usual name or folder in common languages.
pub(crate) fn test_file(relative: &str) -> bool {
    let lower = relative.to_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    let stem = name.rsplit_once('.').map_or(name, |(stem, _)| stem);
    lower.split('/').any(|part| TEST_DIRS.contains(&part))
        || name.contains(".test.")
        || name.contains(".spec.")
        || stem.starts_with("test_")
        || stem.ends_with("_test")
        || stem.ends_with("_tests")
        || stem.ends_with("_spec")
        || stem == "test"
        || stem == "tests"
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
        // A quote pasted with its line breaks reads as the source does once
        // unwrapped, however the source wraps it.
        let phrase = if phrase.contains('\n') {
            unwrapped(&phrase)
        } else {
            phrase
        };
        let phrase = first_words(phrase.trim().to_lowercase());
        if phrase.chars().count() >= 3
            && phrase.chars().any(char::is_alphanumeric)
            && !found.contains(&phrase)
        {
            found.push(phrase);
        }
        at += end + 2;
    }
    found
}

/// `phrase` cut to its first words that fit in `MAX_PHRASE_CHARS`. Every
/// file that holds the whole quote holds these words too, and a quote that
/// ends differently from the source (a period added or left off) still
/// matches.
fn first_words(phrase: String) -> String {
    let Some((cut, _)) = phrase.char_indices().nth(MAX_PHRASE_CHARS) else {
        return phrase;
    };
    let head = &phrase[..cut];
    let words = if phrase[cut..].starts_with(char::is_whitespace) {
        head
    } else {
        head.rsplit_once(char::is_whitespace)
            .map_or(head, |(words, _)| words)
    };
    words.trim_end().to_owned()
}

/// `text` with each line break, and the indent and comment mark after it,
/// read as one space: a docstring or comment wraps the sentence a prompt
/// quotes on one line ("...return the\n    result(s).").
pub(crate) fn unwrapped(text: &str) -> String {
    let mut joined = String::with_capacity(text.len());
    for line in text.lines().map(str::trim) {
        let after = line.trim_start_matches(['#', '/', '*', '!']);
        let line = if after.is_empty() || after.starts_with(char::is_whitespace) {
            after.trim_start()
        } else {
            line
        };
        if !line.is_empty() {
            joined.push_str(line);
            joined.push(' ');
        }
    }
    joined
}

/// For each of `phrases`, whether `text` holds it, on one line or wrapped.
pub(crate) fn quoted(text: &str, phrases: &[String]) -> Vec<bool> {
    let mut joined: Option<String> = None;
    (phrases.iter())
        .map(|phrase| {
            text.contains(phrase.as_str())
                || (text.contains('\n')
                    && (joined.get_or_insert_with(|| unwrapped(text))).contains(phrase.as_str()))
        })
        .collect()
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

/// Whether `text` holds `term` with no letter, digit or `_` on either side,
/// so `enum` is not found in `enumerate` nor `completion` in
/// `shell_completion`.
pub(crate) fn whole_word(text: &str, term: &str) -> bool {
    let part = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
    text.match_indices(term).any(|(at, _)| {
        !part(text[..at].chars().next_back()) && !part(text[at + term.len()..].chars().next())
    })
}

/// For each of `terms`, whether `text` holds it once `_` and `-` are
/// dropped. A term found as written, per `hits`, is held either way, so the
/// text is joined only when one is not.
pub(crate) fn spelled(text: &str, terms: &[String], hits: &[u8]) -> Vec<bool> {
    let mut joined: Option<String> = None;
    (terms.iter().zip(hits))
        .map(|(term, &hits)| {
            hits > 0
                || (text.contains(['_', '-'])
                    && joined
                        .get_or_insert_with(|| text.replace(['_', '-'], ""))
                        .contains(term.as_str()))
        })
        .collect()
}

/// For each of `terms`, whether the file's path holds it.
pub(crate) fn in_path(relative: &str, terms: &[String]) -> Vec<bool> {
    let lower = relative.to_lowercase().replace(['-', '_'], "");
    terms
        .iter()
        .map(|term| lower.contains(term.as_str()))
        .collect()
}

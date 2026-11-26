//! The context a prompt gets from the excerpts its search picked.

use super::names::holds;
use super::seen::Span;
use super::{Rendered, HEADER, MAX_CONTEXT_CHARS, MAX_OTHER_FILES, REPEATED_HEADER};
use crate::context_assistance_engine::PickedExcerpt;
use crate::context_assistance_prompt_files::{asks_for_tests, test_file};
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::path::Path;

/// Only excerpts that mention something the prompt asked about; nothing at
/// all when none do, so an unrelated prompt never carries project code. A
/// file this prompt's search did not rank, which an earlier prompt loaded,
/// must mention two different things it asked about, when it asked about
/// more than one. Tests an earlier prompt loaded give way to source here
/// too, unless this prompt asks about tests. Files this prompt's search
/// ranked come first, in that order, ahead of files an earlier prompt
/// loaded. An excerpt that mentions fewer than half as many of the prompt's
/// words as the best one does is a passing match, such as a progress bar
/// that only shares the word "error" with a request about choices, and is
/// left out. When tests give way, only source excerpts set that bar.
fn relevant<'a>(
    picked: &'a [PickedExcerpt],
    ranked: &[String],
    words: &[String],
) -> Vec<&'a PickedExcerpt> {
    // A quoted word is in `words` twice; each word counts once.
    let distinct: BTreeSet<&str> = words.iter().map(String::as_str).collect();
    let mut mentions: Vec<(&PickedExcerpt, usize)> = picked
        .iter()
        .map(|excerpt| {
            let text = excerpt.text.to_lowercase();
            let path = excerpt.path.to_lowercase().replace(['-', '_'], "");
            let mentioned = distinct
                .iter()
                .filter(|word| text.contains(**word) || path.contains(**word))
                .count();
            (excerpt, mentioned)
        })
        .filter(|(excerpt, mentioned)| {
            let needed = if distinct.len() > 1 && !ranked.contains(&excerpt.path) {
                2
            } else {
                1
            };
            *mentioned >= needed
        })
        .collect();
    // Tests give way before the best match is measured, so a test that
    // repeats the prompt's words cannot push the source it covers out. One
    // the search ranked stays: the prompt named it, or it alone holds a quote.
    // A test that stays still does not set the bar, so a source the prompt
    // names beside a quoted test keeps its code.
    let shown = |path: &String| !test_file(path) || ranked.contains(path);
    let tests_give_way =
        !asks_for_tests(words) && mentions.iter().any(|(e, _)| !test_file(&e.path));
    if tests_give_way {
        mentions.retain(|(excerpt, _)| shown(&excerpt.path));
    }
    let best = mentions
        .iter()
        .filter(|(excerpt, _)| !tests_give_way || !test_file(&excerpt.path))
        .map(|(_, mentioned)| *mentioned)
        .max();
    let close = best.unwrap_or_default().div_ceil(2);
    let mut found: Vec<&PickedExcerpt> = mentions
        .into_iter()
        .filter(|(_, mentioned)| *mentioned >= close)
        .map(|(excerpt, _)| excerpt)
        .collect();
    found.sort_by_key(|excerpt| {
        ranked
            .iter()
            .position(|path| *path == excerpt.path)
            .unwrap_or(usize::MAX)
    });
    found
}

/// The context text, never longer than `MAX_CONTEXT_CHARS`, or `None` when
/// no relevant excerpt fits. An excerpt an `earlier` prompt of the session
/// already showed is named rather than sent again. When the prompt `named`
/// project code, `None` too unless an excerpt shown or named holds some of
/// it: code that only shares the prompt's other words is about something
/// else, and the matched files serve better.
pub(super) fn render(
    picked: &[PickedExcerpt],
    found: &[String],
    words: &[String],
    earlier: &[Span],
    named: &[String],
) -> Option<Rendered> {
    let mut blocks = String::new();
    let mut shown: Vec<Span> = Vec::new();
    let mut repeated: Vec<Span> = Vec::new();
    let mut held = named.is_empty();
    for excerpt in relevant(picked, found, words) {
        let text = excerpt.text.trim_end();
        let span = Span::new(&excerpt.path, excerpt.start_line, excerpt.end_line, text);
        let code = as_code(&excerpt.path, text);
        if earlier.contains(&span) {
            held = held || holds(&code, named);
            repeated.push(span);
            continue;
        }
        let fence = fence_for(text);
        let block = format!(
            "\n\n{} (lines {}-{})\n{fence}{}\n{}\n{fence}",
            excerpt.path,
            excerpt.start_line,
            excerpt.end_line,
            language(&excerpt.path),
            text,
        );
        if HEADER.len() + blocks.len() + block.len() > MAX_CONTEXT_CHARS {
            continue;
        }
        held = held || holds(&code, named);
        blocks.push_str(&block);
        shown.push(span);
    }
    if !held {
        return None;
    }
    let mut out = match (shown.is_empty(), repeated.is_empty()) {
        (false, _) => format!("{HEADER}{blocks}"),
        (true, false) => REPEATED_HEADER.to_owned(),
        (true, true) => return None,
    };
    let mut before = String::new();
    for span in &repeated {
        let item = if before.is_empty() {
            format!("\n\nAlready shown earlier in this session: {}", lines(span))
        } else {
            format!(", {}", lines(span))
        };
        if out.len() + before.len() + item.len() > MAX_CONTEXT_CHARS {
            break;
        }
        before.push_str(&item);
    }
    out.push_str(&before);
    let named = |path: &str| shown.iter().chain(&repeated).any(|span| span.path == path);
    let others = found
        .iter()
        .map(String::as_str)
        .filter(|path| !named(path))
        .take(MAX_OTHER_FILES);
    let mut listed = String::new();
    for path in others {
        let item = if listed.is_empty() {
            format!("\n\nOther matching files: {path}")
        } else {
            format!(", {path}")
        };
        if out.len() + listed.len() + item.len() > MAX_CONTEXT_CHARS {
            break;
        }
        listed.push_str(&item);
    }
    out.push_str(&listed);
    Some(Rendered { text: out, shown })
}

/// What a prose file writes as code: fenced blocks (``` or ~~~), inline
/// code between matching backtick runs on one line (Markdown, and the
/// double backticks of reStructuredText), and words shaped like code
/// (`parse_args`, `ScheduleWakeup`, `run()`, `a::b`). Other files count
/// whole, and so does an excerpt whose fences do not balance, such as a
/// chunk that starts inside a code block. A plan that only uses a word the
/// prompt wrote as code, as in "with a reproducible prompt" for `prompt`,
/// is not about that code.
fn as_code<'a>(path: &str, text: &'a str) -> Cow<'a, str> {
    let extension = Path::new(path).extension().and_then(|ext| ext.to_str());
    let prose = ["md", "mdx", "markdown", "rst", "txt", "adoc"];
    if !extension.is_some_and(|ext| prose.iter().any(|p| ext.eq_ignore_ascii_case(p))) {
        return Cow::Borrowed(text);
    }
    let mut code = Vec::new();
    let mut fence: Option<(char, usize)> = None;
    for line in text.lines() {
        let trimmed = line.trim_start();
        let mark = trimmed.chars().next().filter(|c| matches!(c, '`' | '~'));
        let run = mark.map_or(0, |m| trimmed.chars().take_while(|&c| c == m).count());
        match (fence, mark) {
            (Some((open, len)), Some(m))
                if m == open && run >= len && trimmed[run..].trim().is_empty() =>
            {
                fence = None
            }
            (Some(_), _) => code.push(line),
            // A backtick fence's info string has no backticks, so
            // ```code``` on one line is inline code.
            (None, Some(m)) if run >= 3 && (m == '~' || !trimmed[run..].contains('`')) => {
                fence = Some((m, run))
            }
            (None, _) => {
                code.extend(inline_code(line));
                code.extend(line.split_whitespace().filter(|word| shaped(word)));
            }
        }
    }
    if fence.is_some() {
        return Cow::Borrowed(text);
    }
    Cow::Owned(code.join("\n"))
}

/// Text between a run of backticks and the next run of the same length on
/// the same line. An opening run with no match is a literal backtick.
fn inline_code(line: &str) -> Vec<&str> {
    let mut spans = Vec::new();
    let mut rest = line;
    while let Some(open) = rest.find('`') {
        let run = rest[open..].bytes().take_while(|&b| b == b'`').count();
        let after = &rest[open + run..];
        let mut at = 0;
        rest = after;
        while let Some(found) = after[at..].find('`') {
            let start = at + found;
            let len = after[start..].bytes().take_while(|&b| b == b'`').count();
            if len == run {
                spans.push(&after[..start]);
                rest = &after[start + len..];
                break;
            }
            at = start + len;
        }
    }
    spans
}

/// A word written the way code is: a capital inside it, an underscore
/// between letters (not `_emphasis_`), a call (`run(`, not "(prompt"), or
/// a path (`a::b`).
fn shaped(word: &str) -> bool {
    let chars: Vec<char> = word.chars().collect();
    let inner_capital = chars
        .windows(2)
        .any(|p| p[0].is_lowercase() && p[1].is_uppercase());
    let inner_underscore = chars
        .windows(3)
        .any(|w| w[1] == '_' && w[0].is_alphanumeric() && w[2].is_alphanumeric());
    let call = chars
        .windows(2)
        .any(|p| p[1] == '(' && (p[0].is_alphanumeric() || p[0] == '_'));
    inner_capital || inner_underscore || call || word.contains("::")
}

fn lines(span: &Span) -> String {
    format!("{} (lines {}-{})", span.path, span.start, span.end)
}

/// A backtick fence longer than any backtick run in `text`, so file
/// contents that hold their own fences cannot close the block early.
pub(super) fn fence_for(text: &str) -> String {
    let longest = text.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    "`".repeat(longest.max(2) + 1)
}

pub(super) fn language(path: &str) -> &'static str {
    let extension = Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match extension.as_str() {
        "ts" | "mts" | "cts" => "ts",
        "tsx" => "tsx",
        "js" | "mjs" | "cjs" => "js",
        "jsx" => "jsx",
        "py" => "python",
        "rs" => "rust",
        "go" => "go",
        "css" | "scss" | "sass" | "less" => "css",
        "html" | "vue" | "svelte" | "astro" => "html",
        "json" => "json",
        "md" | "mdx" => "markdown",
        "sh" => "bash",
        "yaml" | "yml" => "yaml",
        "toml" => "toml",
        _ => "",
    }
}

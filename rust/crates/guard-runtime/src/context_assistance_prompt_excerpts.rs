//! The context a prompt gets from the excerpts its search picked.

use super::names::holds;
use super::seen::Span;
use super::{Rendered, HEADER, MAX_CONTEXT_CHARS, MAX_OTHER_FILES, REPEATED_HEADER};
use crate::context_assistance_engine::PickedExcerpt;
use crate::context_assistance_prompt_files::{asks_for_tests, test_file};
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
        if earlier.contains(&span) {
            held = held || holds(text, named);
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
        held = held || holds(text, named);
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

//! Comment stripping and statement splitting for script source, so a path
//! named in a note is not read as one the script opens and an inline
//! statement is scanned on its own line.

use super::Language;

/// The source without ordinary comments, so a path in a note is not
/// mistaken for one the script opens. Python comment markers inside quoted
/// strings are not comments: truncating there would hide later statements.
/// When the simple quote scan cannot establish the boundary (triple-quoted
/// strings, f-string fields or line continuations), retain the full Python
/// line and split semicolons conservatively, erring toward review.
pub(super) fn code_lines(language: Language, source: &str) -> String {
    let marker = match language {
        Language::Python => "#",
        Language::Node => "//",
    };
    // Python treats bare CR, LF and CRLF as physical line boundaries.
    // Preserve those boundaries before stripping comments to avoid hiding code.
    let normalized: std::borrow::Cow<'_, str> = if source.contains('\r') {
        std::borrow::Cow::Owned(source.replace("\r\n", "\n").replace('\r', "\n"))
    } else {
        std::borrow::Cow::Borrowed(source)
    };
    let opaque_python = language == Language::Python
        && (normalized.contains("\"\"\"")
            || normalized.contains("'''")
            || normalized.contains("\\\n"));
    let mut code = String::with_capacity(normalized.len());
    let mut in_block = false;
    for line in normalized.lines() {
        let trimmed = line.trim_start();
        if language == Language::Node && (in_block || trimmed.starts_with("/*")) {
            in_block = !trimmed.contains("*/");
            if in_block || trimmed.trim_end().ends_with("*/") {
                continue;
            }
        }
        if language == Language::Node && trimmed.starts_with(marker) {
            continue;
        }
        let end = match language {
            Language::Python if opaque_python => line.len(),
            Language::Python => python_comment_end(line),
            Language::Node => line
                .match_indices(marker)
                .find(|(at, _)| line[..*at].ends_with([' ', '\t']))
                .map_or(line.len(), |(at, _)| at),
        };
        // Python inline commands can put statements on one line.
        match language {
            // Continued strings, triple quotes and f-strings make quote state
            // across physical lines uncertain. Split every semicolon in this
            // case, even if it looks quoted, rather than hide a later import.
            Language::Python if opaque_python => {
                code.push_str(&line[..end].replace(';', "\n"));
            }
            Language::Python => code.push_str(&split_statements(&line[..end])),
            Language::Node => code.push_str(&line[..end]),
        }
        code.push('\n');
    }
    if language == Language::Python && normalized.contains("\\\n") {
        // Explicit backslash-newline joins Python tokens, including an import
        // keyword and its module name. Inspect the joined form *in addition*
        // to physical lines: a backslash in a Python comment does not join
        // the next line, which may itself contain an executable import.
        // Keep comments and split all semicolons in the extra scan so no
        // apparent quote boundary can hide a sensitive operation.
        let joined = normalized.replace("\\\n", "");
        code.push('\n');
        code.push_str(&joined.replace(';', "\n"));
    }
    code
}

/// Find a Python comment boundary only when it is outside an ordinary
/// single- or double-quoted string. Ambiguous syntax is not stripped:
/// keeping more source can cause review, but cannot hide a later operation.
fn python_comment_end(line: &str) -> usize {
    if line.contains("\"\"\"") || line.contains("'''") || line.contains('{') {
        return line.len();
    }
    let (mut quote, mut escaped) = (None, false);
    for (offset, character) in line.char_indices() {
        match quote {
            Some(_) if escaped => escaped = false,
            Some(_) if character == '\\' => escaped = true,
            Some(open) if character == open => quote = None,
            Some(_) => {}
            None if matches!(character, '\'' | '"') => quote = Some(character),
            None if character == '#' => return offset,
            None => {}
        }
    }
    line.len()
}

/// A Python line with each `;` outside a string literal starting a new line.
/// A line whose strings this cannot follow, with a triple quote, an f-string
/// field or a string left open, splits at every `;`, which only finds more.
fn split_statements(line: &str) -> String {
    let everywhere = || line.replace(';', "\n");
    if line.contains("\"\"\"") || line.contains("'''") || line.contains('{') {
        return everywhere();
    }
    let mut split = String::with_capacity(line.len());
    let (mut quote, mut escaped) = (None, false);
    for character in line.chars() {
        match quote {
            Some(_) if escaped => escaped = false,
            Some(_) if character == '\\' => escaped = true,
            Some(open) if character == open => quote = None,
            Some(_) => {}
            None if matches!(character, '\'' | '"') => quote = Some(character),
            None if character == ';' => {
                split.push('\n');
                continue;
            }
            None => {}
        }
        split.push(character);
    }
    if quote.is_some() {
        return everywhere();
    }
    split
}

#[cfg(test)]
mod normalization_tests {
    use super::code_lines;
    use crate::pretool::script_content::{python_network, Language};

    #[test]
    fn python_bare_carriage_return_does_not_hide_network_imports() {
        let code = code_lines(Language::Python, "print(1) #\rimport socket\n");
        assert!(python_network(&code));
        let code = code_lines(Language::Python, "marker = \" #\"; import socket\r");
        assert!(python_network(&code));
    }

    #[test]
    fn python_continued_string_does_not_hide_an_inline_network_import() {
        // Python joins the physical lines before parsing this statement.
        // A quote in the comment must not pair with the continued string.
        let source = concat!("marker = \"a\\\n", "b\"; import socket # \"\n");
        let code = code_lines(Language::Python, source);
        assert!(python_network(&code), "normalized source: {code:?}");
    }

    #[test]
    fn python_explicit_continuation_cannot_hide_imports_or_following_line() {
        for source in [
            concat!("import \\", "\n socket\n"),
            concat!("import so\\", "\ncket\n"),
            concat!("from \\", "\n socket import create_connection\n"),
            concat!("print(1) #\\", "\nimport socket\n"),
        ] {
            let code = code_lines(Language::Python, source);
            assert!(python_network(&code), "normalized source: {code:?}");
        }
    }
}

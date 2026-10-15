//! Aliased imports of process and filesystem modules in inline Python
//! (`_script_has_aliased_risky_import` in `shell_static_safety.py`).
//!
//! Python parses the script and walks its tree. Rust has no Python parser, so
//! this reads the same statements from a lexical pass that masks comments and
//! string literals. A script that Python rejects as a syntax error is not
//! treated as safe here: an aliased risky import in it still reports `true`,
//! which only makes the caller stricter.

// Consumed by the later classifier slices.
#![allow(dead_code)]

use unicode_normalization::UnicodeNormalization;

const RISKY_ROOTS: [&str; 4] = ["os", "pathlib", "shutil", "subprocess"];

/// Python NFKC-normalises identifiers while parsing, so a module spelled with
/// compatibility characters names the same module as its ASCII form.
fn is_risky_root(name: &str) -> bool {
    let normalized: String = name.nfkc().collect();
    RISKY_ROOTS.contains(&normalized.as_str())
}

#[derive(Debug, PartialEq, Eq)]
enum Token {
    Word(String),
    Symbol(char),
    Newline,
}

fn is_word_start(c: char) -> bool {
    c == '_' || c.is_alphabetic()
}

fn is_word_char(c: char) -> bool {
    c == '_' || c.is_alphanumeric()
}

/// Split `script` into words, single-character symbols and logical newlines.
/// Comments and string literals produce no tokens; newlines inside brackets
/// and after a backslash do not end the statement.
fn tokenize(script: &str) -> Vec<Token> {
    // Python normalises CRLF and lone CR to LF before tokenizing.
    let normalized = script.replace("\r\n", "\n").replace('\r', "\n");
    let chars: Vec<char> = normalized.chars().collect();
    let mut tokens = Vec::new();
    let mut depth = 0usize;
    let mut index = 0;
    while index < chars.len() {
        let c = chars[index];
        if c == '#' {
            while index < chars.len() && chars[index] != '\n' {
                index += 1;
            }
            continue;
        }
        if c == '\\' && chars.get(index + 1) == Some(&'\n') {
            index += 2;
            continue;
        }
        if c == '\n' || c == '\r' {
            if depth == 0 {
                tokens.push(Token::Newline);
            }
            index += 1;
            continue;
        }
        if c.is_whitespace() {
            index += 1;
            continue;
        }
        if c == '"' || c == '\'' {
            index = skip_string(&chars, index, false);
            continue;
        }
        if is_word_start(c) {
            let start = index;
            while index < chars.len() && is_word_char(chars[index]) {
                index += 1;
            }
            // String prefixes (`b"..."`, `rf'...'`) belong to the literal.
            let word: String = chars[start..index].iter().collect();
            if index < chars.len()
                && (chars[index] == '"' || chars[index] == '\'')
                && word.len() <= 2
                && word
                    .chars()
                    .all(|ch| matches!(ch.to_ascii_lowercase(), 'r' | 'b' | 'u' | 'f'))
            {
                let formatted = word.chars().any(|ch| matches!(ch, 'f' | 'F'));
                index = skip_string(&chars, index, formatted);
                continue;
            }
            tokens.push(Token::Word(word));
            continue;
        }
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
        tokens.push(Token::Symbol(c));
        index += 1;
    }
    tokens
}

/// Index just past the string literal that opens at `start`. In an f-string
/// (`formatted`) the replacement fields hold expressions that may contain
/// their own quotes (PEP 701), so they are skipped as nested code rather than
/// as string text.
fn skip_string(chars: &[char], start: usize, formatted: bool) -> usize {
    let quote = chars[start];
    let triple = chars.get(start + 1) == Some(&quote) && chars.get(start + 2) == Some(&quote);
    let mut index = start + if triple { 3 } else { 1 };
    while index < chars.len() {
        let c = chars[index];
        if c == '\\' {
            index += 2;
            continue;
        }
        if formatted && c == '{' {
            if chars.get(index + 1) == Some(&'{') {
                index += 2;
            } else {
                index = skip_replacement_field(chars, index + 1);
            }
            continue;
        }
        if triple {
            if c == quote
                && chars.get(index + 1) == Some(&quote)
                && chars.get(index + 2) == Some(&quote)
            {
                return index + 3;
            }
        } else if c == quote {
            return index + 1;
        } else if c == '\n' {
            return index;
        }
        index += 1;
    }
    chars.len()
}

/// Index just past the `}` that closes the replacement field whose body
/// starts at `start`.
fn skip_replacement_field(chars: &[char], start: usize) -> usize {
    let mut depth = 0usize;
    let mut index = start;
    while index < chars.len() {
        match chars[index] {
            '"' | '\'' => {
                let prefix = chars[start..index]
                    .iter()
                    .rev()
                    .take_while(|ch| ch.is_ascii_alphabetic())
                    .count()
                    .min(2);
                let formatted = chars[index - prefix..index]
                    .iter()
                    .any(|ch| matches!(ch, 'f' | 'F'));
                index = skip_string(chars, index, formatted);
                continue;
            }
            '{' | '(' | '[' => depth += 1,
            '}' if depth == 0 => return index + 1,
            '}' | ')' | ']' => depth = depth.saturating_sub(1),
            // A top-level colon starts the format spec, where quotes are plain
            // text (`f"{x:'>10}"` uses `'` as the fill character).
            ':' if depth == 0 => return skip_format_spec(chars, index + 1),
            _ => {}
        }
        index += 1;
    }
    chars.len()
}

/// Index just past the `}` that ends a format spec starting at `start`.
/// Nested replacement fields inside the spec are skipped as code.
fn skip_format_spec(chars: &[char], start: usize) -> usize {
    let mut index = start;
    while index < chars.len() {
        match chars[index] {
            '}' => return index + 1,
            '{' => index = skip_replacement_field(chars, index + 1),
            _ => index += 1,
        }
    }
    chars.len()
}

/// Whether any import statement aliases `os`, `pathlib`, `shutil` or
/// `subprocess` (`import os as o`, `from os import path as p`).
pub(crate) fn script_has_aliased_risky_import(script: &str) -> bool {
    let tokens = tokenize(script);
    let mut index = 0;
    while index < tokens.len() {
        let Token::Word(word) = &tokens[index] else {
            index += 1;
            continue;
        };
        let previous_is_dot = index > 0 && tokens[index - 1] == Token::Symbol('.');
        if previous_is_dot || (word != "import" && word != "from") {
            index += 1;
            continue;
        }
        let end = statement_end(&tokens, index);
        let statement = &tokens[index + 1..end];
        if word == "import" {
            if import_statement_aliases(statement) {
                return true;
            }
        } else if from_statement_aliases(statement) {
            return true;
        }
        index = end.max(index + 1);
    }
    false
}

fn statement_end(tokens: &[Token], start: usize) -> usize {
    let mut index = start + 1;
    while index < tokens.len() {
        if matches!(tokens[index], Token::Newline | Token::Symbol(';')) {
            return index;
        }
        index += 1;
    }
    index
}

fn dotted_root(statement: &[Token], start: usize) -> Option<&str> {
    match statement.get(start) {
        Some(Token::Word(word)) => Some(word.as_str()),
        _ => None,
    }
}

/// `import a.b as c, d`.
fn import_statement_aliases(statement: &[Token]) -> bool {
    let mut index = 0;
    while index < statement.len() {
        let root = dotted_root(statement, index);
        // Walk one `dotted.name [as alias]` item.
        let mut cursor = index;
        while matches!(statement.get(cursor), Some(Token::Word(_)))
            && matches!(statement.get(cursor + 1), Some(Token::Symbol('.')))
        {
            cursor += 2;
        }
        if matches!(statement.get(cursor), Some(Token::Word(_))) {
            cursor += 1;
        }
        let aliased = matches!(statement.get(cursor), Some(Token::Word(word)) if word == "as");
        if aliased && root.is_some_and(is_risky_root) {
            return true;
        }
        while cursor < statement.len() && statement[cursor] != Token::Symbol(',') {
            cursor += 1;
        }
        index = cursor + 1;
    }
    false
}

/// `from a.b import c as d`.
fn from_statement_aliases(statement: &[Token]) -> bool {
    let Some(import_at) = statement
        .iter()
        .position(|token| matches!(token, Token::Word(word) if word == "import"))
    else {
        return false;
    };
    let first_name = statement
        .iter()
        .position(|token| !matches!(token, Token::Symbol('.')))
        .unwrap_or(statement.len());
    let Some(root) = dotted_root(statement, first_name) else {
        return false;
    };
    if !is_risky_root(root) {
        return false;
    }
    statement[import_at + 1..]
        .iter()
        .any(|token| matches!(token, Token::Word(word) if word == "as"))
}

#[cfg(test)]
mod tests {
    use super::script_has_aliased_risky_import;

    #[test]
    fn detects_aliased_risky_imports() {
        for script in [
            "import os as o",
            "import sys, os.path as p",
            "from subprocess import run as r",
            "from os import (\n  path as p,\n)",
            "if 1:\n    import shutil as s",
            "x = 1; import pathlib as pl",
            "from .os import path as p",
            "from \u{ff4f}\u{ff53} import remove as r\nr('x')",
            "import \u{ff53}ubprocess as sp",
            "f\"{\"'''\"}\"\nimport os as o\n#'''",
            "f\"{x!r:>{width}}\"\nimport os as o",
            "f\"{x:'>10}\" import os as o #'",
            "# x\rfrom os import system as s\rs('id')",
            "from os import system \\\r\n as s\r\ns('id')",
        ] {
            assert!(script_has_aliased_risky_import(script), "{script}");
        }
    }

    #[test]
    fn ignores_plain_imports_strings_and_other_modules() {
        for script in [
            "import os",
            "from os import path",
            "import json as j",
            "print('import os as o')",
            "# import os as o",
            "x = \"\"\"\nimport os as o\n\"\"\"",
            "from collections import OrderedDict as od",
            "obj.import_thing",
            "f\"{\"import os as o\"}\"",
            "f\"{{import os as o}}\"",
        ] {
            assert!(!script_has_aliased_risky_import(script), "{script}");
        }
    }
}

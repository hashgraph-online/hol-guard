//! Whether the source of a `python3 -c` program only computes and prints.
//!
//! The program is split into words and marks with every string literal and
//! comment set aside, except the expressions an f-string evaluates. Imports
//! must name a module from [`super::names`], each imported module may only be
//! used as `module.attribute` with an allowed attribute, and no word may name
//! a builtin that opens a file, reads the terminal, starts a pager or reaches
//! another object's internals.

use super::names;
use std::collections::HashSet;

#[derive(Debug, PartialEq)]
enum Token {
    Word(String),
    Number,
    Mark(char),
    Text,
    End,
}

/// Builtins and attribute names that open files, evaluate text, read the
/// terminal, start a pager, or reach an object's namespace or frame. String
/// formatting is here too: a replacement field such as `{0.attr[key]}` walks
/// attributes, and string literals are not screened as code.
const BANNED: &[&str] = &[
    "Formatter",
    "attrgetter",
    "breakpoint",
    "builtins",
    "compile",
    "copyright",
    "credits",
    "delattr",
    "dir",
    "eval",
    "exec",
    "execfile",
    "file",
    "format",
    "format_map",
    "getattr",
    "globals",
    "help",
    "input",
    "license",
    "locals",
    "memoryview",
    "methodcaller",
    "modules",
    "open",
    "raw_input",
    "reload",
    "setattr",
    "type",
    "vars",
    "vformat",
];

/// Attribute prefixes of generator, coroutine, frame, traceback and code
/// objects, which lead back to a module namespace without a dunder.
const INTERNAL_PREFIXES: &[&str] = &["ag_", "co_", "cr_", "f_", "gi_", "tb_"];

const STRING_PREFIXES: &[&str] = &["b", "br", "f", "fr", "r", "rb", "rf", "rt", "t", "tr", "u"];

/// Whether `program` only computes over its input and prints the result.
pub(super) fn screened(program: &str) -> bool {
    if !program.is_ascii()
        || program.contains(['\0', '\x0c'])
        || program.contains("__")
        || program.contains("coding")
    {
        return false;
    }
    let Some(tokens) = lex(program) else {
        return false;
    };
    words_allowed(&tokens) && imports_allowed(&tokens)
}

fn lex(source: &str) -> Option<Vec<Token>> {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0;
    while let Some(&character) = chars.get(index) {
        match character {
            // CPython treats bare CR as a physical line ending too. A comment
            // must not conceal a following import across a CR-only boundary.
            '#' => {
                while chars.get(index).is_some_and(|c| !matches!(*c, '\n' | '\r')) {
                    index += 1;
                }
            }
            '\n' | '\r' | ';' => {
                tokens.push(Token::End);
                index += 1;
            }
            '\\' if chars.get(index + 1) == Some(&'\n') => index += 2,
            '\\' => return None,
            '\'' | '"' => index = string(&chars, index, false, &mut tokens)?,
            c if c.is_ascii_whitespace() => index += 1,
            c if c.is_ascii_alphabetic() || c == '_' => {
                let start = index;
                while chars
                    .get(index)
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
                {
                    index += 1;
                }
                let word: String = chars[start..index].iter().collect();
                let lower = word.to_ascii_lowercase();
                if matches!(chars.get(index), Some('\'' | '"'))
                    && STRING_PREFIXES.contains(&lower.as_str())
                {
                    index = string(&chars, index, lower.contains(['f', 't']), &mut tokens)?;
                } else {
                    tokens.push(Token::Word(word));
                }
            }
            c if c.is_ascii_digit() => {
                while chars
                    .get(index)
                    .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'))
                {
                    index += 1;
                }
                tokens.push(Token::Number);
            }
            c => {
                tokens.push(Token::Mark(c));
                index += 1;
            }
        }
    }
    Some(tokens)
}

/// Skips the string literal that opens at `start`. An f-string's replacement
/// fields are lexed as code; the expression may not use the delimiter's quote
/// or a backslash, so the field cannot hide where the literal ends.
fn string(chars: &[char], start: usize, formatted: bool, tokens: &mut Vec<Token>) -> Option<usize> {
    let quote = chars[start];
    let triple = chars.get(start + 1) == Some(&quote) && chars.get(start + 2) == Some(&quote);
    let mut index = start + if triple { 3 } else { 1 };
    let mut depth = 0usize;
    let mut field = String::new();
    let mut inner: Option<char> = None;
    loop {
        let character = *chars.get(index)?;
        if character == '\n' && !triple && (depth == 0 || inner.is_some()) {
            return None;
        }
        if depth > 0 {
            match character {
                '\\' => return None,
                c if c == quote => return None,
                c if inner == Some(c) => inner = None,
                '\'' | '"' if inner.is_none() => inner = Some(character),
                '{' if inner.is_none() => depth += 1,
                '}' if inner.is_none() => depth -= 1,
                _ => {}
            }
            if depth == 0 {
                tokens.extend(lex(&field)?);
                tokens.push(Token::End);
                field.clear();
            } else {
                field.push(character);
            }
            index += 1;
            continue;
        }
        match character {
            '\\' => index += 2,
            c if c == quote
                && (!triple
                    || (chars.get(index + 1) == Some(&quote)
                        && chars.get(index + 2) == Some(&quote))) =>
            {
                tokens.push(Token::Text);
                return Some(index + if triple { 3 } else { 1 });
            }
            '{' | '}' if formatted && chars.get(index + 1) == Some(&character) => index += 2,
            '{' if formatted => {
                depth = 1;
                index += 1;
            }
            '}' if formatted => return None,
            _ => index += 1,
        }
    }
}

fn word(tokens: &[Token], index: usize) -> Option<&str> {
    match tokens.get(index) {
        Some(Token::Word(word)) => Some(word),
        _ => None,
    }
}

fn mark(tokens: &[Token], index: usize, expected: char) -> bool {
    tokens.get(index) == Some(&Token::Mark(expected))
}

fn words_allowed(tokens: &[Token]) -> bool {
    tokens.iter().enumerate().all(|(index, token)| {
        let Token::Word(name) = token else {
            return true;
        };
        let attribute = index > 0 && mark(tokens, index - 1, '.');
        if attribute
            && (name.starts_with('_')
                || INTERNAL_PREFIXES
                    .iter()
                    .any(|prefix| name.starts_with(prefix)))
        {
            return false;
        }
        if !BANNED.contains(&name.as_str()) {
            return true;
        }
        // `re.compile` builds a pattern, and `print(..., file=sys.stderr)`
        // names the stream to print to.
        (name == "compile" && attribute && index >= 2 && word(tokens, index - 2) == Some("re"))
            || (name == "file" && mark(tokens, index + 1, '=') && !mark(tokens, index + 2, '='))
    })
}

fn statement_start(tokens: &[Token], index: usize) -> bool {
    index == 0 || matches!(tokens.get(index - 1), Some(Token::End | Token::Mark(':')))
}

fn statement_end(tokens: &[Token], index: usize) -> bool {
    matches!(tokens.get(index), None | Some(Token::End))
}

/// Every import names an allowed module plainly, and every later use of an
/// imported module reads one allowed attribute from it.
fn imports_allowed(tokens: &[Token]) -> bool {
    let mut imported = HashSet::new();
    let mut statements = HashSet::new();
    let mut index = 0;
    while index < tokens.len() {
        let is_import = word(tokens, index) == Some("import") && statement_start(tokens, index);
        let is_from = word(tokens, index) == Some("from")
            && statement_start(tokens, index)
            && word(tokens, index + 2) == Some("import");
        if is_import {
            let start = index;
            index += 1;
            loop {
                let Some(module) = word(tokens, index).filter(|module| names::importable(module))
                else {
                    return false;
                };
                imported.insert(module.to_owned());
                index += 1;
                if mark(tokens, index, ',') {
                    index += 1;
                } else if statement_end(tokens, index) {
                    break;
                } else {
                    return false;
                }
            }
            statements.extend(start..index);
        } else if is_from {
            let start = index;
            let Some(module) = word(tokens, index + 1).filter(|module| names::importable(module))
            else {
                return false;
            };
            index += 3;
            let grouped = mark(tokens, index, '(');
            index += usize::from(grouped);
            loop {
                while grouped && tokens.get(index) == Some(&Token::End) {
                    index += 1;
                }
                if grouped && mark(tokens, index, ')') {
                    index += 1;
                    break;
                }
                let Some(name) = word(tokens, index) else {
                    return false;
                };
                if !names::attribute_allowed(module, name) {
                    return false;
                }
                index += 1;
                while grouped && tokens.get(index) == Some(&Token::End) {
                    index += 1;
                }
                if mark(tokens, index, ',') {
                    index += 1;
                } else if grouped && mark(tokens, index, ')') {
                    index += 1;
                    break;
                } else if !grouped && statement_end(tokens, index) {
                    break;
                } else {
                    return false;
                }
            }
            if !statement_end(tokens, index) {
                return false;
            }
            statements.extend(start..index);
        } else {
            index += 1;
        }
    }
    tokens.iter().enumerate().all(|(index, token)| {
        let Token::Word(name) = token else {
            return true;
        };
        if statements.contains(&index) {
            return true;
        }
        if name == "import" {
            return false;
        }
        if !imported.contains(name) || (index > 0 && mark(tokens, index - 1, '.')) {
            return true;
        }
        mark(tokens, index + 1, '.')
            && word(tokens, index + 2)
                .is_some_and(|attribute| names::attribute_allowed(name, attribute))
    })
}

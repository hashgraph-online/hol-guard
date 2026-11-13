//! Shell words and the boundaries between simple commands.
//!
//! Unlike a plain word split, this keeps unquoted `;`, `&`, `|`, parentheses
//! and newlines as boundaries, so `echo ';' rm x` stays one command and
//! `echo ready` followed by `rm x` on the next line becomes two. Quoted text
//! stays inside its word. A command substitution (`$(...)`, backticks, and
//! `<(...)`/`>(...)`) is handed back as its own command without ending the
//! outer one, also inside double quotes. Here-document bodies are input, not
//! commands, and are skipped. An unclosed quote runs to the end of the
//! command, so a malformed command still yields its words.

use std::iter::Peekable;
use std::str::Chars;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Token {
    Word(String),
    /// Ends a simple command.
    Boundary,
    /// `<`, `>` and their variants: the next word is a redirection target.
    Redirect,
    /// A command substitution's text, run as its own command.
    Substitution(String),
}

pub(super) fn tokens(command: &str) -> Vec<Token> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut heredocs: Vec<(String, bool)> = Vec::new();
    let mut chars = command.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                for quoted in chars.by_ref() {
                    if quoted == '\'' {
                        break;
                    }
                    word.push(quoted);
                }
            }
            '"' => {
                in_word = true;
                while let Some(quoted) = chars.next() {
                    match quoted {
                        '"' => break,
                        '\\' => match chars.next() {
                            Some(escaped @ ('"' | '\\' | '$' | '`')) => word.push(escaped),
                            Some('\n') | None => {}
                            Some(other) => {
                                word.push('\\');
                                word.push(other);
                            }
                        },
                        '$' if chars.next_if_eq(&'(').is_some() => {
                            out.push(Token::Substitution(until_close_paren(&mut chars)));
                        }
                        '`' => out.push(Token::Substitution(until_backtick(&mut chars))),
                        _ => word.push(quoted),
                    }
                }
            }
            '\\' => {
                if let Some(escaped) = chars.next().filter(|next| *next != '\n') {
                    in_word = true;
                    word.push(escaped);
                }
            }
            '$' if chars.next_if_eq(&'(').is_some() => {
                in_word = true;
                out.push(Token::Substitution(until_close_paren(&mut chars)));
            }
            '`' => {
                in_word = true;
                out.push(Token::Substitution(until_backtick(&mut chars)));
            }
            '#' if !in_word => while chars.next_if(|next| *next != '\n').is_some() {},
            ' ' | '\t' | '\r' => finish(&mut out, &mut word, &mut in_word),
            '\n' => {
                finish(&mut out, &mut word, &mut in_word);
                out.push(Token::Boundary);
                for (delimiter, strip_tabs) in heredocs.drain(..) {
                    skip_heredoc_body(&mut chars, &delimiter, strip_tabs);
                }
            }
            ';' | '|' | '(' | ')' => {
                finish(&mut out, &mut word, &mut in_word);
                out.push(Token::Boundary);
            }
            '&' => {
                finish(&mut out, &mut word, &mut in_word);
                if chars.next_if_eq(&'>').is_some() {
                    chars.next_if_eq(&'>');
                    out.push(Token::Redirect);
                } else {
                    out.push(Token::Boundary);
                }
            }
            '<' | '>' => {
                // A descriptor number before the operator (`2>`) is not a word.
                if in_word && !word.is_empty() && word.chars().all(|d| d.is_ascii_digit()) {
                    word.clear();
                    in_word = false;
                } else {
                    finish(&mut out, &mut word, &mut in_word);
                }
                if chars.next_if_eq(&'(').is_some() {
                    // `<(...)` and `>(...)` run a command; they name no file.
                    out.push(Token::Substitution(until_close_paren(&mut chars)));
                    continue;
                }
                let mut operator = String::from(c);
                while let Some(next) = chars.next_if(|next| matches!(next, '<' | '>')) {
                    operator.push(next);
                }
                if operator == "<<" {
                    let strip_tabs = chars.next_if_eq(&'-').is_some();
                    if let Some(delimiter) = heredoc_delimiter(&mut chars) {
                        heredocs.push((delimiter, strip_tabs));
                    }
                } else if chars.next_if_eq(&'&').is_some() {
                    // `>&2` copies a descriptor and names no file.
                    while chars
                        .next_if(|next| next.is_ascii_digit() || *next == '-')
                        .is_some()
                    {}
                } else {
                    out.push(Token::Redirect);
                }
            }
            _ => {
                in_word = true;
                word.push(c);
            }
        }
    }
    finish(&mut out, &mut word, &mut in_word);
    out
}

fn finish(out: &mut Vec<Token>, word: &mut String, in_word: &mut bool) {
    if *in_word {
        out.push(Token::Word(std::mem::take(word)));
        *in_word = false;
    }
}

/// The text up to the `)` that closes an already-opened `(`, with nested
/// parentheses and quoted text kept whole.
fn until_close_paren(chars: &mut Peekable<Chars>) -> String {
    let mut text = String::new();
    let mut depth = 1;
    while let Some(c) = chars.next() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            '\'' | '"' => {
                text.push(c);
                while let Some(quoted) = chars.next() {
                    text.push(quoted);
                    if quoted == '\\' && c == '"' {
                        if let Some(escaped) = chars.next() {
                            text.push(escaped);
                        }
                    } else if quoted == c {
                        break;
                    }
                }
                continue;
            }
            '\\' => {
                text.push(c);
                if let Some(escaped) = chars.next() {
                    text.push(escaped);
                }
                continue;
            }
            _ => {}
        }
        text.push(c);
    }
    text
}

fn until_backtick(chars: &mut Peekable<Chars>) -> String {
    let mut text = String::new();
    while let Some(c) = chars.next() {
        match c {
            '`' => break,
            '\\' => {
                if let Some(escaped) = chars.next() {
                    text.push(escaped);
                }
            }
            _ => text.push(c),
        }
    }
    text
}

/// The word after `<<`, with its quotes removed, as the body's end line.
fn heredoc_delimiter(chars: &mut Peekable<Chars>) -> Option<String> {
    while chars.next_if(|next| matches!(next, ' ' | '\t')).is_some() {}
    let mut delimiter = String::new();
    while let Some(c) = chars.next_if(|next| {
        !next.is_whitespace() && !matches!(next, ';' | '|' | '&' | '<' | '>' | '(' | ')')
    }) {
        if !matches!(c, '\'' | '"' | '\\') {
            delimiter.push(c);
        }
    }
    Some(delimiter).filter(|delimiter| !delimiter.is_empty())
}

/// Skips the lines of a here-document body, through its delimiter line.
fn skip_heredoc_body(chars: &mut Peekable<Chars>, delimiter: &str, strip_tabs: bool) {
    while chars.peek().is_some() {
        let mut line = String::new();
        while let Some(c) = chars.next_if(|next| *next != '\n') {
            line.push(c);
        }
        chars.next_if_eq(&'\n');
        let line = if strip_tabs {
            line.trim_start_matches('\t')
        } else {
            line.as_str()
        };
        if line == delimiter {
            return;
        }
    }
}

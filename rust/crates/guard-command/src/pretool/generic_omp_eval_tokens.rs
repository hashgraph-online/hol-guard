//! Literal-only lexer shared by the bounded OMP eval parser.
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq)]
pub(super) enum Token {
    Ident(String),
    Str(String),
    Num(Value),
    Punct(char),
}

fn escape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>, quote: char) -> Option<char> {
    match chars.next()? {
        '\\' => Some('\\'),
        'n' => Some('\n'),
        't' => Some('\t'),
        c if c == quote || matches!(c, '\'' | '"' | '`') => Some(c),
        _ => None,
    }
}

pub(super) fn tokenize(code: &str) -> Option<Vec<Token>> {
    tokenize_lines(code).map(|lexed| lexed.tokens)
}

pub(super) struct Lexed {
    pub(super) tokens: Vec<Token>,
    /// Whether a line terminator came before each token. JavaScript inserts
    /// a semicolon after `return` when a line ends there, so a parser that
    /// reads `return` needs to know where the lines broke.
    pub(super) breaks: Vec<bool>,
    /// Whether each token is a template literal whose raw text is its value:
    /// no escape (a tag reads `strings.raw`, where `\n` stays two
    /// characters). Literal template line endings are normalized to LF.
    pub(super) raw_templates: Vec<bool>,
}

/// Tokens, with where the lines broke and which templates are raw text.
pub(super) fn tokenize_lines(code: &str) -> Option<Lexed> {
    let mut tokens = Vec::new();
    let mut breaks = Vec::new();
    let mut raw_templates = Vec::new();
    let mut broke = false;
    let mut chars = code.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_whitespace() {
            broke |= matches!(c, '\n' | '\r');
            chars.next();
            continue;
        }
        breaks.push(std::mem::take(&mut broke));
        raw_templates.push(false);
        if c.is_ascii_alphabetic() || c == '_' || c == '$' {
            let mut ident = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_ascii_alphanumeric() || c == '_' || c == '$' {
                    ident.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            tokens.push(Token::Ident(ident));
        } else if c.is_ascii_digit() {
            let mut seen_dot = false;
            let mut digits = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_ascii_digit() || (c == '.' && !seen_dot) {
                    seen_dot |= c == '.';
                    digits.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            if chars
                .peek()
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
            {
                return None;
            }
            // Fractions and unparsable literals become a non-integer, which
            // no modeled option accepts, so they are reviewed.
            let number = digits.parse::<u64>().map_or(json!(-1), |n| json!(n));
            tokens.push(Token::Num(number));
        } else if matches!(c, '\'' | '"' | '`') {
            chars.next();
            let mut value = String::new();
            let mut raw = c == '`';
            loop {
                match chars.next()? {
                    '\\' => {
                        raw = false;
                        value.push(escape(&mut chars, c)?);
                    }
                    '$' if c == '`' && chars.peek() == Some(&'{') => return None,
                    '\n' | '\r' if c != '`' => return None,
                    ch if ch == c => break,
                    ch if ch.is_control() && !matches!(ch, '\n' | '\t' | '\r') => return None,
                    ch => value.push(ch),
                }
            }
            // ECMAScript normalizes physical CR and CRLF line terminators
            // in cooked and raw template strings before `sh` runs them.
            if c == '`' {
                value = value.replace("\r\n", "\n").replace('\r', "\n");
            }
            if let Some(last) = raw_templates.last_mut() {
                *last = raw;
            }
            tokens.push(Token::Str(value));
        } else if "(){}[],;:.=".contains(c) {
            chars.next();
            tokens.push(Token::Punct(c));
        } else {
            // Comments, operators, regex literals and non-ASCII outside
            // strings are all outside the grammar.
            return None;
        }
    }
    Some(Lexed {
        tokens,
        breaks,
        raw_templates,
    })
}

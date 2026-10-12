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
    let mut tokens = Vec::new();
    let mut chars = code.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_whitespace() {
            chars.next();
        } else if c.is_ascii_alphabetic() || c == '_' || c == '$' {
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
            loop {
                match chars.next()? {
                    '\\' => value.push(escape(&mut chars, c)?),
                    '$' if c == '`' && chars.peek() == Some(&'{') => return None,
                    '\n' | '\r' if c != '`' => return None,
                    ch if ch == c => break,
                    ch if ch.is_control() && !matches!(ch, '\n' | '\t' | '\r') => return None,
                    ch => value.push(ch),
                }
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
    Some(tokens)
}

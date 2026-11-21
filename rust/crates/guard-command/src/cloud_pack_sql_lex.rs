//! Tokenizer for the SQL statements a cloud action pack classifies.
//!
//! Anything this reader cannot follow returns `None`, which the classifier
//! treats as destructive.

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Token {
    Word(String),
    Open,
    Close,
    Semicolon,
    Literal,
    Other(char),
}

/// Split SQL into tokens, uppercasing words. `None` for text dialects read
/// differently: an open quote or comment, a backslash in a string, `#`, a
/// MySQL executable comment, or `--` not followed by a space.
pub(crate) fn tokenize(text: &str) -> Option<Vec<Token>> {
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        match byte {
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                if !bytes.get(i + 2).is_none_or(u8::is_ascii_whitespace) {
                    return None;
                }
                i = bytes[i..]
                    .iter()
                    .position(|b| *b == b'\n')
                    .map_or(bytes.len(), |p| i + p);
            }
            b'#' => return None,
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                let close = text[i + 2..].find("*/")?;
                let body = &text[i + 2..i + 2 + close];
                if body.starts_with('!') || body.contains("/*") {
                    return None;
                }
                i += close + 4;
            }
            b'\'' => {
                i = closing_quote(bytes, i)?;
                tokens.push(Token::Literal);
            }
            b'"' | b'`' => {
                let end = closing_quote(bytes, i)?;
                tokens.push(Token::Word(format!("\u{0}{}", &text[i + 1..end - 1])));
                i = end;
            }
            b'$' => {
                let tag_end = bytes[i + 1..]
                    .iter()
                    .position(|b| !(b.is_ascii_alphanumeric() || *b == b'_'))
                    .map_or(bytes.len(), |p| i + 1 + p);
                // `$` inside a word (`x$a$` in PostgreSQL) continues the word and
                // never opens a dollar quote.
                let continues = i > 0 && (is_word_byte(bytes[i - 1]) || bytes[i - 1] == b'$');
                let tagged = !continues
                    && bytes.get(tag_end) == Some(&b'$')
                    && !bytes.get(i + 1).is_some_and(u8::is_ascii_digit);
                if tagged {
                    let tag = &text[i..=tag_end];
                    let close = text[tag_end + 1..].find(tag)?;
                    i = tag_end + 1 + close + tag.len();
                    tokens.push(Token::Literal);
                } else {
                    // `$1` is a placeholder; `SYSTEM$NAME` continues the word before it.
                    let part = text[i..tag_end].to_ascii_uppercase();
                    match tokens.last_mut() {
                        Some(Token::Word(word)) if continues => {
                            word.push_str(&part);
                        }
                        _ => tokens.push(Token::Word(part)),
                    }
                    i = tag_end;
                }
            }
            b'(' => {
                tokens.push(Token::Open);
                i += 1;
            }
            b')' => {
                tokens.push(Token::Close);
                i += 1;
            }
            b';' => {
                tokens.push(Token::Semicolon);
                i += 1;
            }
            _ if byte.is_ascii_whitespace() => i += 1,
            _ if is_word_byte(byte) => {
                let end = bytes[i..]
                    .iter()
                    .position(|b| !is_word_byte(*b))
                    .map_or(bytes.len(), |p| i + p);
                tokens.push(Token::Word(text[i..end].to_ascii_uppercase()));
                i = end;
            }
            _ => {
                let ch = text[i..].chars().next()?;
                tokens.push(Token::Other(ch));
                i += ch.len_utf8();
            }
        }
    }
    Some(tokens)
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte >= 0x80
}

/// The index after the quote that closes the one at `start`; a doubled quote
/// is an escaped one.
fn closing_quote(bytes: &[u8], start: usize) -> Option<usize> {
    let quote = bytes[start];
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => return None,
            b if b == quote && bytes.get(i + 1) == Some(&quote) => i += 2,
            b if b == quote => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

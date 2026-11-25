//! Arithmetic expansions over the loop variable in a loop body.
//!
//! `for n in 5315 5600; do sed -n "$n,$((n+6))p" job.log; done` prints a few
//! lines from each of two places in a log. The shell works out `$((n+6))` on
//! every pass, so the first pass runs `sed -n "5315,5321p" job.log`. When the
//! loop words are plain decimal numbers and an expansion holds nothing but
//! the loop variable, numbers, `+`, `-` and `*`, the value is the same on any
//! shell, so the body of each pass can be written out with that value in
//! place and proven like any other unrolled pass.

/// The loop body text, `rest`, once for each word, with every arithmetic
/// expansion written out as its value on that pass.
///
/// `Some(None)` when the body holds no arithmetic expansion. `None` when it
/// holds one this does not evaluate, or when a word is not a plain decimal
/// number; that loop keeps its review.
pub(super) fn evaluated_bodies(
    rest: &str,
    name: &str,
    words: &[String],
) -> Option<Option<Vec<String>>> {
    if !rest.contains("$((") {
        return Some(None);
    }
    // Every pass reads the loop variable, so a header past the word bound is
    // refused later anyway; refuse it before writing out any pass.
    if words.len() > super::MAX_WORDS {
        return None;
    }
    words
        .iter()
        .map(|word| {
            let value = plain_number(word)?;
            evaluated(rest, name, value)
        })
        .collect::<Option<Vec<_>>>()
        .map(Some)
}

/// A decimal number as the shell's arithmetic reads it. A leading zero
/// reads as octal, so only `0` itself may start with one.
fn plain_number(word: &str) -> Option<i64> {
    if word.is_empty()
        || word.len() > 9
        || !word.bytes().all(|byte| byte.is_ascii_digit())
        || (word.len() > 1 && word.starts_with('0'))
    {
        return None;
    }
    word.parse().ok()
}

/// `text` with each `$((...))` outside single quotes replaced by its value.
/// An apostrophe inside double quotes is a plain character and opens no
/// single-quoted span.
fn evaluated(text: &str, name: &str, value: i64) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut single = false;
    let mut double = false;
    let mut index = 0;
    while let Some(character) = text[index..].chars().next() {
        let rest = &text[index..];
        if single {
            single = character != '\'';
        } else if character == '\'' && !double {
            single = true;
        } else if character == '"' {
            double = !double;
        } else if character == '\\' {
            let escaped = rest[1..].chars().next().map_or(0, char::len_utf8);
            out.push_str(&rest[..1 + escaped]);
            index += 1 + escaped;
            continue;
        } else if let Some(inner) = rest.strip_prefix("$((") {
            let end = inner.find("))")?;
            out.push_str(&expression(&inner[..end], name, value)?.to_string());
            index += 3 + end + 2;
            continue;
        }
        out.push(character);
        index += character.len_utf8();
    }
    Some(out)
}

/// The value of a sum of products of numbers and the loop variable, or
/// `None` for anything else, including an overflow.
fn expression(text: &str, name: &str, value: i64) -> Option<i64> {
    let tokens = tokens(text, name, value)?;
    let mut total: i64 = 0;
    let mut sign: i64 = 1;
    let mut index = 0;
    loop {
        let (product, next) = product(&tokens, index)?;
        total = total.checked_add(sign.checked_mul(product)?)?;
        match tokens.get(next) {
            None => return Some(total),
            Some(Token::Plus) => sign = 1,
            Some(Token::Minus) => sign = -1,
            _ => return None,
        }
        index = next + 1;
    }
}

/// The product that starts at `index`, and where it ends.
fn product(tokens: &[Token], mut index: usize) -> Option<(i64, usize)> {
    let mut total = operand(tokens.get(index)?)?;
    index += 1;
    while tokens.get(index) == Some(&Token::Times) {
        total = total.checked_mul(operand(tokens.get(index + 1)?)?)?;
        index += 2;
    }
    Some((total, index))
}

fn operand(token: &Token) -> Option<i64> {
    match token {
        Token::Number(number) => Some(*number),
        _ => None,
    }
}

#[derive(PartialEq)]
enum Token {
    Number(i64),
    Plus,
    Minus,
    Times,
}

fn tokens(text: &str, name: &str, value: i64) -> Option<Vec<Token>> {
    let mut tokens = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        match byte {
            b' ' | b'\t' => index += 1,
            b'+' => {
                tokens.push(Token::Plus);
                index += 1;
            }
            b'-' => {
                tokens.push(Token::Minus);
                index += 1;
            }
            b'*' => {
                tokens.push(Token::Times);
                index += 1;
            }
            b'0'..=b'9' => {
                let end = text[index..]
                    .find(|c: char| !c.is_ascii_digit())
                    .map_or(text.len(), |end| index + end);
                tokens.push(Token::Number(plain_number(&text[index..end])?));
                index = end;
            }
            _ => {
                let start = index + usize::from(byte == b'$');
                let end = text[start..]
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .map_or(text.len(), |end| start + end);
                if &text[start..end] != name {
                    return None;
                }
                tokens.push(Token::Number(value));
                index = end;
            }
        }
    }
    // `++`, `--` and a leading sign are operators this does not read.
    let operands = tokens
        .iter()
        .step_by(2)
        .all(|token| matches!(token, Token::Number(_)));
    let operators = tokens
        .iter()
        .skip(1)
        .step_by(2)
        .all(|token| !matches!(token, Token::Number(_)));
    (operands && operators && tokens.len() % 2 == 1).then_some(tokens)
}

#[cfg(test)]
#[path = "for_loop_unroll_arithmetic_tests.rs"]
mod tests;

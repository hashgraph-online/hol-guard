//! Credential-named values that code computes instead of spelling out.
//!
//! Ordinary application source is full of lines such as
//! `const token = await signToken(user.id);`, `token: z.string().min(1),`,
//! `token: query.get('token') ?? '',`, `` const token = `${head}.${sig}`; ``,
//! `if (token === expected) {` or `type MakeToken = (input: Input) => Promise<string>;`.
//! Each one matches the credential assignment rule on its identifier alone, yet
//! the value is a call, a template of variables, a comparison or a function
//! type, and none of those holds secret material. Reading such source stopped
//! agents on every file that issues, signs or verifies tokens.
//!
//! The check reads the whole expression after the separator, up to the end of
//! the line. A value is code only when it has syntax that a literal secret
//! cannot (a call, `await`, `new`, a cast, an interpolation, an arrow) and
//! every literal inside it is short or reads as a word, a slug or a path. A
//! quoted value, a bare word, a dotenv-style upper-case key, a fallback
//! literal (`?? 'dev-secret'`), a concatenation, an encoded-looking argument,
//! a hash pair (`'password' => 'x'`), a default handed to a getter and an
//! expression longer than the cursor reads are never treated as code here.

use crate::code_cursor::{
    is_identifier_byte, is_identifier_start, text_ok, Cursor, Scan, MAX_EXPRESSION_BYTES,
};

const KEYWORDS: [&[u8]; 9] = [
    b"null",
    b"undefined",
    b"true",
    b"false",
    b"None",
    b"True",
    b"False",
    b"nil",
    b"NaN",
];

/// Whether a credential assignment match carries a code expression rather than
/// a secret value. `rest_of_line` is the text after the match on the same line.
pub(crate) fn is_code_expression(matched: &str, rest_of_line: &str) -> bool {
    let Some(index) = matched.find([':', '=']) else {
        return false;
    };
    let separator = matched.as_bytes()[index];
    let tail = &matched[index + 1..];
    // `KEY=value` with an upper-case key is dotenv or shell data.
    if crate::code_value::environment_style_key(&matched[..index])
        && !(separator == b'=' && tail.starts_with(char::is_whitespace))
    {
        return false;
    }
    let mut body = tail.trim_start();
    let mut mode = Mode::Assign;
    if body.starts_with('=') {
        body = body.trim_start_matches('=');
        mode = if separator == b':' {
            Mode::Assign
        } else {
            Mode::Compare
        };
    } else if body.starts_with('>') && separator == b'=' {
        // `'password' => 'x'` pairs a key with a value in Perl, PHP and Ruby
        // maps; only a bare parameter names an arrow function.
        if matched[..index].trim().ends_with(['"', '\'']) {
            return false;
        }
        body = &body[1..];
        mode = Mode::Arrow;
    }
    let mut expression = String::with_capacity(body.len() + rest_of_line.len());
    expression.push_str(body.trim_start());
    expression.push_str(rest_of_line);
    // The cursor stops at its limit, so a longer expression could hide a literal.
    if expression.len() > MAX_EXPRESSION_BYTES {
        return false;
    }
    let mut cursor = Cursor::new(&expression);
    match mode {
        Mode::Arrow => {
            cursor.skip_blanks();
            // A value that starts as a literal is a map entry, not a function.
            !matches!(cursor.peek(0), b'"' | b'\'' | b'`' | b'0'..=b'9')
                && cursor.scan(None, 1) != Scan::Fail
        }
        Mode::Compare => cursor.comparison(),
        Mode::Assign => cursor.assigned(),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Assign,
    Compare,
    Arrow,
}

impl<'a> Cursor<'a> {
    /// The end of a value: the line, a separator or closer, or a comment.
    fn value_ends(&mut self) -> bool {
        self.skip_blanks();
        self.done()
            || b",;)}]".contains(&self.bytes[self.at])
            || self.starts_with(b"//")
            || self.starts_with(b"/*")
    }

    /// An operand chain, with fallbacks and a cast, that proves it is code.
    fn chain(&mut self) -> bool {
        let Some(first) = self.operand(true) else {
            return false;
        };
        let mut structural = first.structural;
        let fallback_proves = first.structural || first.dotted;
        loop {
            self.skip_blanks();
            if self.starts_with(b"??") || self.starts_with(b"||") || self.starts_with(b"&&") {
                self.at += 2;
                self.skip_blanks();
                if self.done() {
                    return false;
                }
                let next = self.bytes[self.at];
                if next == b'"' || next == b'\'' {
                    // Only an empty fallback is inert; any other is a literal.
                    if self.peek(1) != next {
                        return false;
                    }
                    self.at += 2;
                } else if next == b'`' {
                    return false;
                } else {
                    let start = self.at;
                    let Some(fallback) = self.operand(true) else {
                        return false;
                    };
                    // A long bare word of letters spells a value; a variable
                    // reads as camelCase, snake_case or a member path.
                    if !fallback.structural
                        && !fallback.dotted
                        && spelled_word(&self.bytes[start..self.at])
                    {
                        return false;
                    }
                }
                structural = structural || fallback_proves;
            } else if self.keyword(b"as") || self.keyword(b"satisfies") {
                if self.scan(None, 1) == Scan::Fail {
                    return false;
                }
                structural = true;
                break;
            } else {
                break;
            }
        }
        structural && self.value_ends()
    }

    /// A value after `=` or `:`.
    fn assigned(&mut self) -> bool {
        self.skip_blanks();
        if self.done() {
            return false;
        }
        match self.bytes[self.at] {
            b'"' | b'\'' => false,
            b'`' => {
                let (scan, interpolations) = self.template();
                scan != Scan::Fail
                    && interpolations > 0
                    && (scan == Scan::Incomplete || self.value_ends())
            }
            b'$' if self.peek(1) == b'{' => self.interpolated_word(),
            b'{' => self.rest_is(b"{") || self.rest_is(b"{}"),
            b'[' => self.rest_is(b"[") || self.rest_is(b"[]"),
            b'(' => self.arrow(),
            _ => {
                let start = self.at;
                if let Some(name) = self.identifier() {
                    if KEYWORDS.contains(&name) {
                        self.skip_blanks();
                        if self.value_ends() {
                            return true;
                        }
                    }
                }
                self.at = start;
                self.chain()
            }
        }
    }

    fn rest_is(&self, expected: &[u8]) -> bool {
        self.bytes[self.at..].trim_ascii() == expected
    }

    /// `${name}` at the start of a value, possibly followed by more template
    /// text (`${base}/confirm?id=${id}`), when the match began inside a
    /// template literal or a shell string.
    fn interpolated_word(&mut self) -> bool {
        self.at += 2;
        if self.scan(Some(b'}'), 1) != Scan::Done {
            return false;
        }
        let mut text: Vec<u8> = Vec::new();
        while !self.done() {
            let byte = self.bytes[self.at];
            if matches!(byte, b' ' | b'\t' | b'"' | b'\'' | b'`') {
                break;
            }
            if byte == b'$' && self.peek(1) == b'{' {
                if !text_ok(&text) {
                    return false;
                }
                text.clear();
                self.at += 2;
                if self.scan(Some(b'}'), 1) != Scan::Done {
                    return false;
                }
                continue;
            }
            text.push(byte);
            self.at += 1;
        }
        text_ok(&text)
    }

    /// A function value: `(input: Input) => Output`, or its opening line.
    fn arrow(&mut self) -> bool {
        let start = self.at;
        self.at += 1;
        match self.scan(Some(b')'), 1) {
            Scan::Fail => return false,
            Scan::Incomplete => {
                // A parameter list that runs on to the next line must open
                // with a typed or destructured parameter.
                let inner = self.bytes[start + 1..].trim_ascii_start();
                return starts_typed_parameter(inner)
                    || matches!(inner.first().copied(), Some(b'{' | b'['));
            }
            Scan::Done => {}
        }
        self.skip_blanks();
        if self.peek(0) == b':' {
            // A return type, such as `: value is Token`, before the arrow.
            let bytes: &'a [u8] = self.bytes;
            let Some(arrow) = bytes[self.at..].windows(2).position(|pair| pair == b"=>") else {
                return false;
            };
            let end = self.at + arrow;
            let mut annotation = Cursor::over(&bytes[self.at + 1..end]);
            if annotation.scan(None, 1) == Scan::Fail || !annotation.done() {
                return false;
            }
            self.at = end;
        }
        if !self.starts_with(b"=>") {
            return false;
        }
        self.at += 2;
        self.scan(None, 1) != Scan::Fail
    }

    /// A comparison such as `token === expected`: the other side must be code,
    /// never a literal.
    fn comparison(&mut self) -> bool {
        self.skip_blanks();
        if self.done() || matches!(self.bytes[self.at], b'"' | b'\'' | b'`') {
            return false;
        }
        let start = self.at;
        self.operand(false).is_some()
            && self.scan(None, 1) != Scan::Fail
            && equality_literals_ok(&self.bytes[start..self.at])
    }
}

/// A bare run of at least sixteen lower-case letters, as in a passphrase.
fn spelled_word(word: &[u8]) -> bool {
    word.len() >= 16 && word.iter().all(u8::is_ascii_lowercase)
}

/// Literals set against a value by `==` or `!=` anywhere in a comparison: only
/// an empty string or a short plain word is a mode or a label. A literal with a
/// digit, or a long one, is a value that stays a credential finding.
fn equality_literals_ok(expression: &[u8]) -> bool {
    let mut at = 0usize;
    while at + 1 < expression.len() {
        if !matches!(&expression[at..at + 2], b"==" | b"!=") {
            at += 1;
            continue;
        }
        let mut after = at + 2;
        while expression.get(after) == Some(&b'=') {
            after += 1;
        }
        if let Some(literal) = leading_literal(expression[after..].trim_ascii_start()) {
            if !label(literal) {
                return false;
            }
        }
        if let Some(literal) = trailing_literal(expression[..at].trim_ascii_end()) {
            if !label(literal) {
                return false;
            }
        }
        at = after;
    }
    true
}

fn label(literal: &[u8]) -> bool {
    literal.len() <= 12
        && literal
            .iter()
            .all(|&byte| byte.is_ascii_alphabetic() || byte == b'-' || byte == b'_')
}

/// The body of a quoted literal that opens `text`, or the rest when unclosed.
fn leading_literal(text: &[u8]) -> Option<&[u8]> {
    let quote = *text.first()?;
    if !matches!(quote, b'"' | b'\'' | b'`') {
        return None;
    }
    let body = &text[1..];
    let end = body.iter().position(|&byte| byte == quote);
    Some(&body[..end.unwrap_or(body.len())])
}

/// The body of a quoted literal that closes `text`, or the rest when unopened.
fn trailing_literal(text: &[u8]) -> Option<&[u8]> {
    let quote = *text.last()?;
    if !matches!(quote, b'"' | b'\'' | b'`') {
        return None;
    }
    let body = &text[..text.len() - 1];
    let start = body.iter().rposition(|&byte| byte == quote);
    Some(&body[start.map_or(0, |index| index + 1)..])
}

/// `name:` or `name?:` at the start of a parameter list.
fn starts_typed_parameter(inner: &[u8]) -> bool {
    let inner = inner.strip_prefix(b"...").unwrap_or(inner);
    let name = inner
        .iter()
        .take_while(|&&byte| is_identifier_byte(byte))
        .count();
    if name == 0 || !is_identifier_start(inner[0]) {
        return false;
    }
    let after = inner[name..].trim_ascii_start();
    let after = after.strip_prefix(b"?").unwrap_or(after).trim_ascii_start();
    after.first() == Some(&b':')
}

#[cfg(test)]
#[path = "code_expression_tests.rs"]
mod tests;

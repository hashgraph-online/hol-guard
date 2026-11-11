//! Handler code whose credential-named values hold no secret: a header read
//! into `token`, a `typeof` guard choosing `apiKey` between two variables, an
//! arrow function that lists its typed parameters one per line, and a Fetch
//! `credentials` mode. Each shape is read narrowly, so a literal that could be
//! a secret anywhere in it keeps the credential finding.

use crate::code_cursor::Cursor;
use crate::code_expression::{label, leading_literal, spelled_word, starts_typed_parameter};

/// The parameter lines read after `name = (` before the list must have closed.
const MAX_PARAMETER_LINES: usize = 16;

/// Whether `receiver.name(...)` reads a request or response header: the
/// Express and Node `header`, `getHeader` and `get` methods, and `get` on a
/// Fetch `Headers` object.
pub(crate) fn header_accessor(receiver: &[u8], name: &[u8]) -> bool {
    match name {
        b"header" | b"getHeader" => true,
        b"get" => matches!(receiver, b"headers" | b"req" | b"request"),
        _ => false,
    }
}

/// An `x-` extension header name such as `x-service-maintenance-token`. It may
/// run past the three words a slug allows, but only in lower-case letters,
/// with no digits to encode anything. Accepted only as the argument of a
/// [`header_accessor`] call.
pub(crate) fn extension_header_name(literal: &[u8]) -> bool {
    let Some(rest) = literal.strip_prefix(b"x-") else {
        return false;
    };
    let words: Vec<&[u8]> = rest.split(|&byte| byte == b'-').collect();
    literal.len() <= 64
        && (1..=5).contains(&words.len())
        && words
            .iter()
            .all(|word| (1..16).contains(&word.len()) && word.iter().all(u8::is_ascii_lowercase))
}

/// `credentials: 'omit'` in a Fetch request: the key takes only the modes
/// `omit`, `same-origin` and `include`, so the value names a cookie policy and
/// never holds secret material. Anything after the literal other than the end
/// of the entry keeps the finding.
pub(crate) fn fetch_credentials_mode(key: &str, tail: &str, rest_of_line: &str) -> bool {
    let key = key.trim().trim_matches(['"', '\'']);
    if key != "credentials" {
        return false;
    }
    let value = format!("{tail}{rest_of_line}");
    let value = value.trim();
    ["omit", "same-origin", "include"].iter().any(|mode| {
        ['"', '\''].iter().any(|quote| {
            value
                .strip_prefix(*quote)
                .and_then(|rest| rest.strip_prefix(mode))
                .and_then(|rest| rest.strip_prefix(*quote))
                .is_some_and(|rest| matches!(rest.trim(), "" | "," | "}" | "})" | "});" | "},"))
        })
    })
}

/// `const requireToken = (` with nothing after the bracket, followed by an
/// arrow function's parameter list written one typed parameter per line and
/// closed by `) =>` or `): Type =>`. Every line before the close must open a
/// typed parameter and hold no quote, so a tuple or call that spells a value
/// on a later line (`user: "admin",`) keeps the finding.
pub(crate) fn opens_typed_parameter_list(
    matched: &str,
    rest_of_line: &str,
    following_lines: &str,
) -> bool {
    let Some(index) = matched.find('=') else {
        return false;
    };
    if matched[index + 1..].trim() != "(" || !rest_of_line.trim().is_empty() {
        return false;
    }
    for (parameters, line) in following_lines
        .split('\n')
        .map(|line| line.trim_end_matches('\r').trim())
        .filter(|line| !line.is_empty())
        .take(MAX_PARAMETER_LINES)
        .enumerate()
    {
        if line.starts_with(')') {
            return parameters > 0 && line.contains("=>") && !line.contains(['"', '\'', '`']);
        }
        if !starts_typed_parameter(line.as_bytes()) || line.contains(['"', '\'', '`']) {
            return false;
        }
    }
    false
}

impl Cursor<'_> {
    /// `===`, `!==`, `==` or `!=`, stepped over.
    pub(crate) fn equality_operator(&mut self) -> bool {
        for operator in [b"===".as_slice(), b"!==", b"==", b"!="] {
            if self.starts_with(operator) {
                self.at += operator.len();
                return true;
            }
        }
        false
    }

    /// The rest of `x === 'string' ? x : undefined` after the operator: a
    /// label or an operand, then a choice between two operands. Neither branch
    /// may be a literal, a number, or a bare word long enough to spell a
    /// passphrase, so a value chosen here is always some other variable.
    pub(crate) fn guarded_choice(&mut self) -> bool {
        self.skip_blanks();
        if let Some(literal) = leading_literal(&self.bytes[self.at..]) {
            let quote = self.bytes[self.at];
            if self.bytes.get(self.at + literal.len() + 1) != Some(&quote) || !label(literal) {
                return false;
            }
            self.at += literal.len() + 2;
        } else if self.operand(false).is_none() {
            return false;
        }
        self.skip_blanks();
        if self.peek(0) != b'?' || matches!(self.peek(1), b'?' | b'.') {
            return false;
        }
        self.at += 1;
        let branch = |cursor: &mut Self| {
            cursor.skip_blanks();
            let start = cursor.at;
            cursor.operand(false).is_some_and(|operand| {
                operand.structural
                    || operand.dotted
                    || !spelled_word(&cursor.bytes[start..cursor.at])
            })
        };
        if !branch(self) {
            return false;
        }
        self.skip_blanks();
        if self.peek(0) != b':' {
            return false;
        }
        self.at += 1;
        branch(self)
    }
}

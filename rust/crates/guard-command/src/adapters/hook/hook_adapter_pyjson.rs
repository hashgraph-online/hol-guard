//! Python-compatible `json.loads` for the hook adapter port.

use crate::hook_adapter_value::{canonical_float, canonical_int, OMap, OValue};

/// Failure of the Python-compatible JSON parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PyJsonError {
    /// CPython would raise `JSONDecodeError` (callers keep the original text).
    Decode,
    /// CPython would accept the input but the port cannot represent it
    /// (lone surrogates, `NaN`/`Infinity`, non-finite floats, deep nesting).
    Unsupported,
}

const MAX_PARSE_DEPTH: usize = 64;

/// `json.loads(text)` over an already-stripped string.
pub fn parse_python_json(text: &str) -> Result<OValue, PyJsonError> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        text,
        index: 0,
    };
    parser.skip_ws();
    let value = parser.value(0)?;
    parser.skip_ws();
    if parser.index != parser.bytes.len() {
        return Err(PyJsonError::Decode);
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    text: &'a str,
    index: usize,
}

impl Parser<'_> {
    fn skip_ws(&mut self) {
        while matches!(
            self.bytes.get(self.index),
            Some(b' ' | b'\t' | b'\n' | b'\r')
        ) {
            self.index += 1;
        }
    }

    fn eat(&mut self, literal: &str) -> bool {
        if self.bytes[self.index..].starts_with(literal.as_bytes()) {
            self.index += literal.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: usize) -> Result<OValue, PyJsonError> {
        if depth > MAX_PARSE_DEPTH {
            return Err(PyJsonError::Unsupported);
        }
        match self.bytes.get(self.index) {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(OValue::Str),
            Some(b't') if self.eat("true") => Ok(OValue::Bool(true)),
            Some(b'f') if self.eat("false") => Ok(OValue::Bool(false)),
            Some(b'n') if self.eat("null") => Ok(OValue::Null),
            Some(b'N') if self.bytes[self.index..].starts_with(b"NaN") => {
                Err(PyJsonError::Unsupported)
            }
            Some(b'I') if self.bytes[self.index..].starts_with(b"Infinity") => {
                Err(PyJsonError::Unsupported)
            }
            Some(b'-') if self.bytes[self.index..].starts_with(b"-Infinity") => {
                Err(PyJsonError::Unsupported)
            }
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(PyJsonError::Decode),
        }
    }

    fn number(&mut self) -> Result<OValue, PyJsonError> {
        let start = self.index;
        if self.bytes.get(self.index) == Some(&b'-') {
            self.index += 1;
        }
        match self.bytes.get(self.index) {
            Some(b'0') => self.index += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(PyJsonError::Decode),
        }
        let mut is_float = false;
        if self.bytes.get(self.index) == Some(&b'.')
            && matches!(self.bytes.get(self.index + 1), Some(b'0'..=b'9'))
        {
            is_float = true;
            self.index += 1;
            self.digits();
        }
        if matches!(self.bytes.get(self.index), Some(b'e' | b'E')) {
            let mut probe = self.index + 1;
            if matches!(self.bytes.get(probe), Some(b'+' | b'-')) {
                probe += 1;
            }
            if matches!(self.bytes.get(probe), Some(b'0'..=b'9')) {
                is_float = true;
                self.index = probe;
                self.digits();
            }
        }
        let token = &self.text[start..self.index];
        if is_float {
            canonical_float(token)
                .map(OValue::Float)
                .map_err(|_| PyJsonError::Unsupported)
        } else {
            if token.trim_start_matches('-').len() > 4300 {
                return Err(PyJsonError::Unsupported);
            }
            Ok(OValue::Int(canonical_int(token)))
        }
    }

    fn digits(&mut self) {
        while matches!(self.bytes.get(self.index), Some(b'0'..=b'9')) {
            self.index += 1;
        }
    }

    fn hex4(&mut self) -> Result<u32, PyJsonError> {
        let slice = self
            .text
            .get(self.index..self.index + 4)
            .ok_or(PyJsonError::Decode)?;
        if !slice.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(PyJsonError::Decode);
        }
        self.index += 4;
        u32::from_str_radix(slice, 16).map_err(|_| PyJsonError::Decode)
    }

    fn string(&mut self) -> Result<String, PyJsonError> {
        self.index += 1;
        let mut out = String::new();
        loop {
            let rest = &self.text[self.index..];
            let ch = rest.chars().next().ok_or(PyJsonError::Decode)?;
            self.index += ch.len_utf8();
            match ch {
                '"' => return Ok(out),
                '\\' => {
                    let escape = self.text[self.index..]
                        .chars()
                        .next()
                        .ok_or(PyJsonError::Decode)?;
                    self.index += escape.len_utf8();
                    match escape {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'b' => out.push('\u{08}'),
                        'f' => out.push('\u{0c}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => {
                            let first = self.hex4()?;
                            let code = if (0xd800..0xdc00).contains(&first) {
                                let paired = self.bytes[self.index..].starts_with(b"\\u");
                                if !paired {
                                    return Err(PyJsonError::Unsupported);
                                }
                                self.index += 2;
                                let second = self.hex4()?;
                                if !(0xdc00..0xe000).contains(&second) {
                                    return Err(PyJsonError::Unsupported);
                                }
                                0x1_0000 + ((first - 0xd800) << 10) + (second - 0xdc00)
                            } else if (0xdc00..0xe000).contains(&first) {
                                return Err(PyJsonError::Unsupported);
                            } else {
                                first
                            };
                            out.push(char::from_u32(code).ok_or(PyJsonError::Unsupported)?);
                        }
                        _ => return Err(PyJsonError::Decode),
                    }
                }
                control if (control as u32) < 0x20 => return Err(PyJsonError::Decode),
                other => out.push(other),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<OValue, PyJsonError> {
        self.index += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.bytes.get(self.index) == Some(&b']') {
            self.index += 1;
            return Ok(OValue::List(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth + 1)?);
            self.skip_ws();
            match self.bytes.get(self.index) {
                Some(b',') => self.index += 1,
                Some(b']') => {
                    self.index += 1;
                    return Ok(OValue::List(items));
                }
                _ => return Err(PyJsonError::Decode),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<OValue, PyJsonError> {
        self.index += 1;
        let mut map = OMap::new();
        self.skip_ws();
        if self.bytes.get(self.index) == Some(&b'}') {
            self.index += 1;
            return Ok(OValue::Map(map));
        }
        loop {
            self.skip_ws();
            if self.bytes.get(self.index) != Some(&b'"') {
                return Err(PyJsonError::Decode);
            }
            let key = self.string()?;
            self.skip_ws();
            if self.bytes.get(self.index) != Some(&b':') {
                return Err(PyJsonError::Decode);
            }
            self.index += 1;
            self.skip_ws();
            let value = self.value(depth + 1)?;
            map.insert(&key, value);
            self.skip_ws();
            match self.bytes.get(self.index) {
                Some(b',') => self.index += 1,
                Some(b'}') => {
                    self.index += 1;
                    return Ok(OValue::Map(map));
                }
                _ => return Err(PyJsonError::Decode),
            }
        }
    }
}

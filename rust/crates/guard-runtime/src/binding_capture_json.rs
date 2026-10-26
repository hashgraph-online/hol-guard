//! Bounded JSON for the opt-in Codex binding capture.
//!
//! The capture format is defined by Python's `json` module: duplicate keys are
//! rejected, `NaN`/`Infinity` tokens parse (and are then refused as non-finite),
//! and canonical output is sorted compact UTF-8. This parser mirrors that
//! grammar exactly instead of reusing the transport parser, whose depth and
//! collection ceilings differ from the capture's documented 64/4096 bounds.

use std::collections::HashSet;

use guard_contracts::python_float_repr;

pub(crate) const MAX_CANONICAL_BYTES: usize = 64 * 1024;
const MAX_DEPTH: usize = 64;
const MAX_NODES: usize = 4096;
const MAX_STRING_CHARS: usize = 64 * 1024;
/// CPython refuses to convert integer literals longer than this many digits.
const MAX_INT_DIGITS: usize = 4300;
const PARSE_DEPTH_GUARD: usize = 100;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Json {
    Null,
    Bool(bool),
    /// Normalised decimal text of an arbitrary-precision integer.
    Int(String),
    Float(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub(crate) fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(text) => Some(text),
            _ => None,
        }
    }

    pub(crate) fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Int(text) => text.parse().ok(),
            _ => None,
        }
    }

    pub(crate) fn keys(&self) -> Vec<&str> {
        match self {
            Json::Obj(entries) => entries.iter().map(|(k, _)| k.as_str()).collect(),
            _ => Vec::new(),
        }
    }

    pub(crate) fn int(value: i64) -> Json {
        Json::Int(value.to_string())
    }

    pub(crate) fn object(entries: Vec<(&str, Json)>) -> Json {
        Json::Obj(
            entries
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v))
                .collect(),
        )
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    index: usize,
    nodes: usize,
}

type ParseResult<T> = Result<T, ()>;

impl Parser<'_> {
    fn whitespace(&mut self) {
        while matches!(
            self.bytes.get(self.index),
            Some(b' ' | b'\t' | b'\n' | b'\r')
        ) {
            self.index += 1;
        }
    }

    fn rest_starts_with(&self, text: &[u8]) -> bool {
        self.bytes[self.index..].starts_with(text)
    }

    fn charge(&mut self) -> ParseResult<()> {
        if self.nodes >= MAX_NODES {
            return Err(());
        }
        self.nodes += 1;
        Ok(())
    }

    fn value(&mut self, depth: usize) -> ParseResult<Json> {
        if depth > PARSE_DEPTH_GUARD {
            return Err(());
        }
        self.charge()?;
        self.whitespace();
        match self.bytes.get(self.index) {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Json::Str),
            Some(b't') => self.literal(b"true", Json::Bool(true)),
            Some(b'f') => self.literal(b"false", Json::Bool(false)),
            Some(b'n') => self.literal(b"null", Json::Null),
            Some(b'N') => self.literal(b"NaN", Json::Float(f64::NAN)),
            Some(b'I') => self.literal(b"Infinity", Json::Float(f64::INFINITY)),
            Some(b'-') if self.bytes[self.index..].starts_with(b"-Infinity") => {
                self.literal(b"-Infinity", Json::Float(f64::NEG_INFINITY))
            }
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(()),
        }
    }

    fn literal(&mut self, text: &[u8], value: Json) -> ParseResult<Json> {
        if !self.rest_starts_with(text) {
            return Err(());
        }
        self.index += text.len();
        Ok(value)
    }

    fn digits(&mut self) -> usize {
        let start = self.index;
        while matches!(self.bytes.get(self.index), Some(b'0'..=b'9')) {
            self.index += 1;
        }
        self.index - start
    }

    fn number(&mut self) -> ParseResult<Json> {
        let start = self.index;
        if self.bytes.get(self.index) == Some(&b'-') {
            self.index += 1;
        }
        match self.bytes.get(self.index) {
            Some(b'0') => self.index += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(()),
        }
        let integer_end = self.index;
        let mut is_float = false;
        if self.bytes.get(self.index) == Some(&b'.')
            && matches!(self.bytes.get(self.index + 1), Some(b'0'..=b'9'))
        {
            self.index += 1;
            self.digits();
            is_float = true;
        }
        if matches!(self.bytes.get(self.index), Some(b'e' | b'E')) {
            let mut probe = self.index + 1;
            if matches!(self.bytes.get(probe), Some(b'+' | b'-')) {
                probe += 1;
            }
            if matches!(self.bytes.get(probe), Some(b'0'..=b'9')) {
                self.index = probe;
                self.digits();
                is_float = true;
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.index]).map_err(|_| ())?;
        if is_float {
            return text.parse::<f64>().map(Json::Float).map_err(|_| ());
        }
        let integer = &text[..integer_end - start];
        let magnitude = integer.trim_start_matches('-');
        if magnitude.len() > MAX_INT_DIGITS {
            return Err(());
        }
        let normalised = if magnitude == "0" { "0" } else { integer };
        Ok(Json::Int(normalised.to_owned()))
    }

    fn hex4(&mut self) -> ParseResult<u32> {
        let chunk = self.bytes.get(self.index..self.index + 4).ok_or(())?;
        let mut value = 0u32;
        for byte in chunk {
            value = value * 16 + (*byte as char).to_digit(16).ok_or(())?;
        }
        self.index += 4;
        Ok(value)
    }

    fn string(&mut self) -> ParseResult<String> {
        self.index += 1;
        let mut out = String::new();
        loop {
            let byte = *self.bytes.get(self.index).ok_or(())?;
            match byte {
                b'"' => {
                    self.index += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.index += 1;
                    let escape = *self.bytes.get(self.index).ok_or(())?;
                    self.index += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let first = self.hex4()?;
                            let code = if (0xd800..0xdc00).contains(&first)
                                && self.rest_starts_with(b"\\u")
                            {
                                let saved = self.index;
                                self.index += 2;
                                let second = self.hex4()?;
                                if (0xdc00..0xe000).contains(&second) {
                                    0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00)
                                } else {
                                    self.index = saved;
                                    first
                                }
                            } else {
                                first
                            };
                            // A lone surrogate is representable in Python but
                            // never encodable, so every consumer refuses it.
                            out.push(char::from_u32(code).ok_or(())?);
                        }
                        _ => return Err(()),
                    }
                }
                0x00..=0x1f => return Err(()),
                _ => {
                    let width = utf8_width(byte);
                    let chunk = self.bytes.get(self.index..self.index + width).ok_or(())?;
                    out.push_str(std::str::from_utf8(chunk).map_err(|_| ())?);
                    self.index += width;
                }
            }
        }
    }

    fn array(&mut self, depth: usize) -> ParseResult<Json> {
        self.index += 1;
        let mut items = Vec::new();
        self.whitespace();
        if self.bytes.get(self.index) == Some(&b']') {
            self.index += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.whitespace();
            match self.bytes.get(self.index) {
                Some(b',') => self.index += 1,
                Some(b']') => {
                    self.index += 1;
                    return Ok(Json::Arr(items));
                }
                _ => return Err(()),
            }
        }
    }

    fn object(&mut self, depth: usize) -> ParseResult<Json> {
        self.index += 1;
        let mut entries: Vec<(String, Json)> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        self.whitespace();
        if self.bytes.get(self.index) == Some(&b'}') {
            self.index += 1;
            return Ok(Json::Obj(entries));
        }
        loop {
            self.whitespace();
            if self.bytes.get(self.index) != Some(&b'"') {
                return Err(());
            }
            let key = self.string()?;
            self.charge()?;
            if !seen.insert(key.clone()) {
                return Err(());
            }
            self.whitespace();
            if self.bytes.get(self.index) != Some(&b':') {
                return Err(());
            }
            self.index += 1;
            let value = self.value(depth + 1)?;
            entries.push((key, value));
            self.whitespace();
            match self.bytes.get(self.index) {
                Some(b',') => self.index += 1,
                Some(b'}') => {
                    self.index += 1;
                    return Ok(Json::Obj(entries));
                }
                _ => return Err(()),
            }
        }
    }
}

fn utf8_width(lead: u8) -> usize {
    match lead {
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => 1,
    }
}

/// Parse one complete JSON document the way `json.loads` does.
pub(crate) fn parse(text: &str) -> Option<Json> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        index: 0,
        nodes: 0,
    };
    let value = parser.value(0).ok()?;
    parser.whitespace();
    (parser.index == parser.bytes.len()).then_some(value)
}

fn walk(value: &Json, depth: usize, nodes: &mut usize) -> bool {
    if depth > MAX_DEPTH || *nodes >= MAX_NODES {
        return false;
    }
    *nodes += 1;
    match value {
        Json::Null | Json::Bool(_) | Json::Int(_) => true,
        Json::Float(number) => number.is_finite(),
        Json::Str(text) => {
            text.chars().count() <= MAX_STRING_CHARS && text.len() <= MAX_CANONICAL_BYTES
        }
        Json::Arr(items) => items.iter().all(|item| walk(item, depth + 1, nodes)),
        Json::Obj(entries) => entries.iter().all(|(key, item)| {
            key.chars().count() <= MAX_STRING_CHARS
                && key.len() <= MAX_CANONICAL_BYTES
                && walk_key(depth + 1, nodes)
                && walk(item, depth + 1, nodes)
        }),
    }
}

fn walk_key(depth: usize, nodes: &mut usize) -> bool {
    if depth > MAX_DEPTH || *nodes >= MAX_NODES {
        return false;
    }
    *nodes += 1;
    true
}

pub(crate) fn valid(value: &Json) -> bool {
    walk(value, 0, &mut 0)
}

/// Parse bounded UTF-8 into a validated JSON object (`_json_object`).
pub(crate) fn parse_object(raw: &[u8]) -> Option<Json> {
    if raw.len() > MAX_CANONICAL_BYTES {
        return None;
    }
    let value = parse(std::str::from_utf8(raw).ok()?)?;
    (matches!(value, Json::Obj(_)) && valid(&value)).then_some(value)
}

fn write_string(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in text.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{09}' => out.extend_from_slice(b"\\t"),
            '\u{0a}' => out.extend_from_slice(b"\\n"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            '\u{0d}' => out.extend_from_slice(b"\\r"),
            ch if (ch as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", ch as u32).as_bytes());
            }
            ch => {
                let mut buffer = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn write_value(value: &Json, out: &mut Vec<u8>) {
    match value {
        Json::Null => out.extend_from_slice(b"null"),
        Json::Bool(true) => out.extend_from_slice(b"true"),
        Json::Bool(false) => out.extend_from_slice(b"false"),
        Json::Int(text) => out.extend_from_slice(text.as_bytes()),
        Json::Float(number) => out.extend_from_slice(python_float_repr(*number).as_bytes()),
        Json::Str(text) => write_string(text, out),
        Json::Arr(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_value(item, out);
            }
            out.push(b']');
        }
        Json::Obj(entries) => {
            let mut sorted: Vec<&(String, Json)> = entries.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            out.push(b'{');
            for (index, (key, item)) in sorted.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                write_value(item, out);
            }
            out.push(b'}');
        }
    }
}

/// Unbounded sorted compact encoding (`json.dumps(sort_keys=True)` shape).
pub(crate) fn encode(value: &Json) -> Vec<u8> {
    let mut out = Vec::new();
    write_value(value, &mut out);
    out
}

/// Validated canonical bytes no larger than the capture ceiling.
pub(crate) fn canonical(value: &Json) -> Option<Vec<u8>> {
    if !valid(value) {
        return None;
    }
    let encoded = encode(value);
    (encoded.len() <= MAX_CANONICAL_BYTES).then_some(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_object_parses_and_duplicate_keys_fail() {
        assert!(parse_object(br#"{"a":1}"#).is_some());
        assert!(parse_object(br#"{"a":1,"a":2}"#).is_none());
    }

    #[test]
    fn wide_object_under_the_byte_ceiling_is_rejected_during_parse() {
        let mut body = String::from("{");
        for index in 0..6000 {
            if index > 0 {
                body.push(',');
            }
            body.push_str(&format!("\"{index:04}\":1"));
        }
        body.push('}');
        assert!(body.len() < MAX_CANONICAL_BYTES);
        assert!(parse_object(body.as_bytes()).is_none());
    }
}

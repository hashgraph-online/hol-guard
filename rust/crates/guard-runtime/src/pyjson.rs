//! Order-preserving JSON with the CPython `json.loads` rules the adapter
//! detectors were written against: objects keep file order (a duplicate key
//! keeps its first position and takes the last value), `NaN`/`Infinity` parse,
//! integers keep their full digits, and `str()` of a scalar matches CPython.
//!
//! A syntax error is a distinct outcome from input CPython would raise on
//! instead of returning (nesting past the recursion limit, an integer past the
//! digit limit): callers refuse the second kind. A lone `\uXXXX` surrogate
//! escape is not one of those refusals in a value. Rust `char` cannot store
//! the unpaired surrogate CPython keeps, so the escape decodes to U+FFFD and
//! parsing continues. An object key carrying one is refused instead: two keys
//! that differ only in the surrogate would merge onto U+FFFD and the later
//! member would silently replace a member CPython lists separately.

use serde_json::Value;

const MAX_DEPTH: usize = 900;
const MAX_INT_DIGITS: usize = 4300;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PyVal {
    Null,
    Bool(bool),
    /// Canonical decimal digits, as `str(int(text))` renders them.
    Int(String),
    Float(f64),
    Str(String),
    List(Vec<PyVal>),
    Dict(Vec<(String, PyVal)>),
}

#[derive(Debug, PartialEq)]
pub(crate) enum JsonFailure {
    /// `json.JSONDecodeError`: the text is not JSON.
    Syntax,
    /// Input CPython raises a non-`JSONDecodeError` exception on.
    Unrepresentable,
    /// An integer literal over CPython's decimal digit limit (a `ValueError`).
    IntegerLimit,
    /// A repeated object key, with [`parse_unique`].
    Duplicate,
}

impl PyVal {
    pub(crate) fn get(&self, key: &str) -> Option<&PyVal> {
        match self {
            PyVal::Dict(entries) => entries
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            PyVal::Str(text) => Some(text),
            _ => None,
        }
    }

    pub(crate) fn as_dict(&self) -> Option<&[(String, PyVal)]> {
        match self {
            PyVal::Dict(entries) => Some(entries),
            _ => None,
        }
    }

    pub(crate) fn as_list(&self) -> Option<&[PyVal]> {
        match self {
            PyVal::List(items) => Some(items),
            _ => None,
        }
    }

    /// `bool(value)`.
    pub(crate) fn truthy(&self) -> bool {
        match self {
            PyVal::Null => false,
            PyVal::Bool(flag) => *flag,
            PyVal::Int(digits) => digits != "0",
            PyVal::Float(number) => *number != 0.0,
            PyVal::Str(text) => !text.is_empty(),
            PyVal::List(items) => !items.is_empty(),
            PyVal::Dict(entries) => !entries.is_empty(),
        }
    }

    /// `str(value)` for `str`, `int`, `float` and `bool`; `None` otherwise.
    pub(crate) fn scalar_text(&self) -> Option<String> {
        match self {
            PyVal::Str(text) => Some(text.clone()),
            PyVal::Bool(true) => Some("True".to_owned()),
            PyVal::Bool(false) => Some("False".to_owned()),
            PyVal::Int(digits) => Some(digits.clone()),
            PyVal::Float(number) => Some(float_repr(*number)),
            _ => None,
        }
    }

    /// The JSON value carried on the wire; a non-finite float has no JSON form.
    pub(crate) fn to_json(&self) -> Option<Value> {
        Some(match self {
            PyVal::Null => Value::Null,
            PyVal::Bool(flag) => Value::Bool(*flag),
            PyVal::Int(digits) => serde_json::from_str(digits).ok()?,
            PyVal::Float(number) => Value::Number(serde_json::Number::from_f64(*number)?),
            PyVal::Str(text) => Value::String(text.clone()),
            PyVal::List(items) => Value::Array(
                items
                    .iter()
                    .map(PyVal::to_json)
                    .collect::<Option<Vec<_>>>()?,
            ),
            PyVal::Dict(entries) => {
                let mut map = serde_json::Map::new();
                for (key, value) in entries {
                    map.insert(key.clone(), value.to_json()?);
                }
                Value::Object(map)
            }
        })
    }

    /// An injective rendering with sorted keys: two values render equally
    /// exactly when `json.dumps(sort_keys=True)` renders them equally.
    pub(crate) fn canonical_key(&self) -> String {
        let mut out = String::new();
        self.write_key(&mut out);
        out
    }

    fn write_key(&self, out: &mut String) {
        match self {
            PyVal::Null => out.push_str("null"),
            PyVal::Bool(true) => out.push_str("true"),
            PyVal::Bool(false) => out.push_str("false"),
            PyVal::Int(digits) => out.push_str(digits),
            PyVal::Float(number) => {
                out.push('f');
                out.push_str(&float_repr(*number));
            }
            PyVal::Str(text) => {
                out.push_str(&serde_json::to_string(text).unwrap_or_default());
            }
            PyVal::List(items) => {
                out.push('[');
                for item in items {
                    item.write_key(out);
                    out.push(',');
                }
                out.push(']');
            }
            PyVal::Dict(entries) => {
                let mut sorted: Vec<&(String, PyVal)> = entries.iter().collect();
                sorted.sort_by(|left, right| left.0.cmp(&right.0));
                out.push('{');
                for (key, value) in sorted {
                    out.push_str(&serde_json::to_string(key).unwrap_or_default());
                    out.push(':');
                    value.write_key(out);
                    out.push(',');
                }
                out.push('}');
            }
        }
    }
}

/// CPython `repr(float)`: shortest round-trip digits, fixed notation for a
/// decimal exponent in `-4..16`, scientific otherwise.
pub(crate) fn float_repr(number: f64) -> String {
    if number.is_nan() {
        return "nan".to_owned();
    }
    if number.is_infinite() {
        return if number > 0.0 { "inf" } else { "-inf" }.to_owned();
    }
    if number == 0.0 {
        return if number.is_sign_negative() {
            "-0.0"
        } else {
            "0.0"
        }
        .to_owned();
    }
    let scientific = format!("{:e}", number.abs());
    let (mantissa, exponent) = scientific.split_once('e').unwrap_or((&scientific, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let sign = if number < 0.0 { "-" } else { "" };
    if (-4..16).contains(&exponent) {
        if exponent >= 0 {
            let point = exponent as usize + 1;
            if digits.len() <= point {
                format!("{sign}{digits}{}.0", "0".repeat(point - digits.len()))
            } else {
                format!("{sign}{}.{}", &digits[..point], &digits[point..])
            }
        } else {
            format!("{sign}0.{}{digits}", "0".repeat((-exponent - 1) as usize))
        }
    } else {
        let tail = if digits.len() > 1 {
            format!("{}.{}", &digits[..1], &digits[1..])
        } else {
            digits
        };
        let exp_sign = if exponent < 0 { '-' } else { '+' };
        format!("{sign}{tail}e{exp_sign}{:02}", exponent.abs())
    }
}

pub(crate) fn parse(text: &str) -> Result<PyVal, JsonFailure> {
    parse_with(text, false, char::REPLACEMENT_CHARACTER)
}

/// A noncharacter standing in for a lone surrogate in a value, for callers
/// that must tell the text CPython keeps (and cannot later encode) from a
/// genuine U+FFFD.
pub(crate) const LONE_SURROGATE_MARK: char = '\u{fdd0}';

/// Parse like [`parse`], decoding a lone surrogate escape in a value to
/// [`LONE_SURROGATE_MARK`] instead of U+FFFD.
pub(crate) fn parse_marking_lone_surrogates(text: &str) -> Result<PyVal, JsonFailure> {
    parse_with(text, false, LONE_SURROGATE_MARK)
}

/// Parse like an `object_pairs_hook` that rejects a repeated key: the failure
/// surfaces when the object closes, so a later syntax error in the same
/// object still wins.
pub(crate) fn parse_unique(text: &str) -> Result<PyVal, JsonFailure> {
    parse_with(text, true, char::REPLACEMENT_CHARACTER)
}

fn parse_with(text: &str, unique: bool, lone_surrogate: char) -> Result<PyVal, JsonFailure> {
    parse_parser(Parser::new(text, unique, lone_surrogate, false)).map(|(value, _)| value)
}

/// First code point of the private-use range a lone surrogate maps onto in
/// [`parse_mapping_lone_surrogates`]: U+D800..=U+DFFF become
/// U+F0000..=U+F07FF, so a value or key keeps one distinct character per
/// surrogate CPython would keep.
pub(crate) const SURROGATE_PLANE_BASE: u32 = 0xF0000;

/// Whether `character` lies in the range lone surrogates map onto.
pub(crate) fn in_surrogate_plane(character: char) -> bool {
    (SURROGATE_PLANE_BASE..SURROGATE_PLANE_BASE + 0x800).contains(&(character as u32))
}

/// A parse in which every lone surrogate escape, in a key or a value, maps
/// onto [`SURROGATE_PLANE_BASE`] instead of being replaced or refused.
pub(crate) struct SurrogateMapped {
    pub(crate) value: PyVal,
    /// At least one lone surrogate was mapped.
    pub(crate) mapped: bool,
    /// The text already held a character in the mapped range, so a mapped
    /// character can no longer be told from a genuine one.
    pub(crate) collision: bool,
}

pub(crate) fn parse_mapping_lone_surrogates(text: &str) -> Result<SurrogateMapped, JsonFailure> {
    let raw_collision = text.chars().any(in_surrogate_plane);
    let (value, parser_state) =
        parse_parser(Parser::new(text, false, char::REPLACEMENT_CHARACTER, true))?;
    Ok(SurrogateMapped {
        value,
        mapped: parser_state.0,
        collision: raw_collision || parser_state.1,
    })
}

fn parse_parser(mut parser: Parser<'_>) -> Result<(PyVal, (bool, bool)), JsonFailure> {
    parser.skip_space();
    let value = parser.value(0)?;
    parser.skip_space();
    if parser.position != parser.text.len() {
        return Err(JsonFailure::Syntax);
    }
    Ok((value, (parser.mapped, parser.plane_collision)))
}

struct Parser<'a> {
    text: &'a [u8],
    position: usize,
    unique: bool,
    saw_lone_surrogate: bool,
    /// What a lone surrogate escape in a value decodes to.
    lone_surrogate: char,
    /// Map lone surrogates onto [`SURROGATE_PLANE_BASE`] in keys and values.
    map_surrogates: bool,
    mapped: bool,
    plane_collision: bool,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str, unique: bool, lone_surrogate: char, map_surrogates: bool) -> Self {
        Parser {
            text: text.as_bytes(),
            position: 0,
            unique,
            saw_lone_surrogate: false,
            lone_surrogate,
            map_surrogates,
            mapped: false,
            plane_collision: false,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.text.get(self.position).copied()
    }

    fn skip_space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.position += 1;
        }
    }

    fn literal(&mut self, word: &str, value: PyVal) -> Result<PyVal, JsonFailure> {
        if self.text[self.position..].starts_with(word.as_bytes()) {
            self.position += word.len();
            Ok(value)
        } else {
            Err(JsonFailure::Syntax)
        }
    }

    fn value(&mut self, depth: usize) -> Result<PyVal, JsonFailure> {
        match self.peek().ok_or(JsonFailure::Syntax)? {
            b'"' => self.string().map(PyVal::Str),
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'n' => self.literal("null", PyVal::Null),
            b't' => self.literal("true", PyVal::Bool(true)),
            b'f' => self.literal("false", PyVal::Bool(false)),
            b'N' => self.literal("NaN", PyVal::Float(f64::NAN)),
            b'I' => self.literal("Infinity", PyVal::Float(f64::INFINITY)),
            b'-' if self.text[self.position..].starts_with(b"-Infinity") => {
                self.literal("-Infinity", PyVal::Float(f64::NEG_INFINITY))
            }
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(JsonFailure::Syntax),
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.position;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.position += 1;
        }
        self.position - start
    }

    fn number(&mut self) -> Result<PyVal, JsonFailure> {
        let start = self.position;
        if self.peek() == Some(b'-') {
            self.position += 1;
        }
        match self.peek() {
            Some(b'0') => self.position += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(JsonFailure::Syntax),
        }
        let integer_end = self.position;
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            let mark = self.position;
            self.position += 1;
            if self.digits() == 0 {
                self.position = mark;
            } else {
                is_float = true;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            let mark = self.position;
            self.position += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.position += 1;
            }
            if self.digits() == 0 {
                self.position = mark;
            } else {
                is_float = true;
            }
        }
        let literal = std::str::from_utf8(&self.text[start..self.position])
            .map_err(|_| JsonFailure::Syntax)?;
        if is_float {
            return literal
                .parse::<f64>()
                .map(PyVal::Float)
                .map_err(|_| JsonFailure::Syntax);
        }
        let integer = &literal[..integer_end - start];
        let magnitude = integer.trim_start_matches('-');
        if magnitude.len() > MAX_INT_DIGITS {
            return Err(JsonFailure::IntegerLimit);
        }
        Ok(PyVal::Int(if magnitude == "0" {
            "0".to_owned()
        } else {
            integer.to_owned()
        }))
    }

    fn hex4(&mut self) -> Result<u32, JsonFailure> {
        let end = self.position + 4;
        let digits = self
            .text
            .get(self.position..end)
            .ok_or(JsonFailure::Syntax)?;
        let text = std::str::from_utf8(digits).map_err(|_| JsonFailure::Syntax)?;
        if !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(JsonFailure::Syntax);
        }
        self.position = end;
        u32::from_str_radix(text, 16).map_err(|_| JsonFailure::Syntax)
    }

    fn string(&mut self) -> Result<String, JsonFailure> {
        self.position += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let byte = self.peek().ok_or(JsonFailure::Syntax)?;
            self.position += 1;
            match byte {
                b'"' => break,
                0..=0x1f => return Err(JsonFailure::Syntax),
                b'\\' => {
                    let escape = self.peek().ok_or(JsonFailure::Syntax)?;
                    self.position += 1;
                    match escape {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let mut code = self.hex4()?;
                            if (0xd800..0xdc00).contains(&code)
                                && self.text[self.position..].starts_with(b"\\u")
                            {
                                let mark = self.position;
                                self.position += 2;
                                let low = self.hex4()?;
                                if (0xdc00..0xe000).contains(&low) {
                                    code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                                } else {
                                    self.position = mark;
                                }
                            }
                            let character = match char::from_u32(code) {
                                Some(character) => {
                                    if self.map_surrogates && in_surrogate_plane(character) {
                                        self.plane_collision = true;
                                    }
                                    character
                                }
                                None if self.map_surrogates => {
                                    self.mapped = true;
                                    char::from_u32(SURROGATE_PLANE_BASE + code - 0xd800)
                                        .ok_or(JsonFailure::Syntax)?
                                }
                                None => {
                                    self.saw_lone_surrogate = true;
                                    self.lone_surrogate
                                }
                            };
                            let mut buffer = [0_u8; 4];
                            out.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
                        }
                        _ => return Err(JsonFailure::Syntax),
                    }
                }
                other => out.push(other),
            }
        }
        String::from_utf8(out).map_err(|_| JsonFailure::Syntax)
    }

    fn array(&mut self, depth: usize) -> Result<PyVal, JsonFailure> {
        if depth >= MAX_DEPTH {
            return Err(JsonFailure::Unrepresentable);
        }
        self.position += 1;
        let mut items = Vec::new();
        self.skip_space();
        if self.peek() == Some(b']') {
            self.position += 1;
            return Ok(PyVal::List(items));
        }
        loop {
            self.skip_space();
            items.push(self.value(depth + 1)?);
            self.saw_lone_surrogate = false;
            self.skip_space();
            match self.peek() {
                Some(b',') => self.position += 1,
                Some(b']') => {
                    self.position += 1;
                    return Ok(PyVal::List(items));
                }
                _ => return Err(JsonFailure::Syntax),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<PyVal, JsonFailure> {
        if depth >= MAX_DEPTH {
            return Err(JsonFailure::Unrepresentable);
        }
        self.position += 1;
        let mut entries: Vec<(String, PyVal)> = Vec::new();
        let mut duplicate = false;
        // Key -> entries index, so a duplicate member replaces the value at its
        // original position without rescanning every parsed key.
        let mut positions: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        self.skip_space();
        if self.peek() == Some(b'}') {
            self.position += 1;
            return Ok(PyVal::Dict(entries));
        }
        loop {
            self.skip_space();
            if self.peek() != Some(b'"') {
                return Err(JsonFailure::Syntax);
            }
            let key = self.string()?;
            if std::mem::take(&mut self.saw_lone_surrogate) {
                return Err(JsonFailure::Unrepresentable);
            }
            self.skip_space();
            if self.peek() != Some(b':') {
                return Err(JsonFailure::Syntax);
            }
            self.position += 1;
            self.skip_space();
            let value = self.value(depth + 1)?;
            self.saw_lone_surrogate = false;
            match positions.get(key.as_str()) {
                Some(&index) => {
                    if self.unique {
                        duplicate = true;
                    }
                    entries[index].1 = value;
                }
                None => {
                    positions.insert(key.clone(), entries.len());
                    entries.push((key, value));
                }
            }
            self.skip_space();
            match self.peek() {
                Some(b',') => self.position += 1,
                Some(b'}') => {
                    self.position += 1;
                    if duplicate {
                        return Err(JsonFailure::Duplicate);
                    }
                    return Ok(PyVal::Dict(entries));
                }
                _ => return Err(JsonFailure::Syntax),
            }
        }
    }
}

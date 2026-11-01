//! Strict JSON intake and canonical bytes for hosted cloud actions.
//!
//! A cloud action's exact identity is a digest over canonical JSON. Two inputs
//! that mean the same JSON value produce the same bytes; inputs whose meaning
//! is ambiguous (duplicate keys, non-integral or out-of-range numbers, deep
//! nesting) are rejected rather than resolved by a parser's last-key-wins
//! habit. Strings are compared by exact code points: no Unicode normalization,
//! so two spellings that render alike are two actions and each needs its own
//! approval.

use std::collections::HashSet;
use std::fmt;

use serde::de::{DeserializeSeed, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Deepest object/array nesting accepted anywhere in a request.
pub const MAX_DEPTH: usize = 32;
/// Largest canonical encoding accepted for one action's arguments.
pub const MAX_ARGUMENT_BYTES: usize = 64 * 1024;
/// Integers outside this range lose precision in common JSON consumers.
const MAX_SAFE_INTEGER: i128 = 9_007_199_254_740_991;
const ARBITRARY_PRECISION_NUMBER_TOKEN: &str = "$serde_json::private::Number";
/// serde_json gives strings with this prefix a meaning of their own while it
/// builds a value (a one-entry object becomes a number or a re-parsed document).
const RESERVED_STRING_PREFIX: &str = "$serde_json::private::";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalError {
    DuplicateKey,
    TooDeep,
    UnsupportedNumber,
    TooLarge,
    Malformed,
}

impl CanonicalError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::DuplicateKey => "duplicate_key",
            Self::TooDeep => "too_deep",
            Self::UnsupportedNumber => "unsupported_number",
            Self::TooLarge => "too_large",
            Self::Malformed => "malformed",
        }
    }
}

/// Parse a JSON document, rejecting duplicate object keys at any depth and
/// nesting deeper than [`MAX_DEPTH`].
pub fn parse_strict(bytes: &[u8]) -> Result<Value, CanonicalError> {
    if spells_reserved_string(bytes) {
        return Err(CanonicalError::Malformed);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    match (StrictSeed { depth: 0 }).deserialize(&mut deserializer) {
        Ok(()) => {}
        Err(error) => return Err(classify(&error.to_string())),
    }
    deserializer.end().map_err(|_| CanonicalError::Malformed)?;
    serde_json::from_slice(bytes).map_err(|_| CanonicalError::Malformed)
}

/// Whether any string, key or value, decodes to one that starts with
/// [`RESERVED_STRING_PREFIX`], whatever escapes spell it. No cloud action has a
/// use for such a string, and accepting it would let one document mean two things.
fn spells_reserved_string(bytes: &[u8]) -> bool {
    let shortest = RESERVED_STRING_PREFIX.len();
    let mut index = 0;
    while let Some(offset) = bytes[index..].iter().position(|byte| *byte == b'"') {
        let start = index + offset;
        let mut end = start + 1;
        while end < bytes.len() && bytes[end] != b'"' {
            end += if bytes[end] == b'\\' { 2 } else { 1 };
        }
        if end >= bytes.len() {
            return false;
        }
        // A decoded string is never longer than its encoding, so anything
        // shorter than the prefix cannot spell it. There is no upper bound:
        // escapes can make an encoding arbitrarily long.
        let inner = end - start - 1;
        if inner >= shortest
            && serde_json::from_slice::<String>(&bytes[start..=end])
                .is_ok_and(|text| text.starts_with(RESERVED_STRING_PREFIX))
        {
            return true;
        }
        index = end + 1;
    }
    false
}

fn classify(message: &str) -> CanonicalError {
    if message.starts_with("duplicate_key") {
        CanonicalError::DuplicateKey
    } else if message.starts_with("too_deep") {
        CanonicalError::TooDeep
    } else {
        CanonicalError::Malformed
    }
}

struct StrictSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(StrictVisitor { depth: self.depth })
    }
}

struct StrictVisitor {
    depth: usize,
}

impl StrictVisitor {
    fn nested<E: serde::de::Error>(&self) -> Result<usize, E> {
        let depth = self.depth + 1;
        if depth > MAX_DEPTH {
            return Err(E::custom("too_deep"));
        }
        Ok(depth)
    }
}

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let depth = self.nested()?;
        while seq.next_element_seed(StrictSeed { depth })?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let Some(first) = map.next_key::<String>()? else {
            self.nested::<A::Error>()?;
            return Ok(());
        };
        // `arbitrary_precision` hands a number over as a one-entry map.
        if first == ARBITRARY_PRECISION_NUMBER_TOKEN {
            map.next_value::<String>()?;
            if map.next_key::<String>()?.is_some() {
                return Err(A::Error::custom("malformed"));
            }
            return Ok(());
        }
        let depth = self.nested()?;
        map.next_value_seed(StrictSeed { depth })?;
        let mut seen = HashSet::from([first]);
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key) {
                return Err(A::Error::custom("duplicate_key"));
            }
            map.next_value_seed(StrictSeed { depth })?;
        }
        Ok(())
    }
}

/// RFC 8785 canonical bytes for the JSON subset cloud actions accept:
/// object keys sorted by UTF-16 code units, minimal string escapes, and
/// integers only (within the IEEE-754 safe range).
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    let mut out = Vec::new();
    write_value(value, &mut out, 0)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut Vec<u8>, depth: usize) -> Result<(), CanonicalError> {
    if depth > MAX_DEPTH {
        return Err(CanonicalError::TooDeep);
    }
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => write_integer(&number.to_string(), out)?,
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_value(item, out, depth + 1)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push(b'{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                write_value(&map[key], out, depth + 1)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// `arbitrary_precision` keeps the literal's text. Accept only a plain integer
/// literal within the safe range and write its shortest form.
fn write_integer(literal: &str, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
    let digits = literal.strip_prefix('-').unwrap_or(literal);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) || digits.len() > 16 {
        return Err(CanonicalError::UnsupportedNumber);
    }
    let parsed: i128 = literal
        .parse()
        .map_err(|_| CanonicalError::UnsupportedNumber)?;
    if parsed.abs() > MAX_SAFE_INTEGER {
        return Err(CanonicalError::UnsupportedNumber);
    }
    out.extend_from_slice(parsed.to_string().as_bytes());
    Ok(())
}

fn write_string(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for character in text.chars() {
        match character {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buffer = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// Canonical bytes for one action's arguments, bounded by [`MAX_ARGUMENT_BYTES`].
pub fn canonical_arguments(arguments: &Value) -> Result<Vec<u8>, CanonicalError> {
    if !arguments.is_object() {
        return Err(CanonicalError::Malformed);
    }
    let bytes = canonical_bytes(arguments)?;
    if bytes.len() > MAX_ARGUMENT_BYTES {
        return Err(CanonicalError::TooLarge);
    }
    Ok(bytes)
}

/// Domain-separated SHA-256 over length-prefixed parts, hex encoded.
pub fn domain_digest(domain: &str, parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0u8]);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hex::encode(hasher.finalize())
}

#![forbid(unsafe_code)]

use serde_json::{Map, Number, Value};

#[path = "strict_json_value.rs"]
mod value;

pub(crate) fn from_value<T: serde::de::DeserializeOwned>(
    value: Value,
) -> Result<T, serde_json::Error> {
    value::from_value(value)
}

const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_COLLECTION_ITEMS: usize = 4_096;
const MAX_JSON_STRING_BYTES: usize = 1024 * 1024;

/// Parse containers directly so arbitrary-precision numbers cannot appear as
/// serde's synthetic map tokens. Primitive escape/number syntax remains owned
/// by serde_json, matching the pair parser's existing token-span convention.
struct StrictJsonParser<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl StrictJsonParser<'_> {
    fn whitespace(&mut self) {
        while matches!(
            self.bytes.get(self.index),
            Some(b' ' | b'\n' | b'\r' | b'\t')
        ) {
            self.index += 1;
        }
    }

    fn consume(&mut self, byte: u8) -> bool {
        if self.bytes.get(self.index) == Some(&byte) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, &'static str> {
        if depth > MAX_JSON_DEPTH {
            return Err("native_json_depth_exceeded");
        }
        self.whitespace();
        match self.bytes.get(self.index) {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self
                .string("native_json_string_too_large")
                .map(Value::String),
            Some(b't') => self.literal(b"true", Value::Bool(true)),
            Some(b'f') => self.literal(b"false", Value::Bool(false)),
            Some(b'n') => self.literal(b"null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err("native_request_invalid_json"),
        }
    }

    fn literal(&mut self, text: &[u8], value: Value) -> Result<Value, &'static str> {
        if !self.bytes[self.index..].starts_with(text) {
            return Err("native_request_invalid_json");
        }
        self.index += text.len();
        Ok(value)
    }

    fn string(&mut self, size_error: &'static str) -> Result<String, &'static str> {
        let start = self.index;
        if !self.consume(b'"') {
            return Err("native_request_invalid_json");
        }
        while let Some(byte) = self.bytes.get(self.index) {
            match byte {
                b'"' => {
                    self.index += 1;
                    let value: String = serde_json::from_slice(&self.bytes[start..self.index])
                        .map_err(|_| "native_request_invalid_json")?;
                    if value.len() > MAX_JSON_STRING_BYTES {
                        return Err(size_error);
                    }
                    return Ok(value);
                }
                b'\\' => {
                    self.index += 1;
                    if self.index == self.bytes.len() {
                        return Err("native_request_invalid_json");
                    }
                    self.index += 1;
                }
                _ => self.index += 1,
            }
        }
        Err("native_request_invalid_json")
    }

    fn number(&mut self) -> Result<Value, &'static str> {
        let start = self.index;
        while matches!(
            self.bytes.get(self.index),
            Some(b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
        ) {
            self.index += 1;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.index])
            .map_err(|_| "native_json_number_invalid")?;
        let number: Number = text.parse().map_err(|_| "native_json_number_invalid")?;
        if text.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E'))
            && !number.as_f64().is_some_and(f64::is_finite)
        {
            return Err("native_json_number_invalid");
        }
        Ok(Value::Number(number))
    }

    fn array(&mut self, depth: usize) -> Result<Value, &'static str> {
        self.index += 1;
        self.whitespace();
        let mut output = Vec::new();
        if self.consume(b']') {
            return Ok(Value::Array(output));
        }
        loop {
            if output.len() >= MAX_JSON_COLLECTION_ITEMS {
                return Err("native_json_array_too_wide");
            }
            output.push(self.value(depth + 1)?);
            self.whitespace();
            if self.consume(b']') {
                return Ok(Value::Array(output));
            }
            if !self.consume(b',') {
                return Err("native_request_invalid_json");
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, &'static str> {
        self.index += 1;
        self.whitespace();
        let mut output = Map::new();
        if self.consume(b'}') {
            return Ok(Value::Object(output));
        }
        loop {
            self.whitespace();
            let key = self.string("native_json_key_too_large")?;
            if output.contains_key(&key) {
                return Err("native_json_duplicate_key");
            }
            if output.len() >= MAX_JSON_COLLECTION_ITEMS {
                return Err("native_json_object_too_wide");
            }
            self.whitespace();
            if !self.consume(b':') {
                return Err("native_request_invalid_json");
            }
            output.insert(key, self.value(depth + 1)?);
            self.whitespace();
            if self.consume(b'}') {
                return Ok(Value::Object(output));
            }
            if !self.consume(b',') {
                return Err("native_request_invalid_json");
            }
        }
    }
}

pub(crate) fn parse(bytes: &[u8]) -> Result<Value, String> {
    let mut parser = StrictJsonParser { bytes, index: 0 };
    let value = parser.value(0).map_err(str::to_owned)?;
    parser.whitespace();
    if parser.index != bytes.len() {
        return Err("native_request_trailing_json".to_owned());
    }
    Ok(value)
}

#[cfg(test)]
pub(crate) const TEST_MAX_JSON_DEPTH: usize = MAX_JSON_DEPTH;

#[cfg(test)]
pub(crate) const TEST_MAX_JSON_COLLECTION_ITEMS: usize = MAX_JSON_COLLECTION_ITEMS;

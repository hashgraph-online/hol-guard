//! Data-only JSON boundary for the Gauntlet Rust migration.
//!
//! These limits and canonical bytes follow `ci/gauntlet/benchmark/json_data.py`
//! at the separately reviewed Gauntlet source revision. No candidate code is
//! imported or executed to interpret a record.

use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;

mod identity;
mod policy;
mod runner_config;
mod schema;
mod worker_request;
mod worker_response;
pub use identity::{is_git_sha, validate_source_identity, IdentityError};
pub use policy::{bind_gate_policy, GatePolicyError};
pub use runner_config::{
    canonical_relative_asset_path, validate_runner_declaration, RunnerConfigError,
    RunnerDeclaration,
};
pub use schema::{load_record, schema_kinds, Record, RecordError};
pub use worker_request::{WorkerAction, WorkerRequest, WorkerRequestError};
pub use worker_response::{WorkerResponse, WorkerResponseError, WorkerState};

pub const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_DEPTH: usize = 32;
pub const MAX_NODES: usize = 500_000;
const MAX_INTEGER_DIGITS: usize = 4_300; // CPython 3.12's default decimal-int limit.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractError {
    TooManyBytes,
    TooDeep,
    TooManyNodes,
    TooManyIntegerDigits,
    InvalidJson,
    DuplicateKey,
    NonFiniteNumber,
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::TooManyBytes => "JSON record exceeds its byte limit",
            Self::TooDeep => "JSON record exceeds its depth limit",
            Self::TooManyNodes => "JSON record exceeds its node limit",
            Self::TooManyIntegerDigits => "JSON integer exceeds the Python decimal digit limit",
            Self::InvalidJson => "invalid JSON record",
            Self::DuplicateKey => "duplicate JSON object key",
            Self::NonFiniteNumber => "non-finite JSON number",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ContractError {}

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Null,
    Bool(bool),
    Integer(String),
    Float(f64),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

struct Parser<'a> {
    bytes: &'a [u8],
    offset: usize,
    nodes: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.offset += 1;
        }
    }

    fn byte(&mut self, expected: u8) -> Result<(), ContractError> {
        if self.peek() != Some(expected) {
            return Err(ContractError::InvalidJson);
        }
        self.offset += 1;
        Ok(())
    }

    fn literal(&mut self, expected: &[u8]) -> Result<(), ContractError> {
        if !self.bytes[self.offset..].starts_with(expected) {
            return Err(ContractError::InvalidJson);
        }
        self.offset += expected.len();
        Ok(())
    }

    fn string(&mut self) -> Result<String, ContractError> {
        let start = self.offset;
        self.byte(b'"')?;
        loop {
            let ch = self.peek().ok_or(ContractError::InvalidJson)?;
            self.offset += 1;
            match ch {
                b'"' => {
                    return serde_json::from_slice(&self.bytes[start..self.offset])
                        .map_err(|_| ContractError::InvalidJson)
                }
                b'\\' => {
                    if self.peek().is_none() {
                        return Err(ContractError::InvalidJson);
                    }
                    self.offset += 1;
                }
                0..=31 => return Err(ContractError::InvalidJson),
                _ => {}
            }
        }
    }

    fn number(&mut self) -> Result<Value, ContractError> {
        let start = self.offset;
        if self.peek() == Some(b'-') {
            self.offset += 1;
        }
        let digits = self.offset;
        match self.peek() {
            Some(b'0') => self.offset += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.offset += 1;
                }
            }
            _ => return Err(ContractError::InvalidJson),
        }
        let integer_digits = self.offset - digits;
        let mut floating = false;
        if self.peek() == Some(b'.') {
            floating = true;
            self.offset += 1;
            let fraction_start = self.offset;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.offset += 1;
            }
            if self.offset == fraction_start {
                return Err(ContractError::InvalidJson);
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            floating = true;
            self.offset += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.offset += 1;
            }
            let exponent_start = self.offset;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.offset += 1;
            }
            if self.offset == exponent_start {
                return Err(ContractError::InvalidJson);
            }
        }
        let raw = std::str::from_utf8(&self.bytes[start..self.offset])
            .map_err(|_| ContractError::InvalidJson)?;
        if floating {
            let parsed = raw.parse::<f64>().map_err(|_| ContractError::InvalidJson)?;
            if !parsed.is_finite() {
                return Err(ContractError::NonFiniteNumber);
            }
            Ok(Value::Float(parsed))
        } else {
            if integer_digits > MAX_INTEGER_DIGITS {
                return Err(ContractError::TooManyIntegerDigits);
            }
            Ok(Value::Integer(
                if raw == "-0" { "0" } else { raw }.to_owned(),
            ))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, ContractError> {
        if depth > MAX_DEPTH {
            return Err(ContractError::TooDeep);
        }
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(ContractError::TooManyNodes);
        }
        self.whitespace();
        match self.peek() {
            Some(b'n') => {
                self.literal(b"null")?;
                Ok(Value::Null)
            }
            Some(b't') => {
                self.literal(b"true")?;
                Ok(Value::Bool(true))
            }
            Some(b'f') => {
                self.literal(b"false")?;
                Ok(Value::Bool(false))
            }
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b'[') => self.array(depth),
            Some(b'{') => self.object(depth),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(ContractError::InvalidJson),
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, ContractError> {
        self.byte(b'[')?;
        self.whitespace();
        let mut rows = Vec::new();
        if self.peek() == Some(b']') {
            self.offset += 1;
            return Ok(Value::Array(rows));
        }
        loop {
            rows.push(self.value(depth + 1)?);
            self.whitespace();
            match self.peek() {
                Some(b',') => self.offset += 1,
                Some(b']') => {
                    self.offset += 1;
                    return Ok(Value::Array(rows));
                }
                _ => return Err(ContractError::InvalidJson),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, ContractError> {
        self.byte(b'{')?;
        self.whitespace();
        let mut rows = BTreeMap::new();
        if self.peek() == Some(b'}') {
            self.offset += 1;
            return Ok(Value::Object(rows));
        }
        loop {
            self.whitespace();
            let key = self.string()?;
            if rows.contains_key(&key) {
                return Err(ContractError::DuplicateKey);
            }
            self.whitespace();
            self.byte(b':')?;
            let value = self.value(depth + 1)?;
            rows.insert(key, value);
            self.whitespace();
            match self.peek() {
                Some(b',') => self.offset += 1,
                Some(b'}') => {
                    self.offset += 1;
                    return Ok(Value::Object(rows));
                }
                _ => return Err(ContractError::InvalidJson),
            }
        }
    }
}

fn write(out: &mut Vec<u8>, value: &Value) -> Result<(), ContractError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Integer(raw) => out.extend_from_slice(raw.as_bytes()),
        Value::Float(number) => out.extend_from_slice(python_float(*number).as_bytes()),
        Value::String(value) => out.extend_from_slice(
            serde_json::to_string(value)
                .map_err(|_| ContractError::InvalidJson)?
                .as_bytes(),
        ),
        Value::Array(rows) => {
            out.push(b'[');
            for (index, row) in rows.iter().enumerate() {
                if index != 0 {
                    out.push(b',');
                }
                write(out, row)?;
            }
            out.push(b']');
        }
        Value::Object(rows) => {
            out.push(b'{');
            for (index, (key, row)) in rows.iter().enumerate() {
                if index != 0 {
                    out.push(b',');
                }
                out.extend_from_slice(
                    serde_json::to_string(key)
                        .map_err(|_| ContractError::InvalidJson)?
                        .as_bytes(),
                );
                out.push(b':');
                write(out, row)?;
            }
            out.push(b'}');
        }
    }
    if out.len() > MAX_RECORD_BYTES {
        return Err(ContractError::TooManyBytes);
    }
    Ok(())
}

fn python_float(value: f64) -> String {
    // serde_json supplies shortest round-trip digits, but its choice between
    // fixed and scientific notation differs from Python's json.dumps.
    let raw = serde_json::to_string(&value).expect("finite float serializes");
    if value == 0.0 {
        return raw; // Preserve 0.0 versus -0.0.
    }
    let (mantissa, exponent) = match raw.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (
            mantissa,
            exponent
                .parse::<i32>()
                .expect("serializer emits finite exponent"),
        ),
        None => (raw.as_str(), 0),
    };
    let negative = value.is_sign_negative();
    let unsigned = mantissa.strip_prefix('-').unwrap_or(mantissa);
    let point = unsigned.find('.').unwrap_or(unsigned.len());
    let all_digits: String = unsigned.chars().filter(|ch| *ch != '.').collect();
    let leading_zeroes = all_digits
        .bytes()
        .take_while(|digit| *digit == b'0')
        .count();
    let digits = all_digits[leading_zeroes..].trim_end_matches('0');
    let decimal_at = point as i32 + exponent - leading_zeroes as i32;
    let scientific_exponent = decimal_at - 1;
    let sign = if negative { "-" } else { "" };
    if (-4..16).contains(&scientific_exponent) {
        let fixed = if decimal_at <= 0 {
            format!("0.{}{}", "0".repeat((-decimal_at) as usize), digits)
        } else if decimal_at as usize >= digits.len() {
            format!(
                "{}{}.0",
                digits,
                "0".repeat(decimal_at as usize - digits.len())
            )
        } else {
            let position = decimal_at as usize;
            format!("{}.{}", &digits[..position], &digits[position..])
        };
        return format!("{sign}{fixed}");
    }
    let coefficient = if digits.len() == 1 {
        digits.to_owned()
    } else {
        format!("{}.{}", &digits[..1], &digits[1..])
    };
    format!("{sign}{coefficient}e{scientific_exponent:+03}")
}

fn decode_utf16(raw: &[u8], big_endian: bool) -> Result<String, ContractError> {
    if raw.len() % 2 != 0 {
        return Err(ContractError::InvalidJson);
    }
    let units = raw.chunks_exact(2).map(|pair| {
        let bytes = [pair[0], pair[1]];
        if big_endian {
            u16::from_be_bytes(bytes)
        } else {
            u16::from_le_bytes(bytes)
        }
    });
    std::char::decode_utf16(units)
        .map(|result| result.map_err(|_| ContractError::InvalidJson))
        .collect()
}

fn decode_utf32(raw: &[u8], big_endian: bool) -> Result<String, ContractError> {
    if raw.len() % 4 != 0 {
        return Err(ContractError::InvalidJson);
    }
    raw.chunks_exact(4)
        .map(|chunk| {
            let bytes = [chunk[0], chunk[1], chunk[2], chunk[3]];
            let codepoint = if big_endian {
                u32::from_be_bytes(bytes)
            } else {
                u32::from_le_bytes(bytes)
            };
            char::from_u32(codepoint).ok_or(ContractError::InvalidJson)
        })
        .collect()
}

fn decode_json_bytes(raw: &[u8]) -> Result<Cow<'_, [u8]>, ContractError> {
    // Match Python json.loads(bytes) encoding detection. The common UTF-8
    // path borrows its input; UTF-16/32 is decoded before the JSON parser.
    if let Some(data) = raw.strip_prefix(&[0, 0, 0xfe, 0xff]) {
        return Ok(Cow::Owned(decode_utf32(data, true)?.into_bytes()));
    }
    if let Some(data) = raw.strip_prefix(&[0xff, 0xfe, 0, 0]) {
        return Ok(Cow::Owned(decode_utf32(data, false)?.into_bytes()));
    }
    if let Some(data) = raw.strip_prefix(&[0xfe, 0xff]) {
        return Ok(Cow::Owned(decode_utf16(data, true)?.into_bytes()));
    }
    if let Some(data) = raw.strip_prefix(&[0xff, 0xfe]) {
        return Ok(Cow::Owned(decode_utf16(data, false)?.into_bytes()));
    }
    if let Some(data) = raw.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        return Ok(Cow::Borrowed(data));
    }
    if raw.len() >= 4 {
        if raw[0] == 0 {
            let decoded = if raw[1] == 0 {
                decode_utf32(raw, true)?
            } else {
                decode_utf16(raw, true)?
            };
            return Ok(Cow::Owned(decoded.into_bytes()));
        }
        if raw[1] == 0 {
            let decoded = if raw[2] == 0 && raw[3] == 0 {
                decode_utf32(raw, false)?
            } else {
                decode_utf16(raw, false)?
            };
            return Ok(Cow::Owned(decoded.into_bytes()));
        }
    } else if raw.len() == 2 {
        if raw[0] == 0 {
            return Ok(Cow::Owned(decode_utf16(raw, true)?.into_bytes()));
        }
        if raw[1] == 0 {
            return Ok(Cow::Owned(decode_utf16(raw, false)?.into_bytes()));
        }
    }
    Ok(Cow::Borrowed(raw))
}

/// Parse inert JSON with Python-compatible bounds and return its canonical bytes.
pub fn canonicalize(raw: &[u8]) -> Result<Vec<u8>, ContractError> {
    if raw.len() > MAX_RECORD_BYTES {
        return Err(ContractError::TooManyBytes);
    }
    let decoded = decode_json_bytes(raw)?;
    let mut parser = Parser {
        bytes: decoded.as_ref(),
        offset: 0,
        nodes: 0,
    };
    let value = parser.value(0)?;
    parser.whitespace();
    if parser.offset != decoded.len() {
        return Err(ContractError::InvalidJson);
    }
    let mut output = Vec::new();
    write(&mut output, &value)?;
    Ok(output)
}

/// SHA-256 over the exact canonical UTF-8 bytes, never over source formatting.
pub fn canonical_sha256(raw: &[u8]) -> Result<String, ContractError> {
    let bytes = canonicalize(raw)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

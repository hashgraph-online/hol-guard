//! Authenticated records and stored rows of the extension-control authority.
//!
//! Every comparison here mirrors the Python store it replaces: records are
//! re-canonicalized before their digest and MAC are checked, stored columns
//! are read the way `str(row[...])` and `int(row[...])` read them, and payload
//! fields compare with Python equality, so `1 == 1.0 == True` and a missing
//! field equals `None`.

use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use rusqlite::types::Value as SqlValue;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::guard_store_json::dumps_sorted;

pub(super) const SNAPSHOT_PURPOSE: &str = "extension-control.snapshot";
pub(super) const TRANSITION_PURPOSE: &str = "extension-control.transition";
pub(super) const ANCHOR_PURPOSE: &str = "extension-control.anchor";
pub(super) const CATALOG_MANIFEST_PURPOSE: &str = "hol-guard.extension-control-catalog-manifest.v1";
const AUTH_DOMAIN: &[u8] = b"hol-guard.extension-control-authority.v1\0";
const PRIVATE_REF_DOMAIN: &[u8] = b"hol-guard.extension-control.private-ref.v1\x00";

/// Why a read could not produce a view. `Tampered` is what Python raised as
/// `ExtensionControlAuthorityError`; `Degraded` is any other failure, which
/// the Python readers turned into a degraded view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Fault {
    Tampered(String),
    Degraded(String),
}

pub(crate) type Res<T> = Result<T, Fault>;

pub(super) fn tampered(reason: &str) -> Fault {
    Fault::Tampered(reason.to_owned())
}

pub(super) fn degraded(reason: &str) -> Fault {
    Fault::Degraded(reason.to_owned())
}

pub(super) fn store_fault(_: rusqlite::Error) -> Fault {
    degraded("extension control authority store unavailable")
}

/// `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`.
pub(crate) fn canonical(value: &Value) -> Res<String> {
    dumps_sorted(value).ok_or_else(|| degraded("authority record is not encodable"))
}

pub(super) fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn hmac_hex(key: &[u8], message: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    hex::encode(mac.finalize().into_bytes())
}

fn purpose_key(key: &[u8], purpose: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(AUTH_DOMAIN);
    mac.update(purpose.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// `hmac.compare_digest` over two `str` values: a non-ASCII operand is a
/// `TypeError`, not a mismatch.
fn compare_digest(actual: &str, expected: &str) -> Res<bool> {
    if !expected.is_ascii() {
        return Err(degraded(
            "comparing strings with non-ASCII characters is not supported",
        ));
    }
    let (left, right) = (actual.as_bytes(), expected.as_bytes());
    let mut difference = left.len() ^ right.len();
    for (index, byte) in left.iter().enumerate() {
        difference |= usize::from(byte ^ right.get(index).copied().unwrap_or(0));
    }
    Ok(difference == 0)
}

/// `authenticated_record`: the framed canonical record, its digest and MAC.
pub(crate) fn authenticated_record(
    payload: &Map<String, Value>,
    key: &[u8],
    purpose: &str,
) -> Res<(String, String, String)> {
    let mut framed = payload.clone();
    framed.insert("authority_schema_version".to_owned(), json!(1));
    framed.insert("purpose".to_owned(), json!(purpose));
    let encoded = canonical(&Value::Object(framed))?;
    let digest = sha256_hex(&encoded);
    let mac = hmac_hex(&purpose_key(key, purpose), encoded.as_bytes());
    Ok((encoded, digest, mac))
}

/// `verify_authenticated_record`.
pub(crate) fn verify_record(
    encoded: &str,
    expected_digest: &str,
    expected_mac: &str,
    key: &[u8],
    purpose: &str,
) -> Res<Map<String, Value>> {
    let Ok(Value::Object(payload)) = serde_json::from_str::<Value>(encoded) else {
        return Err(tampered("invalid authenticated authority record"));
    };
    if !py_eq(field(&payload, "authority_schema_version"), &json!(1)) {
        return Err(tampered("unsupported authority schema"));
    }
    if !py_eq(field(&payload, "purpose"), &json!(purpose)) {
        return Err(tampered("authority record purpose mismatch"));
    }
    let canonical = canonical(&Value::Object(payload.clone()))?;
    let digest = sha256_hex(&canonical);
    let mac = hmac_hex(&purpose_key(key, purpose), canonical.as_bytes());
    let digest_ok = compare_digest(&digest, expected_digest)?;
    if !digest_ok || !compare_digest(&mac, expected_mac)? {
        return Err(tampered("authority record authentication failed"));
    }
    Ok(payload)
}

/// `payload.get(name)`, with a missing field read as `None`.
pub(crate) fn field<'a>(payload: &'a Map<String, Value>, name: &str) -> &'a Value {
    payload.get(name).unwrap_or(&Value::Null)
}

/// `any(payload.get(name) != value for name, value in expected)`, negated.
pub(super) fn fields_match(
    payload: &Map<String, Value>,
    expected: &[(&str, Option<Value>)],
) -> bool {
    expected.iter().all(|(name, value)| match value {
        Some(value) => py_eq(field(payload, name), value),
        None => false,
    })
}

/// Python `==` between two values decoded by `json.loads`.
pub(crate) fn py_eq(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Null, Value::Null) => true,
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| py_eq(x, y))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(name, x)| b.get(name).is_some_and(|y| py_eq(x, y)))
        }
        (Value::Bool(_) | Value::Number(_), Value::Bool(_) | Value::Number(_)) => {
            numeric_eq(left, right)
        }
        _ => false,
    }
}

enum Numeric {
    Int(i128),
    Float(f64),
}

fn numeric(value: &Value) -> Option<Numeric> {
    match value {
        Value::Bool(flag) => Some(Numeric::Int(i128::from(*flag))),
        Value::Number(number) => {
            let text = number.to_string();
            if text.contains(['.', 'e', 'E']) {
                text.parse().ok().map(Numeric::Float)
            } else {
                text.parse().ok().map(Numeric::Int)
            }
        }
        _ => None,
    }
}

fn numeric_eq(left: &Value, right: &Value) -> bool {
    match (numeric(left), numeric(right)) {
        (Some(Numeric::Int(a)), Some(Numeric::Int(b))) => a == b,
        (Some(Numeric::Float(a)), Some(Numeric::Float(b))) => a == b,
        (Some(Numeric::Int(a)), Some(Numeric::Float(b)))
        | (Some(Numeric::Float(b)), Some(Numeric::Int(a))) => {
            b.is_finite() && b.fract() == 0.0 && (b as i128) == a && (a as f64) == b
        }
        // Integers beyond 128 bits compare by their decimal spelling.
        _ => left == right,
    }
}

/// An integer field as `type(value) is int` sees it: never a bool or float.
pub(super) fn exact_int(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) if !number.to_string().contains(['.', 'e', 'E']) => number.as_i64(),
        _ => None,
    }
}

// --- stored rows -----------------------------------------------------------

pub(super) type Row = BTreeMap<String, SqlValue>;

/// Retain a committed activation binding without reserving a new activation.
pub(super) fn snapshot_pack_binding(row: &Row, key: &[u8]) -> Res<Option<String>> {
    let payload = verify_record(
        &row_text(row, "snapshot_json")?,
        &row_text(row, "snapshot_digest")?,
        &row_text(row, "snapshot_mac")?,
        key,
        SNAPSHOT_PURPOSE,
    )?;
    match field(&payload, "command_pack_record_digest") {
        Value::Null => Ok(None),
        Value::String(digest) => Ok(Some(digest.clone())),
        _ => Err(tampered("invalid retained command pack binding")),
    }
}

pub(super) fn query_rows<P: rusqlite::Params>(
    connection: &rusqlite::Connection,
    sql: &str,
    params: P,
) -> Res<Vec<Row>> {
    let mut statement = connection.prepare(sql).map_err(store_fault)?;
    let names: Vec<String> = statement
        .column_names()
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    let rows = statement
        .query_map(params, |row| {
            let mut values = Row::new();
            for (index, name) in names.iter().enumerate() {
                values.insert(name.clone(), row.get::<_, SqlValue>(index)?);
            }
            Ok(values)
        })
        .map_err(store_fault)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(store_fault)
}

pub(super) fn query_row<P: rusqlite::Params>(
    connection: &rusqlite::Connection,
    sql: &str,
    params: P,
) -> Res<Option<Row>> {
    Ok(query_rows(connection, sql, params)?.into_iter().next())
}

fn column<'a>(row: &'a Row, name: &str) -> Res<&'a SqlValue> {
    row.get(name)
        .ok_or_else(|| degraded("no such authority column"))
}

/// `_row_str`.
pub(super) fn row_str(row: &Row, name: &str) -> Res<String> {
    match column(row, name)? {
        SqlValue::Text(text) => Ok(text.clone()),
        _ => Err(tampered("invalid extension control authority row")),
    }
}

/// `_row_int`.
pub(super) fn row_int(row: &Row, name: &str) -> Res<i64> {
    match column(row, name)? {
        SqlValue::Integer(value) => Ok(*value),
        _ => Err(tampered("invalid extension control authority row")),
    }
}

/// `str(row[name])`.
pub(super) fn row_text(row: &Row, name: &str) -> Res<String> {
    Ok(match column(row, name)? {
        SqlValue::Text(text) => text.clone(),
        SqlValue::Integer(value) => value.to_string(),
        SqlValue::Real(value) if value.is_nan() => "nan".to_owned(),
        SqlValue::Real(value) if value.is_infinite() => {
            if *value > 0.0 { "inf" } else { "-inf" }.to_owned()
        }
        SqlValue::Real(value) => canonical(&json!(value))?,
        SqlValue::Null => "None".to_owned(),
        SqlValue::Blob(bytes) => format!("b'{}'", hex::encode(bytes)),
    })
}

/// `int(row[name])`.
pub(super) fn row_py_int(row: &Row, name: &str) -> Res<i64> {
    let invalid = || degraded("invalid literal for int()");
    match column(row, name)? {
        SqlValue::Integer(value) => Ok(*value),
        SqlValue::Real(value) if value.is_finite() && value.abs() < 9.2e18 => {
            Ok(value.trunc() as i64)
        }
        SqlValue::Text(text) => text.trim().parse().map_err(|_| invalid()),
        _ => Err(invalid()),
    }
}

/// `row[name]` as the value a decoded payload field is compared with. `None`
/// stands for a value no decoded JSON field can equal.
pub(super) fn row_value(row: &Row, name: &str) -> Res<Option<Value>> {
    Ok(match column(row, name)? {
        SqlValue::Null => Some(Value::Null),
        SqlValue::Integer(value) => Some(json!(value)),
        SqlValue::Real(value) if value.is_finite() => Some(json!(value)),
        SqlValue::Text(text) => Some(json!(text)),
        SqlValue::Real(_) | SqlValue::Blob(_) => None,
    })
}

/// `_private_hash`.
pub(super) fn private_hash(value: &str, key: &[u8], purpose: &str) -> String {
    let mut message = PRIVATE_REF_DOMAIN.to_vec();
    message.extend_from_slice(purpose.as_bytes());
    message.push(0);
    message.extend_from_slice(value.as_bytes());
    hmac_hex(key, &message)
}

// --- anchor ----------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase {
    Prepared,
    Anchored,
    Committed,
}

impl Phase {
    pub(super) fn parse(text: &str) -> Option<Self> {
        match text {
            "prepared" => Some(Self::Prepared),
            "anchored" => Some(Self::Anchored),
            "committed" => Some(Self::Committed),
            _ => None,
        }
    }

    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Anchored => "anchored",
            Self::Committed => "committed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Anchor {
    pub(super) revision: i64,
    pub(super) snapshot_digest: String,
    pub(super) phase: Phase,
}

impl Anchor {
    pub(super) fn to_value(&self) -> Value {
        json!({
            "revision": self.revision,
            "snapshot_digest": self.snapshot_digest,
            "phase": self.phase.as_str(),
        })
    }
}

/// `anchor_from_json`.
pub(super) fn parse_anchor(text: &str, key: &[u8]) -> Res<Anchor> {
    let Ok(Value::Object(envelope)) = serde_json::from_str::<Value>(text) else {
        return Err(tampered("invalid authority anchor"));
    };
    let (Some(record), Some(digest), Some(mac)) = (
        field(&envelope, "record").as_str(),
        field(&envelope, "digest").as_str(),
        field(&envelope, "mac").as_str(),
    ) else {
        return Err(tampered("invalid authority anchor"));
    };
    let payload = verify_record(record, digest, mac, key, ANCHOR_PURPOSE)?;
    let revision = exact_int(field(&payload, "revision"))
        .filter(|revision| *revision >= 0)
        .ok_or_else(|| tampered("invalid authority anchor revision"))?;
    let snapshot_digest = field(&payload, "snapshot_digest")
        .as_str()
        .filter(|digest| digest.chars().count() == 64)
        .ok_or_else(|| tampered("invalid authority anchor digest"))?;
    let phase = field(&payload, "phase")
        .as_str()
        .and_then(Phase::parse)
        .ok_or_else(|| tampered("invalid authority anchor phase"))?;
    Ok(Anchor {
        revision,
        snapshot_digest: snapshot_digest.to_owned(),
        phase,
    })
}

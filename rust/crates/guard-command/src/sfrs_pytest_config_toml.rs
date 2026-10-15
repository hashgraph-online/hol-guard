//! The TOML grammars of `pytest_config._parse_toml` (`pytest.toml`,
//! `.pytest.toml` and `pyproject.toml`) over the `toml` crate.

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::collections::BTreeMap;

use toml::value::{Datetime, Offset};
use toml::Value;

use crate::sfrs_pytest_config_value::{config_value, py_str, PytestConfigValue, Raw, ValueFailure};

/// The exception class of a failed parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TomlFailure {
    /// `TOMLDecodeError` whose message mentions "overwrite".
    Duplicate,
    /// Any other `TOMLDecodeError` or `ValueError`.
    Syntax,
    /// `TypeError`.
    Type,
}

impl From<ValueFailure> for TomlFailure {
    fn from(failure: ValueFailure) -> Self {
        match failure {
            ValueFailure::Value => Self::Syntax,
            ValueFailure::Type => Self::Type,
        }
    }
}

/// `str(datetime.date | time | datetime)` of a parsed TOML date-time.
fn datetime_text(value: &Datetime) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(date) = value.date {
        parts.push(format!(
            "{:04}-{:02}-{:02}",
            date.year, date.month, date.day
        ));
    }
    if let Some(time) = value.time {
        let mut text = format!("{:02}:{:02}:{:02}", time.hour, time.minute, time.second);
        let micro = time.nanosecond / 1000;
        if micro != 0 {
            text.push_str(&format!(".{micro:06}"));
        }
        if let Some(offset) = value.offset {
            let minutes = match offset {
                Offset::Z => 0,
                Offset::Custom { minutes } => i32::from(minutes),
            };
            let sign = if minutes < 0 { '-' } else { '+' };
            text.push_str(&format!(
                "{sign}{:02}:{:02}",
                minutes.abs() / 60,
                minutes.abs() % 60
            ));
        }
        parts.push(text);
    }
    parts.join(" ")
}

fn raw_of(value: &Value) -> Raw {
    match value {
        Value::String(text) => Raw::Str(text.clone()),
        Value::Integer(number) => Raw::Int(*number),
        Value::Float(number) => Raw::Float(*number),
        Value::Boolean(flag) => Raw::Bool(*flag),
        Value::Datetime(stamp) => Raw::Date(datetime_text(stamp)),
        Value::Array(items) => Raw::List(items.iter().map(raw_of).collect()),
        Value::Table(table) => Raw::Table(table_of(table)),
    }
}

fn table_of(table: &toml::Table) -> BTreeMap<String, Raw> {
    table
        .iter()
        .map(|(key, value)| (key.clone(), raw_of(value)))
        .collect()
}

/// Key path and array-ness of the table header that starts at `start`.
fn header_at(text: &str, start: usize) -> Option<(Vec<String>, bool)> {
    let line = text.get(start..)?.lines().next()?.trim_start();
    let array = line.starts_with("[[");
    let inner = line.trim_start_matches('[');
    let inner = inner.split(']').next()?;
    let path = inner
        .split('.')
        .map(|part| part.trim().trim_matches(['"', '\'']).to_owned())
        .collect();
    Some((path, array))
}

/// Whether `tomllib` would call a conflicting header an "overwrite" (a scalar
/// or an array-of-tables clash) rather than a "declare ... twice".
fn header_overwrites(text: &str, start: usize) -> bool {
    let Some((path, array)) = header_at(text, start) else {
        return false;
    };
    let Ok(document) = text[..start].parse::<toml::Table>() else {
        return false;
    };
    let mut current = &document;
    for (position, key) in path.iter().enumerate() {
        let last = position + 1 == path.len();
        match current.get(key) {
            None => return false,
            Some(Value::Table(table)) => {
                if last {
                    return array;
                }
                current = table;
            }
            Some(Value::Array(items)) => match items.last() {
                Some(Value::Table(table)) if !last => current = table,
                _ => return false,
            },
            Some(_) => return true,
        }
    }
    false
}

/// Map a decoder error to the class `tomllib` raises for the same document.
fn classify(text: &str, error: &toml::de::Error) -> TomlFailure {
    let message = error.message().to_lowercase();
    if message.contains("invalid table header") {
        let overwrites = error
            .span()
            .is_some_and(|span| header_overwrites(text, span.start));
        return if overwrites {
            TomlFailure::Duplicate
        } else {
            TomlFailure::Syntax
        };
    }
    if message.contains("duplicate key") {
        TomlFailure::Duplicate
    } else {
        TomlFailure::Syntax
    }
}

/// `_parse_toml`.
pub(crate) fn parse_toml(
    text: &str,
    filename: &str,
) -> Result<Option<PytestConfigValue>, TomlFailure> {
    if text.starts_with('\u{feff}') {
        return Err(TomlFailure::Syntax);
    }
    let payload: toml::Table = text.parse().map_err(|error| classify(text, &error))?;
    if matches!(filename, "pytest.toml" | ".pytest.toml") {
        return match payload.get("pytest") {
            None => Ok(Some(PytestConfigValue::default())),
            Some(Value::Table(table)) => Ok(Some(config_value(&table_of(table))?)),
            Some(_) => Err(TomlFailure::Type),
        };
    }
    let Some(tool) = payload.get("tool") else {
        return Ok(None);
    };
    let Value::Table(tool) = tool else {
        return Err(TomlFailure::Type);
    };
    let Some(pytest) = tool.get("pytest") else {
        return Ok(None);
    };
    let Value::Table(pytest) = pytest else {
        return Err(TomlFailure::Type);
    };
    let ini_options = pytest.get("ini_options");
    let native: BTreeMap<String, Raw> = pytest
        .iter()
        .filter(|(key, _)| key.as_str() != "ini_options")
        .map(|(key, value)| (key.clone(), raw_of(value)))
        .collect();
    if !native.is_empty() && ini_options.is_some() {
        return Err(TomlFailure::Syntax);
    }
    if !native.is_empty() {
        return Ok(Some(config_value(&native)?));
    }
    let Some(ini_options) = ini_options else {
        return Ok(None);
    };
    let Value::Table(ini_options) = ini_options else {
        return Err(TomlFailure::Type);
    };
    match ini_options.get("addopts") {
        None | Some(Value::String(_)) => {}
        Some(Value::Array(items)) if items.iter().all(Value::is_str) => {}
        Some(_) => return Err(TomlFailure::Type),
    }
    let compatible: BTreeMap<String, Raw> = ini_options
        .iter()
        .map(|(key, value)| {
            let raw = raw_of(value);
            let kept = if matches!(raw, Raw::List(_)) {
                raw
            } else {
                Raw::Str(py_str(&raw))
            };
            (key.clone(), kept)
        })
        .collect();
    Ok(Some(config_value(&compatible)?))
}

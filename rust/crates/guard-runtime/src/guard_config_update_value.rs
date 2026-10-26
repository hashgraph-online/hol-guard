//! Config values for the native settings writer.
//!
//! `config.toml` is held as an ordered table of [`Tv`] values so a write
//! preserves every key the dashboard never edits. Rendering mirrors the
//! writer in `guard/config.py`: sorted keys, scalars before sub-tables, and
//! JSON-escaped strings. TOML datetimes keep the text Python's `str()` gave
//! them, because that is what the Python writer stored.

use guard_contracts::write_json_string;
use serde_json::{Map, Number, Value};
use toml::value::{Datetime, Offset};

use crate::pyjson::{float_repr, PyVal};

/// One `config.toml` value (or a coerced settings value).
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Tv {
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    /// A TOML date, time or datetime, as Python's `str()` renders it.
    Moment(String),
    List(Vec<Tv>),
    Table(Table),
}

/// An insertion-ordered table, like the Python dict it replaces.
pub(crate) type Table = Vec<(String, Tv)>;

pub(crate) fn get<'a>(table: &'a Table, key: &str) -> Option<&'a Tv> {
    table
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

pub(crate) fn set(table: &mut Table, key: &str, value: Tv) {
    match table.iter_mut().find(|(name, _)| name == key) {
        Some(slot) => slot.1 = value,
        None => table.push((key.to_owned(), value)),
    }
}

pub(crate) fn remove(table: &mut Table, key: &str) {
    table.retain(|(name, _)| name != key);
}

pub(crate) fn is_str(value: Option<&Tv>, expected: &str) -> bool {
    matches!(value, Some(Tv::Str(text)) if text == expected)
}

pub(crate) fn from_toml_table(table: toml::Table) -> Table {
    table
        .into_iter()
        .map(|(key, value)| (key, from_toml(value)))
        .collect()
}

fn from_toml(value: toml::Value) -> Tv {
    match value {
        toml::Value::String(text) => Tv::Str(text),
        toml::Value::Integer(number) => Tv::Int(number),
        toml::Value::Float(number) => Tv::Float(number),
        toml::Value::Boolean(flag) => Tv::Bool(flag),
        toml::Value::Datetime(moment) => Tv::Moment(python_moment_text(&moment)),
        toml::Value::Array(items) => Tv::List(items.into_iter().map(from_toml).collect()),
        toml::Value::Table(table) => Tv::Table(from_toml_table(table)),
    }
}

/// `str()` of the `date`, `time` or `datetime` that `tomllib` returns.
fn python_moment_text(moment: &Datetime) -> String {
    let mut text = String::new();
    if let Some(date) = moment.date {
        text.push_str(&format!(
            "{:04}-{:02}-{:02}",
            date.year, date.month, date.day
        ));
    }
    if let Some(time) = moment.time {
        if moment.date.is_some() {
            text.push(' ');
        }
        text.push_str(&format!(
            "{:02}:{:02}:{:02}",
            time.hour, time.minute, time.second
        ));
        let micros = time.nanosecond / 1_000;
        if micros != 0 {
            text.push_str(&format!(".{micros:06}"));
        }
    }
    match moment.offset {
        Some(Offset::Z) => text.push_str("+00:00"),
        Some(Offset::Custom { minutes }) => {
            let sign = if minutes < 0 { '-' } else { '+' };
            let minutes = minutes.unsigned_abs();
            text.push_str(&format!("{sign}{:02}:{:02}", minutes / 60, minutes % 60));
        }
        None => {}
    }
    text
}

/// Python truthiness.
pub(crate) fn truthy(value: &Tv) -> bool {
    match value {
        Tv::Bool(flag) => *flag,
        Tv::Int(number) => *number != 0,
        Tv::Float(number) => *number != 0.0,
        Tv::Str(text) => !text.is_empty(),
        Tv::Moment(_) => true,
        Tv::List(items) => !items.is_empty(),
        Tv::Table(table) => !table.is_empty(),
    }
}

/// Python `str()`.
pub(crate) fn py_str(value: &Tv) -> String {
    match value {
        Tv::Str(text) | Tv::Moment(text) => text.clone(),
        other => py_repr(other),
    }
}

fn py_repr(value: &Tv) -> String {
    match value {
        Tv::Bool(true) => "True".to_owned(),
        Tv::Bool(false) => "False".to_owned(),
        Tv::Int(number) => number.to_string(),
        Tv::Float(number) => float_repr(*number),
        Tv::Str(text) | Tv::Moment(text) => py_str_repr(text),
        Tv::List(items) => format!(
            "[{}]",
            items.iter().map(py_repr).collect::<Vec<_>>().join(", ")
        ),
        Tv::Table(table) => format!(
            "{{{}}}",
            table
                .iter()
                .map(|(key, item)| format!("{}: {}", py_str_repr(key), py_repr(item)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Python `repr()` of a decoded JSON value.
pub(crate) fn py_json_repr(value: &PyVal) -> String {
    match value {
        PyVal::Null => "None".to_owned(),
        PyVal::Bool(true) => "True".to_owned(),
        PyVal::Bool(false) => "False".to_owned(),
        PyVal::Int(text) => text.clone(),
        PyVal::Float(number) => float_repr(*number),
        PyVal::Str(text) => py_str_repr(text),
        PyVal::List(items) => format!(
            "[{}]",
            items
                .iter()
                .map(py_json_repr)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        PyVal::Dict(items) => format!(
            "{{{}}}",
            items
                .iter()
                .map(|(key, item)| format!("{}: {}", py_str_repr(key), py_json_repr(item)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Code points `str.isprintable()` rejects outside ASCII (Zs, Zl, Zp, Cc,
/// Cf, Cs and Co).
fn non_printable(character: char) -> bool {
    matches!(
        u32::from(character),
        0x80..=0xa0
            | 0xad
            | 0x600..=0x605
            | 0x61c
            | 0x6dd
            | 0x70f
            | 0x1680
            | 0x180e
            | 0x2000..=0x200f
            | 0x2028..=0x202f
            | 0x205f..=0x2064
            | 0x2066..=0x206f
            | 0x3000
            | 0xe000..=0xf8ff
            | 0xfeff
            | 0xfff9..=0xfffb
            | 0xe0001
            | 0xe0020..=0xe007f
            | 0xf0000..
    )
}

/// CPython `unicode_repr`.
fn py_str_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for character in text.chars() {
        let code = u32::from(character);
        match character {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ if character == quote => {
                out.push('\\');
                out.push(quote);
            }
            _ if code < 0x20 || code == 0x7f => out.push_str(&format!("\\x{code:02x}")),
            _ if code < 0x7f || !non_printable(character) => out.push(character),
            _ if code <= 0xff => out.push_str(&format!("\\x{code:02x}")),
            _ if code <= 0xffff => out.push_str(&format!("\\u{code:04x}")),
            _ => out.push_str(&format!("\\U{code:08x}")),
        }
    }
    out.push(quote);
    out
}

/// Marker a non-JSON value carries into the managed-policy composition, so it
/// never compares equal to a real JSON value.
const OPAQUE_PREFIX: &str = "\u{0}guard-config-opaque:";

/// The value as the managed-policy composition sees it.
pub(crate) fn to_json(value: &Tv) -> Value {
    match value {
        Tv::Bool(flag) => Value::Bool(*flag),
        Tv::Int(number) => Value::from(*number),
        Tv::Float(number) => Number::from_f64(*number)
            .map(Value::Number)
            .unwrap_or_else(|| Value::String(format!("{OPAQUE_PREFIX}{}", float_repr(*number)))),
        Tv::Str(text) => Value::String(text.clone()),
        Tv::Moment(text) => Value::String(format!("{OPAQUE_PREFIX}{text}")),
        Tv::List(items) => Value::Array(items.iter().map(to_json).collect()),
        Tv::Table(table) => Value::Object(table_to_json(table)),
    }
}

pub(crate) fn table_to_json(table: &Table) -> Map<String, Value> {
    table
        .iter()
        .map(|(key, item)| (key.clone(), to_json(item)))
        .collect()
}

/// Python `==` between decoded JSON values (`True == 1 == 1.0`).
pub(crate) fn py_eq(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Bool(_) | Value::Number(_), Value::Bool(_) | Value::Number(_)) => {
            match (as_integer(left), as_integer(right)) {
                (Some(a), Some(b)) => a == b,
                _ => as_float(left) == as_float(right),
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| py_eq(x, y))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, x)| b.get(key).is_some_and(|y| py_eq(x, y)))
        }
        _ => left == right,
    }
}

fn as_integer(value: &Value) -> Option<i128> {
    match value {
        Value::Bool(flag) => Some(i128::from(*flag)),
        Value::Number(number) => number.to_string().parse().ok(),
        _ => None,
    }
}

fn as_float(value: &Value) -> Option<f64> {
    match value {
        Value::Bool(flag) => Some(f64::from(u8::from(*flag))),
        Value::Number(number) => number.as_f64(),
        _ => None,
    }
}

/// Python `value == number` for a decoded payload value.
pub(crate) fn py_json_eq_int(value: &PyVal, number: i64) -> bool {
    match value {
        PyVal::Bool(flag) => i64::from(*flag) == number,
        PyVal::Int(text) => text.parse::<i128>().ok() == Some(i128::from(number)),
        PyVal::Float(float) => *float == number as f64,
        _ => false,
    }
}

/// `BARE_TOML_KEY.match`: `$` also matches before one trailing newline.
fn is_bare_key(key: &str) -> bool {
    let body = key.strip_suffix('\n').unwrap_or(key);
    !body.is_empty()
        && body
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn json_string(text: &str) -> String {
    let mut out = Vec::with_capacity(text.len() + 2);
    write_json_string(text, &mut out);
    String::from_utf8(out).unwrap_or_default()
}

fn toml_key(key: &str) -> String {
    if is_bare_key(key) {
        key.to_owned()
    } else {
        json_string(key)
    }
}

fn toml_literal(value: &Tv) -> String {
    match value {
        Tv::Bool(flag) => if *flag { "true" } else { "false" }.to_owned(),
        Tv::Int(number) => number.to_string(),
        Tv::Float(number) => float_repr(*number),
        Tv::Str(text) | Tv::Moment(text) => json_string(text),
        Tv::List(items) => format!(
            "[{}]",
            items
                .iter()
                .map(toml_literal)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Tv::Table(table) => {
            let items: Vec<String> = sorted(table)
                .into_iter()
                .map(|(key, item)| format!("{} = {}", toml_key(key), toml_literal(item)))
                .collect();
            format!("{{ {} }}", items.join(", "))
        }
    }
}

fn sorted(table: &Table) -> Vec<(&String, &Tv)> {
    let mut items: Vec<(&String, &Tv)> = table.iter().map(|(key, value)| (key, value)).collect();
    items.sort_by(|left, right| left.0.cmp(right.0));
    items
}

fn table_lines(table: &Table, path: &mut Vec<String>, lines: &mut Vec<String>) {
    let start = lines.len();
    let items = sorted(table);
    if !path.is_empty() {
        let header: Vec<String> = path.iter().map(|part| toml_key(part)).collect();
        lines.push(format!("[{}]", header.join(".")));
    }
    for (key, value) in &items {
        if !matches!(value, Tv::Table(_)) {
            lines.push(format!("{} = {}", toml_key(key), toml_literal(value)));
        }
    }
    for (key, value) in items {
        if let Tv::Table(nested) = value {
            if lines.len() > start {
                lines.push(String::new());
            }
            path.push(key.clone());
            table_lines(nested, path, lines);
            path.pop();
        }
    }
}

/// `_write_guard_config` text: `"\n".join(lines).strip() + "\n"`.
pub(crate) fn render(table: &Table) -> String {
    let mut lines = Vec::new();
    table_lines(table, &mut Vec::new(), &mut lines);
    let joined = lines.join("\n");
    format!("{}\n", joined.trim_matches(is_py_space))
}

/// `str.isspace()`: Rust whitespace plus the ASCII separators `\x1c`-`\x1f`.
pub(crate) fn is_py_space(character: char) -> bool {
    character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
}

/// `str.strip()`.
pub(crate) fn py_strip(text: &str) -> &str {
    text.trim_matches(is_py_space)
}

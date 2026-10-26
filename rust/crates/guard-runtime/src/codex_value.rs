//! The value model shared by Codex `config.toml` and `hooks.json` sources:
//! what `tomllib` and `json.loads` hand the Python hook inventory, the
//! Python-equality rules the ownership bindings use, and the canonical JSON
//! the hook identity digests are computed over (`json.dumps(sort_keys=True,
//! separators=(",", ":"), ensure_ascii=False)`).

use serde_json::Value;

use super::pyjson::{float_repr, PyVal};

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum HookVal {
    Null,
    Bool(bool),
    /// Canonical decimal digits, as `str(int)` renders them.
    Int(String),
    Float(f64),
    Str(String),
    List(Vec<HookVal>),
    Dict(Vec<(String, HookVal)>),
    /// A TOML date, time or datetime: Python's type name and its `isoformat()`.
    Temporal(&'static str, String),
}

impl HookVal {
    pub(crate) fn get(&self, key: &str) -> Option<&HookVal> {
        match self {
            HookVal::Dict(entries) => entries
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            HookVal::Str(text) => Some(text),
            _ => None,
        }
    }

    pub(crate) fn as_dict(&self) -> Option<&[(String, HookVal)]> {
        match self {
            HookVal::Dict(entries) => Some(entries),
            _ => None,
        }
    }

    pub(crate) fn as_list(&self) -> Option<&[HookVal]> {
        match self {
            HookVal::List(items) => Some(items),
            _ => None,
        }
    }

    /// `mapping.get(key)` where a JSON `null` and a missing key both read as `None`.
    pub(crate) fn field(&self, key: &str) -> Option<&HookVal> {
        self.get(key)
            .filter(|value| !matches!(value, HookVal::Null))
    }

    pub(crate) fn from_py(value: &PyVal) -> HookVal {
        match value {
            PyVal::Null => HookVal::Null,
            PyVal::Bool(flag) => HookVal::Bool(*flag),
            PyVal::Int(digits) => HookVal::Int(digits.clone()),
            PyVal::Float(number) => HookVal::Float(*number),
            PyVal::Str(text) => HookVal::Str(text.clone()),
            PyVal::List(items) => HookVal::List(items.iter().map(HookVal::from_py).collect()),
            PyVal::Dict(entries) => HookVal::Dict(
                entries
                    .iter()
                    .map(|(key, item)| (key.clone(), HookVal::from_py(item)))
                    .collect(),
            ),
        }
    }

    /// A document in `tomllib` key order: a table keeps the order its keys
    /// were first created in, even when an implicit parent is declared by a
    /// later sub-table header before its own header.
    pub(crate) fn from_document(table: &toml_edit::Table) -> HookVal {
        // `tomllib` keeps the order keys were first created in, but toml_edit
        // re-inserts a table at the end of its parent when a header later
        // redefines an implicit one (`[a.b.c]` then `[a]`). Header positions
        // are document order, so children sort by where they first appeared.
        let body = body_rank(table);
        let mut children: Vec<(usize, &str, &toml_edit::Item)> = table
            .iter()
            .map(|(key, item)| (first_rank(item).unwrap_or(body), key, item))
            .collect();
        children.sort_by_key(|(rank, _, _)| *rank);
        HookVal::Dict(
            children
                .into_iter()
                .filter_map(|(_, key, item)| Some((key.to_owned(), HookVal::from_item(item)?)))
                .collect(),
        )
    }

    fn from_item(item: &toml_edit::Item) -> Option<HookVal> {
        match item {
            toml_edit::Item::None => None,
            toml_edit::Item::Value(value) => Some(HookVal::from_edit(value)),
            toml_edit::Item::Table(table) => Some(HookVal::from_document(table)),
            toml_edit::Item::ArrayOfTables(tables) => Some(HookVal::List(
                tables.iter().map(HookVal::from_document).collect(),
            )),
        }
    }

    fn from_edit(value: &toml_edit::Value) -> HookVal {
        match value {
            toml_edit::Value::String(text) => HookVal::Str(text.value().clone()),
            toml_edit::Value::Integer(number) => HookVal::Int(number.value().to_string()),
            toml_edit::Value::Float(number) => HookVal::Float(*number.value()),
            toml_edit::Value::Boolean(flag) => HookVal::Bool(*flag.value()),
            toml_edit::Value::Datetime(stamp) => temporal(stamp.value()),
            toml_edit::Value::Array(items) => {
                HookVal::List(items.iter().map(HookVal::from_edit).collect())
            }
            toml_edit::Value::InlineTable(table) => HookVal::Dict(
                table
                    .iter()
                    .map(|(key, item)| (key.to_owned(), HookVal::from_edit(item)))
                    .collect(),
            ),
        }
    }
}

/// `datetime`, `date` or `time` with its `isoformat()` (microsecond precision,
/// a numeric UTC offset, never `Z`).
fn temporal(stamp: &toml_edit::Datetime) -> HookVal {
    let date = stamp
        .date
        .map(|date| format!("{:04}-{:02}-{:02}", date.year, date.month, date.day));
    let time = stamp.time.map(|time| {
        let mut text = format!("{:02}:{:02}:{:02}", time.hour, time.minute, time.second);
        let micros = time.nanosecond / 1000;
        if micros != 0 {
            text.push_str(&format!(".{micros:06}"));
        }
        text
    });
    let offset = stamp.offset.map(|offset| {
        let minutes = match offset {
            toml::value::Offset::Z => 0,
            toml::value::Offset::Custom { minutes } => i32::from(minutes),
        };
        let sign = if minutes < 0 { '-' } else { '+' };
        format!("{sign}{:02}:{:02}", minutes.abs() / 60, minutes.abs() % 60)
    });
    match (date, time) {
        (Some(date), Some(time)) => HookVal::Temporal(
            "datetime",
            format!("{date}T{time}{}", offset.unwrap_or_default()),
        ),
        (Some(date), None) => HookVal::Temporal("date", date),
        (None, Some(time)) => {
            HookVal::Temporal("time", format!("{time}{}", offset.unwrap_or_default()))
        }
        (None, None) => HookVal::Temporal("datetime", String::new()),
    }
}

/// The decimal digits of an integral float, as `int(value)` renders them.
fn integral_digits(number: f64) -> String {
    let digits = format!("{number:.0}");
    if digits == "-0" {
        "0".to_owned()
    } else {
        digits
    }
}

enum Num {
    Int(String),
    Float(f64),
}

fn numeric_pair(left: &HookVal, right: &Value) -> Option<(Num, Num)> {
    fn left_num(value: &HookVal) -> Option<Num> {
        match value {
            HookVal::Bool(flag) => Some(Num::Int(u8::from(*flag).to_string())),
            HookVal::Int(digits) => Some(Num::Int(digits.clone())),
            HookVal::Float(number) => Some(Num::Float(*number)),
            _ => None,
        }
    }
    fn right_num(value: &Value) -> Option<Num> {
        match value {
            Value::Bool(flag) => Some(Num::Int(u8::from(*flag).to_string())),
            Value::Number(number) => {
                if let Some(int) = number.as_i64() {
                    Some(Num::Int(int.to_string()))
                } else if let Some(int) = number.as_u64() {
                    Some(Num::Int(int.to_string()))
                } else {
                    number.as_f64().map(Num::Float)
                }
            }
            _ => None,
        }
    }
    Some((left_num(left)?, right_num(right)?))
}

fn numbers_equal(left: &Num, right: &Num) -> bool {
    match (left, right) {
        (Num::Int(a), Num::Int(b)) => a == b,
        (Num::Float(a), Num::Float(b)) => a == b,
        (Num::Int(digits), Num::Float(number)) | (Num::Float(number), Num::Int(digits)) => {
            number.is_finite() && number.fract() == 0.0 && integral_digits(*number) == *digits
        }
    }
}

/// Python `==` between a parsed source value and a JSON binding value:
/// `True == 1 == 1.0`, dictionaries compare without order.
pub(crate) fn equals_json(value: &HookVal, other: Option<&Value>) -> bool {
    let other = other.unwrap_or(&Value::Null);
    match (value, other) {
        (HookVal::Null, Value::Null) => true,
        (HookVal::Str(left), Value::String(right)) => left == right,
        (HookVal::List(left), Value::Array(right)) => {
            left.len() == right.len()
                && left.iter().zip(right).all(|(a, b)| equals_json(a, Some(b)))
        }
        (HookVal::Dict(left), Value::Object(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .all(|(key, item)| right.get(key).is_some_and(|b| equals_json(item, Some(b))))
        }
        _ => numeric_pair(value, other).is_some_and(|(left, right)| numbers_equal(&left, &right)),
    }
}

/// One node of the canonical JSON tree.
pub(crate) enum Canon {
    Null,
    Bool(bool),
    /// Number text exactly as Python renders it.
    Num(String),
    Str(String),
    List(Vec<Canon>),
    Obj(Vec<(String, Canon)>),
}

impl Canon {
    pub(crate) fn text(text: &str) -> Canon {
        Canon::Str(text.to_owned())
    }

    pub(crate) fn object(entries: Vec<(&str, Canon)>) -> Canon {
        Canon::Obj(
            entries
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        )
    }

    pub(crate) fn write(&self, out: &mut String) {
        match self {
            Canon::Null => out.push_str("null"),
            Canon::Bool(true) => out.push_str("true"),
            Canon::Bool(false) => out.push_str("false"),
            Canon::Num(text) => out.push_str(text),
            Canon::Str(text) => write_string(text, out),
            Canon::List(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Canon::Obj(entries) => {
                let mut sorted: Vec<&(String, Canon)> = entries.iter().collect();
                sorted.sort_by(|left, right| left.0.cmp(&right.0));
                out.push('{');
                for (index, (key, item)) in sorted.into_iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    write_string(key, out);
                    out.push(':');
                    item.write(out);
                }
                out.push('}');
            }
        }
    }
}

/// `json.dumps` string with `ensure_ascii=False`.
fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
}

/// `_canonical_value`.
pub(crate) fn canonical_value(value: &HookVal) -> Canon {
    match value {
        HookVal::Null => Canon::Null,
        HookVal::Bool(flag) => Canon::Bool(*flag),
        HookVal::Int(digits) => Canon::Num(digits.clone()),
        HookVal::Float(number) => {
            if !number.is_finite() {
                Canon::object(vec![
                    ("type", Canon::text("float")),
                    ("value", Canon::Str(float_repr(*number))),
                ])
            } else if number.fract() == 0.0 {
                Canon::Num(integral_digits(*number))
            } else {
                Canon::Num(float_repr(*number))
            }
        }
        HookVal::Str(text) => Canon::Str(text.clone()),
        HookVal::List(items) => Canon::List(items.iter().map(canonical_value).collect()),
        HookVal::Dict(entries) => canonical_mapping(entries, &[]),
        HookVal::Temporal(kind, text) => Canon::object(vec![
            ("type", Canon::text(kind)),
            ("value", Canon::Str(text.clone())),
        ]),
    }
}

/// `_canonical_mapping`: string keys, the excluded ones dropped.
pub(crate) fn canonical_mapping(entries: &[(String, HookVal)], excluded: &[&str]) -> Canon {
    Canon::Obj(
        entries
            .iter()
            .filter(|(key, _)| !excluded.contains(&key.as_str()))
            .map(|(key, item)| (key.clone(), canonical_value(item)))
            .collect(),
    )
}

/// Where a table's own key-value pairs sit relative to the headers: after its
/// header and before the next one.
fn body_rank(table: &toml_edit::Table) -> usize {
    table.position().map_or(0, |position| position * 2 + 1)
}

/// The document position of the first header that created `item`, counting
/// headers of its descendants (a header like `[a.b.c]` creates `a` and `b`).
fn first_rank(item: &toml_edit::Item) -> Option<usize> {
    match item {
        toml_edit::Item::Table(table) => table_rank(table),
        toml_edit::Item::ArrayOfTables(tables) => tables.iter().filter_map(table_rank).min(),
        _ => None,
    }
}

fn table_rank(table: &toml_edit::Table) -> Option<usize> {
    let own = table.position().map(|position| position * 2);
    let inner = table.iter().filter_map(|(_, item)| first_rank(item)).min();
    match (own, inner) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (left, right) => left.or(right),
    }
}

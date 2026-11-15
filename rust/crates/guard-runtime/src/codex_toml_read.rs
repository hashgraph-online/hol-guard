//! `runner_authority` kind `codex_toml_read`: the Codex `config.toml` reader
//! `guard/codex_config.py` and `guard/codex_hook_sources.py` ran through
//! `tomllib` before it moved here.
//!
//! The file parses into the order-preserving payload `tomllib` builds. A
//! value JSON cannot carry (a TOML date, time or datetime, an infinite or
//! NaN float) crosses as a token naming its meaning, the form the
//! `codex_toml_render` kind and the Codex adapter ops read back. Equal
//! meanings share a token. The token prefix is random and checked against
//! every string the file holds.
//!
//! Request: `{"text": <TOML text>}`. Answer: `{"payload": <JSON text>,
//! "tokens": {token: meaning}}`, or `{"error": "duplicate_key" | "malformed"}`
//! for a file `tomllib` refuses.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};
use toml_edit::{Datetime, DocumentMut, Item, Offset, Table, TableLike};

use super::hook_env_stamp::dumps;
use super::pyjson::PyVal;
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

/// Why `tomllib` refused the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadError {
    /// `Cannot overwrite a value`: a key given twice.
    DuplicateKey,
    /// Any other parse failure.
    Malformed,
}

impl ReadError {
    pub(crate) fn code(self) -> &'static str {
        match self {
            ReadError::DuplicateKey => "duplicate_key",
            ReadError::Malformed => "malformed",
        }
    }
}

/// One value as `tomllib` returns it, before the wire tokens.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TomlVal {
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    /// Python's type name (`date`, `time`, `datetime`) and its `isoformat()`.
    Moment(&'static str, String),
    List(Vec<TomlVal>),
    Table(Vec<(String, TomlVal)>),
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let map = args_object(args)?;
    if map.len() != 1 {
        return Err(ERR_INVALID);
    }
    let text = map.get("text").and_then(Value::as_str).ok_or(ERR_INVALID)?;
    Ok(match read(text) {
        Ok(entries) => {
            let (payload, tokens) = wire(&entries);
            let mut out = String::new();
            dumps(&payload, false, false, &mut out);
            json!({ "payload": out, "tokens": tokens })
        }
        Err(error) => json!({ "error": error.code() }),
    })
}

/// `tomllib.loads(text)`.
pub(crate) fn read(text: &str) -> Result<Vec<(String, TomlVal)>, ReadError> {
    let document: DocumentMut = text.parse().map_err(|error: toml_edit::TomlError| {
        if error.message().contains("duplicate key") {
            ReadError::DuplicateKey
        } else {
            ReadError::Malformed
        }
    })?;
    Ok(table_entries(document.as_table()))
}

fn table_entries(table: &dyn TableLike) -> Vec<(String, TomlVal)> {
    table
        .iter()
        .filter_map(|(key, item)| item_value(item).map(|value| (key.to_owned(), value)))
        .collect()
}

fn item_value(item: &Item) -> Option<TomlVal> {
    match item {
        Item::None => None,
        Item::Value(value) => Some(value_of(value)),
        Item::Table(table) => Some(TomlVal::Table(table_entries(table))),
        Item::ArrayOfTables(tables) => Some(TomlVal::List(
            tables
                .iter()
                .map(|table: &Table| TomlVal::Table(table_entries(table)))
                .collect(),
        )),
    }
}

fn value_of(value: &toml_edit::Value) -> TomlVal {
    match value {
        toml_edit::Value::String(text) => TomlVal::Str(text.value().clone()),
        toml_edit::Value::Integer(number) => TomlVal::Int(*number.value()),
        toml_edit::Value::Float(number) => TomlVal::Float(*number.value()),
        toml_edit::Value::Boolean(flag) => TomlVal::Bool(*flag.value()),
        toml_edit::Value::Datetime(moment) => moment_of(moment.value()),
        toml_edit::Value::Array(items) => TomlVal::List(items.iter().map(value_of).collect()),
        toml_edit::Value::InlineTable(table) => TomlVal::Table(table_entries(table)),
    }
}

/// The `date`, `time` or `datetime` `tomllib` returns, by its `isoformat()`.
fn moment_of(moment: &Datetime) -> TomlVal {
    let mut text = String::new();
    if let Some(date) = moment.date {
        text.push_str(&format!(
            "{:04}-{:02}-{:02}",
            date.year, date.month, date.day
        ));
    }
    if let Some(time) = moment.time {
        if moment.date.is_some() {
            text.push('T');
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
    let kind = match (moment.date.is_some(), moment.time.is_some()) {
        (true, true) => "datetime",
        (true, false) => "date",
        _ => "time",
    };
    TomlVal::Moment(kind, text)
}

/// The payload as order-preserving JSON, with the tokens it uses.
pub(crate) fn wire(entries: &[(String, TomlVal)]) -> (PyVal, Map<String, Value>) {
    wire_avoiding(entries, &[])
}

/// [`wire`], with a prefix no string in `avoid` starts with either, for a
/// payload compared with values read from elsewhere.
pub(crate) fn wire_avoiding(
    entries: &[(String, TomlVal)],
    avoid: &[&str],
) -> (PyVal, Map<String, Value>) {
    let mut strings: Vec<&str> = avoid.to_vec();
    for (key, value) in entries {
        strings.push(key.as_str());
        collect_strings(value, &mut strings);
    }
    let prefix = loop {
        let candidate = random_prefix();
        if !strings.iter().any(|text| text.starts_with(&candidate)) {
            break candidate;
        }
    };
    let mut tokens = Tokens {
        prefix,
        issued: BTreeMap::new(),
        meanings: Map::new(),
    };
    let payload = PyVal::Dict(
        entries
            .iter()
            .map(|(key, value)| (key.clone(), tokens.value(value)))
            .collect(),
    );
    (payload, tokens.meanings)
}

fn collect_strings<'a>(value: &'a TomlVal, out: &mut Vec<&'a str>) {
    match value {
        TomlVal::Str(text) => out.push(text),
        TomlVal::List(items) => items.iter().for_each(|item| collect_strings(item, out)),
        TomlVal::Table(entries) => {
            for (key, item) in entries {
                out.push(key);
                collect_strings(item, out);
            }
        }
        _ => {}
    }
}

fn random_prefix() -> String {
    let mut bytes = [0_u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        // A fixed prefix still cannot collide: every string is checked.
        return "codex-toml-wire".to_owned();
    }
    hex::encode(bytes)
}

struct Tokens {
    prefix: String,
    issued: BTreeMap<String, String>,
    meanings: Map<String, Value>,
}

impl Tokens {
    fn token(&mut self, meaning: Value) -> PyVal {
        let key = meaning.to_string();
        if let Some(token) = self.issued.get(&key) {
            return PyVal::Str(token.clone());
        }
        let token = format!("{}-{}", self.prefix, self.meanings.len());
        self.issued.insert(key, token.clone());
        self.meanings.insert(token.clone(), meaning);
        PyVal::Str(token)
    }

    fn value(&mut self, value: &TomlVal) -> PyVal {
        match value {
            TomlVal::Bool(flag) => PyVal::Bool(*flag),
            TomlVal::Int(number) => PyVal::Int(number.to_string()),
            TomlVal::Float(number) if number.is_finite() => PyVal::Float(*number),
            TomlVal::Float(number) => {
                let text = if number.is_nan() {
                    "nan"
                } else if *number > 0.0 {
                    "inf"
                } else {
                    "-inf"
                };
                self.token(json!({ "type": "float", "value": text }))
            }
            TomlVal::Str(text) => PyVal::Str(text.clone()),
            TomlVal::Moment(kind, text) => self.token(json!({ "type": kind, "value": text })),
            TomlVal::List(items) => {
                PyVal::List(items.iter().map(|item| self.value(item)).collect())
            }
            TomlVal::Table(entries) => PyVal::Dict(
                entries
                    .iter()
                    .map(|(key, item)| (key.clone(), self.value(item)))
                    .collect(),
            ),
        }
    }
}

#[cfg(test)]
#[path = "codex_toml_read_tests.rs"]
mod tests;

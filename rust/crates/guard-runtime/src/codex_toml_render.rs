//! `runner_authority` kind `codex_toml_render`: the Codex `config.toml` writer
//! `guard/codex_config.py` ran through tomlkit before it moved here.
//!
//! Guard reads `config.toml` into a plain payload and writes it back. With the
//! text Guard read as `original`, the payload is applied to that parsed file
//! with the fewest edits, so every comment and spelling Guard did not change
//! survives. The result is parsed back and has to mean exactly the payload;
//! anything else (a file that does not parse, a value TOML cannot hold, a
//! readback that differs) falls back to the plain renderer.
//!
//! Request: `{"payload": <order-preserving JSON text>, "tokens": {token:
//! meaning}, "original": text | null}`, with the wire tokens
//! `native_codex_hook_identity` uses for values JSON cannot carry. Answer:
//! `{"text": <rendered TOML>}`.

use serde_json::{json, Map, Value};
use toml_edit::{ArrayOfTables, DocumentMut, InlineTable, Item, Table, TableLike};

use super::codex_value::{token_value, HookVal};
use super::pyjson::{self, PyVal};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let map = args_object(args)?;
    if map.len() != 3 {
        return Err(ERR_INVALID);
    }
    let payload = payload(map)?;
    let original = match map.get("original") {
        Some(Value::Null) => None,
        Some(Value::String(text)) => Some(text.as_str()),
        _ => return Err(ERR_INVALID),
    };
    Ok(json!({ "text": render(&payload, original) }))
}

fn payload(map: &Map<String, Value>) -> Result<Vec<(String, HookVal)>, &'static str> {
    let text = map
        .get("payload")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let tokens = map
        .get("tokens")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    let parsed = pyjson::parse(text).map_err(|_| ERR_INVALID)?;
    let PyVal::Dict(entries) = parsed else {
        return Err(ERR_INVALID);
    };
    entries
        .iter()
        .map(|(key, item)| Ok((key.clone(), detokenize(HookVal::from_py(item), tokens)?)))
        .collect()
}

/// The payload with every wire token replaced by the value it stands for.
fn detokenize(value: HookVal, tokens: &Map<String, Value>) -> Result<HookVal, &'static str> {
    Ok(match value {
        HookVal::Str(text) => match tokens.get(&text) {
            Some(meaning) => token_value(meaning).ok_or(ERR_INVALID)?,
            None => HookVal::Str(text),
        },
        HookVal::List(items) => HookVal::List(
            items
                .into_iter()
                .map(|item| detokenize(item, tokens))
                .collect::<Result<_, _>>()?,
        ),
        HookVal::Dict(entries) => HookVal::Dict(
            entries
                .into_iter()
                .map(|(key, item)| Ok((key, detokenize(item, tokens)?)))
                .collect::<Result<_, &'static str>>()?,
        ),
        other => other,
    })
}

/// `dump_toml(payload, original=original)`.
pub(crate) fn render(payload: &[(String, HookVal)], original: Option<&str>) -> String {
    if let Some(preserved) = original
        .filter(|text| !text.is_empty())
        .and_then(|text| onto_original(payload, text))
    {
        return preserved;
    }
    plain::render(payload)
}

/// Why an edit could not be applied in place; the plain renderer takes over.
struct Unsupported;

type Applied<T = ()> = Result<T, Unsupported>;

fn onto_original(payload: &[(String, HookVal)], original: &str) -> Option<String> {
    let mut document = original.parse::<DocumentMut>().ok()?;
    apply_table(document.as_table_mut(), payload, false).ok()?;
    let rendered = document.to_string();
    let readback = rendered.parse::<DocumentMut>().ok()?;
    let expected = HookVal::Dict(without_nulls(payload));
    same(&HookVal::from_document(readback.as_table()), &expected).then_some(rendered)
}

/// A dict payload with `None` dropped from every dict in it, the way the
/// plain renderer reads it.
fn without_nulls(entries: &[(String, HookVal)]) -> Vec<(String, HookVal)> {
    entries
        .iter()
        .filter(|(_, value)| !matches!(value, HookVal::Null))
        .map(|(key, value)| (key.clone(), plain_value(value)))
        .collect()
}

fn plain_value(value: &HookVal) -> HookVal {
    match value {
        HookVal::Dict(entries) => HookVal::Dict(without_nulls(entries)),
        HookVal::List(items) => HookVal::List(items.iter().map(plain_value).collect()),
        other => other.clone(),
    }
}

/// Whether two values are the same, with `1`, `True` and `1.0` all different.
fn same(left: &HookVal, right: &HookVal) -> bool {
    match (left, right) {
        (HookVal::Dict(left), HookVal::Dict(right)) => {
            left.len() == right.len()
                && left.iter().all(|(key, item)| {
                    right
                        .iter()
                        .find(|(name, _)| name == key)
                        .is_some_and(|(_, other)| same(item, other))
                })
        }
        (HookVal::List(left), HookVal::List(right)) => {
            left.len() == right.len() && left.iter().zip(right).all(|(a, b)| same(a, b))
        }
        (HookVal::Float(left), HookVal::Float(right)) => left == right,
        (HookVal::Null, HookVal::Null) => true,
        (HookVal::Bool(left), HookVal::Bool(right)) => left == right,
        (HookVal::Int(left), HookVal::Int(right)) | (HookVal::Str(left), HookVal::Str(right)) => {
            left == right
        }
        (HookVal::Temporal(kind, left), HookVal::Temporal(other, right)) => {
            kind == other && left == right
        }
        _ => false,
    }
}

/// Make one parsed table match `payload` with the fewest edits.
fn apply_table(table: &mut dyn TableLike, payload: &[(String, HookVal)], inline: bool) -> Applied {
    let stale: Vec<String> = table
        .iter()
        .map(|(key, _)| key.to_owned())
        .filter(|key| {
            payload
                .iter()
                .find(|(name, _)| name == key)
                .is_none_or(|(_, value)| matches!(value, HookVal::Null))
        })
        .collect();
    for key in stale {
        table.remove(&key);
    }
    for (key, value) in payload {
        if matches!(value, HookVal::Null) {
            continue;
        }
        if let Some(existing) = table.get_mut(key) {
            if let HookVal::Dict(entries) = value {
                let nested = existing.is_inline_table();
                if let Some(inner) = existing.as_table_like_mut() {
                    apply_table(inner, entries, nested)?;
                    continue;
                }
            }
            let replacement = plain_value(value);
            if let HookVal::List(items) = &replacement {
                if apply_list(existing, items)? {
                    continue;
                }
            }
            // Already the wanted value: assigning it would respell it and drop
            // the comment on its line.
            if HookVal::from_item(existing).is_some_and(|current| same(&current, &replacement)) {
                continue;
            }
            // Replaced where it stands, so the comments above the key and the
            // one after its value stay, as tomlkit keeps the old trivia.
            let mut item = new_item(&replacement, inline)?;
            if let (Item::Value(old), Item::Value(new)) = (&*existing, &mut item) {
                *new.decor_mut() = old.decor().clone();
            }
            *existing = item;
            continue;
        }
        table.insert(key, new_item(&plain_value(value), inline)?);
    }
    Ok(())
}

fn new_item(value: &HookVal, inline: bool) -> Applied<Item> {
    if inline {
        Ok(Item::Value(build_value(value)?))
    } else {
        build_item(value)
    }
}

/// Where one wanted array element comes from.
#[derive(Clone, Copy)]
enum Source {
    /// An element already holding the wanted value, wherever it sits.
    Kept(usize),
    /// A changed element of the same shape, edited in place.
    Edit(usize),
    New,
}

/// Hook groups are not stable by position: install drops Guard's group and
/// appends it, so matching by index would write the user's group into Guard's
/// old table and its comments would leave with Guard's values. An element that
/// already has the wanted value keeps its parsed item; each other wanted value
/// takes the next leftover element in turn.
fn plan(current: &[HookVal], wanted: &[HookVal]) -> Vec<Source> {
    let mut used = vec![false; current.len()];
    let kept: Vec<Option<usize>> = wanted
        .iter()
        .map(|item| {
            let index =
                (0..current.len()).find(|&index| !used[index] && same(&current[index], item))?;
            used[index] = true;
            Some(index)
        })
        .collect();
    let mut leftovers = (0..current.len()).filter(|&index| !used[index]);
    wanted
        .iter()
        .zip(kept)
        .map(|(item, kept)| match kept {
            Some(index) => Source::Kept(index),
            None => match leftovers.next() {
                Some(index) => match (item, &current[index]) {
                    (HookVal::Dict(_), HookVal::Dict(_)) | (HookVal::List(_), HookVal::List(_)) => {
                        Source::Edit(index)
                    }
                    _ => Source::New,
                },
                None => Source::New,
            },
        })
        .collect()
}

/// Make a parsed array match `wanted`; `false` when `existing` is no array.
fn apply_list(existing: &mut Item, wanted: &[HookVal]) -> Applied<bool> {
    match existing {
        Item::ArrayOfTables(tables) => rebuild_tables(tables, wanted)?,
        Item::Value(toml_edit::Value::Array(array)) => rebuild_array(array, wanted)?,
        _ => return Ok(false),
    }
    Ok(true)
}

fn rebuild_tables(tables: &mut ArrayOfTables, wanted: &[HookVal]) -> Applied {
    let current: Vec<Table> = tables.iter().cloned().collect();
    let values: Vec<HookVal> = current.iter().map(HookVal::from_document).collect();
    let mut slots = Vec::new();
    current
        .iter()
        .for_each(|table| positions(table, &mut slots));
    slots.sort_unstable();
    let mut rebuilt = Vec::with_capacity(wanted.len());
    let mut origins = Vec::new();
    for (source, item) in plan(&values, wanted).into_iter().zip(wanted) {
        let HookVal::Dict(entries) = item else {
            return Err(Unsupported);
        };
        rebuilt.push(match source {
            Source::Kept(index) => {
                origins.push(index);
                current[index].clone()
            }
            Source::Edit(index) => {
                origins.push(index);
                let mut table = current[index].clone();
                apply_table(&mut table, entries, false)?;
                table
            }
            Source::New => build_table(entries)?,
        });
    }
    tables.clear();
    rebuilt.into_iter().for_each(|table| {
        tables.push(table);
    });
    // A table renders at its parsed position, so moved groups take the slots
    // of the old ones in their new order, each header still ahead of its own
    // sub-tables.
    if origins.windows(2).any(|pair| pair[0] > pair[1]) {
        let mut slots = slots.into_iter();
        tables
            .iter_mut()
            .for_each(|table| renumber(table, &mut slots));
    }
    Ok(())
}

fn positions(table: &Table, out: &mut Vec<usize>) {
    if let Some(position) = table.position().filter(|_| !table.is_dotted()) {
        out.push(position);
    }
    for (_, item) in table.iter() {
        match item {
            Item::Table(inner) => positions(inner, out),
            Item::ArrayOfTables(inner) => inner.iter().for_each(|table| positions(table, out)),
            _ => {}
        }
    }
}

fn renumber(table: &mut Table, slots: &mut impl Iterator<Item = usize>) {
    if table.position().is_some() && !table.is_dotted() {
        if let Some(slot) = slots.next() {
            table.set_position(slot);
        }
    }
    for (_, item) in table.iter_mut() {
        match item {
            Item::Table(inner) => renumber(inner, slots),
            Item::ArrayOfTables(inner) => inner.iter_mut().for_each(|table| renumber(table, slots)),
            _ => {}
        }
    }
}

fn rebuild_array(array: &mut toml_edit::Array, wanted: &[HookVal]) -> Applied {
    let current: Vec<toml_edit::Value> = array.iter().cloned().collect();
    let values: Vec<HookVal> = current.iter().map(HookVal::from_edit).collect();
    let mut rebuilt = Vec::with_capacity(wanted.len());
    for (source, item) in plan(&values, wanted).into_iter().zip(wanted) {
        rebuilt.push(match source {
            Source::Kept(index) => current[index].clone(),
            Source::Edit(index) => {
                let mut value = current[index].clone();
                match (&mut value, item) {
                    (toml_edit::Value::InlineTable(table), HookVal::Dict(entries)) => {
                        apply_table(table, entries, true)?;
                    }
                    (toml_edit::Value::Array(inner), HookVal::List(items)) => {
                        rebuild_array(inner, items)?;
                    }
                    _ => return Err(Unsupported),
                }
                value
            }
            Source::New => build_value(item)?,
        });
    }
    array.clear();
    rebuilt
        .into_iter()
        .for_each(|value| array.push_formatted(value));
    Ok(())
}

/// A new value at table level: a dict becomes a table and a list of dicts an
/// array of tables, the way tomlkit writes them.
fn build_item(value: &HookVal) -> Applied<Item> {
    match value {
        HookVal::Dict(entries) => Ok(Item::Table(build_table(entries)?)),
        HookVal::List(items)
            if !items.is_empty() && items.iter().all(|item| matches!(item, HookVal::Dict(_))) =>
        {
            let mut tables = ArrayOfTables::new();
            for item in items {
                if let HookVal::Dict(entries) = item {
                    tables.push(build_table(entries)?);
                }
            }
            Ok(Item::ArrayOfTables(tables))
        }
        other => Ok(Item::Value(build_value(other)?)),
    }
}

fn build_table(entries: &[(String, HookVal)]) -> Applied<Table> {
    let mut table = Table::new();
    for (key, value) in entries {
        if !matches!(value, HookVal::Null) {
            table.insert(key, build_item(value)?);
        }
    }
    // A table holding only tables needs no header of its own.
    let only_tables = table
        .iter()
        .all(|(_, item)| item.is_table() || item.is_array_of_tables());
    table.set_implicit(!table.is_empty() && only_tables);
    Ok(table)
}

/// A new value inside an array or inline table.
fn build_value(value: &HookVal) -> Applied<toml_edit::Value> {
    Ok(match value {
        HookVal::Null => return Err(Unsupported),
        HookVal::Bool(flag) => (*flag).into(),
        HookVal::Int(digits) => digits.parse::<i64>().map_err(|_| Unsupported)?.into(),
        HookVal::Float(number) => (*number).into(),
        HookVal::Str(text) => text.as_str().into(),
        HookVal::Temporal(_, text) => text
            .parse::<toml_edit::Datetime>()
            .map_err(|_| Unsupported)?
            .into(),
        HookVal::List(items) => {
            let mut array = toml_edit::Array::new();
            for item in items {
                array.push(build_value(item)?);
            }
            toml_edit::Value::Array(array)
        }
        HookVal::Dict(entries) => {
            let mut table = InlineTable::new();
            for (key, item) in entries {
                if !matches!(item, HookVal::Null) {
                    table.insert(key, build_value(item)?);
                }
            }
            toml_edit::Value::InlineTable(table)
        }
    })
}

#[path = "codex_toml_plain.rs"]
mod plain;

#[cfg(test)]
#[path = "codex_toml_render_tests.rs"]
mod tests;

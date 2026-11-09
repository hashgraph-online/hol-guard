//! TOML settings files, edited in place so comments and layout are kept.

use serde_json::Value;

use super::{Fields, Tool, EDIT_ERROR, SERVER_NAME};

pub(super) fn toml_edit_entry(tool: &Tool, text: &str, fields: &Fields) -> Result<String, String> {
    let edit_error = || EDIT_ERROR.to_owned();
    let mut document: toml_edit::DocumentMut = text.parse().map_err(|_| edit_error())?;
    let mut values = Vec::new();
    for (key, value) in fields.entry(Some(tool)) {
        values.push((key, toml_value(&value).ok_or_else(edit_error)?));
    }
    let inline = root_servers_is_inline(&document, tool);
    let root = document.as_table_mut();
    if !root.contains_key(tool.table) {
        let mut servers = toml_edit::Table::new();
        servers.set_implicit(true);
        root.insert(tool.table, toml_edit::Item::Table(servers));
    }
    let servers = root
        .get_mut(tool.table)
        .and_then(toml_edit::Item::as_table_like_mut)
        .ok_or_else(edit_error)?;
    let dotted = servers.is_dotted();
    match servers.get_mut(SERVER_NAME) {
        Some(existing) => {
            let existing = existing.as_table_like_mut().ok_or_else(edit_error)?;
            let stale: Vec<String> = existing
                .iter()
                .map(|(key, _)| key.to_owned())
                .filter(|key| !values.iter().any(|(wanted, _)| wanted == key))
                .collect();
            for key in stale {
                existing.remove(&key);
            }
            for (key, value) in values {
                existing.insert(key, toml_edit::Item::Value(value));
            }
        }
        None if dotted => {
            let mut entry = toml_edit::Table::new();
            entry.set_dotted(true);
            for (key, value) in values {
                entry.insert(key, toml_edit::Item::Value(value));
            }
            servers.insert(SERVER_NAME, toml_edit::Item::Table(entry));
        }
        None if inline => {
            let mut entry = toml_edit::InlineTable::new();
            for (key, value) in values {
                entry.insert(key, value);
            }
            servers.insert(
                SERVER_NAME,
                toml_edit::Item::Value(toml_edit::Value::InlineTable(entry)),
            );
        }
        None => {
            let mut entry = toml_edit::Table::new();
            for (key, value) in values {
                entry.insert(key, toml_edit::Item::Value(value));
            }
            servers.insert(SERVER_NAME, toml_edit::Item::Table(entry));
        }
    }
    Ok(collapse_trailing_blank(document.to_string(), text))
}

fn root_servers_is_inline(document: &toml_edit::DocumentMut, tool: &Tool) -> bool {
    matches!(
        document.as_table().get(tool.table),
        Some(toml_edit::Item::Value(toml_edit::Value::InlineTable(_)))
    )
}

pub(super) fn toml_remove_entry(
    tool: &Tool,
    text: &str,
    drop_empty_table: bool,
) -> Result<String, String> {
    let edit_error = || EDIT_ERROR.to_owned();
    let mut document: toml_edit::DocumentMut = text.parse().map_err(|_| edit_error())?;
    let root = document.as_table_mut();
    let servers = root
        .get_mut(tool.table)
        .and_then(toml_edit::Item::as_table_like_mut)
        .ok_or_else(edit_error)?;
    servers.remove(SERVER_NAME).ok_or_else(edit_error)?;
    if servers.is_empty() && drop_empty_table {
        root.remove(tool.table);
    }
    Ok(collapse_trailing_blank(document.to_string(), text))
}

fn collapse_trailing_blank(rendered: String, text: &str) -> String {
    if rendered.ends_with("\n\n") && !text.ends_with("\n\n") {
        format!("{}\n", rendered.trim_end_matches('\n'))
    } else {
        rendered
    }
}

/// A TOML value for a string or a list of strings, always in basic quotes.
fn toml_value(value: &Value) -> Option<toml_edit::Value> {
    match value {
        Value::String(text) => serde_json::to_string(text).ok()?.parse().ok(),
        Value::Array(items) => {
            let mut array = toml_edit::Array::new();
            for item in items {
                array.push(toml_value(item)?);
            }
            Some(toml_edit::Value::Array(array))
        }
        _ => None,
    }
}

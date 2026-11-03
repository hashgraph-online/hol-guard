//! `runner_authority` kind `codex_host_inventory`: reads the replies an
//! existing Codex host gave to `app/installed` and `app/read` into the public
//! app rows Guard shows.
//!
//! Python keeps the private socket, the peer authentication and the JSON-RPC
//! exchange, and sends each decoded `result` here. Two requests:
//!
//! - `{"installed": result}` answers `{"apps": [row, ...]}`, one row per
//!   installed app, with no tools yet.
//! - `{"page": [row, ...], "read": result}` takes up to 100 of those rows and
//!   the `app/read` reply for them, and answers
//!   `{"apps": [row, ...], "complete": bool}`: the same rows in the same order,
//!   with each covered app's name and tool summaries filled in.
//!
//! A reply the host should not have sent answers `{"error": code}` with the
//! code Python raised for it: `codex_host_limit` for a list that is missing or
//! too long, `codex_host_invalid` for anything else. Host text is display
//! metadata only: identifiers must already be exact, display text is bounded
//! and has its whitespace collapsed the way Python's `str.split` does.

use std::collections::HashSet;

use serde_json::{json, Map, Value};

use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const INVALID: &str = "codex_host_invalid";
const LIMIT: &str = "codex_host_limit";
const MAX_APPS: usize = 1000;
const MAX_PAGE: usize = 100;
const MAX_TOOLS: usize = 10_000;
const MAX_NAME: usize = 256;
const MAX_TITLE: usize = 512;
const MAX_DESCRIPTION: usize = 4000;

type HostResult<T> = Result<T, &'static str>;
type Rows = Vec<Map<String, Value>>;

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let map = args_object(args)?;
    let answer = match (
        map.len(),
        map.get("installed"),
        map.get("page"),
        map.get("read"),
    ) {
        (1, Some(Value::Object(installed)), None, None) => {
            installed_apps(installed).map(|apps| json!({ "apps": apps }))
        }
        (2, None, Some(page), Some(Value::Object(read))) => {
            let page = page_rows(page)?;
            merge_metadata(page, read)
                .map(|(apps, complete)| json!({ "apps": apps, "complete": complete }))
        }
        _ => return Err(ERR_INVALID),
    };
    Ok(answer.unwrap_or_else(|code| json!({ "error": code })))
}

/// The page Python asks about: objects with distinct string `app_id`s.
fn page_rows(page: &Value) -> Result<Rows, &'static str> {
    let rows = page.as_array().ok_or(ERR_INVALID)?;
    if rows.len() > MAX_PAGE {
        return Err(ERR_INVALID);
    }
    let mut ids: HashSet<&str> = HashSet::new();
    for row in rows {
        let app_id = row
            .get("app_id")
            .and_then(Value::as_str)
            .ok_or(ERR_INVALID)?;
        if !ids.insert(app_id) {
            return Err(ERR_INVALID);
        }
    }
    Ok(rows
        .iter()
        .filter_map(|row| row.as_object().cloned())
        .collect())
}

/// `_installed_apps`.
fn installed_apps(result: &Map<String, Value>) -> HostResult<Vec<Value>> {
    let mut apps = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for value in array(result.get("apps"), MAX_APPS)? {
        let row = object(value)?;
        let app_id = identifier(row.get("id"))?;
        let enabled = row.get("enabled").and_then(Value::as_bool);
        let callable = row.get("callable").and_then(Value::as_bool);
        let (Some(enabled), Some(callable)) = (enabled, callable) else {
            return Err(INVALID);
        };
        if !seen.insert(app_id.clone()) {
            return Err(INVALID);
        }
        let name = text(row.get("runtimeName"), MAX_NAME, false)?.unwrap_or_else(|| app_id.clone());
        apps.push(json!({
            "app_id": app_id,
            "name": name,
            "enabled": enabled,
            "callable": callable,
            "tools": [],
            "metadata_available": false,
        }));
    }
    Ok(apps)
}

/// `_merge_metadata`: the page with each covered app's metadata, and whether
/// every app on it came back with tool summaries.
fn merge_metadata(mut page: Rows, result: &Map<String, Value>) -> HostResult<(Rows, bool)> {
    let requested: Vec<String> = page
        .iter()
        .map(|row| {
            row.get("app_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        })
        .collect();
    let mut covered: HashSet<String> = HashSet::new();
    let mut complete = true;
    for value in array(result.get("apps"), MAX_PAGE)? {
        let row = object(value)?;
        let app_id = identifier(row.get("id"))?;
        let Some(index) = requested.iter().position(|id| *id == app_id) else {
            return Err(INVALID);
        };
        if !covered.insert(app_id) {
            return Err(INVALID);
        }
        let name = text(row.get("name"), MAX_NAME, true)?.ok_or(INVALID)?;
        // `row.get("toolSummaries", row.get("tools"))`: a present but null
        // `toolSummaries` never falls back to `tools`.
        let summaries = row
            .get("toolSummaries")
            .or_else(|| row.get("tools"))
            .filter(|value| !value.is_null());
        let entries: &[Value] = match summaries {
            Some(value) => array(Some(value), MAX_TOOLS)?,
            None => &[],
        };
        let mut tools = Vec::with_capacity(entries.len());
        let mut names: HashSet<String> = HashSet::new();
        for entry in entries {
            let tool = object(entry)?;
            let tool_name = identifier(tool.get("name"))?;
            if !names.insert(tool_name.clone()) {
                return Err(INVALID);
            }
            tools.push(json!({
                "name": tool_name,
                "title": summary_text(tool.get("title"), MAX_TITLE)?,
                "description": summary_text(tool.get("description"), MAX_DESCRIPTION)?,
            }));
        }
        let app = &mut page[index];
        app.insert("name".to_owned(), Value::String(name));
        app.insert("tools".to_owned(), Value::Array(tools));
        app.insert(
            "metadata_available".to_owned(),
            Value::Bool(summaries.is_some()),
        );
        complete = summaries.is_some() && complete;
    }
    let missing = array(result.get("missingAppIds"), MAX_PAGE)?;
    for value in missing {
        let app_id = identifier(Some(value))?;
        if !requested.contains(&app_id) || !covered.insert(app_id) {
            return Err(INVALID);
        }
    }
    if covered.len() != requested.len() {
        return Err(INVALID);
    }
    Ok((page, missing.is_empty() && complete))
}

/// Python's `str.isspace`: Unicode whitespace plus the four information
/// separators U+001C..U+001F.
fn is_python_space(character: char) -> bool {
    character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
}

/// `_object`.
fn object(value: &Value) -> HostResult<&Map<String, Value>> {
    value.as_object().ok_or(INVALID)
}

/// `_array`: a missing value is not a list either.
fn array(value: Option<&Value>, maximum: usize) -> HostResult<&[Value]> {
    match value {
        Some(Value::Array(items)) if items.len() <= maximum => Ok(items.as_slice()),
        _ => Err(LIMIT),
    }
}

/// `_text`: `None` for absent, null or (unless required) blank text.
fn text(value: Option<&Value>, maximum: usize, required: bool) -> HostResult<Option<String>> {
    match value {
        None | Some(Value::Null) if !required => Ok(None),
        Some(Value::String(raw)) => checked_text(raw, maximum, required),
        _ => Err(INVALID),
    }
}

fn checked_text(raw: &str, maximum: usize, required: bool) -> HostResult<Option<String>> {
    let collapsed = raw
        .split(is_python_space)
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if collapsed.is_empty() && !required {
        return Ok(None);
    }
    if collapsed.is_empty() || raw.chars().count() > maximum || raw.contains('\0') {
        return Err(INVALID);
    }
    Ok(Some(collapsed))
}

/// `_identifier`: exact text, with no whitespace or control character.
fn identifier(value: Option<&Value>) -> HostResult<String> {
    let raw = value.and_then(Value::as_str).ok_or(INVALID)?;
    let length = raw.chars().count();
    if length == 0
        || length > MAX_NAME
        || raw
            .chars()
            .any(|character| is_python_space(character) || u32::from(character) < 32)
    {
        return Err(INVALID);
    }
    Ok(raw.to_owned())
}

/// `_summary_text`: host descriptions have no protocol cap, so text without
/// NUL is cut to `maximum` characters before it is checked.
fn summary_text(value: Option<&Value>, maximum: usize) -> HostResult<Option<String>> {
    match value {
        Some(Value::String(raw)) if !raw.contains('\0') => {
            let cut: String = raw.chars().take(maximum).collect();
            checked_text(&cut, maximum, false)
        }
        other => text(other, maximum, false),
    }
}

#[cfg(test)]
#[path = "codex_host_inventory_tests.rs"]
mod tests;

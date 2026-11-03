//! `runner_authority` kind `copilot_lifecycle_state`: which Copilot lifecycle
//! state Guard trusts (`_validated_entry`, `copilot_state_authorizes_backup_reuse`
//! and `_valid_backup_envelope` in
//! `guard/adapters/_modules/copilot/copilot_state_paths.py` before they moved
//! here).
//!
//! Python keeps the locks, the file reads, the `lstat` calls, path resolution
//! and the MAC check, which runs in the separate `adapter_state_integrity` op
//! with the state key, so only state files that authenticated reach this kind.
//! Python sends what those found; this kind decides.
//!
//! `backup_reuse` answers `{"decision": "reuse" | "replace" | "refuse"}`: reuse
//! the backup an authenticated state binds to this target, replace it when no
//! authenticated state binds the pair, and refuse when the bound backup is not
//! a regular file holding a backup envelope.
//!
//! `state_entries` answers `{"entries": [...]}`, one item per authenticated
//! state file: `null` when Guard does not manage what it names, the index of
//! the config it manages, or `{"raise": index}` when Python could not name that
//! config's state and backup paths and keeps the error the original raised.
//!
//! Paths compared as `pathlib.Path` values arrive already `normcase`d; the
//! stored backup spelling is compared as the exact string it was. Python's
//! decoder also accepted `NaN`, `Infinity` and lone surrogate escapes; a
//! backup holding one reads as invalid here, and Guard never writes one.

use serde_json::{json, Map, Value};

use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const REUSE_KEYS: [&str; 4] = ["action", "recorded", "expected", "backup"];
const ENTRIES_KEYS: [&str; 2] = ["action", "entries"];
const ENTRY_KEYS: [&str; 3] = ["state", "fields", "candidates"];
const CANDIDATE_KEYS: [&str; 4] = ["source", "keys", "contained", "paths"];
const PATHS_KEYS: [&str; 3] = ["owned", "state", "backup"];
/// Where a candidate config comes from: the home, the workspace the
/// authenticated state recorded, or the workspace Guard runs in now.
const SOURCES: [&str; 3] = ["global", "recorded", "current"];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    match fields.get("action").and_then(Value::as_str) {
        Some("backup_reuse") => backup_reuse(exact(fields, &REUSE_KEYS)?),
        Some("state_entries") => state_entries(exact(fields, &ENTRIES_KEYS)?),
        _ => Err(ERR_INVALID),
    }
}

fn exact<'a>(
    fields: &'a Map<String, Value>,
    keys: &[&str],
) -> Result<&'a Map<String, Value>, &'static str> {
    if fields.len() == keys.len() && keys.iter().all(|key| fields.contains_key(*key)) {
        Ok(fields)
    } else {
        Err(ERR_INVALID)
    }
}

fn object<'a>(value: &'a Value, keys: &[&str]) -> Result<&'a Map<String, Value>, &'static str> {
    exact(value.as_object().ok_or(ERR_INVALID)?, keys)
}

fn optional_str(value: &Value) -> Result<Option<&str>, &'static str> {
    match value {
        Value::Null => Ok(None),
        Value::String(text) => Ok(Some(text.as_str())),
        _ => Err(ERR_INVALID),
    }
}

fn pair(value: &Value) -> Result<[&Value; 2], &'static str> {
    match value.as_array().map(Vec::as_slice) {
        Some([first, second]) => Ok([first, second]),
        _ => Err(ERR_INVALID),
    }
}

fn strings(value: &Value) -> Result<Vec<&str>, &'static str> {
    value
        .as_array()
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|item| item.as_str().ok_or(ERR_INVALID))
        .collect()
}

/// `copilot_state_authorizes_backup_reuse`.
fn backup_reuse(fields: &Map<String, Value>) -> KindResult {
    let recorded = pair(&fields["recorded"])?.map(optional_str);
    let expected = pair(&fields["expected"])?.map(Value::as_str);
    let backup = match &fields["backup"] {
        Value::Null => None,
        value => Some(optional_str(&object(value, &["text"])?["text"])?),
    };
    let mut bound = true;
    for (recorded, expected) in recorded.into_iter().zip(expected) {
        let expected = expected.ok_or(ERR_INVALID)?;
        bound &= recorded? == Some(expected);
    }
    let decision = if !bound {
        "replace"
    } else if backup.flatten().is_some_and(valid_backup_envelope) {
        "reuse"
    } else {
        "refuse"
    };
    Ok(json!({ "decision": decision }))
}

/// `_valid_backup_envelope`: exactly `existed` and `content`, with content
/// text when the config existed and `null` when it did not.
pub(super) fn valid_backup_envelope(text: &str) -> bool {
    let Ok(Value::Object(envelope)) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    envelope.len() == 2
        && matches!(
            (envelope.get("existed"), envelope.get("content")),
            (Some(Value::Bool(true)), Some(Value::String(_)))
                | (Some(Value::Bool(false)), Some(Value::Null))
        )
}

/// The facts Python gathered about one config a state file may name.
struct Candidate<'a> {
    source: &'a str,
    keys: Vec<&'a str>,
    contained: bool,
    /// `None` when naming the config's state and backup paths raised.
    paths: Option<Paths<'a>>,
}

/// The state and backup Guard keeps for one config.
struct Paths<'a> {
    owned: bool,
    state: &'a str,
    backup: [&'a str; 2],
}

/// One authenticated state file: its resolved path, its `managed_config_path`
/// and `backup_path` when they are strings, and its candidates.
struct Entry<'a> {
    state: &'a str,
    managed: Option<&'a str>,
    backup: Option<&'a str>,
    candidates: Vec<Candidate<'a>>,
}

fn candidate(value: &Value) -> Result<Candidate<'_>, &'static str> {
    let fields = object(value, &CANDIDATE_KEYS)?;
    let source = fields["source"]
        .as_str()
        .filter(|source| SOURCES.contains(source))
        .ok_or(ERR_INVALID)?;
    let paths = match &fields["paths"] {
        Value::Null => None,
        value => {
            let paths = object(value, &PATHS_KEYS)?;
            let [spelled, resolved] = pair(&paths["backup"])?.map(Value::as_str);
            Some(Paths {
                owned: paths["owned"].as_bool().ok_or(ERR_INVALID)?,
                state: paths["state"].as_str().ok_or(ERR_INVALID)?,
                backup: [spelled.ok_or(ERR_INVALID)?, resolved.ok_or(ERR_INVALID)?],
            })
        }
    };
    Ok(Candidate {
        source,
        keys: strings(&fields["keys"])?,
        contained: fields["contained"].as_bool().ok_or(ERR_INVALID)?,
        paths,
    })
}

fn entry(value: &Value) -> Result<Entry<'_>, &'static str> {
    let fields = object(value, &ENTRY_KEYS)?;
    let [managed, backup] = pair(&fields["fields"])?.map(Value::as_str);
    Ok(Entry {
        state: fields["state"].as_str().ok_or(ERR_INVALID)?,
        managed,
        backup,
        candidates: fields["candidates"]
            .as_array()
            .ok_or(ERR_INVALID)?
            .iter()
            .map(candidate)
            .collect::<Result<_, _>>()?,
    })
}

fn state_entries(fields: &Map<String, Value>) -> KindResult {
    let entries = fields["entries"]
        .as_array()
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|value| entry(value).map(|parsed| verdict(&parsed)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({ "entries": entries }))
}

fn usable(value: Option<&str>) -> Option<&str> {
    value.filter(|text| !text.is_empty() && !text.contains('\0'))
}

/// `_validated_entry` after authentication, first failure wins.
fn verdict(entry: &Entry<'_>) -> Value {
    let (Some(managed), Some(backup)) = (usable(entry.managed), usable(entry.backup)) else {
        return Value::Null;
    };
    // A workspace the authenticated state recorded replaces the current one.
    let recorded = entry
        .candidates
        .iter()
        .any(|candidate| candidate.source == "recorded");
    let skipped = if recorded { "current" } else { "recorded" };
    // The original built a dict keyed by spelling, so a later config wins.
    let Some((index, candidate)) = entry
        .candidates
        .iter()
        .enumerate()
        .rev()
        .filter(|(_, candidate)| candidate.source != skipped)
        .find(|(_, candidate)| candidate.keys.contains(&managed))
    else {
        return Value::Null;
    };
    if !candidate.contained {
        return Value::Null;
    }
    let Some(paths) = &candidate.paths else {
        return json!({ "raise": index });
    };
    if !paths.owned || entry.state != paths.state || !paths.backup.contains(&backup) {
        return Value::Null;
    }
    json!(index)
}

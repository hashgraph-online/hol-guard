//! `publication_short_replies`: the short-reply instruction Guard writes to
//! the Codex config while CIGAR is on.
//!
//! Codex reads `developer_instructions` as a system instruction. Asking it
//! there to keep its own words short cut the bill by 5–14% on top of CIGAR in
//! Guard's benchmark, with no task lost; the same sentence in CIGAR's note did
//! nothing. So Guard writes it by default when CIGAR is turned on, and the
//! user can turn it off. Guard never touches instructions the user wrote: it
//! records the exact text it wrote, per config file, and only removes that
//! text. Turning it off is remembered, so turning CIGAR on again later does
//! not bring it back. The caller holds the Codex install lock.
//!
//! Request: `{"action": "status" | "enable" | "disable" | "ensure", "home":
//! <guard home>, "home_dir": <user home>, "codex_home": text | null}`.
//! `ensure` is the default: it writes the text unless the user turned it off,
//! set instructions of their own, or has no Codex config folder. Answer: the
//! switch's view, or `{"error": <code>}` for a refusal the user can act on.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::output::managed_write;
use super::publication::Call;
use super::publication_lean::{
    ascii_string, config_path, read_config, record_key, write_config, Checked,
};
use super::Step;
use crate::codex_value::HookVal;

const KEY: &str = "developer_instructions";
/// The text measured in the benchmark. Changing it needs a new measurement.
pub(super) const TEXT: &str = "Keep your own words short. No preamble, no restating the task, \
no narration of what you are about to do, no summary of tool output. Final answer: one or two \
lines naming what changed or the answer. Code, commands, paths and identifiers stay exact.";
const SCHEMA: &str = "guard-codex-short-replies.v1";
const RECORD_NAME: &str = "codex-short-replies.json";
const PRIVATE_MODE: u32 = 0o600;
/// The record value for a config the user turned this off for.
const OFF: &str = "off";

pub(super) fn short_replies(call: &mut Call<'_>) -> Step<Value> {
    let action = call.text("action")?.to_owned();
    let guard_home = call.home()?;
    let home_dir = call.path("home_dir")?;
    let codex_home = call.args.get("codex_home").and_then(Value::as_str);
    let path = config_path(&home_dir, codex_home);
    let answer = match action.as_str() {
        "status" => status(&guard_home, &path),
        "enable" => enable(call, &guard_home, &path)?,
        "disable" => disable(call, &guard_home, &path)?,
        "ensure" => ensure(call, &guard_home, &path)?,
        _ => return Err(super::Fault::Transition("files_invalid")),
    };
    Ok(answer.unwrap_or_else(|refusal| json!({ "error": refusal.0 })))
}

fn status(guard_home: &Path, path: &Path) -> Checked<Value> {
    let (_text, payload) = read_config(path)?;
    Ok(view(path, current(&payload), &recorded(guard_home, path)))
}

/// The default: on, unless the user said no, wrote their own, or has no Codex.
fn ensure(call: &mut Call<'_>, guard_home: &Path, path: &Path) -> Step<Checked<Value>> {
    let record = recorded(guard_home, path);
    let codex_missing = path.parent().is_none_or(|folder| !folder.is_dir());
    if record == Record::Off || codex_missing {
        return Ok(match read_config(path) {
            Ok((_text, payload)) => Ok(view(path, current(&payload), &record)),
            Err(refusal) => Err(refusal),
        });
    }
    if let Record::Wrote(_) = record {
        let (_text, payload) = match read_config(path) {
            Ok(read) => read,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if current(&payload).is_none() {
            // Guard wrote it and the user deleted the line: that is a no.
            write_record(call, guard_home, path, Record::Off)?;
            return Ok(Ok(view(path, None, &Record::Off)));
        }
    }
    enable(call, guard_home, path)
}

fn enable(call: &mut Call<'_>, guard_home: &Path, path: &Path) -> Step<Checked<Value>> {
    let (text, mut payload) = match read_config(path) {
        Ok(read) => read,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let record = recorded(guard_home, path);
    let current = current(&payload).map(ToOwned::to_owned);
    match current.as_deref() {
        // Guard's text with no record that Guard wrote it: someone else put
        // it there, so Guard does not claim it (a later "off" would delete it).
        Some(value) if value == TEXT => {
            return Ok(Ok(view(path, current.as_deref(), &record)));
        }
        Some(value) if !matches!(&record, Record::Wrote(wrote) if wrote == value) => {
            // Instructions the user wrote: Guard leaves them as they are.
            return Ok(Ok(view(path, Some(value), &record)));
        }
        _ => {}
    }
    // The record goes first: if Guard stops between the two writes, the
    // config still holds what it held and Guard never claims text it did not
    // write.
    write_record(call, guard_home, path, Record::Wrote(TEXT.to_owned()))?;
    set(&mut payload, HookVal::Str(TEXT.to_owned()));
    if let Err(fault) = write_config(call, path, &payload, text.as_deref()) {
        // The write can fail after the new config is already in place (a
        // mode or directory sync error); then Guard's text is there and
        // Guard keeps owning it.
        let published =
            matches!(read_config(path), Ok((_, now)) if self::current(&now) == Some(TEXT));
        if !published {
            write_record(call, guard_home, path, record)?;
        }
        return Err(fault);
    }
    Ok(Ok(view(path, Some(TEXT), &Record::Wrote(TEXT.to_owned()))))
}

fn disable(call: &mut Call<'_>, guard_home: &Path, path: &Path) -> Step<Checked<Value>> {
    let (text, mut payload) = match read_config(path) {
        Ok(read) => read,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let record = recorded(guard_home, path);
    let current = current(&payload).map(ToOwned::to_owned);
    let ours = matches!((&current, &record), (Some(value), Record::Wrote(wrote)) if value == wrote);
    if !ours {
        write_record(call, guard_home, path, Record::Off)?;
        return Ok(Ok(view(path, current.as_deref(), &Record::Off)));
    }
    remove(&mut payload);
    write_config(call, path, &payload, text.as_deref())?;
    // A record still naming the text would claim instructions the user
    // writes later, so a failed record write puts the config back.
    if let Err(fault) = write_record(call, guard_home, path, Record::Off) {
        if let Some(original) = text.as_deref() {
            call.events
                .push(managed_write(path, original.as_bytes(), PRIVATE_MODE)?);
        }
        return Err(fault);
    }
    Ok(Ok(view(path, None, &Record::Off)))
}

fn view(path: &Path, current: Option<&str>, record: &Record) -> Value {
    let state = match (current, record) {
        (Some(value), Record::Wrote(wrote)) if value == wrote => "on",
        (Some(_), _) => "yours",
        (None, Record::Off) => "off",
        (None, _) => "not_set",
    };
    json!({
        "schema": SCHEMA,
        "state": state,
        "text": TEXT,
        "config_path": path.to_string_lossy(),
    })
}

/// The instructions in the config, when they are text.
fn current(payload: &HookVal) -> Option<&str> {
    match payload.get(KEY) {
        Some(HookVal::Str(text)) => Some(text),
        Some(_) => Some(""),
        None => None,
    }
}

fn set(payload: &mut HookVal, value: HookVal) {
    if let HookVal::Dict(entries) = payload {
        match entries.iter_mut().find(|(key, _)| key == KEY) {
            Some((_, slot)) => *slot = value,
            None => entries.push((KEY.to_owned(), value)),
        }
    }
}

fn remove(payload: &mut HookVal) {
    if let HookVal::Dict(entries) = payload {
        entries.retain(|(key, _)| key != KEY);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Record {
    None,
    Off,
    Wrote(String),
}

fn record_path(guard_home: &Path) -> PathBuf {
    guard_home.join(RECORD_NAME)
}

/// What Guard did to each Codex config, keyed by the config's path: the
/// text it wrote, or `{"off": true}` once the user turned it off.
pub(super) fn records(guard_home: &Path) -> Map<String, Value> {
    let parsed = fs::read(record_path(guard_home))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    match parsed.as_ref().and_then(|value| value.get("configs")) {
        Some(Value::Object(configs)) => configs
            .iter()
            .filter(|(_, value)| value.is_string())
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        _ => Map::new(),
    }
}

/// Whether turning CIGAR on should ask Codex for short replies: Guard has not
/// asked yet, and the Guard home sits in the user's home folder. A home
/// elsewhere belongs to a test or a sandbox, and the Codex config in the home
/// folder is not its to change.
pub(crate) fn first_ask_due(guard_home: &Path, user_home: Option<&Path>) -> bool {
    let parent = fs::canonicalize(guard_home)
        .ok()
        .and_then(|home| home.parent().map(Path::to_path_buf));
    let user_home = user_home.and_then(|home| fs::canonicalize(home).ok());
    // Any record file, even one Guard cannot read, means Guard asked before.
    let never_asked = matches!(
        fs::symlink_metadata(record_path(guard_home)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    );
    parent.is_some() && parent == user_home && never_asked
}

/// The record value is the text Guard wrote, or the word `off`. The written
/// text is never the bare word, so the two cannot be confused.
pub(super) fn recorded(guard_home: &Path, path: &Path) -> Record {
    match records(guard_home)
        .get(&record_key(path))
        .and_then(Value::as_str)
    {
        Some(OFF) => Record::Off,
        Some(text) => Record::Wrote(text.to_owned()),
        None => Record::None,
    }
}

fn write_record(call: &mut Call<'_>, guard_home: &Path, path: &Path, record: Record) -> Step<()> {
    let mut records = records(guard_home);
    match record {
        Record::Off => records.insert(record_key(path), json!(OFF)),
        Record::Wrote(text) => records.insert(record_key(path), json!(text)),
        Record::None => records.remove(&record_key(path)),
    };
    let file = record_path(guard_home);
    if records.is_empty() {
        return match fs::remove_file(&file) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
            _ => Ok(()),
        };
    }
    let mut keys: Vec<&String> = records.keys().collect();
    keys.sort();
    let body: Vec<String> = keys
        .into_iter()
        .map(|key| {
            let value = records[key].as_str().unwrap_or_default();
            format!("{}: {}", ascii_string(key), ascii_string(value))
        })
        .collect();
    let text = format!("{{\"configs\": {{{}}}}}\n", body.join(", "));
    call.events
        .push(managed_write(&file, text.as_bytes(), PRIVATE_MODE)?);
    Ok(())
}

#[cfg(test)]
#[path = "tests_publication_short_replies.rs"]
mod tests;

//! `runner_authority` kind `harness_shim_refresh`: which harness launcher
//! shims daemon startup regenerates after a Guard upgrade
//! (`refresh_stale_harness_shims` in `guard/shim_refresh.py`).
//!
//! Python lists the shim directory, reads each shim, builds the body an
//! install would write now and installs it. Two ops decide the rest:
//!
//! - `plan`: given the file names in the shim directory and each adapter's
//!   `[harness, launcher, legacy_names]`, the shims to visit in order. A shim
//!   whose launcher no adapter knows is `unknown` and left alone. A legacy
//!   name whose canonical shim is also present is `drop_legacy`: remove it
//!   without reading it, so its context cannot overwrite the canonical one.
//!   Every other shim is `check`ed.
//! - `context`: the home and workspace an installed shim was generated for,
//!   read from its `base_command` line. A shim with no `--workspace` keeps the
//!   workspace its managed install recorded. `recognized` is false when the
//!   body has no parseable `base_command`.
//!
//! `base_command` is read as a list of plain string literals, the only shape
//! the generator writes. Python's `ast.literal_eval` also took implicit
//! concatenation and trailing comments; a hand-edited shim using them now
//! reports as unrecognized and is left alone.

use std::collections::BTreeMap;

use guard_command::shims::parse_py_str_list;
use serde_json::{json, Map, Value};

use crate::daemon_lifecycle_text::{py_splitlines, py_strip};
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const PREFIX: &str = "guard-";
const BASE_COMMAND: &str = "base_command = ";
const COMMENTED_BASE_COMMAND: &str = "# base_command = ";

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    match fields.get("op").and_then(Value::as_str) {
        Some("plan") => plan(fields),
        Some("context") => context(fields),
        _ => Err(ERR_INVALID),
    }
}

fn plan(fields: &Map<String, Value>) -> KindResult {
    exact_keys(fields, &["op", "entries", "adapters"])?;
    let mut entries = strings(fields.get("entries"))?;
    let launchers = launcher_map(fields.get("adapters"))?;
    entries.sort_unstable();
    let present: Vec<&str> = entries
        .iter()
        .filter(|name| !name.ends_with(".cmd"))
        .filter_map(|name| name.strip_prefix(PREFIX))
        .collect();
    let steps: Vec<Value> = present
        .iter()
        .map(|&name| {
            let Some((harness, canonical)) = launchers.get(name) else {
                return json!({"name": name, "action": "unknown"});
            };
            let legacy = name != canonical;
            let action = if legacy && present.contains(&canonical.as_str()) {
                "drop_legacy"
            } else {
                "check"
            };
            json!({
                "name": name,
                "action": action,
                "harness": harness,
                "canonical": canonical,
                "legacy": legacy,
            })
        })
        .collect();
    Ok(json!({ "steps": steps }))
}

/// `_launcher_map`: the first adapter to claim a launcher name keeps it.
fn launcher_map(value: Option<&Value>) -> Result<BTreeMap<String, (String, String)>, &'static str> {
    let mut mapping = BTreeMap::new();
    for adapter in value.and_then(Value::as_array).ok_or(ERR_INVALID)? {
        let [harness, launcher, legacy] =
            adapter.as_array().map(Vec::as_slice).ok_or(ERR_INVALID)?
        else {
            return Err(ERR_INVALID);
        };
        let harness = harness.as_str().ok_or(ERR_INVALID)?;
        let launcher = launcher.as_str().ok_or(ERR_INVALID)?;
        let entry = (harness.to_owned(), launcher.to_owned());
        mapping
            .entry(launcher.to_owned())
            .or_insert_with(|| entry.clone());
        for name in strings(Some(legacy))? {
            mapping.entry(name).or_insert_with(|| entry.clone());
        }
    }
    Ok(mapping)
}

fn context(fields: &Map<String, Value>) -> KindResult {
    exact_keys(fields, &["op", "body", "install_workspace"])?;
    let body = fields["body"].as_str().ok_or(ERR_INVALID)?;
    let install_workspace = match &fields["install_workspace"] {
        Value::Null => None,
        Value::String(text) => Some(text.as_str()),
        _ => return Err(ERR_INVALID),
    };
    let Some(base_command) = installed_base_command(body) else {
        return Ok(json!({"recognized": false, "home": null, "workspace": null}));
    };
    let workspace = flag_value(&base_command, "--workspace")
        .or_else(|| install_workspace.filter(|text| !py_strip(text).is_empty()));
    Ok(json!({
        "recognized": true,
        "home": flag_value(&base_command, "--home"),
        "workspace": workspace,
    }))
}

/// `_installed_base_command`: the first `base_command` line decides.
fn installed_base_command(body: &str) -> Option<Vec<String>> {
    let line = py_splitlines(body)
        .into_iter()
        .find(|line| line.starts_with(COMMENTED_BASE_COMMAND) || line.starts_with(BASE_COMMAND))?;
    let value = line
        .strip_prefix(COMMENTED_BASE_COMMAND)
        .or_else(|| line.strip_prefix(BASE_COMMAND))?;
    parse_py_str_list(value)
}

/// `_flag_value`: the argument after the first `flag`, if any.
fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].as_str())
}

fn strings(value: Option<&Value>) -> Result<Vec<String>, &'static str> {
    value
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|item| item.as_str().map(str::to_owned).ok_or(ERR_INVALID))
        .collect()
}

fn exact_keys(fields: &Map<String, Value>, keys: &[&str]) -> Result<(), &'static str> {
    if fields.len() == keys.len() && keys.iter().all(|key| fields.contains_key(*key)) {
        Ok(())
    } else {
        Err(ERR_INVALID)
    }
}

#[cfg(test)]
#[path = "harness_shim_refresh_tests.rs"]
mod tests;

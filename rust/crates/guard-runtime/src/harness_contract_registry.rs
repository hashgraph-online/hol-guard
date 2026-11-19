//! `runner_authority` kind `harness_contract_registry`: the harness
//! protection contracts, loaded and validated from the bundled
//! `harness-protection-contracts.v1.json` and answered ready to use.
//!
//! - `{"op": "contracts"}` answers `{"contracts": [...]}`: every contract in
//!   file order.
//! - `{"op": "contract", "harness"}` answers `{"contract": ...}`: the contract
//!   a harness name or install alias identifies, `null` for a name that no
//!   contract has. When two contracts claim one name the later one answers.
//! - `{"op": "harnesses"}` answers `{"harnesses": [...]}`: the canonical
//!   harness names in file order.
//!
//! A contract is `{harness, install_aliases, config_paths, event_surfaces,
//! native_approval, browser_fallback, resume_support, known_blind_spots,
//! smoke_command, surface_capabilities, supported_actions, docs_path,
//! icon_label, capability_events}`. A capability event is `{harness, adapter,
//! host_version_scope, os_arch, local_hosted, event, tools, surface,
//! transport, mode, declared_actions, error_behavior,
//! mandatory_compatibility, known_blind_spots, source_reference}`, with the
//! defaults for omitted fields already applied. A bundle that is malformed
//! answers nothing at all: no partial registry is ever returned.
//!
//! This reads a declaration of what each adapter can do. It never decides a
//! tool call, and nothing here feeds policy, approval, or admission.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde_json::{json, Map, Value};

use crate::claude_hook_bridge_render::py_strip;
use crate::harness_protection_contract::{CONTRACT, SCHEMA};
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const CONTRACT_KEYS: [&str; 14] = [
    "harness",
    "install_aliases",
    "config_paths",
    "event_surfaces",
    "native_approval",
    "browser_fallback",
    "resume_support",
    "known_blind_spots",
    "smoke_command",
    "surface_capabilities",
    "supported_actions",
    "docs_path",
    "icon_label",
    "capability_events",
];
const EVENT_KEYS: [&str; 17] = [
    "harness",
    "adapter",
    "host_version_scope",
    "os_arch",
    "local_hosted",
    "event",
    "tools",
    "transport",
    "mode",
    "surface",
    "failure_behavior",
    "claim",
    "declared_actions",
    "error_behavior",
    "mandatory_compatibility",
    "known_blind_spots",
    "source_reference",
];
const LOCAL_HOSTED: [&str; 3] = ["local", "hosted", "unknown"];
const DECLARED_ACTIONS: [&str; 9] = [
    "inspect",
    "observe",
    "block",
    "approval",
    "suggest",
    "rewrite",
    "redact-before-forward",
    "inventory",
    "unavailable",
];

type Row = Map<String, Value>;
type Checked<T> = Result<T, ()>;

struct Registry {
    contracts: Vec<Value>,
    by_name: HashMap<String, usize>,
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args.as_object().ok_or(ERR_INVALID)?;
    let op = fields
        .get("op")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let registry = bundled().ok_or(ERR_INVALID)?;
    match (op, fields.len()) {
        ("contracts", 1) => Ok(json!({ "contracts": registry.contracts })),
        ("harnesses", 1) => Ok(json!({ "harnesses": registry.harnesses() })),
        ("contract", 2) => {
            let name = fields
                .get("harness")
                .and_then(Value::as_str)
                .ok_or(ERR_INVALID)?;
            Ok(json!({ "contract": registry.contract(name) }))
        }
        _ => Err(ERR_INVALID),
    }
}

/// The config paths a harness's contract names, by harness or install alias.
pub(crate) fn config_paths(name: &str) -> Option<Vec<String>> {
    let row = bundled()?.contract(name)?;
    row["config_paths"]
        .as_array()?
        .iter()
        .map(|path| path.as_str().map(str::to_owned))
        .collect()
}

fn bundled() -> Option<&'static Registry> {
    static REGISTRY: OnceLock<Option<Registry>> = OnceLock::new();
    REGISTRY
        .get_or_init(|| {
            serde_json::from_str::<Value>(CONTRACT)
                .ok()
                .and_then(|document| Registry::load(&document))
        })
        .as_ref()
}

impl Registry {
    /// The registry a document declares, or `None` when any part is malformed.
    fn load(document: &Value) -> Option<Self> {
        let document = document.as_object()?;
        if document.get("schema").and_then(Value::as_str) != Some(SCHEMA) {
            return None;
        }
        let rows = document.get("contracts")?.as_array()?;
        let contracts = rows
            .iter()
            .map(contract)
            .collect::<Checked<Vec<Value>>>()
            .ok()?;
        let mut by_name = HashMap::new();
        for (index, row) in contracts.iter().enumerate() {
            for name in std::iter::once(&row["harness"]).chain(row["install_aliases"].as_array()?) {
                by_name.insert(name.as_str()?.to_owned(), index);
            }
        }
        Some(Self { contracts, by_name })
    }

    fn contract(&self, name: &str) -> Option<&Value> {
        self.by_name.get(name).map(|index| &self.contracts[*index])
    }

    fn harnesses(&self) -> Vec<&Value> {
        self.contracts.iter().map(|row| &row["harness"]).collect()
    }
}

fn object<'a>(value: &'a Value, keys: &[&str]) -> Checked<&'a Row> {
    let row = value.as_object().ok_or(())?;
    if row.keys().all(|key| keys.contains(&key.as_str())) {
        Ok(row)
    } else {
        Err(())
    }
}

fn text(row: &Row, key: &str, default: Option<&str>) -> Checked<String> {
    match row.get(key) {
        Some(Value::String(value)) => Ok(value.clone()),
        None => default.map(str::to_owned).ok_or(()),
        Some(_) => Err(()),
    }
}

/// A required text that is not blank, as a capability row demands.
fn named(row: &Row, key: &str, default: Option<&str>) -> Checked<String> {
    let value = text(row, key, default)?;
    if py_strip(&value).is_empty() {
        Err(())
    } else {
        Ok(value)
    }
}

fn optional_text(row: &Row, key: &str) -> Checked<Value> {
    match row.get(key) {
        None | Some(Value::Null) => Ok(Value::Null),
        Some(Value::String(value)) => Ok(json!(value)),
        Some(_) => Err(()),
    }
}

fn texts(row: &Row, key: &str, required: bool) -> Checked<Vec<String>> {
    match row.get(key) {
        None if !required => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned).ok_or(()))
            .collect(),
        _ => Err(()),
    }
}

fn filled(items: Vec<String>) -> Checked<Vec<String>> {
    if items.iter().all(|item| !py_strip(item).is_empty()) {
        Ok(items)
    } else {
        Err(())
    }
}

fn flag(row: &Row, key: &str) -> Checked<bool> {
    row.get(key).and_then(Value::as_bool).ok_or(())
}

fn contract(value: &Value) -> Checked<Value> {
    let row = object(value, &CONTRACT_KEYS)?;
    let harness = text(row, "harness", None)?;
    let events = row
        .get("capability_events")
        .and_then(Value::as_array)
        .filter(|events| !events.is_empty())
        .ok_or(())?;
    let events = events
        .iter()
        .map(|event| capability(&harness, event))
        .collect::<Checked<Vec<Value>>>()?;
    Ok(json!({
        "harness": harness,
        "install_aliases": texts(row, "install_aliases", true)?,
        "config_paths": texts(row, "config_paths", true)?,
        "event_surfaces": texts(row, "event_surfaces", true)?,
        "native_approval": flag(row, "native_approval")?,
        "browser_fallback": flag(row, "browser_fallback")?,
        "resume_support": flag(row, "resume_support")?,
        "known_blind_spots": text(row, "known_blind_spots", None)?,
        "smoke_command": text(row, "smoke_command", None)?,
        "surface_capabilities": texts(row, "surface_capabilities", false)?,
        "supported_actions": texts(row, "supported_actions", false)?,
        "docs_path": optional_text(row, "docs_path")?,
        "icon_label": optional_text(row, "icon_label")?,
        "capability_events": events,
    }))
}

fn capability(harness: &str, value: &Value) -> Checked<Value> {
    let row = object(value, &EVENT_KEYS)?;
    let local_hosted = text(row, "local_hosted", Some("local"))?;
    let declared_actions = filled(texts(row, "declared_actions", true)?)?;
    if !LOCAL_HOSTED.contains(&local_hosted.as_str())
        || declared_actions
            .iter()
            .any(|action| !DECLARED_ACTIONS.contains(&action.as_str()))
    {
        return Err(());
    }
    Ok(json!({
        "harness": named(row, "harness", Some(harness))?,
        "adapter": named(row, "adapter", Some(harness))?,
        "host_version_scope": named(row, "host_version_scope", Some("unknown"))?,
        "os_arch": named(row, "os_arch", Some("unknown"))?,
        "local_hosted": local_hosted,
        "event": named(row, "event", None)?,
        "tools": texts(row, "tools", false)?,
        "surface": optional_text(row, "surface")?,
        "transport": named(row, "transport", None)?,
        "mode": named(row, "mode", None)?,
        "declared_actions": declared_actions,
        "error_behavior": named(row, "error_behavior", None)?,
        "mandatory_compatibility": named(row, "mandatory_compatibility", None)?,
        "known_blind_spots": filled(texts(row, "known_blind_spots", true)?)?,
        "source_reference": named(row, "source_reference", None)?,
    }))
}

#[cfg(test)]
#[path = "harness_contract_registry_tests.rs"]
mod tests;

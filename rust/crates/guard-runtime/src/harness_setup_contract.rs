//! `runner_authority` kind `harness_setup_contract`: what the guided setup
//! shows for a supported harness, read from the bundled harness protection
//! contract.
//!
//! - `{"op": "contract", "harness"}` answers `{"contract": ...}`: the setup
//!   contract of the harness a name or install alias identifies, `null` for
//!   a name that no contract has. When two contracts claim one name the later
//!   one answers. The contract is `{harness, display_name, install_aliases,
//!   setup_steps, verify_steps, repair_steps, coverage}` plus
//!   `surface_capabilities`, `supported_actions`, `docs_path` and
//!   `icon_label` when the contract has them. A step is `{step_id, title,
//!   body, command, writes_config, requires_confirmation}` and the coverage
//!   is `{native_hooks, browser_fallback, mcp_proxy, prompt_hooks,
//!   blind_spots}`.
//! - `{"op": "display_name", "harness"}` answers `{"display_name": text}`:
//!   the label for a name or alias, or the name itself when no label exists.

use std::sync::OnceLock;

use serde_json::{json, Map, Value};

use crate::harness_protection_contract::CONTRACT;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const DISPLAY_NAMES: [(&str, &str); 18] = [
    ("codex", "Codex"),
    ("claude-code", "Claude Code"),
    ("opencode", "OpenCode"),
    ("copilot", "Copilot"),
    ("cursor", "Cursor"),
    ("cline", "Cline"),
    ("gemini", "Gemini"),
    ("hermes", "Hermes"),
    ("openclaw", "OpenClaw"),
    ("antigravity", "Antigravity"),
    ("kimi", "Kimi"),
    ("grok", "Grok"),
    ("pi", "Pi"),
    ("omp", "Oh My Pi"),
    ("zcode", "ZCode"),
    ("devin", "Devin"),
    ("muse", "Muse"),
    ("paseo", "Paseo"),
];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args.as_object().ok_or(ERR_INVALID)?;
    let op = fields
        .get("op")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let name = fields
        .get("harness")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    if fields.len() != 2 {
        return Err(ERR_INVALID);
    }
    match op {
        "contract" => Ok(json!({ "contract": contract_for(name).map(setup_contract) })),
        "display_name" => Ok(json!({ "display_name": display_name(name) })),
        _ => Err(ERR_INVALID),
    }
}

fn contracts() -> &'static [Value] {
    static CONTRACTS: OnceLock<Vec<Value>> = OnceLock::new();
    CONTRACTS.get_or_init(|| {
        serde_json::from_str::<Value>(CONTRACT)
            .ok()
            .and_then(|document| match document.get("contracts") {
                Some(Value::Array(contracts)) => Some(contracts.clone()),
                _ => None,
            })
            .unwrap_or_default()
    })
}

/// The contract a harness name or install alias identifies; the last contract
/// that claims the name answers.
fn contract_for(name: &str) -> Option<&'static Value> {
    contracts().iter().rev().find(|contract| {
        contract.get("harness").and_then(Value::as_str) == Some(name)
            || strings(contract, "install_aliases").any(|alias| alias == name)
    })
}

fn display_name(name: &str) -> String {
    let harness = contract_for(name)
        .and_then(|contract| contract.get("harness"))
        .and_then(Value::as_str)
        .unwrap_or(name);
    label(harness).to_owned()
}

fn label(harness: &str) -> &str {
    DISPLAY_NAMES
        .iter()
        .find(|(key, _)| *key == harness)
        .map_or(harness, |(_, label)| label)
}

fn strings<'a>(contract: &'a Value, key: &str) -> impl Iterator<Item = &'a str> {
    contract
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

fn flag(contract: &Value, key: &str) -> bool {
    contract.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn step(
    step_id: &str,
    title: &str,
    body: &str,
    command: Option<[&str; 4]>,
    writes_config: bool,
) -> Value {
    json!({
        "step_id": step_id,
        "title": title,
        "body": body,
        "command": command.map(|words| words.to_vec()).unwrap_or_default(),
        "writes_config": writes_config,
        "requires_confirmation": false,
    })
}

fn setup_contract(contract: &Value) -> Value {
    let harness = contract
        .get("harness")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let aliases = strings(contract, "install_aliases").collect::<Vec<_>>();
    let alias = aliases.first().copied().unwrap_or(harness);
    let display = label(harness);
    let surfaces = strings(contract, "event_surfaces").collect::<Vec<_>>();
    let command = |verb| Some(["hol-guard", "apps", verb, alias]);
    let connect = if harness == "paseo" {
        "Install native provider hooks on the Paseo daemon host.".to_owned()
    } else {
        format!("Add Guard's local protection hooks for {display}.")
    };
    let mut payload = Map::new();
    payload.insert("harness".into(), json!(harness));
    payload.insert("display_name".into(), json!(display));
    payload.insert("install_aliases".into(), json!(aliases));
    payload.insert(
        "setup_steps".into(),
        json!([
            step(
                "connect",
                &format!("Connect {display}"),
                &connect,
                command("connect"),
                true
            ),
            step(
                "review-coverage",
                "Review what Guard can see",
                "Check covered events and known blind spots before relying on this app.",
                None,
                false
            ),
        ]),
    );
    payload.insert(
        "verify_steps".into(),
        json!([step(
            "safe-test",
            "Run a safe protection test",
            "Confirm Guard can detect the app without reading secrets or changing app config.",
            command("test"),
            false
        )]),
    );
    payload.insert(
        "repair_steps".into(),
        json!([step(
            "repair",
            &format!("Repair {display} protection"),
            "Re-apply Guard managed config if hooks were removed or changed.",
            command("repair"),
            true
        )]),
    );
    payload.insert(
        "coverage".into(),
        json!({
            "native_hooks": flag(contract, "native_approval"),
            "browser_fallback": flag(contract, "browser_fallback"),
            "mcp_proxy": surfaces.contains(&"mcp_tool"),
            "prompt_hooks": surfaces.contains(&"prompt"),
            "blind_spots": [contract.get("known_blind_spots").and_then(Value::as_str).unwrap_or_default()],
        }),
    );
    for key in ["surface_capabilities", "supported_actions"] {
        let listed = strings(contract, key).collect::<Vec<_>>();
        if !listed.is_empty() {
            payload.insert(key.into(), json!(listed));
        }
    }
    for key in ["docs_path", "icon_label"] {
        if let Some(text) = contract.get(key).and_then(Value::as_str) {
            payload.insert(key.into(), json!(text));
        }
    }
    Value::Object(payload)
}

#[cfg(test)]
#[path = "harness_setup_contract_tests.rs"]
mod tests;

//! `runner_authority` kind `cline_install_plan`: the decisions the Cline
//! adapter makes while it installs an enforcement transport
//! (`_auto_transport`, the cleanup choice in `_reconcile_transport`,
//! `_coverage_label` and `_blind_spots` in `adapters/cline.py` before they
//! moved here). Python keeps the file writes, the probes and the state it
//! reads, and sends booleans:
//!
//! - `transport` picks the transport for a normalized surface and says whether
//!   a failed plugin install may fall back to native hooks.
//! - `reconcile` says whether the other managed transport is removed and
//!   whether the switch still waits for a live proof.
//! - `posture` names the coverage label and the blind spots of an install.

use serde_json::{json, Map, Value};

use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const SURFACES: [&str; 5] = ["auto", "hooks", "plugin", "cli", "all"];
const HOOKS_BLIND_SPOT: &str =
    "Native PostToolUse is observation-only; use the plugin transport for model-visible output replacement.";
const JETBRAINS_BLIND_SPOT: &str =
    "JetBrains runtime protection is unverified until Guard observes a live pre-tool deny proof.";

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    let op = fields
        .get("op")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let keys: &[&str] = match op {
        "transport" => &["op", "surface", "frozen", "cli", "vscode", "jetbrains"],
        "reconcile" => &["op", "target_ready", "other_installed", "other_ready"],
        "posture" => &["op", "transport", "hook_ready", "plugin_ready", "jetbrains"],
        _ => return Err(ERR_INVALID),
    };
    if fields.len() != keys.len() || !keys.iter().all(|key| fields.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    match op {
        "transport" => transport(fields),
        "reconcile" => reconcile(fields),
        _ => posture(fields),
    }
}

fn flag(fields: &Map<String, Value>, key: &str) -> Result<bool, &'static str> {
    fields.get(key).and_then(Value::as_bool).ok_or(ERR_INVALID)
}

fn text<'a>(fields: &'a Map<String, Value>, key: &str) -> Result<&'a str, &'static str> {
    fields.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)
}

/// An explicit `hooks` or `plugin` surface is honoured. Otherwise a frozen
/// Desktop runtime, or a CLI-only host, takes the durable plugin and every
/// other host takes native hooks. Only an implicit plugin choice may fall
/// back to hooks when the plugin fails its probe.
fn transport(fields: &Map<String, Value>) -> KindResult {
    let surface = text(fields, "surface")?;
    if !SURFACES.contains(&surface) {
        return Err(ERR_INVALID);
    }
    let frozen = flag(fields, "frozen")?;
    let cli = flag(fields, "cli")?;
    let vscode = flag(fields, "vscode")?;
    let jetbrains = flag(fields, "jetbrains")?;
    let transport = match surface {
        "hooks" | "plugin" => surface,
        _ if frozen || (cli && !vscode && !jetbrains) => "plugin",
        _ => "hooks",
    };
    let fallback = matches!(surface, "auto" | "all" | "cli") && transport != "hooks";
    Ok(json!({"transport": transport, "fallback": fallback}))
}

/// The other transport is removed once the target is ready, or when the other
/// one is not ready either; until then the switch waits for a live proof.
fn reconcile(fields: &Map<String, Value>) -> KindResult {
    let target_ready = flag(fields, "target_ready")?;
    let other_installed = flag(fields, "other_installed")?;
    let other_ready = flag(fields, "other_ready")?;
    let remove_other = other_installed && (target_ready || !other_ready);
    let transition_pending = other_installed && !target_ready && !remove_other;
    Ok(json!({"remove_other": remove_other, "transition_pending": transition_pending}))
}

fn posture(fields: &Map<String, Value>) -> KindResult {
    let transport = text(fields, "transport")?;
    let hook_ready = flag(fields, "hook_ready")?;
    let plugin_ready = flag(fields, "plugin_ready")?;
    let jetbrains = flag(fields, "jetbrains")?;
    let coverage = match transport {
        "plugin" if plugin_ready => "full",
        "plugin" => "pending-live-proof",
        "hooks" if hook_ready => "pre-execution",
        "hooks" if jetbrains => "unverified",
        "hooks" => "pending-live-proof",
        _ => return Err(ERR_INVALID),
    };
    let mut blind_spots: Vec<&str> = Vec::new();
    if transport == "hooks" {
        blind_spots.push(HOOKS_BLIND_SPOT);
    }
    if jetbrains {
        blind_spots.push(JETBRAINS_BLIND_SPOT);
    }
    Ok(json!({"coverage": coverage, "blind_spots": blind_spots}))
}

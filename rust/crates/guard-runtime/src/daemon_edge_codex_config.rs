//! `/v1/context-assistance/codex-lean` and `.../codex-short-replies`: the
//! dashboard's two Codex config switches.
//!
//! A read reports the switch as the Codex config has it. A write turns it on
//! or off behind the approval gate the dashboard uses for settings changes.
//! Lean mode needs the size the user picked; it is checked before the gate,
//! since an approval for a size Guard will refuse is wasted.

use serde_json::{json, Map, Value};

use super::super::super::ReadConfig;
use super::{settings_gate, Reply};
use crate::codex_config_switch::{self as switch, Homes, Switch};

pub(super) const LEAN: &str = "/v1/context-assistance/codex-lean";
pub(super) const SHORT_REPLIES: &str = "/v1/context-assistance/codex-short-replies";

fn which(path: &str) -> Option<(Switch, &'static str)> {
    match path {
        LEAN => Some((Switch::Lean, "codex_lean")),
        SHORT_REPLIES => Some((Switch::ShortReplies, "codex_short_replies")),
        _ => None,
    }
}

/// The homes this daemon's user has: its home folder and `CODEX_HOME`.
pub(in crate::daemon_edge) fn homes(config: &ReadConfig) -> Option<Homes> {
    let home = config
        .user_home
        .as_deref()
        .map(std::path::PathBuf::from)
        .or_else(crate::claude_hook_bridge::home_directory)?;
    let codex_home = std::env::var("CODEX_HOME").ok();
    Some(Homes::here(
        std::path::Path::new(&config.guard_home),
        &home,
        codex_home,
    ))
}

fn unavailable(name: &str, code: &str) -> Reply {
    (
        409,
        json!({"error": format!("{name}_unavailable"), "code": code}),
        true,
    )
}

/// `GET path`.
pub(super) fn get(path: &str, config: &ReadConfig) -> Option<Reply> {
    let (which, name) = which(path)?;
    let Some(homes) = homes(config) else {
        return Some(unavailable(name, switch::UNAVAILABLE));
    };
    Some(match switch::status(which, &homes) {
        Ok(state) => (200, state, true),
        Err(code) => unavailable(name, &code),
    })
}

/// `POST path` with `{enabled, limit?}` and the approval gate's proof.
pub(super) fn post(path: &str, payload: &Map<String, Value>, config: &ReadConfig) -> Option<Reply> {
    let (which, name) = which(path)?;
    let invalid = format!("invalid_{name}_input");
    let Some(Value::Bool(enabled)) = payload.get("enabled") else {
        return Some((400, json!({"error": invalid}), true));
    };
    let limit = payload.get("limit");
    if *enabled && which == Switch::Lean {
        if let Err(code) = switch::check_limit(limit) {
            return Some((400, json!({"error": invalid, "code": code}), true));
        }
    }
    if let Some(refused) = settings_gate(payload, config) {
        return Some(refused);
    }
    let Some(homes) = homes(config) else {
        return Some(unavailable(name, switch::UNAVAILABLE));
    };
    let action = if *enabled { "enable" } else { "disable" };
    Some(match switch::change(which, &homes, action, limit) {
        Ok(state) => (200, state, true),
        Err(code) => unavailable(name, &code),
    })
}

//! Codex: undo what an install changed in `~/.codex/config.toml` and keep
//! everything the user changed since.
//!
//! An install changes three things in the global config: it registers
//! Guard's hook groups, turns on the `hooks` feature (dropping the legacy
//! `codex_hooks` key), and rewrites each MCP server it manages to launch
//! through Guard's proxy. Restoring the pre-install backup over the file
//! undid those and also lost every setting the user added after install.
//! `uninstall_restore` takes the current payload, with Guard's manifest-bound
//! hooks already stripped by Python (`hooks`), and the backup payload, and
//! reverses only those three changes:
//!
//! * each server that launches through Guard's proxy gets back its backup
//!   entry, or is removed when the backup had none;
//! * the hook tables become the stripped ones, when Python sends them;
//! * when no hook group is left, `features.hooks` and `features.codex_hooks`
//!   take their backup values again. When the user's own hooks remain they
//!   keep the feature on, so it is left as it is.
//!
//! Every other key keeps its current value. `delete` is true when the result
//! is empty and the file did not exist before install.

use serde_json::{json, Map, Value};

use super::codex::registered;
use super::codex_merge::{get, payload, pop, py_eq, render, set, Entries};
use super::{Failure, Step};
use crate::cursor_editor_plan::is_guard_proxy;
use crate::pyjson::{self, PyVal};

const HOOK_FEATURES: [&str; 2] = ["hooks", "codex_hooks"];

pub(super) fn uninstall_restore(fields: &Map<String, Value>) -> Step<Value> {
    let current = payload(fields, "payload")?;
    let backup_present = fields.get("backup").is_some_and(|value| !value.is_null());
    let backup = if backup_present {
        payload(fields, "backup")?
    } else {
        Entries::new()
    };
    let mut rendered = current.clone();
    if let Some(raw) = fields.get("hooks").filter(|raw| !raw.is_null()) {
        let raw = raw.as_str().ok_or(Failure::Invalid)?;
        let cleaned = pyjson::parse(raw).map_err(|_| Failure::Invalid)?;
        if cleaned.as_dict().is_some_and(|hooks| !hooks.is_empty()) {
            set(&mut rendered, "hooks", cleaned);
        } else {
            pop(&mut rendered, "hooks");
        }
    }
    if !registered(get(&rendered, "hooks")) {
        restore_hook_features(&mut rendered, &backup);
    }
    restore_proxied_servers(&mut rendered, &backup);
    let changed = !py_eq(
        &PyVal::Dict(rendered.clone()),
        &PyVal::Dict(current.clone()),
    );
    let delete = rendered.is_empty() && (!backup_present || backup.is_empty());
    Ok(json!({
        "rendered": render(rendered),
        "changed": changed,
        "delete": delete,
    }))
}

fn restore_hook_features(rendered: &mut Entries, backup: &Entries) {
    let before = get(backup, "features").and_then(PyVal::as_dict);
    let mut features: Entries = get(rendered, "features")
        .and_then(PyVal::as_dict)
        .map(<[_]>::to_vec)
        .unwrap_or_default();
    let had_features = get(rendered, "features").is_some();
    for key in HOOK_FEATURES {
        match before.and_then(|before| get(before, key)) {
            Some(value) => set(&mut features, key, value.clone()),
            None => {
                pop(&mut features, key);
            }
        }
    }
    if features.is_empty() && before.is_none() {
        pop(rendered, "features");
    } else if had_features || !features.is_empty() {
        set(rendered, "features", PyVal::Dict(features));
    }
}

fn restore_proxied_servers(rendered: &mut Entries, backup: &Entries) {
    let before = get(backup, "mcp_servers").and_then(PyVal::as_dict);
    let Some(PyVal::Dict(servers)) = rendered
        .iter_mut()
        .find_map(|(name, value)| (name == "mcp_servers").then_some(value))
    else {
        return;
    };
    let proxied: Vec<String> = servers
        .iter()
        .filter(|(_, server)| launches_through_guard(server))
        .map(|(name, _)| name.clone())
        .collect();
    if proxied.is_empty() {
        return;
    }
    for name in &proxied {
        match before.and_then(|before| get(before, name)) {
            Some(entry) if !launches_through_guard(entry) => set(servers, name, entry.clone()),
            _ => {
                pop(servers, name);
            }
        }
    }
    if servers.is_empty() && before.is_none_or(<[_]>::is_empty) {
        pop(rendered, "mcp_servers");
    }
}

fn launches_through_guard(server: &PyVal) -> bool {
    let Some(server) = server.as_dict() else {
        return false;
    };
    let args: Vec<String> = get(server, "args")
        .and_then(PyVal::as_list)
        .unwrap_or_default()
        .iter()
        .filter_map(|arg| arg.as_str().map(str::to_owned))
        .collect();
    is_guard_proxy(get(server, "command").and_then(PyVal::as_str), &args)
}

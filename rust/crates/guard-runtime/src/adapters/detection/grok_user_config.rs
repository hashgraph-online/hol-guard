//! `runner_authority` kind `grok_user_config`: the format-preserving merge of
//! Guard's protection settings into Grok's user `config.toml`. It adds the
//! managed deny rules, turns off the Claude and Cursor hook compatibility
//! shims and installs one catch-all hook per event, owning only what it adds:
//! the ownership record (`added_*`, `created_keys`, `prior_compat_hooks`) tells
//! a later merge or removal exactly what to take back. Python reads and writes
//! the file and decides which owned hooks of other Guard clients are stale
//! (`candidates`, then `merge` with the stale `retired_commands`).
//!
//! `grok_toml_engine` reproduces tomlkit's bytes for the common layout; a
//! config laid out differently is merged by `grok_toml_semantic` with the same
//! meaning and tomlkit-independent formatting. Both results are re-parsed and
//! must equal the intended document, or the merge is refused.

use serde_json::{json, Map, Value};
use toml::{Table, Value as Toml};

pub(crate) const MANAGED_DENY_RULES: [&str; 14] = [
    "Bash(hol-guard apps disconnect grok*)",
    "Bash(hol-guard apps uninstall*)",
    "Bash(rm -rf **/.grok/hooks/hol-guard*)",
    "Edit(**/.grok/hooks/hol-guard*)",
    "Edit(**/.grok/managed_config.toml)",
    "Edit(**/.grok/config.toml)",
    "Read(**/.grok/auth/**)",
    "Read(**/.grok/auth.json)",
    "Read(**/.env)",
    "Read(**/.npmrc)",
    "Read(**/.ssh/**)",
    "Read(**/.hol-guard/secrets/**)",
    "Read(**/.hol-guard/totp-secrets/**)",
    "Read(**/.hol-guard/daemon-auth-token)",
];
pub(crate) const FOREIGN_HOOK_COMPAT_VENDORS: [&str; 2] = ["claude", "cursor"];
pub(crate) const PRETOOL_HOOK_EVENT: &str = "PreToolUse";
pub(crate) const OBSERVE_HOOK_EVENTS: [&str; 3] =
    ["UserPromptSubmit", "SubagentStart", "SessionStart"];
pub(crate) const GROK_PRETOOL_HOOK_TIMEOUT_SECONDS: i64 = 90;
pub(crate) const OBSERVE_HOOK_TIMEOUT_SECONDS: i64 = 15;

/// Why an edit stopped: the layout is outside what one editor handles, the
/// edited text no longer parses to the intended document, or the settings
/// themselves are unusable (the message is the one Python raises).
pub(crate) enum Fail {
    Unsupported,
    Mismatch,
    Error(String),
}

pub(crate) type Res<T> = Result<T, Fail>;

fn refuse<T>(message: impl Into<String>) -> Res<T> {
    Err(Fail::Error(message.into()))
}

/// One way of applying the merge steps to a document: `sem` is the parsed
/// meaning the steps decide from, the other methods change the text to match.
pub(crate) trait Editor {
    fn sem(&self) -> &Table;
    fn sem_mut(&mut self) -> &mut Table;
    fn text(&self) -> String;
    fn deny_remove(&mut self, index: usize) -> Res<()>;
    fn hook_remove(&mut self, event: &str, index: usize) -> Res<()>;
    fn compat_set(&mut self, vendor: &str, value: bool) -> Res<()>;
    fn compat_unset(&mut self, vendor: &str) -> Res<()>;
    fn pop(&mut self, path: &[&str]) -> Res<()>;
    fn permission_new(&mut self) -> Res<()>;
    fn deny_new(&mut self) -> Res<()>;
    fn deny_append(&mut self, rule: &str) -> Res<()>;
    fn compat_table_new(&mut self, vendor: &str) -> Res<()>;
    fn compat_hooks_new(&mut self, vendor: &str) -> Res<()>;
    fn hook_add(&mut self, event: &str, command: &str, timeout: i64, created: bool) -> Res<()>;
}

fn events() -> impl Iterator<Item = &'static str> {
    std::iter::once(PRETOOL_HOOK_EVENT).chain(OBSERVE_HOOK_EVENTS)
}

fn only_handler(group: &Toml) -> Option<&Table> {
    let [handler] = group.as_table()?.get("hooks")?.as_array()?.as_slice() else {
        return None;
    };
    handler.as_table()
}

/// `_owned_hook`: a catch-all group whose single handler runs `command`.
fn owned(group: &Toml, command: &str) -> bool {
    let matcher_ok = match group.get("matcher") {
        None => true,
        Some(Toml::String(text)) => text.is_empty(),
        Some(_) => false,
    };
    let Some(handler) = only_handler(group) else {
        return false;
    };
    !command.is_empty()
        && matcher_ok
        && handler.get("type").and_then(Toml::as_str) == Some("command")
        && handler.get("command").and_then(Toml::as_str) == Some(command)
}

fn deny(sem: &Table) -> Option<&Vec<Toml>> {
    sem.get("permission")?.get("deny")?.as_array()
}

fn groups<'a>(sem: &'a Table, event: &str) -> Option<&'a Vec<Toml>> {
    sem.get("hooks")?.get(event)?.as_array()
}

fn table_mut<'a>(sem: &'a mut Table, key: &str) -> Option<&'a mut Table> {
    sem.get_mut(key)?.as_table_mut()
}

fn rules() -> Toml {
    Toml::Array(
        MANAGED_DENY_RULES
            .iter()
            .map(|rule| Toml::String(rule.to_string()))
            .collect(),
    )
}

fn hooks_flag(sem: &mut Table, vendor: &str, value: Option<bool>) {
    let Some(vendor_table) = table_mut(sem, "compat").and_then(|compat| table_mut(compat, vendor))
    else {
        return;
    };
    match value {
        Some(flag) => vendor_table.insert("hooks".to_string(), Toml::Boolean(flag)),
        None => vendor_table.remove("hooks"),
    };
}

fn owned_key(key: &str) -> bool {
    match key.split_once('.') {
        None => matches!(key, "permission" | "compat" | "hooks"),
        Some(("permission", "deny")) => true,
        Some(("compat", vendor)) => FOREIGN_HOOK_COMPAT_VENDORS.contains(&vendor),
        Some(("hooks", event)) => events().any(|known| known == event),
        Some(_) => false,
    }
}

/// `_remove_owned`: take back what the ownership record says Guard added.
pub(crate) fn remove_owned<E: Editor>(ed: &mut E, state: &Value) -> Res<()> {
    let added = state.get("added_deny_rules").and_then(Value::as_array);
    for rule in added.into_iter().flatten().filter_map(Value::as_str) {
        let at = deny(ed.sem())
            .and_then(|list| list.iter().position(|item| item.as_str() == Some(rule)));
        if let Some(index) = at {
            ed.deny_remove(index)?;
            if let Some(list) = table_mut(ed.sem_mut(), "permission")
                .and_then(|permission| permission.get_mut("deny"))
                .and_then(Toml::as_array_mut)
            {
                list.remove(index);
            }
        }
    }
    let command = state.get("hook_command").and_then(Value::as_str);
    let owned_events = state.get("added_hook_events").and_then(Value::as_array);
    if let (Some(command), Some(owned_events)) = (command, owned_events) {
        for event in owned_events.iter().filter_map(Value::as_str) {
            let at = groups(ed.sem(), event)
                .and_then(|list| list.iter().position(|group| owned(group, command)));
            if let Some(index) = at {
                ed.hook_remove(event, index)?;
                remove_group(ed.sem_mut(), event, index);
            }
        }
    }
    if let Some(prior) = state.get("prior_compat_hooks").and_then(Value::as_object) {
        for vendor in FOREIGN_HOOK_COMPAT_VENDORS {
            let now = ed
                .sem()
                .get("compat")
                .and_then(|c| c.get(vendor))
                .and_then(|t| t.get("hooks"));
            if now.and_then(Toml::as_bool) != Some(false) {
                continue;
            }
            match prior.get(vendor) {
                Some(Value::Bool(flag)) => {
                    ed.compat_set(vendor, *flag)?;
                    hooks_flag(ed.sem_mut(), vendor, Some(*flag));
                }
                Some(Value::Null) => {
                    ed.compat_unset(vendor)?;
                    hooks_flag(ed.sem_mut(), vendor, None);
                }
                _ => {}
            }
        }
    }
    let created = state.get("created_keys").and_then(Value::as_array);
    for key in created
        .into_iter()
        .flatten()
        .rev()
        .filter_map(Value::as_str)
        .filter(|key| owned_key(key))
    {
        let path: Vec<&str> = key.split('.').collect();
        let slot = match path.as_slice() {
            [name] => ed.sem().get(*name),
            [parent, name] => ed.sem().get(*parent).and_then(|table| table.get(*name)),
            _ => None,
        };
        let empty = match slot {
            Some(Toml::Table(table)) => table.is_empty(),
            Some(Toml::Array(list)) => list.is_empty(),
            _ => false,
        };
        if empty {
            ed.pop(&path)?;
            match path.as_slice() {
                [name] => ed.sem_mut().remove(*name),
                [parent, name] => {
                    table_mut(ed.sem_mut(), parent).and_then(|table| table.remove(*name))
                }
                _ => None,
            };
        }
    }
    Ok(())
}

fn remove_group(sem: &mut Table, event: &str, index: usize) {
    if let Some(list) = table_mut(sem, "hooks")
        .and_then(|hooks| hooks.get_mut(event))
        .and_then(Toml::as_array_mut)
    {
        list.remove(index);
    }
}

/// Drop the owned groups of the clients Python reported as gone.
fn retire<E: Editor>(ed: &mut E, retired: &[String]) -> Res<()> {
    for event in events() {
        let count = groups(ed.sem(), event).map_or(0, Vec::len);
        for index in (0..count).rev() {
            let stale = groups(ed.sem(), event)
                .and_then(|list| list.get(index))
                .is_some_and(|group| {
                    let command = only_handler(group)
                        .and_then(|h| h.get("command"))
                        .and_then(Toml::as_str);
                    command.is_some_and(|c| owned(group, c) && retired.iter().any(|gone| gone == c))
                });
            if stale {
                ed.hook_remove(event, index)?;
                remove_group(ed.sem_mut(), event, index);
            }
        }
    }
    Ok(())
}

pub(crate) fn candidates(sem: &Table) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for event in events() {
        for group in groups(sem, event).into_iter().flatten() {
            let command = only_handler(group)
                .and_then(|h| h.get("command"))
                .and_then(Toml::as_str);
            if let Some(command) = command.filter(|c| owned(group, c)) {
                found.push(command.to_string());
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

fn expect_table(sem: &Table, key: &str, message: &str) -> Res<()> {
    match sem.get(key) {
        Some(value) if !value.is_table() => refuse(message),
        _ => Ok(()),
    }
}

fn handler_group(command: &str, timeout: i64) -> Toml {
    let mut handler = Table::new();
    handler.insert("type".to_string(), Toml::String("command".to_string()));
    handler.insert("command".to_string(), Toml::String(command.to_string()));
    handler.insert("timeout".to_string(), Toml::Integer(timeout));
    let mut group = Table::new();
    group.insert("hooks".to_string(), Toml::Array(vec![Toml::Table(handler)]));
    Toml::Table(group)
}

fn prepare_permission<E: Editor>(ed: &mut E, created: &mut Vec<String>) -> Res<Vec<String>> {
    expect_table(
        ed.sem(),
        "permission",
        "Grok permission must be a TOML table.",
    )?;
    let all = || {
        MANAGED_DENY_RULES
            .iter()
            .map(|rule| rule.to_string())
            .collect::<Vec<_>>()
    };
    if ed.sem().get("permission").is_none() {
        created.push("permission.deny".to_string());
        let mut permission = Table::new();
        permission.insert("deny".to_string(), rules());
        ed.sem_mut()
            .insert("permission".to_string(), Toml::Table(permission));
        ed.permission_new()?;
        return Ok(all());
    }
    if ed
        .sem()
        .get("permission")
        .is_some_and(|permission| permission.get("deny").is_none())
    {
        created.push("permission.deny".to_string());
        if let Some(permission) = table_mut(ed.sem_mut(), "permission") {
            permission.insert("deny".to_string(), rules());
        }
        ed.deny_new()?;
        return Ok(all());
    }
    if !deny(ed.sem()).is_some_and(|list| list.iter().all(Toml::is_str)) {
        return refuse("Grok permission.deny must be an array of strings.");
    }
    let mut added = Vec::new();
    for rule in MANAGED_DENY_RULES {
        let present =
            deny(ed.sem()).is_some_and(|list| list.iter().any(|item| item.as_str() == Some(rule)));
        if !present {
            ed.deny_append(rule)?;
            if let Some(list) = table_mut(ed.sem_mut(), "permission")
                .and_then(|permission| permission.get_mut("deny"))
                .and_then(Toml::as_array_mut)
            {
                list.push(Toml::String(rule.to_string()));
            }
            added.push(rule.to_string());
        }
    }
    Ok(added)
}

fn prepare_compat<E: Editor>(ed: &mut E, created: &mut Vec<String>) -> Res<Map<String, Value>> {
    expect_table(ed.sem(), "compat", "Grok compat must be a TOML table.")?;
    if ed.sem().get("compat").is_none() {
        ed.sem_mut()
            .insert("compat".to_string(), Toml::Table(Table::new()));
    }
    let mut prior = Map::new();
    for vendor in FOREIGN_HOOK_COMPAT_VENDORS {
        let entry = ed.sem().get("compat").and_then(|compat| compat.get(vendor));
        if entry.is_none() {
            created.push(format!("compat.{vendor}"));
        }
        if entry.is_some_and(|value| !value.is_table()) {
            return refuse(format!("Grok {vendor} must be a TOML table."));
        }
        let previous = entry.and_then(|table| table.get("hooks"));
        if previous.is_some_and(|value| !value.is_bool()) {
            return refuse("Grok compat hooks must be boolean.");
        }
        let previous = previous.and_then(Toml::as_bool);
        prior.insert(
            vendor.to_string(),
            previous.map_or(Value::Null, Value::Bool),
        );
        let known = entry.is_some();
        if !known {
            let mut table = Table::new();
            table.insert("hooks".to_string(), Toml::Boolean(false));
            if let Some(compat) = table_mut(ed.sem_mut(), "compat") {
                compat.insert(vendor.to_string(), Toml::Table(table));
            }
            ed.compat_table_new(vendor)?;
        } else if previous.is_none() {
            hooks_flag(ed.sem_mut(), vendor, Some(false));
            ed.compat_hooks_new(vendor)?;
        } else if previous == Some(true) {
            ed.compat_set(vendor, false)?;
            hooks_flag(ed.sem_mut(), vendor, Some(false));
        }
    }
    Ok(prior)
}

fn prepare_hooks<E: Editor>(
    ed: &mut E,
    command: &str,
    created: &mut Vec<String>,
) -> Res<Vec<String>> {
    expect_table(ed.sem(), "hooks", "Grok hooks must be a TOML table.")?;
    if ed.sem().get("hooks").is_none() {
        ed.sem_mut()
            .insert("hooks".to_string(), Toml::Table(Table::new()));
    }
    let mut added = Vec::new();
    for event in events() {
        if groups(ed.sem(), event).is_none() {
            if ed
                .sem()
                .get("hooks")
                .is_some_and(|hooks| hooks.get(event).is_some())
            {
                return refuse(format!("Grok hooks.{event} must be an array of tables."));
            }
            created.push(format!("hooks.{event}"));
            if let Some(hooks) = table_mut(ed.sem_mut(), "hooks") {
                hooks.insert(event.to_string(), Toml::Array(Vec::new()));
            }
        }
        if groups(ed.sem(), event)
            .is_some_and(|list| list.iter().any(|group| owned(group, command)))
        {
            continue;
        }
        let timeout = if event == PRETOOL_HOOK_EVENT {
            GROK_PRETOOL_HOOK_TIMEOUT_SECONDS
        } else {
            OBSERVE_HOOK_TIMEOUT_SECONDS
        };
        ed.hook_add(
            event,
            command,
            timeout,
            created.contains(&format!("hooks.{event}")),
        )?;
        if let Some(list) = table_mut(ed.sem_mut(), "hooks")
            .and_then(|hooks| hooks.get_mut(event))
            .and_then(Toml::as_array_mut)
        {
            list.push(handler_group(command, timeout));
        }
        added.push(event.to_string());
    }
    Ok(added)
}

/// `prepare_user_config_text` without the retire scan; returns the new ownership record.
pub(crate) fn prepare<E: Editor>(
    ed: &mut E,
    command: &str,
    state: &Value,
    retired: &[String],
) -> Res<Value> {
    remove_owned(ed, state)?;
    retire(ed, retired)?;
    let mut created: Vec<String> = ["permission", "compat", "hooks"]
        .iter()
        .filter(|key| !ed.sem().contains_key(**key))
        .map(|key| key.to_string())
        .collect();
    let added_deny_rules = prepare_permission(ed, &mut created)?;
    let prior = prepare_compat(ed, &mut created)?;
    let added_hook_events = prepare_hooks(ed, command, &mut created)?;
    Ok(json!({
        "added_deny_rules": added_deny_rules,
        "added_hook_events": added_hook_events,
        "hook_command": command,
        "prior_compat_hooks": prior,
        "created_keys": created,
    }))
}

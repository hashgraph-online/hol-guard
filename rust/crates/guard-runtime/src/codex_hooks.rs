//! `codex_hook_inventory.py`: the complete typed inventory of the executable
//! hooks one Codex JSON or TOML source configures, with the exact issue
//! messages Guard reports for shapes it cannot model.

use serde_json::Value;

use super::codex_identity::{command_argv, hook_identity};
use super::codex_value::{equals_json, HookVal};
use super::context_digest::python_strip;

const UNSUPPORTED_EVENT: &str = "codex_hook_inventory_unsupported_event_shape";
const MALFORMED_GROUP: &str = "codex_hook_inventory_malformed_group";
const MALFORMED_HANDLER: &str = "codex_hook_inventory_malformed_handler";
const UNKNOWN_HANDLER: &str = "codex_hook_inventory_unknown_handler_type";

#[derive(Clone, Copy)]
pub(crate) struct Source<'a> {
    pub(crate) path: &'a str,
    pub(crate) scope: &'a str,
    /// `"json"` or `"toml"`.
    pub(crate) format: &'static str,
    pub(crate) hooks_enabled: bool,
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Ownership {
    AuthenticatedManifest,
    ExactLegacyAdoption,
    Unmanaged,
}

pub(crate) struct Record {
    pub(crate) source_path: String,
    pub(crate) source_scope: String,
    pub(crate) source_format: &'static str,
    pub(crate) source_hooks_enabled: bool,
    pub(crate) event_name: String,
    pub(crate) group_index: usize,
    pub(crate) matcher: Option<String>,
    pub(crate) handler_index: usize,
    pub(crate) handler_type: Option<String>,
    pub(crate) command: Option<String>,
    pub(crate) command_argv: Option<Vec<String>>,
    pub(crate) timeout: Option<HookVal>,
    pub(crate) environment_keys: Vec<String>,
    pub(crate) active: bool,
    pub(crate) executable: bool,
    pub(crate) ownership: Ownership,
    pub(crate) canonical_identity: String,
    /// The hook holds text CPython cannot encode, so its identity does not exist.
    pub(crate) unencodable: bool,
}

impl Record {
    pub(crate) fn coordinate(&self) -> String {
        format!(
            "{}/group[{}]/handler[{}]",
            self.event_name, self.group_index, self.handler_index
        )
    }
}

struct Issue {
    reason_code: &'static str,
    message: &'static str,
    event_name: Option<String>,
    group_index: Option<usize>,
    handler_index: Option<usize>,
}

impl Issue {
    fn warning(&self, source_path: &str) -> String {
        let mut coordinate = match &self.event_name {
            None => source_path.to_owned(),
            Some(event) => event.clone(),
        };
        if self.event_name.is_some() {
            if let Some(group) = self.group_index {
                coordinate.push_str(&format!("/group[{group}]"));
            }
            if let Some(handler) = self.handler_index {
                coordinate.push_str(&format!("/handler[{handler}]"));
            }
        }
        format!(
            "{}: {coordinate} in {source_path}. {}",
            self.reason_code, self.message
        )
    }
}

pub(crate) struct Inventory {
    pub(crate) records: Vec<Record>,
    pub(crate) warnings: Vec<String>,
}

/// `enumerate_codex_hooks`: every event, group and handler in the source.
pub(crate) fn enumerate(
    payload: &HookVal,
    source: Source<'_>,
    authenticated: &[Value],
    legacy: &[Value],
) -> Inventory {
    let mut records = Vec::new();
    let mut issues = Vec::new();
    let hooks = payload.field("hooks");
    match hooks {
        None => {}
        Some(HookVal::Dict(events)) => {
            for (event_name, groups) in events {
                if is_state_metadata(event_name, groups, source.format) {
                    continue;
                }
                walk_event(
                    event_name,
                    groups,
                    source,
                    authenticated,
                    legacy,
                    &mut records,
                    &mut issues,
                );
            }
        }
        Some(_) => issues.push(Issue {
            reason_code: UNSUPPORTED_EVENT,
            message: "Codex hooks must be an event table. Repair the hook configuration before retrying install.",
            event_name: None,
            group_index: None,
            handler_index: None,
        }),
    }
    Inventory {
        records,
        warnings: issues
            .iter()
            .map(|issue| issue.warning(source.path))
            .collect(),
    }
}

fn group_issue(message: &'static str, event: &str, group: usize) -> Issue {
    Issue {
        reason_code: MALFORMED_GROUP,
        message,
        event_name: Some(event.to_owned()),
        group_index: Some(group),
        handler_index: None,
    }
}

fn handler_issue(
    reason_code: &'static str,
    message: &'static str,
    event: &str,
    group: usize,
    handler: usize,
) -> Issue {
    Issue {
        reason_code,
        message,
        event_name: Some(event.to_owned()),
        group_index: Some(group),
        handler_index: Some(handler),
    }
}

fn walk_event(
    event_name: &str,
    groups: &HookVal,
    source: Source<'_>,
    authenticated: &[Value],
    legacy: &[Value],
    records: &mut Vec<Record>,
    issues: &mut Vec<Issue>,
) {
    let Some(groups) = groups.as_list() else {
        issues.push(Issue {
            reason_code: UNSUPPORTED_EVENT,
            message: "Each Codex hook event must contain a list of matcher groups. Repair the event shape before retrying install.",
            event_name: Some(event_name.to_owned()),
            group_index: None,
            handler_index: None,
        });
        return;
    };
    for (group_index, group) in groups.iter().enumerate() {
        let HookVal::Dict(entries) = group else {
            issues.push(group_issue(
                "Each Codex hook matcher group must be an object. Repair the group before retrying install.",
                event_name,
                group_index,
            ));
            continue;
        };
        let matcher_ok = matches!(
            group.get("matcher"),
            None | Some(HookVal::Str(_) | HookVal::Null)
        );
        if !activation_fields_are_valid(group) || !matcher_ok {
            issues.push(group_issue(
                "A Codex hook matcher and activation fields must use supported scalar types. Repair the group before retrying install.",
                event_name,
                group_index,
            ));
        }
        let handlers = match group.get("hooks") {
            None | Some(HookVal::Null) => continue,
            Some(HookVal::List(handlers)) => handlers,
            Some(_) => {
                issues.push(group_issue(
                    "A Codex hook group's handlers must be a list. Repair the group before retrying install.",
                    event_name,
                    group_index,
                ));
                continue;
            }
        };
        let group_active = entry_is_active(group);
        for (handler_index, handler) in handlers.iter().enumerate() {
            let at = Coordinate {
                event: event_name,
                group: group_index,
                handler: handler_index,
            };
            let context = Context {
                source,
                authenticated,
                legacy,
                group,
                group_entries: entries,
                group_active,
            };
            if let Some(record) = handler_record(handler, &at, &context, issues) {
                records.push(record);
            }
        }
    }
}

struct Coordinate<'a> {
    event: &'a str,
    group: usize,
    handler: usize,
}

struct Context<'a> {
    source: Source<'a>,
    authenticated: &'a [Value],
    legacy: &'a [Value],
    group: &'a HookVal,
    group_entries: &'a [(String, HookVal)],
    group_active: bool,
}

fn handler_record(
    handler: &HookVal,
    at: &Coordinate<'_>,
    context: &Context<'_>,
    issues: &mut Vec<Issue>,
) -> Option<Record> {
    let HookVal::Dict(handler_entries) = handler else {
        issues.push(handler_issue(
            MALFORMED_HANDLER,
            "Each Codex hook handler must be an object. Repair the handler before retrying install.",
            at.event,
            at.group,
            at.handler,
        ));
        return None;
    };
    let nonblank = |value: Option<&HookVal>| {
        value
            .and_then(HookVal::as_str)
            .filter(|text| !python_strip(text).is_empty())
            .map(str::to_owned)
    };
    let handler_type = nonblank(handler.get("type"));
    let raw_command = handler.field("command");
    let command = nonblank(handler.get("command"));
    let executable = raw_command.is_some() || handler_type.as_deref() == Some("command");
    let mut push = |code, message| {
        issues.push(handler_issue(code, message, at.event, at.group, at.handler));
    };
    if !activation_fields_are_valid(handler) {
        push(
            MALFORMED_HANDLER,
            "Codex hook activation fields must be booleans. Repair the handler before retrying install.",
        );
    }
    if executable && command.is_none() {
        push(
            MALFORMED_HANDLER,
            "An executable Codex command hook must contain a non-empty string command. Repair the handler before retrying install.",
        );
    }
    if !matches!(handler_type.as_deref(), None | Some("command")) {
        push(
            UNKNOWN_HANDLER,
            "Guard found an executable Codex hook type it cannot model. Remove or convert the handler to a supported command hook before retrying install.",
        );
    }
    let timeout = timeout(handler.get("timeout"));
    if handler.field("timeout").is_some() && timeout.is_none() && executable {
        push(
            MALFORMED_HANDLER,
            "An executable Codex hook timeout must be a finite non-negative number. Repair the handler before retrying install.",
        );
    }
    let (environment_keys, environment_valid) = environment_keys(handler);
    if !environment_valid && executable {
        push(
            MALFORMED_HANDLER,
            "An executable Codex hook environment must be a string-keyed object. Repair the handler before retrying install.",
        );
    }
    let ownership = ownership(at.event, context, handler);
    let matcher = context
        .group
        .get("matcher")
        .and_then(HookVal::as_str)
        .map(str::to_owned);
    let identity = hook_identity(
        context.source.scope,
        context.source.hooks_enabled,
        at.event,
        context.group_entries,
        handler_entries,
    );
    let unencodable = identity.is_none();
    let canonical_identity = identity.unwrap_or_default();
    Some(Record {
        source_path: context.source.path.to_owned(),
        source_scope: context.source.scope.to_owned(),
        source_format: context.source.format,
        source_hooks_enabled: context.source.hooks_enabled,
        event_name: at.event.to_owned(),
        group_index: at.group,
        matcher,
        handler_index: at.handler,
        handler_type,
        command_argv: command_argv(command.as_deref()),
        command,
        timeout,
        environment_keys,
        active: context.group_active && entry_is_active(handler),
        executable,
        ownership,
        canonical_identity,
        unencodable,
    })
}

/// `_is_codex_hook_state_metadata`: Codex's reserved TOML `hooks.state` table.
fn is_state_metadata(event_name: &str, value: &HookVal, format: &str) -> bool {
    let HookVal::Dict(states) = value else {
        return false;
    };
    format == "toml"
        && event_name == "state"
        && states.iter().all(|(_, entry)| {
            let HookVal::Dict(fields) = entry else {
                return false;
            };
            fields
                .iter()
                .all(|(key, _)| key == "trusted_hash" || key == "enabled")
                && entry.get("trusted_hash").is_some_and(is_trusted_hash)
                && entry
                    .get("enabled")
                    .is_none_or(|flag| matches!(flag, HookVal::Bool(_)))
        })
}

fn is_trusted_hash(value: &HookVal) -> bool {
    value.as_str().is_some_and(|text| {
        text.strip_prefix("sha256:").is_some_and(|digits| {
            digits.len() == 64 && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    })
}

/// `enabled is not False and disabled is not True`.
fn entry_is_active(entry: &HookVal) -> bool {
    entry.get("enabled") != Some(&HookVal::Bool(false))
        && entry.get("disabled") != Some(&HookVal::Bool(true))
}

fn activation_fields_are_valid(entry: &HookVal) -> bool {
    ["enabled", "disabled"].iter().all(|key| {
        entry
            .get(key)
            .is_none_or(|value| matches!(value, HookVal::Bool(_)))
    })
}

fn has_key(entry: &HookVal, key: &str) -> bool {
    entry
        .as_dict()
        .is_some_and(|entries| entries.iter().any(|(name, _)| name == key))
}

/// `_timeout`: a finite, non-negative number that is not a boolean.
fn timeout(value: Option<&HookVal>) -> Option<HookVal> {
    match value? {
        HookVal::Int(digits) if !digits.starts_with('-') => Some(HookVal::Int(digits.clone())),
        HookVal::Float(number) if number.is_finite() && *number >= 0.0 => {
            Some(HookVal::Float(*number))
        }
        _ => None,
    }
}

/// `_environment_keys`: the sorted keys, and whether the shape is valid.
fn environment_keys(handler: &HookVal) -> (Vec<String>, bool) {
    let raw = if has_key(handler, "env") {
        handler.get("env")
    } else {
        handler.get("environment")
    };
    match raw {
        None | Some(HookVal::Null) => (Vec::new(), true),
        Some(HookVal::Dict(entries))
            if entries
                .iter()
                .all(|(_, value)| matches!(value, HookVal::Str(_))) =>
        {
            let mut keys: Vec<String> = entries.iter().map(|(key, _)| key.clone()).collect();
            keys.sort();
            (keys, true)
        }
        Some(_) => (Vec::new(), false),
    }
}

fn ownership(event_name: &str, context: &Context<'_>, handler: &HookVal) -> Ownership {
    if bindings_contain(context.authenticated, event_name, context.group, handler) {
        Ownership::AuthenticatedManifest
    } else if bindings_contain(context.legacy, event_name, context.group, handler) {
        Ownership::ExactLegacyAdoption
    } else {
        Ownership::Unmanaged
    }
}

/// `_bindings_contain_handler`.
fn bindings_contain(
    bindings: &[Value],
    event_name: &str,
    group: &HookVal,
    handler: &HookVal,
) -> bool {
    let null = HookVal::Null;
    let matcher = group.get("matcher").unwrap_or(&null);
    bindings.iter().any(|binding| {
        let expected_group = binding.get("group").and_then(Value::as_object);
        binding.get("event").and_then(Value::as_str) == Some(event_name)
            && expected_group.is_some_and(|expected| equals_json(matcher, expected.get("matcher")))
            && equals_json(handler, binding.get("handler"))
    })
}

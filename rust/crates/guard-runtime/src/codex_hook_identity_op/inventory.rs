//! `inventory` entries: the complete hook walk of one Codex source.
//!
//! The install path needs every handler a source configures, the shapes it
//! cannot model, which authority owns each handler, and each handler's
//! identity. The walk that answers all of that is the one native detection
//! already runs, so an install reads the same inventory detection does
//! instead of a second walk kept in step with it by hand.
//!
//! The source's events travel as `[name, groups]` pairs in the order the
//! source file wrote them, since that order decides which record and which
//! issue a caller sees first. Scalars JSON cannot carry arrive as the
//! request's `scalar_tokens`, exactly as a handler question's do.

use std::collections::BTreeMap;

use guard_contracts::CodexHookIdentityEntryV1;
use serde_json::{json, Value};

use crate::codex_hooks::{walk, Bindings, Issue, Ownership, Record, Source};
use crate::codex_value::{token_value, HookVal};
use crate::pyjson::float_repr;

/// Whether an inventory entry names a source format and carries only tokens
/// the request defined.
pub(super) fn well_formed(
    entry: &CodexHookIdentityEntryV1,
    tokens: &BTreeMap<String, Value>,
) -> bool {
    source_format(entry).is_some()
        && entry
            .events
            .iter()
            .flatten()
            .all(|(_, groups)| decode(groups, tokens).is_some())
}

/// The source's records and issues, or `{"records": null}` when a handler
/// holds text no identity can be derived over.
pub(super) fn answer(entry: &CodexHookIdentityEntryV1, tokens: &BTreeMap<String, Value>) -> Value {
    let Some(format) = source_format(entry) else {
        return json!({ "records": null });
    };
    let hooks = entry.events.as_ref().map(|events| {
        HookVal::Dict(
            events
                .iter()
                .map(|(name, groups)| {
                    (
                        name.clone(),
                        decode(groups, tokens).unwrap_or(HookVal::Null),
                    )
                })
                .collect(),
        )
    });
    // `events` absent means the source's `hooks` was present but not a table.
    let hooks = hooks.unwrap_or(HookVal::Null);
    let inventory = walk(
        Some(&hooks),
        Source {
            path: "",
            scope: &entry.source_scope,
            format,
            hooks_enabled: entry.source_hooks_enabled,
        },
        Bindings {
            authenticated: &entry.authenticated_bindings,
            legacy: &entry.legacy_bindings,
            self_bound: &entry.self_bindings,
            tokens,
        },
    );
    if inventory.records.iter().any(|record| record.unencodable) {
        return json!({ "records": null });
    }
    json!({
        "records": inventory.records.iter().map(record_json).collect::<Vec<_>>(),
        "issues": inventory.issues.iter().map(issue_json).collect::<Vec<_>>(),
    })
}

fn source_format(entry: &CodexHookIdentityEntryV1) -> Option<&'static str> {
    match entry.source_format.as_deref() {
        Some("json") => Some("json"),
        Some("toml") => Some("toml"),
        _ => None,
    }
}

/// A wire value as the source parser handed it to Python.
///
/// A number JSON spells as an integer is one; anything else it spells is a
/// float. A string the request lists as a token is the scalar it stands for,
/// and a token naming a scalar no Codex source can hold refuses the entry.
fn decode(value: &Value, tokens: &BTreeMap<String, Value>) -> Option<HookVal> {
    Some(match value {
        Value::Null => HookVal::Null,
        Value::Bool(flag) => HookVal::Bool(*flag),
        Value::Number(number) if number.is_i64() || number.is_u64() => {
            HookVal::Int(number.to_string())
        }
        Value::Number(number) => HookVal::Float(number.as_f64()?),
        Value::String(text) => match tokens.get(text) {
            Some(meaning) => token_value(meaning)?,
            None => HookVal::Str(text.clone()),
        },
        Value::Array(items) => HookVal::List(
            items
                .iter()
                .map(|item| decode(item, tokens))
                .collect::<Option<_>>()?,
        ),
        Value::Object(entries) => HookVal::Dict(
            entries
                .iter()
                .map(|(key, item)| Some((key.clone(), decode(item, tokens)?)))
                .collect::<Option<_>>()?,
        ),
    })
}

fn record_json(record: &Record) -> Value {
    json!({
        "event_name": record.event_name,
        "group_index": record.group_index,
        "handler_index": record.handler_index,
        "matcher": record.matcher,
        "handler_type": record.handler_type,
        "command": record.command,
        "command_argv": record.command_argv,
        "timeout": record.timeout.as_ref().and_then(number),
        "environment_keys": record.environment_keys,
        "active": record.active,
        "executable": record.executable,
        "ownership": ownership_name(record.ownership),
        "canonical_identity": record.canonical_identity,
    })
}

/// A timeout as the JSON number Python reads back as the same `int` or
/// `float`. The walk keeps only finite, non-negative ones.
fn number(value: &HookVal) -> Option<Value> {
    let text = match value {
        HookVal::Int(digits) => digits.clone(),
        HookVal::Float(number) if number.is_finite() => float_repr(*number),
        _ => return None,
    };
    serde_json::from_str(&text).ok()
}

fn issue_json(issue: &Issue) -> Value {
    json!({
        "reason_code": issue.reason_code,
        "message": issue.message,
        "event_name": issue.event_name,
        "group_index": issue.group_index,
        "handler_index": issue.handler_index,
    })
}

fn ownership_name(ownership: Ownership) -> &'static str {
    match ownership {
        Ownership::AuthenticatedManifest => "authenticated_manifest",
        Ownership::ExactLegacyAdoption => "exact_legacy_adoption",
        Ownership::SelfInstallBinding => "self_install_binding",
        Ownership::Unmanaged => "unmanaged",
    }
}

#[cfg(test)]
#[path = "inventory_tests.rs"]
mod tests;

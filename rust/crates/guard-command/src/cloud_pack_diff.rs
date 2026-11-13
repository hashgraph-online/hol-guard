//! What changed between two versions of a cloud action pack.
//!
//! A pack update is reviewed like a new pack whenever it widens what an action
//! may do: a new host or scope, a new action, a weaker effect or class, a
//! removed capability, a changed fact derivation or request, looser argument
//! bounds, more response data or looser safety limits. Changes that only
//! narrow, such as a removed action or a tighter bound, are listed but do not
//! need a new review. Anything this module cannot order, such as a rewritten
//! pattern, counts as widening.

use crate::cloud_action_v2::effect_rank;
use crate::cloud_pack::*;
use serde::Serialize;
use std::collections::BTreeMap;

pub const DIFF_SCHEMA: &str = "guard.cloud-action-pack-diff.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackChange {
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_id: Option<String>,
    /// The host, scope, argument, capability or field the change is about.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub widening: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackDiff {
    pub schema: &'static str,
    pub provider_id: String,
    pub widening: bool,
    pub changes: Vec<PackChange>,
}

struct Changes {
    action: Option<String>,
    list: Vec<PackChange>,
}

impl Changes {
    fn push(&mut self, code: &'static str, subject: Option<&str>, widening: bool) {
        self.list.push(PackChange {
            code,
            action_id: self.action.clone(),
            subject: subject.map(str::to_string),
            widening,
        });
    }

    fn when(&mut self, changed: bool, code: &'static str, subject: Option<&str>, widening: bool) {
        if changed {
            self.push(code, subject, widening);
        }
    }
}

/// Compare an installed pack with its proposed replacement.
pub fn diff(old: &CloudActionPack, new: &CloudActionPack) -> Result<PackDiff, PackError> {
    if old.provider.id != new.provider.id {
        return Err(PackError::new(
            "cloud_pack_provider_mismatch",
            "/provider/id",
        ));
    }
    let mut changes = Changes {
        action: None,
        list: Vec::new(),
    };
    for host in new.hosts.iter().filter(|host| !old.hosts.contains(host)) {
        changes.push("host_added", Some(host), true);
    }
    for host in old.hosts.iter().filter(|host| !new.hosts.contains(host)) {
        changes.push("host_removed", Some(host), false);
    }
    changes.when(
        old.auth.mode != new.auth.mode,
        "auth_mode_changed",
        None,
        true,
    );
    for scope in new.auth.scopes.difference(&old.auth.scopes) {
        changes.push("scope_added", Some(scope), true);
    }
    for scope in old.auth.scopes.difference(&new.auth.scopes) {
        changes.push("scope_removed", Some(scope), false);
    }
    changes.when(
        old.provider.publisher != new.provider.publisher,
        "publisher_changed",
        None,
        true,
    );
    changes.when(
        old.provider.name != new.provider.name,
        "name_changed",
        None,
        false,
    );
    let old_actions: BTreeMap<_, _> = old
        .actions
        .iter()
        .map(|a| (a.action_id.as_str(), a))
        .collect();
    let new_actions: BTreeMap<_, _> = new
        .actions
        .iter()
        .map(|a| (a.action_id.as_str(), a))
        .collect();
    for (id, action) in &new_actions {
        changes.action = Some((*id).to_string());
        match old_actions.get(id) {
            None => changes.push("action_added", None, true),
            Some(before) => compare_action(&mut changes, before, action),
        }
    }
    for id in old_actions
        .keys()
        .filter(|id| !new_actions.contains_key(*id))
    {
        changes.action = Some((*id).to_string());
        changes.push("action_removed", None, false);
    }
    Ok(PackDiff {
        schema: DIFF_SCHEMA,
        provider_id: new.provider.id.clone(),
        widening: changes.list.iter().any(|change| change.widening),
        changes: changes.list,
    })
}

fn compare_action(changes: &mut Changes, old: &PackAction, new: &PackAction) {
    changes.when(old.title != new.title, "title_changed", None, false);
    changes.when(old.link != new.link, "link_changed", None, true);
    changes.when(old.executor != new.executor, "executor_changed", None, true);
    compare_arguments(changes, &old.arguments, &new.arguments);
    let open_looser = match (&old.open_arguments, &new.open_arguments) {
        (None, Some(_)) => true,
        (Some(before), Some(after)) => after.max_bytes > before.max_bytes,
        _ => false,
    };
    if old.open_arguments != new.open_arguments {
        changes.push("open_arguments_changed", None, open_looser);
    }
    // Any class change can move the action into a different policy bucket.
    changes.when(
        old.facts.class != new.facts.class,
        "class_changed",
        None,
        true,
    );
    let mut old_rest = old.facts.clone();
    old_rest.class = new.facts.class;
    changes.when(old_rest != new.facts, "facts_changed", None, true);
    compare_response(changes, &old.response, &new.response);
    compare_safety(changes, &old.safety, &new.safety);
}

fn compare_arguments(
    changes: &mut Changes,
    old: &BTreeMap<String, ArgumentSpec>,
    new: &BTreeMap<String, ArgumentSpec>,
) {
    for (name, spec) in new {
        match old.get(name) {
            None => changes.push("argument_added", Some(name), true),
            Some(before) if before != spec => {
                let looser = argument_looser(before, spec);
                changes.push(
                    if looser {
                        "argument_loosened"
                    } else {
                        "argument_tightened"
                    },
                    Some(name),
                    looser,
                );
            }
            Some(_) => {}
        }
    }
    for name in old.keys().filter(|name| !new.contains_key(*name)) {
        changes.push("argument_removed", Some(name), false);
    }
}

/// Whether `new` accepts any value `old` refused. A change of type, pattern or
/// forbidden rule cannot be ordered and counts as looser.
fn argument_looser(old: &ArgumentSpec, new: &ArgumentSpec) -> bool {
    if old.required() && !new.required() {
        return true;
    }
    match (old, new) {
        (
            ArgumentSpec::Integer {
                minimum: lo,
                maximum: hi,
                ..
            },
            ArgumentSpec::Integer {
                minimum, maximum, ..
            },
        ) => minimum < lo || maximum > hi,
        (ArgumentSpec::Boolean { .. }, ArgumentSpec::Boolean { .. }) => false,
        (
            ArgumentSpec::Array {
                min_items: lo,
                max_items: hi,
                items: before,
                ..
            },
            ArgumentSpec::Array {
                min_items,
                max_items,
                items,
                ..
            },
        ) => min_items < lo || max_items > hi || text_looser(before, items),
        (
            ArgumentSpec::Json {
                max_bytes: before,
                max_items: hi,
                ..
            },
            ArgumentSpec::Json {
                max_bytes,
                max_items,
                ..
            },
        ) => max_bytes > before || items_looser(*hi, *max_items),
        (ArgumentSpec::String { .. }, ArgumentSpec::String { .. }) => {
            match (old.text_rule(), new.text_rule()) {
                (Some(before), Some(after)) => text_looser(&before, &after),
                _ => true,
            }
        }
        _ => true,
    }
}

/// An unbounded array (`None`) is looser than any bound.
fn items_looser(old: Option<u32>, new: Option<u32>) -> bool {
    match (old, new) {
        (Some(before), Some(after)) => after > before,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

fn text_looser(old: &TextRule, new: &TextRule) -> bool {
    new.max_length > old.max_length || old.pattern != new.pattern || old.forbidden != new.forbidden
}

fn compare_response(changes: &mut Changes, old: &ResponseSpec, new: &ResponseSpec) {
    changes.when(
        new.max_bytes > old.max_bytes,
        "response_limit_raised",
        None,
        true,
    );
    changes.when(
        new.max_bytes < old.max_bytes,
        "response_limit_lowered",
        None,
        false,
    );
    changes.when(
        new.empty_ok && !old.empty_ok,
        "response_empty_accepted",
        None,
        true,
    );
    changes.when(
        old.empty_ok && !new.empty_ok,
        "response_empty_refused",
        None,
        false,
    );
    compare_fields(changes, "", &old.fields, &new.fields);
}

fn compare_fields(
    changes: &mut Changes,
    prefix: &str,
    old: &[ResponseField],
    new: &[ResponseField],
) {
    for field in new {
        let path = format!("{prefix}{}", field.name);
        let Some(before) = old.iter().find(|before| before.name == field.name) else {
            changes.push("response_field_added", Some(&path), true);
            continue;
        };
        if before.untrusted && !field.untrusted || before.sensitivity != field.sensitivity {
            changes.push("response_label_changed", Some(&path), true);
        }
        match (&before.value, &field.value) {
            (
                FieldSource::List {
                    from: old_from,
                    max_items: old_max,
                    fields: old_fields,
                },
                FieldSource::List {
                    from,
                    max_items,
                    fields,
                },
            ) => {
                changes.when(
                    old_from != from,
                    "response_field_changed",
                    Some(&path),
                    true,
                );
                changes.when(
                    max_items > old_max,
                    "response_limit_raised",
                    Some(&path),
                    true,
                );
                changes.when(
                    max_items < old_max,
                    "response_limit_lowered",
                    Some(&path),
                    false,
                );
                compare_fields(changes, &format!("{path}."), old_fields, fields);
            }
            (
                FieldSource::Object {
                    from: old_from,
                    fields: old_fields,
                },
                FieldSource::Object { from, fields },
            ) => {
                changes.when(
                    old_from != from,
                    "response_field_changed",
                    Some(&path),
                    true,
                );
                compare_fields(changes, &format!("{path}."), old_fields, fields);
            }
            (before, after) => {
                changes.when(before != after, "response_field_changed", Some(&path), true)
            }
        }
    }
    for field in old
        .iter()
        .filter(|field| !new.iter().any(|after| after.name == field.name))
    {
        changes.push(
            "response_field_removed",
            Some(&format!("{prefix}{}", field.name)),
            false,
        );
    }
}

fn compare_safety(changes: &mut Changes, old: &Safety, new: &Safety) {
    let (before, after) = (effect_rank(old.effect), effect_rank(new.effect));
    changes.when(after < before, "effect_lowered", None, true);
    changes.when(after > before, "effect_raised", None, false);
    for capability in old
        .required_capabilities
        .difference(&new.required_capabilities)
    {
        changes.push("capability_removed", Some(capability.as_str()), true);
    }
    for capability in new
        .required_capabilities
        .difference(&old.required_capabilities)
    {
        changes.push("capability_added", Some(capability.as_str()), false);
    }
    changes.when(old.resource != new.resource, "resource_changed", None, true);
    changes.when(
        old.idempotency != new.idempotency,
        "idempotency_changed",
        None,
        true,
    );
    for scope in new.scopes.difference(&old.scopes) {
        changes.push("action_scope_added", Some(scope), true);
    }
    for scope in old.scopes.difference(&new.scopes) {
        changes.push("action_scope_removed", Some(scope), false);
    }
    let looser = new.max_items > old.max_items
        || new.min_interval_ms < old.min_interval_ms
        || new.timeout_ms > old.timeout_ms;
    let tighter = new.max_items < old.max_items
        || new.min_interval_ms > old.min_interval_ms
        || new.timeout_ms < old.timeout_ms;
    changes.when(looser, "limits_loosened", None, true);
    changes.when(tighter && !looser, "limits_tightened", None, false);
}

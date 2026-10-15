//! Portable policy-change semantics; textual rendering remains presentation.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use serde_json::{json, Value};

type Fields = BTreeMap<String, BTreeSet<String>>;
type Rules<'a> = BTreeMap<String, &'a Value>;

fn rules(document: &Value) -> Result<Rules<'_>, &'static str> {
    let values = document["spec"]["rules"]
        .as_array()
        .ok_or("policy_document_shape")?;
    let mut result = BTreeMap::new();
    for rule in values {
        let id = rule["id"].as_str().ok_or("policy_document_shape")?;
        if !rule["enabled"].is_boolean() || !rule["effect"].is_string() {
            return Err("policy_document_shape");
        }
        result.insert(id.to_owned(), rule);
    }
    Ok(result)
}

fn fields(rule: &Value) -> Result<Fields, &'static str> {
    let values = rule["match"].as_object().ok_or("policy_document_shape")?;
    let mut result = BTreeMap::new();
    for (key, value) in values {
        if super::MATCH_FIELDS.contains(&key.as_str()) {
            if let Some(items) = value.as_array().filter(|items| !items.is_empty()) {
                let items = items
                    .iter()
                    .map(|item| {
                        item.as_str()
                            .map(str::to_owned)
                            .ok_or("policy_document_shape")
                    })
                    .collect::<Result<_, _>>()?;
                result.insert(key.clone(), items);
            }
        }
    }
    Ok(result)
}

fn contains(container: &Fields, contained: &Fields) -> bool {
    container.iter().all(|(key, values)| {
        contained
            .get(key)
            .is_some_and(|inner| values.is_superset(inner))
    })
}

fn overlap(left: &Fields, right: &Fields) -> bool {
    left.iter().all(|(key, values)| {
        right
            .get(key)
            .is_none_or(|other| !values.is_disjoint(other))
    })
}

fn expiry(value: &str) -> (String, String) {
    let value = value.strip_suffix('Z').unwrap_or(value);
    let (seconds, fraction) = value.split_once('.').unwrap_or((value, ""));
    let mut fraction = fraction.to_owned();
    while fraction.len() < 9 {
        fraction.push('0');
    }
    (seconds.to_owned(), fraction)
}

fn relaxed_lifetime(previous: &Value, current: &Value) -> bool {
    let before = &previous["lifetime"];
    let after = &current["lifetime"];
    if before == after {
        return false;
    }
    if before["mode"] == "permanent" {
        return after["mode"] != "permanent";
    }
    if after["mode"] == "permanent" {
        return false;
    }
    if before["mode"] != after["mode"] {
        return true;
    }
    match (before["expiresAt"].as_str(), after["expiresAt"].as_str()) {
        (None, current) => current.is_some(),
        (_, None) => false,
        (Some(previous), Some(current)) => expiry(current) < expiry(previous),
    }
}

fn strength(value: &Value) -> Option<u8> {
    match value.as_str()? {
        "allow" | "ignore" | "observe" => Some(0),
        "warn" | "review" | "prompt" => Some(1),
        "require-reapproval" => Some(2),
        "block" | "enforce" => Some(3),
        _ => None,
    }
}

fn shown(value: Option<&Value>) -> String {
    value.map_or_else(|| "None".into(), super::text)
}

fn enabled(rule: &Value) -> bool {
    rule["enabled"] == true
}
fn restrictive(rule: &Value) -> bool {
    matches!(rule["effect"].as_str(), Some("block" | "review"))
}
fn relaxing(rule: &Value) -> bool {
    matches!(rule["effect"].as_str(), Some("allow" | "ignore"))
}
fn action(rule: &Value) -> &str {
    if enabled(rule) {
        rule["effect"].as_str().unwrap_or("")
    } else {
        "disabled"
    }
}

pub(super) fn evaluate(body: &Value, deadline: Instant) -> Result<Value, &'static str> {
    let before = rules(&body["baseline"])?;
    let after = rules(&body["candidate"])?;
    let additions = after
        .keys()
        .filter(|id| !before.contains_key(*id))
        .cloned()
        .collect::<Vec<_>>();
    let removals = before
        .keys()
        .filter(|id| !after.contains_key(*id))
        .cloned()
        .collect::<Vec<_>>();
    let modifications = before
        .iter()
        .filter(|(id, rule)| after.get(*id).is_some_and(|other| *rule != other))
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    let changed = additions
        .iter()
        .chain(&removals)
        .chain(&modifications)
        .collect::<BTreeSet<_>>();
    let mut scopes = BTreeSet::new();
    let mut harnesses = BTreeSet::new();
    let mut families = BTreeSet::new();
    for id in changed {
        let rule = after
            .get(id)
            .or_else(|| before.get(id))
            .ok_or("policy_document_shape")?;
        for (key, values) in fields(rule)? {
            scopes.insert(key.clone());
            if key == "harnesses" {
                harnesses.extend(values.iter().cloned());
            }
            if key == "artifacts" {
                for value in values {
                    let family = value
                        .split_once(':')
                        .or_else(|| value.split_once('/'))
                        .map_or(value.as_str(), |(prefix, _)| prefix)
                        .to_owned();
                    families.insert(family);
                }
            }
        }
    }
    // Preserve source rule order (including duplicate IDs) for conflict pairs.
    let active = body["candidate"]["spec"]["rules"]
        .as_array()
        .ok_or("policy_document_shape")?
        .iter()
        .filter(|rule| enabled(rule))
        .collect::<Vec<_>>();
    let mut warnings = Vec::new();
    for (index, left) in active.iter().enumerate() {
        for right in &active[index + 1..] {
            if Instant::now() >= deadline {
                return Err("policy_document_deadline");
            }
            if left["effect"] != right["effect"] && overlap(&fields(left)?, &fields(right)?) {
                warnings.push(format!(
                    "overlapping_effects:{}:{}",
                    left["id"].as_str().unwrap_or(""),
                    right["id"].as_str().unwrap_or("")
                ));
            }
        }
    }
    warnings.sort();
    let mut broadened = Vec::new();
    let mut narrowed = Vec::new();
    let mut unchanged = Vec::new();
    let mut actions = Vec::new();
    let mut relaxed = BTreeSet::new();
    for (id, previous) in &before {
        let Some(current) = after.get(id) else {
            continue;
        };
        if previous == current {
            unchanged.push(id.clone());
            continue;
        }
        let previous_fields = fields(previous)?;
        let current_fields = fields(current)?;
        let current_contains = contains(&current_fields, &previous_fields);
        let previous_contains = contains(&previous_fields, &current_fields);
        if current_contains && !previous_contains {
            broadened.push(id.clone());
        } else if previous_contains && !current_contains {
            narrowed.push(id.clone());
        }
        if previous["effect"] != current["effect"] || previous["enabled"] != current["enabled"] {
            actions.push(format!("{id}:{}->{}", action(previous), action(current)));
        }
        if (enabled(previous) && restrictive(previous) && (!enabled(current) || relaxing(current)))
            || (enabled(previous)
                && enabled(current)
                && restrictive(previous)
                && restrictive(current)
                && relaxed_lifetime(previous, current))
            || (enabled(current) && relaxing(current) && current_contains && !previous_contains)
        {
            relaxed.insert(id.clone());
        }
    }
    for id in &additions {
        if enabled(after[id]) && relaxing(after[id]) {
            relaxed.insert(id.clone());
        }
    }
    for id in &removals {
        if enabled(before[id]) && restrictive(before[id]) {
            relaxed.insert(id.clone());
        }
    }
    let previous_defaults = body["baseline"]["spec"]["defaults"]
        .as_object()
        .ok_or("policy_document_shape")?;
    let current_defaults = body["candidate"]["spec"]["defaults"]
        .as_object()
        .ok_or("policy_document_shape")?;
    let keys = previous_defaults
        .keys()
        .chain(current_defaults.keys())
        .collect::<BTreeSet<_>>();
    for key in keys {
        let previous = previous_defaults.get(key);
        let current = current_defaults.get(key);
        if previous == current {
            continue;
        }
        actions.push(format!(
            "defaults.{key}:{}->{}",
            shown(previous),
            shown(current)
        ));
        if previous
            .and_then(strength)
            .zip(current.and_then(strength))
            .is_some_and(|(before, after)| after < before)
        {
            relaxed.insert(format!("defaults.{key}"));
        }
    }
    if Instant::now() >= deadline {
        return Err("policy_document_deadline");
    }
    Ok(
        json!({"additions":additions,"modifications":modifications,"removals":removals,
        "impacted_scopes":scopes,"impacted_harnesses":harnesses,"impacted_artifact_families":families,
        "conflict_warnings":warnings,"broadened_rules":broadened,"narrowed_rules":narrowed,
        "unchanged_rules":unchanged,"effective_action_changes":actions,"broad_relaxing_changes":relaxed}),
    )
}

//! Ordered presentation frames preserve the public document layout.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use super::{projection, Error};

pub(super) fn mapping(class: &str, dto: &Value) -> Result<Value, Error> {
    Ok(node(class, dto, &projection::mapping(class, dto)?))
}

fn pair_keys(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|pair| pair[0].as_str())
        .map(str::to_owned)
        .collect()
}

fn node(class: &str, dto: &Value, value: &Value) -> Value {
    if let Some(items) = value.as_array() {
        return json!({"array":items.iter().enumerate().map(|(index, item)|
            node(class, &dto[index], item)).collect::<Vec<_>>()});
    }
    let Some(object) = value.as_object() else {
        return value.clone();
    };
    let known: &[&str] = match class {
        "GuardPolicyDocument" => &["apiVersion", "kind", "metadata", "spec"],
        "PolicySpec" => &["defaults", "rules", "rolloutState"],
        "PolicyMetadata" => &["id", "name", "revision", "labels"],
        "PolicyDefaults" => &["mode"],
        "PolicyLifetime" => &["mode", "expiresAt"],
        "PolicyProvenance" => &[
            "source",
            "createdAt",
            "receiptIds",
            "suggestionId",
            "createdBy",
            "updatedAt",
            "updatedBy",
            "importSourceDigest",
            "previousRuleRevision",
        ],
        "PolicyRule" => &[
            "id",
            "description",
            "enabled",
            "effect",
            "match",
            "lifetime",
            "provenance",
        ],
        "CommandExpression" => &["combinator", "conditions"],
        "CommandCondition" => &["field", "operator", "value", "caseSensitive"],
        _ => &[],
    };
    let mut keys: Vec<String> = known.iter().map(|key| (*key).into()).collect();
    match class {
        "PolicyMatch" => {
            keys = pair_keys(&dto["fields"]);
            if !dto["command_expression"].is_null() {
                keys.push("commands".into());
            }
        }
        "PolicyDefaults" => keys.extend(pair_keys(&dto["values"])),
        "Pairs" => keys = pair_keys(dto),
        _ => {}
    }
    let remaining: Vec<_> = object
        .keys()
        .filter(|key| !keys.contains(key))
        .cloned()
        .collect();
    keys.extend(remaining);
    let mut seen = BTreeSet::new();
    keys.retain(|key| seen.insert(key.clone()));
    let mut entries = Vec::new();
    for key in keys {
        let Some(value) = object.get(&key) else {
            continue;
        };
        let (child, child_dto) = match (class, key.as_str()) {
            ("GuardPolicyDocument", "metadata") => ("PolicyMetadata", &dto["metadata"]),
            ("GuardPolicyDocument", "spec") => ("PolicySpec", dto),
            ("PolicySpec", "defaults") => ("PolicyDefaults", &dto["defaults"]),
            ("PolicySpec", "rules") => ("PolicyRule", &dto["rules"]),
            ("PolicyRule", "match") => ("PolicyMatch", &dto["match"]),
            ("PolicyRule", "lifetime") => ("PolicyLifetime", &dto["lifetime"]),
            ("PolicyRule", "provenance") => ("PolicyProvenance", &dto["provenance"]),
            ("PolicyMetadata", "labels") => ("Pairs", &dto["labels"]),
            ("PolicyMatch", "commands") if value.is_object() => {
                ("CommandExpression", &dto["command_expression"])
            }
            ("CommandExpression", "conditions") => ("CommandCondition", &dto["conditions"]),
            _ => ("", &Value::Null),
        };
        entries.push(json!([key, node(child, child_dto, value)]));
    }
    json!({"object":entries})
}

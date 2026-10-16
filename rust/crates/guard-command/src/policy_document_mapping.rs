//! Native normalization into the existing public document DTO shapes.

use serde_json::{json, Map, Value};

use super::{canonical, failure, text, truthy, Error, MATCH_FIELDS};

pub(super) struct Projection {
    pub dto: Value,
    pub mapping: Value,
}

fn shape() -> Error {
    failure("TypeError", "validated_policy_document_shape", None)
}
fn object(value: &Value) -> Result<&Map<String, Value>, Error> {
    value.as_object().ok_or_else(shape)
}
fn required<'a>(value: &'a Value, key: &str) -> Result<&'a Value, Error> {
    value
        .get(key)
        .ok_or_else(|| failure("KeyError", &format!("'{key}'"), None))
}
fn optional(value: &Value) -> Value {
    if value.is_string() {
        value.clone()
    } else {
        Value::Null
    }
}
fn integer(value: &Value) -> bool {
    value
        .as_number()
        .is_some_and(|number| !number.to_string().contains(['.', 'e', 'E']))
}

fn extensions(value: &Value, known: &[&str]) -> Result<Value, Error> {
    let mut result = Vec::new();
    for (key, item) in object(value)? {
        if !known.contains(&key.as_str()) {
            result.push(json!([key, canonical(item)?]));
        }
    }
    Ok(json!(result))
}

fn finish(
    mut dto: Value,
    mut mapping: Value,
    value: &Value,
    known: &[&str],
) -> Result<Projection, Error> {
    dto["extensions"] = extensions(value, known)?;
    for (key, item) in object(value)? {
        if !known.contains(&key.as_str()) {
            mapping[key] = item.clone();
        }
    }
    Ok(Projection { dto, mapping })
}

fn metadata(value: &Value) -> Result<Projection, Error> {
    let labels = if value["labels"].is_null() {
        Map::new()
    } else {
        object(&value["labels"])?.clone()
    };
    let revision = required(value, "revision")?;
    if !integer(revision) {
        return Err(shape());
    }
    let pairs = labels
        .iter()
        .map(|(key, value)| json!([key, text(value)]))
        .collect::<Vec<_>>();
    let id = text(required(value, "id")?);
    let name = text(required(value, "name")?);
    let mut mapping = json!({"id":id,"name":name,"revision":revision});
    if !labels.is_empty() {
        mapping["labels"] = json!(labels
            .iter()
            .map(|(key, value)| (key.clone(), json!(text(value))))
            .collect::<Map<_, _>>());
    }
    finish(
        json!({"id":id,"name":name,"revision":revision,"labels":pairs}),
        mapping,
        value,
        &["id", "name", "revision", "labels"],
    )
}

fn defaults(value: &Value) -> Result<Projection, Error> {
    let mut known = vec![
        "mode",
        "defaultAction",
        "unknownPublisherAction",
        "changedHashAction",
        "newNetworkDomainAction",
        "subprocessAction",
        "telemetryEnabled",
        "syncEnabled",
    ];
    known.sort_unstable();
    let mode = text(required(value, "mode")?);
    let mut mapping = json!({"mode":mode});
    let mut pairs = Vec::new();
    for key in &known {
        if *key != "mode" {
            if let Some(item) = value.get(key) {
                pairs.push(json!([key, item]));
                mapping[key] = item.clone();
            }
        }
    }
    finish(json!({"mode":mode,"values":pairs}), mapping, value, &known)
}

fn matcher(value: &Value) -> Result<Projection, Error> {
    let mut pairs = Vec::new();
    let mut mapping = json!({});
    for key in MATCH_FIELDS {
        if let Some(items) = value[key].as_array() {
            let values = items.iter().map(text).collect::<Vec<_>>();
            pairs.push(json!([key, values]));
            mapping[key] = json!(values);
        }
    }
    let command = if value["commands"].is_object() {
        let result = super::command_dto::parse(&value["commands"])?;
        mapping["commands"] = result.mapping;
        result.dto
    } else {
        Value::Null
    };
    finish(
        json!({"fields":pairs,"command_expression":command}),
        mapping,
        value,
        MATCH_FIELDS,
    )
}

fn lifetime(value: &Value) -> Result<Projection, Error> {
    let mode = text(required(value, "mode")?);
    let expires = optional(&value["expiresAt"]);
    finish(
        json!({"mode":mode,"expires_at":expires}),
        json!({"mode":mode,"expiresAt":expires}),
        value,
        &["mode", "expiresAt"],
    )
}

fn provenance(value: &Value) -> Result<Projection, Error> {
    let source = text(required(value, "source")?);
    let created = text(required(value, "createdAt")?);
    let receipts = value["receiptIds"]
        .as_array()
        .map(|items| items.iter().map(text).collect::<Vec<_>>())
        .unwrap_or_default();
    let mut dto = json!({"source":source,"created_at":created,"receipt_ids":receipts});
    let mut mapping = json!({"source":source,"createdAt":created});
    if !receipts.is_empty() {
        mapping["receiptIds"] = json!(receipts);
    }
    let optional_fields = [
        ("suggestion_id", "suggestionId"),
        ("created_by", "createdBy"),
        ("updated_at", "updatedAt"),
        ("updated_by", "updatedBy"),
        ("import_source_digest", "importSourceDigest"),
    ];
    for (field, key) in optional_fields {
        dto[field] = optional(&value[key]);
        if !dto[field].is_null() {
            mapping[key] = dto[field].clone();
        }
    }
    let revision = &value["previousRuleRevision"];
    dto["previous_rule_revision"] = if integer(revision) || revision.is_boolean() {
        revision.clone()
    } else {
        Value::Null
    };
    if !dto["previous_rule_revision"].is_null() {
        mapping["previousRuleRevision"] = revision.clone();
    }
    finish(
        dto,
        mapping,
        value,
        &[
            "source",
            "receiptIds",
            "suggestionId",
            "createdAt",
            "createdBy",
            "updatedAt",
            "updatedBy",
            "importSourceDigest",
            "previousRuleRevision",
        ],
    )
}

fn rule(value: &Value) -> Result<Projection, Error> {
    let id = text(required(value, "id")?);
    let description = optional(&value["description"]);
    let enabled = truthy(required(value, "enabled")?);
    let effect = text(required(value, "effect")?);
    let matcher_value = required(value, "match")?;
    object(matcher_value)?;
    let matcher = matcher(matcher_value)?;
    let lifetime_value = required(value, "lifetime")?;
    object(lifetime_value)?;
    let lifetime = lifetime(lifetime_value)?;
    let provenance_value = required(value, "provenance")?;
    object(provenance_value)?;
    let provenance = provenance(provenance_value)?;
    let mut mapping = json!({"id":id,"enabled":enabled,"effect":effect,"match":matcher.mapping,
        "lifetime":lifetime.mapping,"provenance":provenance.mapping});
    if !description.is_null() {
        mapping["description"] = description.clone();
    }
    finish(
        json!({"id":id,"description":description,"enabled":enabled,"effect":effect,
        "match":matcher.dto,"lifetime":lifetime.dto,"provenance":provenance.dto}),
        mapping,
        value,
        &[
            "id",
            "description",
            "enabled",
            "effect",
            "match",
            "lifetime",
            "provenance",
        ],
    )
}

fn document(value: &Value) -> Result<Projection, Error> {
    let metadata_value = required(value, "metadata")?;
    object(metadata_value)?;
    let spec = required(value, "spec")?;
    object(spec)?;
    let defaults_value = required(spec, "defaults")?;
    object(defaults_value)?;
    let rules = required(spec, "rules")?.as_array().ok_or_else(shape)?;
    let api_version = text(required(value, "apiVersion")?);
    let kind = text(required(value, "kind")?);
    let metadata = metadata(metadata_value)?;
    let defaults = defaults(defaults_value)?;
    let rules = rules
        .iter()
        .map(|value| {
            object(value)?;
            rule(value)
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let rollout = optional(&spec["rolloutState"]);
    let spec_extensions = extensions(spec, &["defaults", "rolloutState", "rules"])?;
    let dto_rules = rules
        .iter()
        .map(|rule| rule.dto.clone())
        .collect::<Vec<_>>();
    let mut result_spec = json!({"defaults":defaults.mapping,
        "rules":rules.into_iter().map(|rule| rule.mapping).collect::<Vec<_>>()});
    if !rollout.is_null() {
        result_spec["rolloutState"] = rollout.clone();
    }
    for (key, item) in object(spec)? {
        if !["defaults", "rolloutState", "rules"].contains(&key.as_str()) {
            result_spec[key] = item.clone();
        }
    }
    finish(
        json!({"api_version":api_version,"kind":kind,"metadata":metadata.dto,"defaults":defaults.dto,
        "rules":dto_rules,"rollout_state":rollout,"spec_extensions":spec_extensions}),
        json!({"apiVersion":api_version,"kind":kind,"metadata":metadata.mapping,"spec":result_spec}),
        value,
        &["apiVersion", "kind", "metadata", "spec"],
    )
}

pub(super) fn parse(class: &str, value: &Value) -> Result<Projection, Error> {
    object(value)?;
    match class {
        "PolicyMetadata" => metadata(value),
        "PolicyDefaults" => defaults(value),
        "PolicyMatch" => matcher(value),
        "PolicyLifetime" => lifetime(value),
        "PolicyProvenance" => provenance(value),
        "PolicyRule" => rule(value),
        "GuardPolicyDocument" => document(value),
        _ => Err(shape()),
    }
}

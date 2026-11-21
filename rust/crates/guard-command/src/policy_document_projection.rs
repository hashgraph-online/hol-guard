//! Serialize already-normalized public DTOs without per-rule resident calls.

use serde_json::{json, Value};

use super::{failure, Error};

pub(super) fn mapping(class: &str, dto: &Value) -> Result<Value, Error> {
    let invalid = || failure("TypeError", "validated_policy_document_shape", None);
    if !dto.is_object() {
        return Err(invalid());
    }
    let mut value = json!({});
    match class {
        "PolicyMetadata" => {
            for key in ["id", "name", "revision"] {
                value[key] = dto[key].clone();
            }
            pairs(&mut value, "labels", &dto["labels"], true)?;
        }
        "PolicyDefaults" => {
            value["mode"] = dto["mode"].clone();
            pairs(&mut value, "", &dto["values"], false)?;
        }
        "PolicyMatch" => {
            pairs(&mut value, "", &dto["fields"], false)?;
            if !dto["command_expression"].is_null() {
                let command = &dto["command_expression"];
                let conditions = command["conditions"].as_array().ok_or_else(invalid)?;
                value["commands"] = json!({"combinator":command["combinator"],
                    "conditions":conditions.iter().map(|condition| json!({"field":condition["field"],
                        "operator":condition["operator"],"value":condition["value"],
                        "caseSensitive":condition["case_sensitive"]})).collect::<Vec<_>>()});
            }
        }
        "PolicyLifetime" => {
            value = json!({"mode":dto["mode"],"expiresAt":dto["expires_at"]});
        }
        "PolicyProvenance" => {
            value = json!({"source":dto["source"],"createdAt":dto["created_at"]});
            if dto["receipt_ids"]
                .as_array()
                .is_some_and(|values| !values.is_empty())
            {
                value["receiptIds"] = dto["receipt_ids"].clone();
            }
            for (wire, key) in [
                ("suggestionId", "suggestion_id"),
                ("createdBy", "created_by"),
                ("updatedAt", "updated_at"),
                ("updatedBy", "updated_by"),
                ("importSourceDigest", "import_source_digest"),
                ("previousRuleRevision", "previous_rule_revision"),
            ] {
                if !dto[key].is_null() {
                    value[wire] = dto[key].clone();
                }
            }
        }
        "PolicyRule" => {
            value = json!({"id":dto["id"],"enabled":dto["enabled"],"effect":dto["effect"],
                "match":mapping("PolicyMatch",&dto["match"])? ,
                "lifetime":mapping("PolicyLifetime",&dto["lifetime"])? ,
                "provenance":mapping("PolicyProvenance",&dto["provenance"])?});
            if !dto["description"].is_null() {
                value["description"] = dto["description"].clone();
            }
        }
        "GuardPolicyDocument" => {
            let rules = dto["rules"].as_array().ok_or_else(invalid)?;
            let mut spec = json!({"defaults":mapping("PolicyDefaults",&dto["defaults"])? ,
                "rules":rules.iter().map(|rule| mapping("PolicyRule",rule)).collect::<Result<Vec<_>,_>>()?});
            if !dto["rollout_state"].is_null() {
                spec["rolloutState"] = dto["rollout_state"].clone();
            }
            extensions(&mut spec, &dto["spec_extensions"])?;
            value = json!({"apiVersion":dto["api_version"],"kind":dto["kind"],
                "metadata":mapping("PolicyMetadata",&dto["metadata"])? ,"spec":spec});
        }
        _ => return Err(invalid()),
    }
    extensions(&mut value, &dto["extensions"])?;
    Ok(value)
}

fn pairs(value: &mut Value, key: &str, pairs: &Value, optional: bool) -> Result<(), Error> {
    let pairs = pairs
        .as_array()
        .ok_or_else(|| failure("TypeError", "validated_policy_document_shape", None))?;
    if optional && pairs.is_empty() {
        return Ok(());
    }
    let target = if key.is_empty() {
        value
    } else {
        value[key] = json!({});
        &mut value[key]
    };
    for pair in pairs {
        let key = pair[0]
            .as_str()
            .ok_or_else(|| failure("TypeError", "validated_policy_document_shape", None))?;
        target[key] = pair[1].clone();
    }
    Ok(())
}

fn extensions(value: &mut Value, pairs: &Value) -> Result<(), Error> {
    let pairs = pairs
        .as_array()
        .ok_or_else(|| failure("TypeError", "validated_policy_document_shape", None))?;
    for pair in pairs {
        let key = pair[0]
            .as_str()
            .ok_or_else(|| failure("TypeError", "validated_policy_document_shape", None))?;
        let encoded = pair[1]
            .as_str()
            .ok_or_else(|| failure("TypeError", "validated_policy_document_shape", None))?;
        value[key] = serde_json::from_str(encoded)
            .map_err(|_| failure("ValueError", "policy_extensions_invalid", None))?;
    }
    Ok(())
}

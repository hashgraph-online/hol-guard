//! Portable document compilation and semantic comparison through native DTOs.

use std::time::Instant;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[path = "policy_document_bounds.rs"]
mod bounds;
#[path = "policy_document_command_dto.rs"]
mod command_dto;
#[path = "policy_document_compile.rs"]
mod compiler;
#[path = "policy_document_diff.rs"]
mod diff;
#[path = "policy_document_mapping.rs"]
mod mapping;
#[path = "policy_document_metadata.rs"]
mod metadata;
#[path = "policy_document_ordered.rs"]
mod ordered;
#[path = "policy_document_projection.rs"]
mod projection;
#[cfg(test)]
#[path = "policy_document_tests.rs"]
mod tests;
#[path = "policy_document_value.rs"]
mod values;
#[path = "policy_document_yaml_tokens.rs"]
mod yaml_tokens;

use values::{canonical, failure, text, truthy, Error};

const MATCH_FIELDS: &[&str] = &[
    "operations",
    "actors",
    "agents",
    "artifacts",
    "commands",
    "devices",
    "domains",
    "ecosystems",
    "environments",
    "harnesses",
    "locations",
    "mcps",
    "packages",
    "paths",
    "publishers",
    "repositories",
    "secretTypes",
    "skills",
    "tools",
    "workspaces",
    "browserIntents",
    "browserOperations",
    "browserProfiles",
    "origins",
    "pathPrefixes",
    "sensitiveSurfaces",
];

pub fn evaluate(query: &str, input: &Value, deadline: Instant) -> Result<Value, &'static str> {
    if Instant::now() >= deadline {
        return Err("policy_document_deadline");
    }
    let output: Result<Value, Error> = (|| match query {
        "validate_yaml_tokens" => yaml_tokens::validate(input, deadline)
            .map_err(|message| failure("ValueError", message, None)),
        "validate_bounds" => bounds::validate(&input["claim"], deadline)
            .map_err(|message| failure("ValueError", message, None)),
        "validate_ids" | "validate_timestamps" => {
            metadata::validate(query, &input["value"], deadline)
                .map_err(|message| failure("ValueError", message, None))
        }
        "from_mapping" | "from_mapping_dto" => {
            let class = input["class_name"]
                .as_str()
                .ok_or_else(|| failure("TypeError", "policy_document_class", None))?;
            let projection = mapping::parse(class, &input["value"])?;
            Ok(if query == "from_mapping_dto" {
                projection.dto
            } else {
                json!({"dto":projection.dto,"mapping":projection.mapping})
            })
        }
        "command_expressions" => Ok(command_dto::document(&input["value"])),
        "canonical" => canonical(&input["value"]).map(Value::String),
        "to_mapping" | "to_mapping_ordered" => {
            let class = input["class_name"]
                .as_str()
                .ok_or_else(|| failure("TypeError", "policy_document_class", None))?;
            if query == "to_mapping_ordered" {
                ordered::mapping(class, &input["dto"])
            } else {
                projection::mapping(class, &input["dto"])
            }
        }
        "bounds" => {
            let rules = input["value"]["spec"]["rules"].as_array();
            let mut path = Value::Null;
            for (index, rule) in rules.into_iter().flatten().enumerate() {
                if rule["match"]["business"].is_object() {
                    let mut bytes = Vec::new();
                    guard_contracts::write_canonical_json_utf8(
                        &rule["match"]["business"],
                        &mut bytes,
                    )
                    .map_err(|_| failure("TypeError", "policy_business_selector_invalid", None))?;
                    if bytes.len() > 64 * 1024 {
                        path = json!(["spec", "rules", index, "match", "business"]);
                        break;
                    }
                }
            }
            Ok(path)
        }
        "digest" => canonical(&input["value"])
            .map(|value| json!(hex::encode(Sha256::digest(value.as_bytes())))),
        "rows" => {
            let result = compiler::rows(input, deadline)?;
            Ok(mapping::parse("GuardPolicyDocument", &result)?.mapping)
        }
        "compile" => compiler::compile(
            &mapping::parse("GuardPolicyDocument", &input["document"])?.mapping,
            deadline,
        ),
        "compile_dto" => compiler::compile(
            &projection::mapping("GuardPolicyDocument", &input["dto"])?,
            deadline,
        ),
        "compile_mapped" => compiler::compile(&input["document"], deadline),
        "compile_page" => compiler::page(input, deadline),
        "diff" => {
            let before = mapping::parse("GuardPolicyDocument", &input["baseline"])?.mapping;
            let after = mapping::parse("GuardPolicyDocument", &input["candidate"])?.mapping;
            diff::evaluate(&json!({"baseline":before,"candidate":after}), deadline)
                .map_err(|message| failure("TypeError", message, None))
        }
        _ => Err(failure("ValueError", "policy_document_query_invalid", None)),
    })();
    if Instant::now() >= deadline {
        return Err("policy_document_deadline");
    }
    Ok(match output {
        Ok(value) => json!({"ok":value}),
        Err(error) => json!({"error":error}),
    })
}

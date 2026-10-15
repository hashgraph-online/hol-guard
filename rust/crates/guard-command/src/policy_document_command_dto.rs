//! Command-expression DTO construction, independent of policy evaluation.

use serde_json::{json, Value};

use super::mapping::Projection;
use super::{failure, Error};

fn error(message: &str) -> Error {
    failure("CommandExpressionError", message, None)
}

pub(super) fn parse(value: &Value) -> Result<Projection, Error> {
    if !value.is_object() {
        return Err(error("command_expression_must_be_object"));
    }
    let combinator = value["combinator"]
        .as_str()
        .ok_or_else(|| error("command_expression_combinator_required"))?;
    let conditions = value["conditions"]
        .as_array()
        .ok_or_else(|| error("command_expression_conditions_required"))?;
    let mut dto = Vec::new();
    let mut mapping = Vec::new();
    for condition in conditions {
        if !condition.is_object() {
            return Err(error("command_condition_must_be_object"));
        }
        if condition["field"] != "command" {
            return Err(error("unsupported_command_condition_field"));
        }
        let operator = condition["operator"]
            .as_str()
            .ok_or_else(|| error("command_condition_operator_required"))?;
        let raw = condition["value"]
            .as_str()
            .ok_or_else(|| error("command_condition_value_required"))?;
        let case = match condition.get("caseSensitive") {
            None => false,
            Some(Value::Bool(flag)) => *flag,
            _ => return Err(error("command_condition_case_sensitive_invalid")),
        };
        if !matches!(
            operator,
            "exact" | "startsWith" | "contains" | "endsWith" | "glob" | "regex"
        ) {
            return Err(error("unsupported_command_pattern_operator"));
        }
        let normalized = raw
            .split(|character: char| {
                character.is_whitespace() || matches!(character, '\u{1c}'..='\u{1f}')
            })
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        if normalized.is_empty() {
            return Err(error("command_value_required"));
        }
        if normalized.chars().count() > 4096 {
            return Err(error("command_value_too_long"));
        }
        if normalized.chars().count() > 512 {
            return Err(error("command_pattern_too_long"));
        }
        dto.push(
            json!({"field":"command","operator":operator,"value":normalized,"case_sensitive":case}),
        );
        mapping.push(
            json!({"field":"command","operator":operator,"value":normalized,"caseSensitive":case}),
        );
    }
    if !matches!(combinator, "all" | "any") {
        return Err(error("unsupported_command_expression_combinator"));
    }
    if conditions.is_empty() {
        return Err(error("command_expression_conditions_required"));
    }
    if conditions.len() > 64 {
        return Err(error("command_expression_conditions_limit"));
    }
    Ok(Projection {
        dto: json!({"combinator":combinator,"conditions":dto}),
        mapping: json!({"combinator":combinator,"conditions":mapping}),
    })
}

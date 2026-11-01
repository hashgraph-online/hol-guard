//! Command-expression DTO construction, independent of policy evaluation.

use serde_json::{json, Value};

use super::mapping::Projection;
use super::{failure, Error};

fn error(message: &str) -> Error {
    failure("CommandExpressionError", message, None)
}

pub(super) fn parse(value: &Value) -> Result<Projection, Error> {
    projection(value).map_err(error)
}

/// `document` - every command expression the document's rules carry, in
/// document order, in the shape `CommandExpressionValidate` reads.
///
/// Python parsed this shape itself before handing the patterns to the runtime
/// that compiles them, so the dialect had two readings and a rule one accepted
/// the other could refuse. A rule an author can fix rides the ok channel with
/// its index, the way the validation op answers, so the caller can still name
/// the rule that carried it.
pub(super) fn document(value: &Value) -> Value {
    let mut expressions = Vec::new();
    for (index, rule) in value["spec"]["rules"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        let commands = &rule["match"]["commands"];
        if !commands.is_object() {
            continue;
        }
        let parsed = match projection(commands) {
            Ok(parsed) => parsed,
            Err(code) => return json!({"invalid": {"index": index, "code": code}}),
        };
        let conditions = parsed.dto["conditions"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|condition| {
                json!({
                    "operator": condition["operator"],
                    "value": condition["value"],
                    "case_sensitive": condition["case_sensitive"],
                })
            })
            .collect::<Vec<_>>();
        expressions.push(json!({
            "index": index,
            "expression": {"combinator": parsed.dto["combinator"], "conditions": conditions},
        }));
    }
    json!({"expressions": expressions})
}

fn projection(value: &Value) -> Result<Projection, &'static str> {
    if !value.is_object() {
        return Err("command_expression_must_be_object");
    }
    let combinator = value["combinator"]
        .as_str()
        .ok_or("command_expression_combinator_required")?;
    let conditions = value["conditions"]
        .as_array()
        .ok_or("command_expression_conditions_required")?;
    let mut dto = Vec::new();
    let mut mapping = Vec::new();
    for condition in conditions {
        if !condition.is_object() {
            return Err("command_condition_must_be_object");
        }
        if condition["field"] != "command" {
            return Err("unsupported_command_condition_field");
        }
        let operator = condition["operator"]
            .as_str()
            .ok_or("command_condition_operator_required")?;
        let raw = condition["value"]
            .as_str()
            .ok_or("command_condition_value_required")?;
        let case = match condition.get("caseSensitive") {
            None => false,
            Some(Value::Bool(flag)) => *flag,
            _ => return Err("command_condition_case_sensitive_invalid"),
        };
        if !matches!(
            operator,
            "exact" | "startsWith" | "contains" | "endsWith" | "glob" | "regex"
        ) {
            return Err("unsupported_command_pattern_operator");
        }
        let normalized = raw
            .split(|character: char| {
                character.is_whitespace() || matches!(character, '\u{1c}'..='\u{1f}')
            })
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        if normalized.is_empty() {
            return Err("command_value_required");
        }
        if normalized.chars().count() > 4096 {
            return Err("command_value_too_long");
        }
        if normalized.chars().count() > 512 {
            return Err("command_pattern_too_long");
        }
        dto.push(
            json!({"field":"command","operator":operator,"value":normalized,"case_sensitive":case}),
        );
        mapping.push(
            json!({"field":"command","operator":operator,"value":normalized,"caseSensitive":case}),
        );
    }
    if !matches!(combinator, "all" | "any") {
        return Err("unsupported_command_expression_combinator");
    }
    if conditions.is_empty() {
        return Err("command_expression_conditions_required");
    }
    if conditions.len() > 64 {
        return Err("command_expression_conditions_limit");
    }
    Ok(Projection {
        dto: json!({"combinator":combinator,"conditions":dto}),
        mapping: json!({"combinator":combinator,"conditions":mapping}),
    })
}

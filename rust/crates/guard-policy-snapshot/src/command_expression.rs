//! Validated literal command expressions. This does not admit a policy snapshot.
//!
//! The wire AST is the existing all/any command-expression shape. Unsupported
//! operators or case folding refuse deserialization before any clause matches.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_COMMAND_CONDITIONS: usize = 64;
pub const MAX_COMMAND_PATTERN_SCALARS: usize = 512;
pub const MAX_COMMAND_SCALARS: usize = 4096;

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum CommandExpressionError {
    #[error("native_command_expression_invalid")]
    InvalidConditions,
    #[error("native_command_casefold_unsupported")]
    CasefoldUnsupported,
    #[error("native_command_operator_unsupported")]
    OperatorUnsupported,
    #[error("native_command_value_unsupported")]
    ValueUnsupported,
    #[error("command_value_required")]
    CommandRequired,
    #[error("command_value_too_long")]
    CommandTooLong,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedCommand(String);

impl NormalizedCommand {
    /// Collapse the exact Python whitespace set without modifying case or quotes.
    /// Length counts Unicode scalar values; Rust strings cannot contain surrogates.
    pub fn new(value: &str) -> Result<Self, CommandExpressionError> {
        let mut output = String::with_capacity(value.len().min(MAX_COMMAND_SCALARS * 4));
        let mut count = 0;
        let mut pending_space = false;
        for character in value.chars() {
            if command_whitespace(character) {
                pending_space = !output.is_empty();
                continue;
            }
            if pending_space {
                output.push(' ');
                count += 1;
                pending_space = false;
            }
            output.push(character);
            count += 1;
            if count > MAX_COMMAND_SCALARS {
                return Err(CommandExpressionError::CommandTooLong);
            }
        }
        if output.is_empty() {
            return Err(CommandExpressionError::CommandRequired);
        }
        Ok(Self(output))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn command_whitespace(value: char) -> bool {
    matches!(
        value as u32,
        0x09..=0x0d
            | 0x1c..=0x20
            | 0x85
            | 0xa0
            | 0x1680
            | 0x2000..=0x200a
            | 0x2028
            | 0x2029
            | 0x202f
            | 0x205f
            | 0x3000
    )
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Combinator {
    All,
    Any,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum CommandField {
    #[serde(rename = "command")]
    Command,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", try_from = "String")]
enum LiteralOperator {
    Exact,
    StartsWith,
    Contains,
    EndsWith,
}

impl TryFrom<String> for LiteralOperator {
    type Error = CommandExpressionError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "exact" => Ok(Self::Exact),
            "startsWith" => Ok(Self::StartsWith),
            "contains" => Ok(Self::Contains),
            "endsWith" => Ok(Self::EndsWith),
            _ => Err(CommandExpressionError::OperatorUnsupported),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Condition {
    field: CommandField,
    operator: LiteralOperator,
    value: String,
    #[serde(rename = "caseSensitive")]
    case_sensitive: bool,
}

impl Condition {
    fn matches(&self, command: &NormalizedCommand) -> bool {
        let value = self.value.as_str();
        match self.operator {
            LiteralOperator::Exact => command.as_str() == value,
            LiteralOperator::StartsWith => command.as_str().starts_with(value),
            LiteralOperator::Contains => command.as_str().contains(value),
            LiteralOperator::EndsWith => command.as_str().ends_with(value),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpressionInput {
    combinator: Combinator,
    conditions: Vec<Condition>,
}

/// An expression is constructible only after every clause has been validated.
/// Selectors, target applicability, expiry and policy authority remain the caller's
/// responsibility and must be composed with this result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "ExpressionInput")]
pub struct NativeCommandExpression {
    combinator: Combinator,
    conditions: Vec<Condition>,
}

impl TryFrom<ExpressionInput> for NativeCommandExpression {
    type Error = CommandExpressionError;

    fn try_from(input: ExpressionInput) -> Result<Self, Self::Error> {
        if input.conditions.is_empty() || input.conditions.len() > MAX_COMMAND_CONDITIONS {
            return Err(CommandExpressionError::InvalidConditions);
        }
        for condition in &input.conditions {
            if !condition.case_sensitive {
                return Err(CommandExpressionError::CasefoldUnsupported);
            }
            let normalized = NormalizedCommand::new(&condition.value)
                .map_err(|_| CommandExpressionError::ValueUnsupported)?;
            if normalized.as_str() != condition.value
                || condition.value.chars().count() > MAX_COMMAND_PATTERN_SCALARS
            {
                return Err(CommandExpressionError::ValueUnsupported);
            }
        }
        Ok(Self {
            combinator: input.combinator,
            conditions: input.conditions,
        })
    }
}

impl NativeCommandExpression {
    /// Match only this expression after complete deserialization validation.
    pub fn matches(&self, command: &NormalizedCommand) -> bool {
        let mut matches = self
            .conditions
            .iter()
            .map(|condition| condition.matches(command));
        match self.combinator {
            Combinator::All => matches.all(|matched| matched),
            Combinator::Any => matches.any(|matched| matched),
        }
    }
}

#[cfg(test)]
#[path = "command_expression_tests.rs"]
mod tests;

//! `CommandPolicyDecide` - wire contract for deciding one shell command
//! against the command-expression rules of a policy document.
//!
//! A command expression is a policy question: does this command match a rule,
//! and which rule then decides it. Answering it in Python meant a second
//! pattern dialect, a second precedence ladder and a second regex engine
//! beside the runtime's, so `policy check` could report a command as allowed
//! while enforcement blocked it. The dialect, the match and the precedence
//! live in the runtime now, and the caller only ships the rules it compiled.
//!
//! The op is pure: it reads the rules in the request and never opens the
//! store, the keyring or a policy file.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const COMMAND_POLICY_DECISION_REQUEST_SCHEMA: &str = "guard-command-policy-decision-request.v1";
/// Schema discriminator for the result.
pub const COMMAND_POLICY_DECISION_RESULT_SCHEMA: &str = "guard-command-policy-decision-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const COMMAND_POLICY_DECISION_FEATURE: &str = "command-policy-decision-v1";
/// Largest canonical request serialization the op will accept. It stays below
/// `MAX_NATIVE_REQUEST_BYTES` so the resident envelope still fits one frame.
pub const COMMAND_POLICY_DECISION_MAX_BYTES: usize = 6 * 1024 * 1024 - 64 * 1024;
/// Most command rules one call may decide against. A document that carries
/// more command rules than this is past what an author can reason about, and
/// the byte limit above is what a real request runs into first.
pub const COMMAND_POLICY_DECISION_MAX_RULES: usize = 4096;
/// Longest pattern one condition may carry.
pub const MAX_COMMAND_PATTERN_LENGTH: usize = 512;
/// Most conditions one expression may combine.
pub const MAX_COMMAND_CONDITIONS: usize = 64;
/// Longest normalized command the dialect will match against.
pub const MAX_NORMALIZED_COMMAND_LENGTH: usize = 4096;

/// One condition of a command expression. `field` is always `command`, so the
/// wire form carries only what varies.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommandConditionV1 {
    /// `exact`, `startsWith`, `contains`, `endsWith`, `glob` or `regex`.
    pub operator: String,
    pub value: String,
    #[serde(default)]
    pub case_sensitive: bool,
}

/// Conditions joined by `all` or `any`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommandExpressionV1 {
    pub combinator: String,
    pub conditions: Vec<CommandConditionV1>,
}

/// One enabled document rule that carries a command expression.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommandPolicyRuleV1 {
    pub rule_id: String,
    /// `allow`, `warn`, `review` or `block`.
    pub action: String,
    pub expression: CommandExpressionV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommandPolicyDecisionRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// Document order: the first rule asking for the strongest action decides.
    pub rules: Vec<CommandPolicyRuleV1>,
    pub command: String,
    pub now: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommandPolicyDecisionResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_command_policy_decision_*` failure codes.
    pub code: String,
    /// The Explain document: `effect`, `ruleId`, `ambiguous`,
    /// `matchLimitExceeded`, `tiedRuleIds`, `candidates`, `lookup` and, when a
    /// rule matched, the `action` the lattice settled on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

/// Schema discriminator for the validation request.
pub const COMMAND_EXPRESSION_VALIDATION_REQUEST_SCHEMA: &str =
    "guard-command-expression-validation-request.v1";
/// Schema discriminator for the validation result.
pub const COMMAND_EXPRESSION_VALIDATION_RESULT_SCHEMA: &str =
    "guard-command-expression-validation-result.v1";
/// Capability advertised by the runtime when validation is available.
pub const COMMAND_EXPRESSION_VALIDATION_FEATURE: &str = "command-expression-validation-v1";
/// Most expressions one document may send for validation. A document carrying
/// more command rules than this is past what `CommandPolicyDecide` will decide.
pub const COMMAND_EXPRESSION_VALIDATION_MAX_EXPRESSIONS: usize = COMMAND_POLICY_DECISION_MAX_RULES;

/// Every command expression a document carries, in document order, compiled
/// once while the document is validated so an author hears about a pattern
/// outside the dialect when they write it rather than when a command runs.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommandExpressionValidationRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    pub expressions: Vec<CommandExpressionV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommandExpressionValidationResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_command_expression_validation_*` codes.
    pub code: String,
    /// `{"invalid": null}` when every expression compiles, or
    /// `{"invalid": {"index": i, "code": "..."}}` for the first that does not.
    /// A pattern an author can fix is an answer, not a runtime failure, so it
    /// rides an `ok` reply with the index of the expression that carried it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

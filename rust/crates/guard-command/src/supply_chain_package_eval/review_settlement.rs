//! How a package evaluation settles a pending package review.
//!
//! The native edge reviews every package install it cannot see through. When
//! the evaluator has judged the same request, its verdict settles that review:
//! a block always applies, because stopping a command runs nothing. The other
//! outcomes only apply to an install whose command the resident proved, so the
//! caller applies them only when the review plan said the verdict may let the
//! command continue.

use super::registry_install_identity::LIFECYCLE_SCRIPTS_ENABLED_CODE;
use super::*;

/// Transport-only key the settlement rides under in an evaluation reply. It
/// is not part of the evaluation view.
pub const REVIEW_SETTLEMENT_KEY: &str = "review_settlement";
const DEFAULT_BLOCK_MESSAGE: &str = "HOL Guard blocked this package install.";

impl PackageEvalResult {
    /// `{"action": ..., "reason": ...}` for this verdict:
    ///
    /// - `block`: the evaluator blocked; `reason` is its first message.
    /// - `allow`: the command may continue. That is an allow, or a watch that
    ///   holds only because no package code runs.
    /// - `guide`: stop the command with the evaluator's guidance for running
    ///   it without lifecycle scripts.
    /// - `review`: the native review stands.
    pub fn review_settlement(&self) -> Value {
        let (action, reason) = match self.decision.as_str() {
            "block" => (
                "block",
                Some(
                    first_message(&self.reasons, |_| true)
                        .unwrap_or_else(|| DEFAULT_BLOCK_MESSAGE.to_owned()),
                ),
            ),
            "allow" => ("allow", None),
            "monitor" if self.script_free_watch() => ("allow", None),
            "ask" => match first_message(&self.reasons, |reason| {
                reason.get("code").and_then(Value::as_str) == Some(LIFECYCLE_SCRIPTS_ENABLED_CODE)
            }) {
                Some(guidance) => ("guide", Some(guidance)),
                None => ("review", None),
            },
            _ => ("review", None),
        };
        json!({"action": action, "reason": reason})
    }

    /// Whether every package is watched only because no package code runs.
    fn script_free_watch(&self) -> bool {
        !self.packages.is_empty()
            && self
                .packages
                .iter()
                .all(|package| package.get("scriptFreeRegistryInstall") == Some(&Value::Bool(true)))
    }
}

fn first_message(
    reasons: &[Map<String, Value>],
    wanted: impl Fn(&Map<String, Value>) -> bool,
) -> Option<String> {
    reasons
        .iter()
        .filter(|&reason| wanted(reason))
        .find_map(|reason| {
            reason
                .get("message")
                .and_then(Value::as_str)
                .filter(|message| !message.is_empty())
                .map(str::to_owned)
        })
}

#[cfg(test)]
#[path = "review_settlement_tests.rs"]
mod tests;

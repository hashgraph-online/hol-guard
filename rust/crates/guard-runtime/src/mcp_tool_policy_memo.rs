//! What one caller's policy passes over a single subject may share.
//!
//! A caller that answers each need and replays `evaluate_pass` for the same
//! subject (`mcp_relay_decide_policy.rs`) would otherwise rerun the subject's
//! native recommendation and its device extension decision every round,
//! though neither reads an observation. The memo keeps both for the subject
//! it was made for, for that one call: a pass over any other subject, such as
//! a revalidation's refreshed one, evaluates afresh. Only a decided answer is
//! kept; a failed evaluation is repeated, and a memo whose lock cannot be
//! taken evaluates afresh.

use std::sync::{Mutex, OnceLock};

use guard_contracts::{McpExtensionInputV1, McpToolPolicySubjectV1};
use serde_json::Value;

use super::{evaluate_current, Flow};
use crate::mcp_tool_policy_decision::Current;
use crate::mcp_tool_policy_extension::extension_decision;

/// The memo of one call's passes over `subject`.
pub(crate) struct PassMemo<'s> {
    subject: &'s McpToolPolicySubjectV1,
    current: OnceLock<Current>,
    /// `extension_decision` answers, by the action each refined.
    extension: Mutex<Vec<(String, Value)>>,
}

impl<'s> PassMemo<'s> {
    pub(crate) fn new(subject: &'s McpToolPolicySubjectV1) -> Self {
        Self {
            subject,
            current: OnceLock::new(),
            extension: Mutex::new(Vec::new()),
        }
    }

    /// Whether this memo was made for `subject` itself. An equal copy does
    /// not count: the borrow keeps the address from being reused meanwhile.
    fn covers(&self, subject: &McpToolPolicySubjectV1) -> bool {
        std::ptr::eq(self.subject, subject)
    }
}

/// `evaluate_current(subject)`, evaluated once per memo that covers it.
pub(super) fn current(
    memo: Option<&PassMemo<'_>>,
    subject: &McpToolPolicySubjectV1,
) -> Flow<Current> {
    let Some(memo) = memo.filter(|memo| memo.covers(subject)) else {
        return evaluate_current(subject);
    };
    if let Some(current) = memo.current.get() {
        return Ok(current.clone());
    }
    let current = evaluate_current(subject)?;
    Ok(memo.current.get_or_init(|| current).clone())
}

/// `extension_decision(extension, action)` for `subject`'s own extension,
/// read from the store once per memo that covers it.
pub(super) fn extension(
    memo: Option<&PassMemo<'_>>,
    subject: &McpToolPolicySubjectV1,
    extension: &McpExtensionInputV1,
    action: &str,
) -> Value {
    let own = subject
        .extension
        .as_ref()
        .is_some_and(|own| std::ptr::eq(own, extension));
    let Some(memo) = memo.filter(|memo| own && memo.covers(subject)) else {
        return extension_decision(extension, action);
    };
    if let Ok(answers) = memo.extension.lock() {
        if let Some((_, answer)) = answers.iter().find(|(seen, _)| seen == action) {
            return answer.clone();
        }
    }
    let answer = extension_decision(extension, action);
    if let Ok(mut answers) = memo.extension.lock() {
        answers.push((action.to_owned(), answer.clone()));
    }
    answer
}

#[cfg(test)]
#[path = "mcp_tool_policy_memo_tests.rs"]
mod tests;

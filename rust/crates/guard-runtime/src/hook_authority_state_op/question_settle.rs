//! `claude_question_settle`: what a Claude `AskUserQuestion` answer to the HOL
//! Guard approval prompt settles, in one transaction against the session's
//! pending permission.
//!
//! The flow loads the session's single pending permission, asks
//! [`crate::claude_guard_question::verdict`] whether the call answers its
//! prompt, and plans the saved decision with
//! [`crate::hook_decision_native_permission_persist::native_permission_persist_plan`].
//! A pending permission whose prompt Claude never showed cannot be answered:
//! the flow records `approval.pending_prompt_unseen` itself and saves nothing.
//!
//! The reply's `outcome` is one of:
//! - `none`: no single pending permission, or the call is not its question,
//!   so the ordinary post-tool review applies;
//! - `unseen`: the question names a prompt that was never shown;
//! - `unanswered`: the question carries no answer that maps to an action, or
//!   the pending permission lacks its artifact identity;
//! - `save`: the plan to write, with the artifact, reason and source of the
//!   policy row. The caller writes it and then removes the pending permission.

use guard_contracts::NativePermissionPersistInputsV1;

use super::*;
use crate::claude_guard_question::{verdict, Question};
use crate::hook_decision_native_permission_persist::native_permission_persist_plan;

const SOURCE: &str = "claude-ask-user-question";
static NULL: Value = Value::Null;
const UNSEEN_EVENT: &str = "approval.pending_prompt_unseen";

fn outcome(name: &str) -> Value {
    json!({ "outcome": name })
}

fn reason(action: &str) -> &'static str {
    if action == "allow" {
        "Allowed through HOL Guard AskUserQuestion approval."
    } else {
        "Blocked through HOL Guard AskUserQuestion approval."
    }
}

impl Env<'_> {
    /// `question` is the hook's projection (`event`, `tool_name`,
    /// `tool_input`, `tool_response` and the ordered `response_answers`);
    /// without one the call is not a question, but the pending permission is
    /// still loaded, as every Claude post-tool hook does.
    pub(super) fn claude_question_settle(
        &self,
        session_id: &str,
        question: Option<&Value>,
        tilde_home: Option<&str>,
    ) -> Result<Value, &'static str> {
        let Some((_, pending)) = self.claude_load_single_pending(session_id) else {
            return Ok(outcome("none"));
        };
        let Some(question) = question else {
            return Ok(outcome("none"));
        };
        let field = |name: &str| question.get(name).unwrap_or(&NULL);
        let answer = verdict(&Question {
            event: question.get("event").and_then(Value::as_str),
            tool_name: field("tool_name"),
            tool_input: field("tool_input"),
            tool_response: field("tool_response"),
            response_answers: question
                .get("response_answers")
                .and_then(Value::as_array)
                .map(Vec::as_slice),
            pending: &Value::Object(pending.clone()),
        });
        if !answer.is_question {
            return Ok(outcome("none"));
        }
        if pending.get("permission_prompt_seen") != Some(&Value::Bool(true)) {
            self.add_event(
                UNSEEN_EVENT,
                &json!({
                    "harness": "claude-code",
                    "source": "claude-pending-permission",
                    "session_id": session_id,
                    "artifact_id": pending.get("artifact_id"),
                    "artifact_hash": pending.get("artifact_hash"),
                }),
            );
            return Ok(outcome("unseen"));
        }
        let (Some(action), Some(artifact_id), Some(artifact_hash)) = (
            answer.action,
            opt_str(&pending, "artifact_id"),
            opt_str(&pending, "artifact_hash"),
        ) else {
            return Ok(outcome("unanswered"));
        };
        let reason = reason(&action);
        let plan = native_permission_persist_plan(&NativePermissionPersistInputsV1 {
            artifact_id: artifact_id.clone(),
            artifact_hash,
            artifact_type: opt_str(&pending, "artifact_type"),
            config_path: opt_str(&pending, "config_path"),
            source_scope: opt_str(&pending, "source_scope"),
            raw_command_text: opt_str(&pending, "raw_command_text").map(Value::String),
            wrapper_chain: pending
                .get("wrapper_chain")
                .filter(|chain| chain.is_array())
                .cloned(),
            action,
            reason: reason.to_owned(),
            source: SOURCE.to_owned(),
            authoritative_action: None,
            tilde_home: tilde_home.map(str::to_owned),
        })
        .map_err(|_| ERROR_INVALID)?;
        Ok(json!({
            "outcome": "save",
            "artifact_id": artifact_id,
            "reason": reason,
            "source": SOURCE,
            "plan": serde_json::to_value(plan).map_err(|_| ERROR_INVALID)?,
        }))
    }
}

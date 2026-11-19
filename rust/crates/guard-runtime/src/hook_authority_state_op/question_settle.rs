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
//!   policy row. The resident save operation writes it and removes the pending
//!   permission in the same transaction.

use base64ct::{Base64UrlUnpadded, Encoding};
use guard_contracts::{NativePermissionPersistInputsV1, NativePermissionPersistPlanV1};

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
    /// Persists a settled AskUserQuestion plan and consumes its pending
    /// permission in the same authority-state transaction.
    pub(super) fn claude_question_save(
        &self,
        session_id: &str,
        payload: &Object,
    ) -> Result<Value, &'static str> {
        let artifact_id = opt_str(payload, "artifact_id").ok_or(ERROR_INVALID)?;
        let reason = opt_str(payload, "reason").ok_or(ERROR_INVALID)?;
        let source = opt_str(payload, "source").ok_or(ERROR_INVALID)?;
        let plan: NativePermissionPersistPlanV1 =
            serde_json::from_value(payload.get("plan").cloned().ok_or(ERROR_INVALID)?)
                .map_err(|_| ERROR_INVALID)?;
        let (Some(stored_artifact_hash), Some(policy_action)) = (
            plan.stored_artifact_hash.as_deref(),
            plan.policy_action.as_deref(),
        ) else {
            return Err(ERROR_INVALID);
        };
        if !matches!(policy_action, "allow" | "block") {
            return Err(ERROR_INVALID);
        }
        for event in plan.events.iter().filter(|event| event.before_policy) {
            if !self.add_event_checked(&event.name, &Value::Object(event.payload.clone())) {
                return Err(ERROR_STORE);
            }
        }
        let mut args = Object::new();
        args.insert("harness".to_owned(), json!("claude-code"));
        args.insert("scope".to_owned(), json!("artifact"));
        args.insert("artifact_id".to_owned(), json!(artifact_id));
        args.insert("artifact_hash".to_owned(), json!(stored_artifact_hash));
        args.insert("action".to_owned(), json!(policy_action));
        args.insert("reason".to_owned(), json!(reason));
        args.insert("source".to_owned(), json!(source));
        args.insert("now".to_owned(), json!(self.now));
        let generation: i64 = self
            .connection
            .query_row(
                "select coalesce(max(integrity_generation), 0) from policy_decisions",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ERROR_STORE)?;
        args.insert("current_generation".to_owned(), json!(generation));
        if let (Some(key), Some(key_id)) = (self.key.as_ref(), self.key_id) {
            args.insert(
                "integrity_key_b64".to_owned(),
                json!(Base64UrlUnpadded::encode_string(key)),
            );
            args.insert("integrity_key_id".to_owned(), json!(key_id));
        }
        crate::guard_store_policy_upsert::upsert_policy(
            self.connection,
            &crate::guard_store_args::Args(&args),
        )
        .map_err(|_| ERROR_STORE)?;
        for event in plan.events.iter().filter(|event| !event.before_policy) {
            if !self.add_event_checked(&event.name, &Value::Object(event.payload.clone())) {
                return Err(ERROR_STORE);
            }
        }
        let pending_key = claude_pending_key(session_id, &artifact_id);
        self.claude_remove_pending(session_id, &pending_key);
        Ok(json!({ "valid": true, "saved": true }))
    }

    /// `question` is the hook's projection (`event`, `tool_name`,
    /// `tool_input`, `tool_response` and the ordered `response_answers`);
    /// without one the call is not a question. The daemon asks only about an
    /// `AskUserQuestion` call, so other post-tool hooks never reach this op.
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

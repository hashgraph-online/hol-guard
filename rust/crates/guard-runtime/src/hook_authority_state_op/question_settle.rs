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
//!   policy row. The resident save operation commits the policy row and audit
//!   events first. The host finalizes the integrity generation, then a
//!   separate authority call consumes the pending permission. A failure after
//!   save does not roll back the committed policy row.

use base64ct::{Base64UrlUnpadded, Encoding};
use guard_contracts::{NativePermissionPersistInputsV1, NativePermissionPersistPlanV1};

use super::*;
use crate::claude_guard_question::{verdict, Question};
use crate::hook_decision_native_permission_persist::native_permission_persist_plan;

const SOURCE: &str = "claude-ask-user-question";
static NULL: Value = Value::Null;
const UNSEEN_EVENT: &str = "approval.pending_prompt_unseen";

fn validated_plan(value: &Value) -> Result<NativePermissionPersistPlanV1, &'static str> {
    let object = value.as_object().ok_or(ERROR_INVALID)?;
    let required = [
        "stored_artifact_hash",
        "policy_action",
        "events",
        "inventory_approved",
    ];
    if object.keys().any(|key| !required.contains(&key.as_str())) {
        return Err(ERROR_INVALID);
    }
    let plan: NativePermissionPersistPlanV1 =
        serde_json::from_value(value.clone()).map_err(|_| ERROR_INVALID)?;
    if (plan.stored_artifact_hash.is_some()) != (plan.policy_action.is_some())
        || plan
            .policy_action
            .as_deref()
            .is_some_and(|action| !matches!(action, "allow" | "block"))
    {
        return Err(ERROR_INVALID);
    }
    let names: Vec<&str> = object
        .get("events")
        .and_then(Value::as_array)
        .ok_or(ERROR_INVALID)?
        .iter()
        .map(|event| {
            let event = event.as_object().ok_or(ERROR_INVALID)?;
            if event
                .keys()
                .any(|key| !matches!(key.as_str(), "name" | "payload" | "before_policy"))
                || !event.get("payload").is_some_and(Value::is_object)
            {
                return Err(ERROR_INVALID);
            }
            let name = event
                .get("name")
                .and_then(Value::as_str)
                .ok_or(ERROR_INVALID)?;
            let before = event
                .get("before_policy")
                .and_then(Value::as_bool)
                .ok_or(ERROR_INVALID)?;
            let expected = match name {
                "claude/native_permission_exact_key_missing" => true,
                "claude/native_permission_saved"
                | "claude/native_permission_current_policy_retained" => false,
                _ => return Err(ERROR_INVALID),
            };
            (before == expected).then_some(name).ok_or(ERROR_INVALID)
        })
        .collect::<Result<_, _>>()?;
    let valid = if plan.stored_artifact_hash.is_some() {
        names.as_slice() == ["claude/native_permission_saved"]
            || names.as_slice()
                == [
                    "claude/native_permission_exact_key_missing",
                    "claude/native_permission_saved",
                ]
    } else {
        names.as_slice() == ["claude/native_permission_current_policy_retained"]
    };
    valid.then_some(plan).ok_or(ERROR_INVALID)
}

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
    /// Persists a settled AskUserQuestion plan. Consumption happens in a
    /// separate authority transaction after the host finalizes integrity.
    pub(super) fn claude_question_save(
        &self,
        _session_id: &str,
        payload: &Object,
    ) -> Result<Value, &'static str> {
        let artifact_id = opt_str(payload, "artifact_id").ok_or(ERROR_INVALID)?;
        let reason = opt_str(payload, "reason").ok_or(ERROR_INVALID)?;
        let source = opt_str(payload, "source").ok_or(ERROR_INVALID)?;
        if guard_policy_snapshot::policy_integrity::is_remote_policy_source(Some(&source)) {
            return Err(ERROR_INVALID);
        }
        let plan = validated_plan(payload.get("plan").ok_or(ERROR_INVALID)?)?;
        let (Some(stored_artifact_hash), Some(policy_action)) = (
            plan.stored_artifact_hash.as_deref(),
            plan.policy_action.as_deref(),
        ) else {
            return Err(ERROR_INVALID);
        };
        if !matches!(policy_action, "allow" | "block") {
            return Err(ERROR_INVALID);
        }
        if let Some(guard_home) = self.guard_home {
            crate::approval_gate_consumers::require_policy_write(
                guard_home,
                crate::approval_gate_op::grants(),
                policy_action,
                "artifact",
                None,
                Some(self.now),
            )
            .map_err(|_| ERROR_STORE)?;
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
        match (self.key.as_ref(), self.key_id) {
            (None, None) => {}
            (Some(key), Some(key_id)) => {
                let generation = payload
                    .get("current_generation")
                    .and_then(Value::as_i64)
                    .filter(|generation| *generation >= 0)
                    .ok_or(ERROR_STORE)?;
                args.insert("current_generation".to_owned(), json!(generation));
                args.insert(
                    "integrity_key_b64".to_owned(),
                    json!(Base64UrlUnpadded::encode_string(key)),
                );
                args.insert("integrity_key_id".to_owned(), json!(key_id));
            }
            _ => return Err(ERROR_INVALID),
        }
        let policy_result = crate::guard_store_policy_upsert::upsert_policy(
            self.connection,
            &crate::guard_store_args::Args(&args),
        )
        .map_err(|_| ERROR_STORE)?;
        for event in plan.events.iter().filter(|event| !event.before_policy) {
            if !self.add_event_checked(&event.name, &Value::Object(event.payload.clone())) {
                return Err(ERROR_STORE);
            }
        }
        Ok(json!({
            "valid": true,
            "saved": true,
            "next_control_state": policy_result.get("next_control_state").cloned().unwrap_or(Value::Null),
        }))
    }

    /// Consumes the pending permission after the policy-integrity control
    /// state has been finalized by the host secret store.
    pub(super) fn claude_question_consume(
        &self,
        session_id: &str,
        payload: &Object,
    ) -> Result<Value, &'static str> {
        let artifact_id = opt_str(payload, "artifact_id").ok_or(ERROR_INVALID)?;
        let pending_artifact_hash =
            opt_str(payload, "pending_artifact_hash").ok_or(ERROR_INVALID)?;
        let pending_key = claude_pending_key(session_id, &artifact_id);
        let same_pending = match self.read(&pending_key) {
            Stored::Object(pending) => {
                let artifact_matches = opt_str(&pending, "artifact_hash").as_deref()
                    == Some(pending_artifact_hash.as_str());
                let pending_id_matches = match opt_str(payload, "pending_id") {
                    Some(expected) => {
                        opt_str(&pending, "pending_id").as_deref() == Some(expected.as_str())
                    }
                    None => true,
                };
                artifact_matches && pending_id_matches
            }
            Stored::Absent => false,
            Stored::Unreadable | Stored::InvalidJson | Stored::List => return Err(ERROR_STORE),
        };
        if same_pending && !self.claude_remove_pending(session_id, &pending_key) {
            return Err(ERROR_STORE);
        }
        Ok(json!({ "consumed": true }))
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
        let mut reply = json!({
            "outcome": "save",
            "artifact_id": artifact_id,
            "pending_artifact_hash": opt_str(&pending, "artifact_hash").ok_or(ERROR_INVALID)?,
            "reason": reason,
            "source": SOURCE,
            "plan": serde_json::to_value(plan).map_err(|_| ERROR_INVALID)?,
        });
        if let Some(pending_id) = opt_str(&pending, "pending_id") {
            reply["pending_id"] = json!(pending_id);
        }
        Ok(reply)
    }
}

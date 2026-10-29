//! `queue_native_review`: the paused native review's approval request, built
//! and queued in one store call.
//!
//! `queue_native_pre_tool_review` (`hook_native_review_approval.py`) used to
//! ask the resident for the request (`review_request`), assemble the
//! `GuardApprovalRequest` with its allow hint, and send it back for the queue
//! write. This builds the same request here and rewrites the call into the
//! queue write it used to make:
//!
//! - `add_silent_native_review_approval_request` (with `daemon`) for a review
//!   the agent never sees;
//! - `add_claude_approval_request` for a prompted Claude Code review that
//!   carries its notice's integrity key;
//! - `add_approval_request` otherwise.
//!
//! The rewrite runs before the store opens its write, so the Codex live wait
//! and the read-back behave exactly as for the method it names. The review's
//! extension or connector hint is decided here too, under the snapshot the
//! resident admitted, within the budget the call's `hint` names.
//!
//! A call that names its `respond` also answers the hook response for the row
//! it stored, the paused review or the silent block the hook used to ask the
//! resident for in a call of its own. A reply without its row carries none,
//! and the hook renders it separately.
//!
//! A review held only for non-recognition names the launch it paused in
//! `connector_lookup`. The call asks the `local_cli_hook` operation for the
//! local CLI it launches before the write, as the daemon used to in a
//! resident call of its own: a connector this device never set up queues
//! the row under the connector's group with its setup hint, keeps the
//! review's context with the connector in the queue write's own transaction,
//! and answers the agent with the setup text. The reply names it under
//! `connector_setup` for the notice the daemon raises.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use guard_contracts::{
    GuardStoreRequestV1, LocalCliHookRequestV1, PausedReviewInputsV1, ReviewRequestQueryV1,
    SilentReviewBlockInputsV1, LOCAL_CLI_HOOK_REQUEST_SCHEMA, MAX_NATIVE_RESPONSE_BYTES,
};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use zeroize::Zeroize;

use crate::guard_store_args::Args;
use crate::guard_store_connector_context::{record_context, scrub_context_text, MAX_SUMMARY_CHARS};
use crate::guard_store_db::{StoreError, StoreResult};
use crate::hook_adapter_op::review_request::{self, pre_tool_command};
use crate::hook_decision_review_response::{paused_review, silent_review_block};
use crate::hook_direct::saved_decision::review_hint::op::queued_hint;
use crate::hook_direct::saved_decision::review_queue::connector::{first_blocked_cause, Connector};
use crate::policy_store::PolicySnapshotStore;

pub(crate) const METHOD: &str = "queue_native_review";

const INVALID: StoreError = StoreError::Invalid("native_guard_store_review_queue_invalid");
/// The resident could not build the review's request from a well-formed
/// query; the hook fails closed and logs this code.
const REFUSED: StoreError = StoreError::Invalid("native_guard_store_review_request_refused");
/// What the notice reads from the hook payload besides the command: the
/// session and the tool name fields.
const NOTICE_PAYLOAD_FIELDS: [&str; 4] = ["session_id", "tool_name", "toolName", "tool"];
/// What the call keeps after the hint for the queue write and its reply, as
/// the daemon kept when it asked for the hint itself.
const WRITE_RESERVE_MS: u64 = 350;
/// The most the connector lookup waits for the store lock, as the direct
/// lane's own lookup does; the queue write keeps the rest of the call.
const LOOKUP_BUSY_TIMEOUT_MS: u64 = 250;
/// The most a stored-row reply carrying its rendered response may encode to,
/// leaving room for the resident's reply envelope.
const REPLY_BUDGET_BYTES: usize = MAX_NATIVE_RESPONSE_BYTES - 128 * 1024;
/// The least time an extension hint is worth starting with
/// (`_MIN_BUDGET_SECONDS`); a connector's setup hint needs none.
const MIN_HINT_BUDGET_MS: u64 = 150;
/// The `local_cli_hook` action the lookup refines.
const REVIEW_ACTION: &str = "review";

/// The hint a call asks for: how long the daemon can wait for it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HintAsk {
    budget_ms: u32,
}

/// The launch a non-recognition review paused, as the daemon's
/// `local_cli_setup_connector` named it to the resident.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LookupAsk {
    command: String,
    cwd: String,
    home_dir: Option<String>,
    user_home: String,
    /// The daemon's environment with the agent's `PATH` (`_launch_env`).
    env: BTreeMap<String, String>,
}

impl LookupAsk {
    /// The `local_cli_hook` request for this launch, bound to the store the
    /// call names. Its store waits never reach into the write's reserve.
    pub(crate) fn request(self, store: &GuardStoreRequestV1) -> LocalCliHookRequestV1 {
        let busy_timeout_ms = store
            .busy_timeout_ms
            .saturating_sub(WRITE_RESERVE_MS)
            .clamp(1, LOOKUP_BUSY_TIMEOUT_MS);
        LocalCliHookRequestV1 {
            schema: LOCAL_CLI_HOOK_REQUEST_SCHEMA.to_owned(),
            request_id: format!("local-cli-hook-{}", store.request_id),
            store_path: store.store_path.clone(),
            guard_home: store.guard_home.clone(),
            source: store.source.clone(),
            busy_timeout_ms,
            command: self.command,
            cwd: self.cwd,
            home_dir: self.home_dir,
            user_home: self.user_home,
            env: self.env,
            current_action: REVIEW_ACTION.to_owned(),
            current_reason_code: None,
            grant_allowed: true,
        }
    }
}

/// The hook response a call asks for with the stored row.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RespondAsk {
    /// A prompted review.
    PausedReview(PausedAsk),
    /// A review the agent never sees.
    SilentReviewBlock(SilentAsk),
}

/// A prompted review takes everything it says from the review and its row.
/// An older daemon also names the setup text it looked up; this call looks
/// the connector up itself, so any field is ignored.
#[derive(Deserialize)]
struct PausedAsk {}

/// The silent block's facts that do not come from the review or its row.
/// The daemon also names the setup and binding facts an older resident
/// renders from; this call derives them from the review and its own lookup,
/// so any other field is ignored.
#[derive(Deserialize)]
struct SilentAsk {
    ask: bool,
    home_dir: String,
}

/// What the response is rendered from besides the stored row.
struct Respond {
    ask: RespondAsk,
    harness: String,
    result: Map<String, Value>,
    /// The connector's setup text in place of the review's.
    setup_reason: Option<String>,
    retry_reuses_approval: bool,
    exact_action_allowable: bool,
    connector_is_local: bool,
}

/// The queue write a `queue_native_review` call stands for.
pub(crate) struct Delegated {
    pub(crate) method: &'static str,
    pub(crate) args: Map<String, Value>,
    respond: Option<Respond>,
    /// The connector context to keep once the row is stored, all but the
    /// row's own wording.
    context: Option<Map<String, Value>>,
    /// What the reply says of the connector the review waits on.
    connector_setup: Option<Value>,
}

impl Drop for Delegated {
    /// Wipe this copy of the notice key the call carried.
    fn drop(&mut self) {
        if let Some(Value::String(key)) = self.args.get_mut("integrity_key_b64") {
            key.zeroize();
        }
    }
}

/// The queue method and arguments a `queue_native_review` call stands for.
///
/// `call_budget_ms` is the call's own busy budget: the hint never spends the
/// part of it the queue write needs. `look_up` names the connector a
/// non-recognition review's launch waits on.
pub(crate) fn delegate(
    args: &Map<String, Value>,
    owner: Option<&PolicySnapshotStore>,
    call_budget_ms: u64,
    look_up: impl FnOnce(LookupAsk) -> Option<Connector>,
) -> StoreResult<Delegated> {
    let started = Instant::now();
    let mut delegated = args.clone();
    let mut query: ReviewRequestQueryV1 =
        serde_json::from_value(delegated.remove("review").ok_or(INVALID)?).map_err(|_| INVALID)?;
    let ask: Option<HintAsk> = take_ask(&mut delegated, "hint")?;
    let respond: Option<RespondAsk> = take_ask(&mut delegated, "respond")?;
    let lookup: Option<LookupAsk> = take_ask(&mut delegated, "connector_lookup")?;
    let silent = take_flag(&mut delegated, "silent")?;
    let claude_notice = take_flag(&mut delegated, "claude_notice")?;
    let silent_response = matches!(respond, Some(RespondAsk::SilentReviewBlock(_)));
    if (silent && claude_notice) || (respond.is_some() && silent_response != silent) {
        return Err(INVALID);
    }
    let reason_code = query
        .result
        .get("reason_code")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let reason_code = reason_code.as_deref();
    // Any other review code carries a risk signal and keeps its per-action
    // review, whatever the launch. A call with no time beyond the write's
    // reserve skips the lookup and queues an ordinary review.
    let connector = lookup
        .filter(|_| crate::connector_setup::is_non_recognition(reason_code))
        .filter(|_| call_budget_ms > WRITE_RESERVE_MS)
        .and_then(look_up);
    if let Some(connector) = &connector {
        query.queue_group_id = Some(connector.queue_group_id().to_owned());
    }
    let built = review_request::build(&query).map_err(|_| REFUSED)?;
    let paused = query.result.as_object().ok_or(INVALID)?;
    // The hint is advisory: whatever it cannot decide in time is left out,
    // and the review queues regardless.
    let connector_value = connector.as_ref().map(Connector::to_value);
    let hint = ask.and_then(|ask| {
        let spent = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let budget_ms = u64::from(ask.budget_ms)
            .min(call_budget_ms.saturating_sub(WRITE_RESERVE_MS))
            .saturating_sub(spent);
        let least = if connector.is_some() {
            1
        } else {
            MIN_HINT_BUDGET_MS
        };
        if budget_ms < least {
            return None;
        }
        queued_hint(
            owner,
            &built.fields,
            query.envelope.workspace.as_deref().unwrap_or_default(),
            query.envelope.home_dir.as_deref().unwrap_or_default(),
            paused,
            connector_value.as_ref(),
            u32::try_from(budget_ms).unwrap_or(u32::MAX),
        )
    });
    let mut request = built.request;
    request.insert(
        "extension_allow_hint".to_owned(),
        hint.unwrap_or(Value::Null),
    );
    let method = if silent {
        delegated.insert("daemon".to_owned(), Value::Bool(true));
        "add_silent_native_review_approval_request"
    } else if claude_notice && delegated.contains_key("integrity_key_b64") {
        let review = notice_review(&query, &request, &built.fields);
        delegated.insert("claude_review".to_owned(), review);
        "add_claude_approval_request"
    } else {
        // Without a key the review still queues; the hook falls back to its
        // ordinary prompt.
        delegated.remove("integrity_key_b64");
        delegated.remove("integrity_key_id");
        "add_approval_request"
    };
    delegated.insert("request".to_owned(), Value::Object(request));
    let context = connector.as_ref().map(|connector| {
        let workspace = query.envelope.workspace.as_deref().map(Path::new);
        let label = workspace
            .and_then(Path::file_name)
            .map(|name| name.to_string_lossy());
        let mut context = Map::new();
        context.insert("cli_id".to_owned(), json!(connector.cli_id()));
        context.insert("identity_hash".to_owned(), json!(connector.identity_hash()));
        context.insert(
            "first_blocked_cause".to_owned(),
            json!(first_blocked_cause(reason_code)),
        );
        context.insert("harness".to_owned(), json!(query.envelope.harness));
        context.insert("workspace_label".to_owned(), json!(label));
        context.insert(
            "observed_at".to_owned(),
            delegated.get("now").cloned().unwrap_or(Value::Null),
        );
        context
    });
    // Approving a row bound to neither the retry nor an exact-action Always
    // cannot let the agent run the action, so the setup text never sends the
    // user there.
    let (bound, exact) = (query.review_binding.is_some(), query.exact_token.is_some());
    let setup_reason = |ask: bool| connector.as_ref().and_then(|c| c.reason(ask, bound, exact));
    let respond = respond.map(|ask| Respond {
        setup_reason: setup_reason(match &ask {
            RespondAsk::PausedReview(_) => true,
            RespondAsk::SilentReviewBlock(silent) => silent.ask,
        }),
        ask,
        harness: query.envelope.harness.clone(),
        result: paused.clone(),
        retry_reuses_approval: bound,
        exact_action_allowable: exact,
        connector_is_local: connector.as_ref().is_some_and(Connector::is_local),
    });
    let connector_setup = connector.as_ref().map(|connector| {
        json!({
            "name": connector.display_name(),
            "is_local": connector.is_local(),
            "setup_reason": respond.as_ref().and_then(|respond| respond.setup_reason.clone()),
        })
    });
    Ok(Delegated {
        method,
        context,
        connector_setup,
        args: delegated,
        respond,
    })
}

impl Delegated {
    /// Keep the queued review's context with the connector it waits on, on the
    /// queue write's own connection. Best effort, as the daemon's separate
    /// call was: the review is queued whether or not this keeps anything. The
    /// row's wording is kept only when it repeats no argument of the command.
    /// A context the store refuses answers its failure code for the daemon's log.
    pub(crate) fn record_connector_context(
        &self,
        connection: &Connection,
        reply: &Value,
    ) -> Option<&'static str> {
        let context = self.context.as_ref()?;
        let row = reply.get("row").and_then(Value::as_object)?;
        let command = row.get("raw_command_text").and_then(Value::as_str);
        let mut args = context.clone();
        for key in ["trigger_summary", "why_now"] {
            let text = row.get(key).and_then(Value::as_str);
            let kept = without_operands(text, command)
                .and_then(|text| scrub_context_text(text, MAX_SUMMARY_CHARS));
            args.insert(key.to_owned(), json!(kept));
        }
        record_context(connection, &Args(&args))
            .err()
            .map(|error| error.code())
    }

    /// `reply` with the hook response rendered from the row it stored, under
    /// `response`, and the connector the review waits on, under
    /// `connector_setup`. A reply without its row, a block the resident
    /// cannot compose, or a response that would not fit the reply frame
    /// carries no response and the hook renders separately.
    pub(crate) fn with_response(&self, mut reply: Value, guard_home: &str) -> Value {
        if let (Some(setup), Some(object)) = (&self.connector_setup, reply.as_object_mut()) {
            object.insert("connector_setup".to_owned(), setup.clone());
        }
        let Some(respond) = &self.respond else {
            return reply;
        };
        let Some(row) = reply.get("row").and_then(Value::as_object) else {
            return reply;
        };
        let text = |key: &str| row.get(key).and_then(Value::as_str).map(str::to_owned);
        let (request_id, approval_url) = (text("request_id"), text("approval_url"));
        let response = match &respond.ask {
            RespondAsk::PausedReview(PausedAsk {}) => {
                let mut verdict = respond.result.clone();
                if let Some(reason) = &respond.setup_reason {
                    verdict.insert("reason".to_owned(), Value::String(reason.clone()));
                }
                // The renderer reads only the link and the request id.
                let approval = [("approval_url", approval_url), ("request_id", request_id)]
                    .into_iter()
                    .filter_map(|(key, value)| Some((key.to_owned(), Value::String(value?))))
                    .collect();
                paused_review(&PausedReviewInputsV1 {
                    harness: respond.harness.clone(),
                    verdict,
                    approval: Some(approval),
                    guard_home: guard_home.to_owned(),
                })
                .response
            }
            RespondAsk::SilentReviewBlock(ask) => {
                let inputs = SilentReviewBlockInputsV1 {
                    harness: respond.harness.clone(),
                    result: respond.result.clone(),
                    setup_reason: respond.setup_reason.clone(),
                    queued: true,
                    request_id,
                    approval_url,
                    ask: ask.ask,
                    retry_reuses_approval: respond.retry_reuses_approval,
                    exact_action_allowable: respond.exact_action_allowable,
                    connector_is_local: respond.connector_is_local,
                    guard_home: guard_home.to_owned(),
                    home_dir: ask.home_dir.clone(),
                };
                match silent_review_block(&inputs) {
                    Ok(block) => block.response,
                    Err(_) => return reply,
                }
            }
        };
        let response = Value::Object(response);
        if encoded_len(&response) + encoded_len(&reply) > REPLY_BUDGET_BYTES {
            return reply;
        }
        if let Some(object) = reply.as_object_mut() {
            object.insert("response".to_owned(), response);
        }
        reply
    }
}

fn encoded_len(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len())
}

/// `text` unless it repeats an argument of `command` (`_without_operands`).
/// Arguments split as Python's `str.split()` does.
fn without_operands<'a>(text: Option<&'a str>, command: Option<&str>) -> Option<&'a str> {
    let text = text.filter(|text| !text.trim().is_empty())?;
    let separator = |c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c);
    let mut operands = command.into_iter().flat_map(|command| {
        command
            .split(separator)
            .filter(|part| !part.is_empty())
            .skip(1)
    });
    (!operands.any(|operand| text.contains(operand))).then_some(text)
}

/// The ask a call names under `key`, or `None` when it names none.
fn take_ask<T: serde::de::DeserializeOwned>(
    args: &mut Map<String, Value>,
    key: &str,
) -> StoreResult<Option<T>> {
    match args.remove(key) {
        None | Some(Value::Null) => Ok(None),
        Some(ask) => serde_json::from_value(ask).map(Some).map_err(|_| INVALID),
    }
}

fn take_flag(args: &mut Map<String, Value>, key: &str) -> StoreResult<bool> {
    match args.remove(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(flag)) => Ok(flag),
        Some(_) => Err(INVALID),
    }
}

/// The `claude_review` facts `add_claude_approval_request` signs a notice
/// from. The hook payload carries only what the notice reads, so the command
/// is not copied in full a second time.
fn notice_review(
    query: &ReviewRequestQueryV1,
    request: &Map<String, Value>,
    fields: &Map<String, Value>,
) -> Value {
    let mut hook_payload: Map<String, Value> = NOTICE_PAYLOAD_FIELDS
        .iter()
        .filter_map(|name| Some(((*name).to_owned(), fields.get(*name)?.clone())))
        .collect();
    if let Some(command) = pre_tool_command(fields) {
        hook_payload.insert("tool_input".to_owned(), json!({ "command": command }));
    }
    json!({
        "harness": query.envelope.harness,
        "hook_payload": hook_payload,
        "reason": query.result.get("reason").cloned().unwrap_or(Value::Null),
        "review_binding": query.review_binding,
        "config_path": request.get("config_path").cloned().unwrap_or(Value::Null),
        "source_scope": request.get("source_scope").cloned().unwrap_or(Value::Null),
    })
}

#[cfg(test)]
#[path = "guard_store_native_review_queue_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "guard_store_native_review_queue_context_tests.rs"]
mod context_tests;

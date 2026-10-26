//! The daemon's approval request for a reviewed `PreToolUse` it pauses.
//!
//! When neither a saved exact-action decision nor an approve-once answers a
//! review, `pause_native_pre_tool_for_approval`
//! (`hook_native_review_approval.py`) queues the action in the approval inbox
//! and pauses the hook with a link to it. This ports that last step.
//!
//! For a home whose blocked-request mode is `ask`:
//!
//! - `queue_native_pre_tool_review`, with the request the review-request
//!   builder derives from the facts the daemon published, written by the same
//!   `add_native_review_approval_request` store operation under the shared
//!   storage gate;
//! - `render_pre_tool_review` (`hook_fail_closed.py`), with the approval link
//!   `native_review_reason` (`approval_link_output.py`) signs;
//! - the `prompted` and `approval_center_url` marks the daemon records the
//!   activity with;
//! - for Claude Code, the permission notice the daemon worker then records
//!   (`record_claude_permission_notice_for_native_review`), written with the
//!   request by `add_claude_native_review_approval_request` in one
//!   transaction.
//!
//! Any other mode keeps the agent on the silent block (`asks_for_approval` is
//! false): the same request and its `approval.created` event
//! (`_record_silent_native_review_event`) are written together by
//! `add_silent_native_review_approval_request`, and the hook answers with the
//! `render_pre_tool` block whose reason `safe_alternative_reason` writes.
//!
//! A review due only to non-recognition of a launch of a local CLI this
//! device has not set up is queued as a connector-setup review
//! (`hook_direct_review_connector.rs`): grouped under the connector with its
//! setup hint, and shown to the agent with the setup reason. The desktop setup
//! notice for it travels to the evidence drain with the hook's evidence.
//!
//! A package review is queued only when `native_package_review_response`
//! provably leaves it to the queue (`hook_direct_review_package.rs`).
//!
//! A paused Cursor review is queued only when its link reaches the agent
//! unchanged: Cursor's hook client signs a loopback link itself, and only
//! when its interpreter can import Guard (`_cursor_reason`).
//!
//! Every other shape defers, so the daemon still answers the hook: a missing
//! fact, a package review the daemon may settle, a Claude Code notice the
//! bound key cannot sign, a Cursor pause whose link its client may sign, and
//! any request or write the resident could not reproduce.

use super::consume::{repair_store_permissions, storage_gate};
use super::review_request::{build, ExactKeys, RequestInput};
use super::{Context, HookDirectDefer, ENVELOPE_BYTES, ESCAPE_FACTOR};
use crate::guard_store_approval_request::rewrite_approval_url;
use crate::local_store_read::STORE_FILE_NAME;
use guard_command::hook_responses::{pre_tool_review, Object};
use guard_contracts::{
    GuardStoreRequestV1, NativeExactActionQueryV1, GUARD_STORE_REQUEST_SCHEMA,
    HOOK_RENDER_MAX_BYTES,
};
use serde_json::{json, Map, Value};
use std::path::Path;
use zeroize::Zeroize;

const WRITE_METHOD: &str = "add_native_review_approval_request";
const SILENT_WRITE_METHOD: &str = "add_silent_native_review_approval_request";
const CLAUDE_WRITE_METHOD: &str = "add_claude_native_review_approval_request";
/// `asks_for_approval`: the mode that pauses the hook for the inbox.
const ASK_MODE: &str = "ask";
/// The harness whose paused review also records a permission notice.
const CLAUDE_CODE: &str = "claude-code";
/// The harness whose hook client rewrites the approval link itself.
const CURSOR: &str = "cursor";
/// The mode the daemon records a silent block with.
const SAFE_ALTERNATIVE_MODE: &str = "safe-alternative";
/// The silent block's reason when the review gave none.
const BLOCKED_REASON: &str = "HOL Guard blocked this action.";
/// `_REVIEW_DEFAULT_REASON` (`hook_fail_closed.py`).
const DEFAULT_REASON: &str = "HOL Guard requires review before this action can execute.";
/// A hook waits this long for a busy store before the daemon takes over.
const BUSY_TIMEOUT_MS: u64 = 250;

/// The facts a queued review needs, or `None` when the daemon pauses it.
struct Facts<'a> {
    /// `asks_for_approval`.
    ask: bool,
    origin: &'a str,
    oauth_source: &'a str,
    host_cwd: &'a str,
    environment: &'a std::collections::BTreeMap<String, String>,
}

/// The paused review response for an action the resident queued itself, and
/// the connector-setup notice the evidence drain raises for it, if any.
pub(super) fn answer(
    context: &Context<'_>,
    result: &Object,
    receipt: Option<&Value>,
    exact: &NativeExactActionQueryV1,
    token: &Result<String, &'static str>,
) -> Result<(Value, Option<Value>), HookDirectDefer> {
    let facts = facts(context, result).ok_or(HookDirectDefer::ReviewQueue)?;
    let review_binding = crate::native_exact_action_op::review_binding_for(
        exact,
        receipt,
        context
            .recorded_payload
            .get(crate::hook_direct::EXECUTION_ENVIRONMENT_FIELD),
    );
    let request_id = request_id().ok_or(HookDirectDefer::ReviewQueue)?;
    let input = RequestInput {
        harness: context.harness,
        payload: context.recorded_payload,
        workspace: context.workspace,
        home_dir: context.home_dir,
        environment: facts.environment,
        host_cwd: Some(facts.host_cwd),
        request_id: &request_id,
        approval_center_url: facts.origin,
        review_binding: review_binding.as_deref(),
        exact: match token {
            Ok(token) => ExactKeys::Token(token),
            Err(reason) => ExactKeys::OnceOnly(reason),
        },
        hint: context.hint,
    };
    let request = build(&input, result, receipt).ok_or(HookDirectDefer::ReviewQueue)?;
    let lookup = connector::prepare(context, result, facts.environment, facts.oauth_source)?;
    let bound = review_binding.is_some();
    if !facts.ask || (!bound && token.is_err()) {
        return silent(
            context,
            result,
            facts.oauth_source,
            request,
            Flags {
                ask: facts.ask,
                retry_reuses_approval: bound,
                exact_action_allowable: token.is_ok(),
            },
            lookup,
        );
    }
    let approval_url = request
        .get("approval_url")
        .and_then(Value::as_str)
        .ok_or(HookDirectDefer::ReviewQueue)?
        .to_owned();
    // Cursor's hook client signs a loopback link with Guard's Python only
    // when it can import it, which its bridge cannot know; such a pause stays
    // with the daemon so the bridge never has to hand a queued hook back.
    if canonical_harness(context.harness) == CURSOR
        && !crate::native_review_link::review_url_stays_unsigned(
            &approval_url,
            Path::new(context.guard_home),
        )
    {
        return Err(HookDirectDefer::ReviewQueue);
    }
    let exact_action_allowable = token.is_ok();
    let auth_token =
        crate::daemon_policy_authority::load_guard_daemon_auth_token(Path::new(context.guard_home));
    // `render_pre_tool_review` with the agent text: the review's own reason,
    // or the connector-setup reason in its place.
    let pause = |setup_reason: Option<&str>, request_id: &str, approval_url: &str| {
        let shown = match setup_reason {
            Some(text) => {
                let mut shown = result.clone();
                shown.insert("reason".to_owned(), json!(text));
                std::borrow::Cow::Owned(shown)
            }
            None => std::borrow::Cow::Borrowed(result),
        };
        let reason = match shown.get("reason") {
            Some(Value::String(text)) if !text.is_empty() => text.as_str(),
            _ => DEFAULT_REASON,
        };
        let linked = crate::native_review_link::native_review_reason(
            &canonical_harness(context.harness),
            reason,
            approval_url,
            auth_token.as_deref(),
            now_micros()?,
        )?;
        respond(
            context.harness,
            &shown,
            request_id,
            approval_url,
            &linked,
            facts.origin,
        )
    };
    // Render the pause before writing, so a pause the resident cannot render
    // leaves the queue to the daemon rather than recording the hook twice. A
    // review the lookup may give a connector also renders with the longest
    // setup reason it could get.
    pause(None, &request_id, &approval_url).ok_or(HookDirectDefer::ReviewQueue)?;
    if lookup.is_some() {
        if let Some(longest) = connector::longest_reason(true, bound, exact_action_allowable) {
            pause(Some(longest.as_str()), &request_id, &approval_url)
                .ok_or(HookDirectDefer::ReviewQueue)?;
        }
    }
    let (method, extra) = store_method(context, result, review_binding.as_deref())?;
    let setup = run_lookup(context, lookup)?;
    let request = queued_request(context, result, request, setup.as_ref());
    let stored_id = write(context, method, facts.oauth_source, request, extra)?;
    let notice = setup
        .as_ref()
        .map(|setup| setup.stored(context, facts.oauth_source, &stored_id));
    let setup_reason = setup
        .as_ref()
        .and_then(|setup| setup.reason(true, bound, exact_action_allowable));
    // A pending request for the same action keeps its id, so a pause the
    // resident still cannot render leaves the daemon to queue the same request.
    let approval_url = rewrite_approval_url(&approval_url, &stored_id);
    let response = pause(setup_reason.as_deref(), &stored_id, &approval_url)
        .ok_or(HookDirectDefer::ReviewQueue)?;
    Ok((response, notice))
}

/// How a silent block may point at its row.
struct Flags {
    /// `asks_for_approval`.
    ask: bool,
    retry_reuses_approval: bool,
    exact_action_allowable: bool,
}

/// The connector a prepared lookup names. It records the launch, so it runs
/// only once nothing but the write and the evidence offer can defer, and only
/// while the evidence queue has room for the hook's record: a record the
/// queue refuses hands the hook to the daemon, which would look it up again.
fn run_lookup(
    context: &Context<'_>,
    lookup: Option<connector::Lookup>,
) -> Result<Option<connector::Setup>, HookDirectDefer> {
    let Some(lookup) = lookup else {
        return Ok(None);
    };
    if context
        .hint
        .is_some_and(|scope| !scope.policy_store.direct_evidence().has_headroom())
    {
        return Err(HookDirectDefer::EvidenceFull);
    }
    lookup.run(context.guard_home)
}

/// The request as it is stored: grouped under its connector with the setup
/// hint, or with the extension hints the review settles.
fn queued_request(
    context: &Context<'_>,
    result: &Object,
    request: Value,
    setup: Option<&connector::Setup>,
) -> Value {
    match setup {
        Some(setup) => setup.apply(request),
        None => super::review_hint::settle(context, result, request),
    }
}

/// The store operation that queues an `ask` review, with its other
/// arguments. The daemon worker records a paused Claude Code review's
/// permission notice once it is queued; both are written in one transaction.
fn store_method(
    context: &Context<'_>,
    result: &Object,
    review_binding: Option<&str>,
) -> Result<(&'static str, Map<String, Value>), HookDirectDefer> {
    let mut extra = Map::new();
    if canonical_harness(context.harness) == CLAUDE_CODE {
        if let Some(notice) = notice::store_args(context, result, review_binding)? {
            extra.insert("claude_notice".to_owned(), notice);
        }
    }
    let method = if extra.is_empty() {
        WRITE_METHOD
    } else {
        CLAUDE_WRITE_METHOD
    };
    Ok((method, extra))
}

/// `str(value or fallback)` for the values the resident reproduces: a string,
/// or a falsy `None`, `False` or `""`. Anything else defers.
fn falsy_or_text<'a>(
    value: Option<&'a Value>,
    fallback: &'a str,
) -> Result<&'a str, HookDirectDefer> {
    match value {
        None | Some(Value::Null) | Some(Value::Bool(false)) => Ok(fallback),
        Some(Value::String(text)) if text.is_empty() => Ok(fallback),
        Some(Value::String(text)) => Ok(text),
        Some(_) => Err(HookDirectDefer::ReviewQueue),
    }
}

/// The published facts for a review the resident may queue.
fn facts<'a>(context: &Context<'a>, result: &Object) -> Option<Facts<'a>> {
    let binding = context.binding;
    let review = &binding.review;
    let mode = review.blocked_request_mode.as_deref()?;
    // `native_package_review_response` may settle a package review first.
    if !package::left_to_queue(context.recorded_payload, result) {
        return None;
    }
    // `_native_review_artifact_id` names the notice's artifact with the
    // harness as the daemon received it; another spelling stays with it.
    if context.harness != CLAUDE_CODE && canonical_harness(context.harness) == CLAUDE_CODE {
        return None;
    }
    Some(Facts {
        ask: mode == ASK_MODE,
        origin: review.approval_center_origin.as_deref()?,
        oauth_source: review.review_oauth_source.as_deref()?,
        host_cwd: review.review_host_cwd.as_deref()?,
        environment: &binding.exact_action_environment.as_ref()?.0,
    })
}

/// `add_approval_request` through the daemon's store operation: the stored
/// request id, which is an earlier pending request's for the same action.
/// `extra` holds the method's other arguments.
fn write(
    context: &Context<'_>,
    method: &str,
    oauth_source: &str,
    request: Value,
    extra: Map<String, Value>,
) -> Result<String, HookDirectDefer> {
    let guard_home = Path::new(context.guard_home);
    let now = super::super::lifecycle::utc_now_isoformat();
    let gate = storage_gate(guard_home).ok();
    let (Some(now), Some(_gate)) = (now, gate) else {
        forget_key(extra);
        return Err(HookDirectDefer::ReviewQueue);
    };
    let mut args = extra;
    args.insert("request".to_owned(), request);
    args.insert("now".to_owned(), json!(now));
    let store_request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "direct-hook-review-queue".to_owned(),
        store_path: guard_home
            .join(STORE_FILE_NAME)
            .to_string_lossy()
            .into_owned(),
        guard_home: context.guard_home.to_owned(),
        method: method.to_owned(),
        source: oauth_source.to_owned(),
        busy_timeout_ms: BUSY_TIMEOUT_MS,
        args,
    };
    let written = crate::guard_store_op::evaluate(&store_request).map(|(payload, _)| payload);
    forget_key(store_request.args);
    repair_store_permissions(guard_home);
    match written {
        Ok(Value::String(request_id)) if !request_id.is_empty() => Ok(request_id),
        _ => Err(HookDirectDefer::ReviewQueue),
    }
}

/// Wipe the bound key a Claude notice carried to the store operation.
fn forget_key(mut args: Map<String, Value>) {
    if let Some(Value::String(key)) = args
        .get_mut("claude_notice")
        .and_then(|notice| notice.get_mut("integrity_key_b64"))
    {
        key.zeroize();
    }
}

/// `render_pre_tool_review` for the queued request, marked as the daemon
/// marks a paused review, or `None` when the daemon's render request could
/// exceed its size limit.
fn respond(
    harness: &str,
    result: &Object,
    request_id: &str,
    approval_url: &str,
    linked_reason: &str,
    approval_center_url: &str,
) -> Option<Value> {
    let mut approval = Object::new();
    approval.insert("request_id".to_owned(), json!(request_id));
    approval.insert("approval_url".to_owned(), json!(approval_url));
    let encoded = serde_json::to_vec(result).ok()?.len()
        + serde_json::to_vec(&approval).ok()?.len()
        + linked_reason.len()
        + harness.len();
    if encoded * ESCAPE_FACTOR + ENVELOPE_BYTES > HOOK_RENDER_MAX_BYTES {
        return None;
    }
    let mut response = pre_tool_review(harness, result, Some(&approval), Some(linked_reason));
    response.insert("prompted".to_owned(), json!(true));
    response.insert("approval_center_url".to_owned(), json!(approval_center_url));
    Some(Value::Object(response))
}

/// `canonical_harness` (`hook_fail_closed.py`).
fn canonical_harness(harness: &str) -> String {
    crate::guard_store_json::py_strip(harness)
        .to_lowercase()
        .replace('_', "-")
}

/// `uuid.uuid4().hex`.
fn request_id() -> Option<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).ok()?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Some(hex::encode(bytes))
}

fn now_micros() -> Option<i64> {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_micros();
    i64::try_from(micros).ok()
}

#[path = "hook_direct_review_silent.rs"]
mod blocked;
use blocked::silent;

#[path = "hook_direct_review_connector.rs"]
mod connector;

#[path = "hook_direct_review_notice.rs"]
mod notice;

#[path = "hook_direct_review_package.rs"]
mod package;

#[cfg(test)]
#[path = "hook_direct_review_queue_tests.rs"]
mod tests;

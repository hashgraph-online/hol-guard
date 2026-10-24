//! The `safe-alternative` block a silent review answers with, once the
//! request is queued with its `approval.created` event. Part of the
//! resident's review queue (`hook_direct_review_queue.rs`).

use super::super::{Context, HookDirectDefer, ENVELOPE_BYTES, ESCAPE_FACTOR};
use super::{
    canonical_harness, connector, falsy_or_text, now_micros, queued_request, run_lookup, write,
    Flags, BLOCKED_REASON, SAFE_ALTERNATIVE_MODE, SILENT_WRITE_METHOD,
};
use crate::blocked_request_mode::safe_alternative_reason_with_retry;
use crate::guard_store_approval_request::rewrite_approval_url;
use guard_command::hook_responses::{pre_tool, Object};
use guard_contracts::HOOK_RENDER_MAX_BYTES;
use serde_json::{json, Map, Value};
use std::path::Path;

/// The silent block for a request queued with its `approval.created` event,
/// and the connector-setup notice the evidence drain raises for it, if any.
pub(super) fn silent(
    context: &Context<'_>,
    result: &Object,
    oauth_source: &str,
    request: Value,
    flags: Flags,
    lookup: Option<connector::Lookup>,
) -> Result<(Value, Option<Value>), HookDirectDefer> {
    let Flags {
        ask,
        retry_reuses_approval,
        exact_action_allowable,
    } = flags;
    let reason = falsy_or_text(result.get("reason"), BLOCKED_REASON)?;
    let reason_code = falsy_or_text(result.get("reason_code"), "unknown")?;
    let safe_reason = safe_alternative_reason_with_retry(
        reason,
        Some(reason_code),
        Some(true),
        retry_reuses_approval,
        exact_action_allowable,
    );
    // The unlinked block renders before the write, so a block the resident
    // cannot render leaves the queue to the daemon. A review the lookup may
    // give a connector also renders with the longest setup reason it could get.
    let unlinked =
        silent_block(context.harness, result, &safe_reason).ok_or(HookDirectDefer::ReviewQueue)?;
    if lookup.is_some() {
        if let Some(longest) =
            connector::longest_reason(ask, retry_reuses_approval, exact_action_allowable)
        {
            silent_block(context.harness, result, &longest).ok_or(HookDirectDefer::ReviewQueue)?;
        }
    }
    let setup = run_lookup(context, lookup)?;
    let setup_reason = setup
        .as_ref()
        .and_then(|setup| setup.reason(ask, retry_reuses_approval, exact_action_allowable));
    let unlinked = match &setup_reason {
        Some(text) => {
            silent_block(context.harness, result, text).ok_or(HookDirectDefer::ReviewQueue)?
        }
        None => unlinked,
    };
    let reason = setup_reason.unwrap_or(safe_reason);
    // Approving a row that is neither bound to the retry nor eligible for an
    // exact-action Always cannot let the agent run the action, so the reason
    // does not send the user to approve it; nor does an MCP setup reason in
    // the default mode.
    let approval_url = request
        .get("approval_url")
        .and_then(Value::as_str)
        .filter(|_| {
            connector::links(
                setup.as_ref(),
                ask,
                retry_reuses_approval,
                exact_action_allowable,
            )
        })
        .map(str::to_owned);
    let request = queued_request(context, result, request, setup.as_ref());
    let stored_id = write(
        context,
        SILENT_WRITE_METHOD,
        oauth_source,
        request,
        Map::new(),
    )?;
    let notice = setup
        .as_ref()
        .map(|setup| setup.stored(context, oauth_source, &stored_id));
    let hint = if retry_reuses_approval {
        crate::blocked_request_mode::approval_wait_hint_for_home(
            &stored_id,
            context.guard_home,
            context.home_dir,
        )
    } else {
        String::new()
    };
    let reason = if hint.is_empty() {
        reason
    } else {
        format!("{reason} {hint}")
    };
    // Diagnostics must not crowd the notification out of a hook protocol
    // that drops extra fields. A compact block preserves the wait command.
    let unlinked = silent_block(context.harness, result, &reason)
        .or_else(|| {
            silent_block(
                context.harness,
                &Map::new(),
                &format!("HOL Guard paused this action. {hint}"),
            )
        })
        .unwrap_or(unlinked);
    // The request is queued now, so a link that cannot be added keeps the
    // unlinked block rather than handing the hook back.
    let linked = approval_url.and_then(|url| {
        let url = rewrite_approval_url(&url, &stored_id);
        let auth_token = crate::daemon_policy_authority::load_guard_daemon_auth_token(Path::new(
            context.guard_home,
        ));
        let reason = crate::native_review_link::native_review_reason(
            &canonical_harness(context.harness),
            &reason,
            &url,
            auth_token.as_deref(),
            now_micros()?,
        )?;
        silent_block(context.harness, result, &reason)
    });
    let mut blocked = linked.unwrap_or(unlinked);
    // Extensions can watch the handle; other harnesses see the read-only wait
    // command in their reason. Only a bound retry gets this notification.
    if retry_reuses_approval {
        blocked.insert(
            "approval_resume".to_owned(),
            json!({"request_id": stored_id, "poll_path": format!("/v1/requests/{stored_id}")}),
        );
    }
    Ok((Value::Object(blocked), notice))
}

/// The `safe-alternative` block for `reason`, or `None` when the daemon's
/// render request could exceed its size limit.
pub(super) fn silent_block(harness: &str, result: &Object, reason: &str) -> Option<Object> {
    let mut blocked = result.clone();
    blocked.insert("decision".to_owned(), json!("deny"));
    blocked.insert("minimum_action".to_owned(), json!("block"));
    blocked.insert("policy_action".to_owned(), json!("block"));
    blocked.insert("reason".to_owned(), json!(reason));
    let encoded = serde_json::to_vec(&blocked).ok()?.len() + harness.len();
    if encoded * ESCAPE_FACTOR + ENVELOPE_BYTES > HOOK_RENDER_MAX_BYTES {
        return None;
    }
    let mut response = pre_tool(harness, &blocked);
    response.insert("prompted".to_owned(), json!(false));
    response.insert(
        "blocked_request_mode".to_owned(),
        json!(SAFE_ALTERNATIVE_MODE),
    );
    Some(response)
}

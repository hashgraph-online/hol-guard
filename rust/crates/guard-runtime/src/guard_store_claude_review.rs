//! `add_claude_native_review_approval_request`: the ask branch of
//! `pause_native_pre_tool_for_approval` (`hook_native_review_approval.py`)
//! for Claude Code, with the permission notice the daemon worker
//! (`hook_worker_native.py`) records once the review is queued, in one store
//! write:
//!
//! 1. `GuardStore.add_approval_request`, as
//!    [`add_native_review_approval_request`] writes it;
//! 2. `record_claude_permission_notice_for_native_review`: the
//!    `claude_record_notice` op of `_record_claude_permission_notice`, signed
//!    under the key the daemon bound to the direct hook lane.
//!
//! A home whose legacy rows still wait for the daemon's backfill answers
//! `null` without writing. As in the daemon's op, a notice the store refuses
//! is skipped and the review stays queued. A notice row signed under another
//! key id fails the op instead, so the queue rolls back with it and the
//! daemon records both with its current key.
//!
//! `add_claude_approval_request` is the daemon worker's own queue write for a
//! Claude Code review (`queue_native_pre_tool_review`): the review goes
//! through `add_approval_request`, and the resident builds and records the
//! permission notice in the same transaction instead of the worker sending it
//! afterwards.

use base64ct::{Base64UrlUnpadded, Encoding};
use rusqlite::Connection;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::guard_store_approval_write::{add_approval_request, add_native_review_approval_request};
use crate::guard_store_args::Args;
use crate::guard_store_db::{StoreError, StoreResult};
use crate::hook_authority_state_op::direct_record::{
    claude_record_notice_current_key, claude_record_notice_direct,
};
use crate::hook_direct::saved_decision::review_queue::notice::{
    review_notice, APPROVAL_CODE_BYTES,
};

const NOTICE_INVALID: StoreError = StoreError::Invalid("native_claude_review_notice_invalid");
const NOTICE_FOREIGN_KEY: StoreError =
    StoreError::Invalid("native_claude_review_notice_foreign_key");

/// Queue the review, then record its Claude permission notice. Returns the
/// stored request id, or `null` (nothing written) while legacy rows wait for
/// the daemon's backfill.
pub(crate) fn add_claude_native_review_approval_request(
    connection: &Connection,
    source: &str,
    args: &Args,
) -> StoreResult<Value> {
    let notice = Args(args.object("claude_notice")?);
    let now = notice.str("now")?;
    let session_id = notice.str("session_id")?;
    let tool_name = notice.opt_str("tool_name")?;
    let payload = notice.raw("payload").ok_or(NOTICE_INVALID)?;
    if !payload.is_object() {
        return Err(NOTICE_INVALID);
    }
    let key = Zeroizing::new(
        Base64UrlUnpadded::decode_vec(notice.str("integrity_key_b64")?)
            .map_err(|_| NOTICE_INVALID)?,
    );
    let key_id = notice.str("integrity_key_id")?;
    if key.is_empty() || key_id.is_empty() {
        return Err(NOTICE_INVALID);
    }
    let Value::String(request_id) = add_native_review_approval_request(connection, source, args)?
    else {
        return Ok(Value::Null);
    };
    claude_record_notice_direct(
        connection, &key, key_id, now, session_id, tool_name, payload,
    )
    .map_err(|_| NOTICE_FOREIGN_KEY)?;
    Ok(Value::String(request_id))
}

/// Queue the review the daemon worker hands over through
/// `add_approval_request`, then record its Claude permission notice from the
/// `claude_review` facts. Returns what `add_approval_request` returns.
///
/// The notice stays best effort, as the worker's retired Python notice was:
/// a hook with no session, facts it cannot build a notice from, a missing
/// key or a notice the store refuses leave the review queued without one.
pub(crate) fn add_claude_approval_request(
    connection: &Connection,
    source: &str,
    args: &Args,
) -> StoreResult<Value> {
    let review = Args(args.object("claude_review")?);
    let request_id = add_approval_request(connection, source, args)?;
    if request_id.is_string() {
        let _ = record_review_notice(connection, args, &review, args.str("now")?);
    }
    Ok(request_id)
}

/// The notice the retired `record_claude_permission_notice_for_native_review`
/// sent, signed under the key the worker read for the store. The key travels
/// in the top-level `integrity_key_b64` and `integrity_key_id` args, which the
/// request digest leaves out. `None` when no notice is recorded.
///
/// The worker holds the current key, so a row signed under a rotated key is
/// cleaned up and re-signed here rather than deferred, as the retired
/// `claude_record_notice` op did.
fn record_review_notice(
    connection: &Connection,
    args: &Args,
    review: &Args,
    now: &str,
) -> Option<()> {
    let key =
        Zeroizing::new(Base64UrlUnpadded::decode_vec(args.str("integrity_key_b64").ok()?).ok()?);
    let key_id = args.str("integrity_key_id").ok()?;
    if key.is_empty() || key_id.is_empty() {
        return None;
    }
    let mut code = [0u8; APPROVAL_CODE_BYTES];
    getrandom::fill(&mut code).ok()?;
    let notice = review_notice(
        review.str("harness").ok()?,
        review.object("hook_payload").ok()?,
        review.raw("reason"),
        review.opt_str("review_binding").ok()?,
        review.str("config_path").ok()?,
        review.str("source_scope").ok()?,
        now,
        &hex::encode(code),
    )
    .ok()??;
    claude_record_notice_current_key(
        connection,
        &key,
        key_id,
        now,
        &notice.session_id,
        notice.tool_name.as_deref(),
        &Value::Object(notice.payload),
    );
    Some(())
}

#[cfg(test)]
#[path = "guard_store_claude_review_tests.rs"]
mod tests;

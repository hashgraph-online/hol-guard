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

use base64ct::{Base64UrlUnpadded, Encoding};
use rusqlite::Connection;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::guard_store_approval_write::add_native_review_approval_request;
use crate::guard_store_args::Args;
use crate::guard_store_db::{StoreError, StoreResult};
use crate::hook_authority_state_op::direct_record::claude_record_notice_direct;

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

#[cfg(test)]
#[path = "guard_store_claude_review_tests.rs"]
mod tests;

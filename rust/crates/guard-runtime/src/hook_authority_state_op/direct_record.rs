//! `claude_record_notice` for a store op that already holds the write lock:
//! the resident's direct hook lane queues a Claude Code review and records
//! its permission notice in the same transaction.

use super::*;

/// `_record_claude_permission_notice`'s `hook_authority_state(store,
/// "claude_record_notice", ...)` call, run on the caller's connection inside
/// its transaction under the key the daemon bound to the direct lane.
///
/// Like the daemon's op, a notice the store refuses is silently skipped. A
/// row signed under another key id is left untouched and reported as
/// [`DirectNoticeDefer::ForeignKey`], so the caller rolls back and the daemon
/// records the notice with its current key.
pub(crate) fn claude_record_notice_direct(
    connection: &Connection,
    key: &[u8],
    key_id: &str,
    now: &str,
    session_id: &str,
    tool_name: Option<&str>,
    payload: &Value,
) -> Result<(), DirectNoticeDefer> {
    let foreign_key = std::cell::Cell::new(false);
    let env = Env {
        connection,
        key: Some(zeroize::Zeroizing::new(key.to_vec())),
        key_id: Some(key_id),
        now,
        foreign_key: Some(&foreign_key),
    };
    env.claude_record_notice(session_id, tool_name, payload);
    if foreign_key.get() {
        return Err(DirectNoticeDefer::ForeignKey);
    }
    Ok(())
}

//! `HookAuthorityState` - resident op that owns the signed Claude and Cursor
//! hook authority state persisted in `sync_state`.
//!
//! Replaces the Python helpers that signed, stored, verified, expired and
//! deleted these rows. Every row is bound to its own state key and to a
//! purpose-derived key: a row that is unsigned, signed for another purpose or
//! key, copied to another key, bound to another session, conversation, artifact
//! or command, or older than the 30 minute window is never returned. It is
//! deleted instead, and each integrity failure leaves a
//! `rule.ignored.local_integrity` audit row. The key material and the clock are
//! shipped by the transport.
//!
//! A row's name is derived here. A Cursor shell row is named by the
//! conversation and the command it belongs to, and a Claude pending permission
//! by its artifact, so the key a row is written under and the key it is read
//! back under have one definition. A request may instead echo a key the
//! resident issued earlier — out of a pending index, or out of an op's own
//! reply — and that key is acted on as given.

use std::time::Duration;

use base64ct::{Base64UrlUnpadded, Encoding};
use guard_contracts::{
    utc_timestamp_micros, HookAuthorityStateRequestV1, HookAuthorityStateResultV1,
    HOOK_AUTHORITY_STATE_MAX_BYTES, HOOK_AUTHORITY_STATE_REQUEST_SCHEMA,
    HOOK_AUTHORITY_STATE_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use guard_policy_snapshot::local_authority_integrity::{
    sign_local_authority_payload, verify_local_authority_payload,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde_json::{json, Map, Value};

use guard_command::cursor_shell_command::{
    normalize_cursor_shell_command, CursorShellNormalization,
};

use crate::guard_store_json::{dumps_default, py_strip};
use crate::package_authority_op::request_digest_with_limit;

/// Notices, pending states, indexes and allowances live for 30 minutes.
const MAX_AGE_SECONDS: i64 = 30 * 60;

type Object = Map<String, Value>;

/// One signed state family: its integrity purpose and its audit identity.
struct Kind {
    purpose: &'static str,
    harness: &'static str,
    source: &'static str,
}

const CLAUDE_NOTICE: Kind = Kind {
    purpose: "claude-permission-notice",
    harness: "claude-code",
    source: "claude-permission-notice",
};
const CLAUDE_PENDING: Kind = Kind {
    purpose: "claude-pending-permission",
    harness: "claude-code",
    source: "claude-pending-permission",
};
const CLAUDE_INDEX: Kind = Kind {
    purpose: "claude-pending-permission-index",
    harness: "claude-code",
    source: "claude-pending-permission-index",
};
const CURSOR_PENDING: Kind = Kind {
    purpose: "cursor-pending-shell",
    harness: "cursor",
    source: "cursor-pending-shell",
};
const CURSOR_INDEX: Kind = Kind {
    purpose: "cursor-pending-shell-index",
    harness: "cursor",
    source: "cursor-pending-shell-index",
};
const CURSOR_ALLOW: Kind = Kind {
    purpose: "cursor-native-shell-allow",
    harness: "cursor",
    source: "cursor-native-session",
};

/// A per-owner index of pending state keys.
struct Family {
    index_prefix: &'static str,
    item_prefix: &'static str,
    owner_field: &'static str,
    kind: &'static Kind,
}

const CLAUDE_FAMILY: Family = Family {
    index_prefix: "claude_pending_permissions:",
    item_prefix: "claude_pending_permission:",
    owner_field: "session_id",
    kind: &CLAUDE_INDEX,
};
const CURSOR_FAMILY: Family = Family {
    index_prefix: "cursor_pending_shells:",
    item_prefix: "cursor_pending_shell:",
    owner_field: "conversation_id",
    kind: &CURSOR_INDEX,
};

const ERROR_INVALID: &str = "native_hook_authority_state_invalid";
const ERROR_STORE: &str = "native_hook_authority_state_store_unavailable";
/// How long a direct hook waits for another writer before deferring.
const DIRECT_BUSY_TIMEOUT_MS: u64 = 250;

pub(crate) fn evaluate_hook_authority_state_request(
    request: &HookAuthorityStateRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, HOOK_AUTHORITY_STATE_MAX_BYTES)
        .map_err(|_| "native_hook_authority_state_too_large".to_owned())?;
    let (status, code, payload) = match evaluate(request) {
        Ok(payload) => ("ok", "ok".to_owned(), Some(payload)),
        Err(code) => ("error", code.to_owned(), None),
    };
    crate::encode_response(&HookAuthorityStateResultV1 {
        schema: HOOK_AUTHORITY_STATE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code,
        payload,
    })
}

pub(crate) fn evaluate(request: &HookAuthorityStateRequestV1) -> Result<Value, &'static str> {
    if request.schema != HOOK_AUTHORITY_STATE_REQUEST_SCHEMA {
        return Err("native_hook_authority_state_schema_mismatch");
    }
    if request.op == "state_is_fresh" {
        let max_age = request.max_age_seconds.ok_or(ERROR_INVALID)?;
        return Ok(
            json!({ "fresh": is_fresh(request.saved_at.as_deref(), &request.now, max_age) }),
        );
    }
    let connection =
        Connection::open_with_flags(&request.store_path, OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(|_| ERROR_STORE)?;
    connection
        .busy_timeout(Duration::from_millis(5000))
        .map_err(|_| ERROR_STORE)?;
    // One writer at a time: every flow reads, then rewrites or consumes state,
    // so concurrent hooks must not interleave between those steps.
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|_| ERROR_STORE)?;
    let env = Env {
        connection: &connection,
        key: request
            .integrity_key_b64
            .as_deref()
            .and_then(|encoded| Base64UrlUnpadded::decode_vec(encoded).ok().map(Into::into)),
        key_id: request.integrity_key_id.as_deref(),
        now: &request.now,
        foreign_key: None,
    };
    match env.dispatch(request) {
        Ok(value) => {
            connection
                .execute_batch("COMMIT")
                .map_err(|_| ERROR_STORE)?;
            Ok(value)
        }
        Err(code) => {
            let _ = connection.execute_batch("ROLLBACK");
            Err(code)
        }
    }
}

/// `_hook_authority_state_is_fresh`: `saved_at` is not in the future and no
/// older than `max_age_seconds`. An unreadable timestamp is never fresh.
fn is_fresh(saved_at: Option<&str>, now: &str, max_age_seconds: i64) -> bool {
    let Some(saved_at) = saved_at.map(py_strip).filter(|text| !text.is_empty()) else {
        return false;
    };
    let (Some(saved), Some(current)) = (utc_timestamp_micros(saved_at), utc_timestamp_micros(now))
    else {
        return false;
    };
    let age = i128::from(current) - i128::from(saved);
    (0..=i128::from(max_age_seconds) * 1_000_000).contains(&age)
}

/// What `sync_state` holds under a key, as the Python store read it.
enum Stored {
    Absent,
    Unreadable,
    InvalidJson,
    List,
    Object(Object),
}

fn fingerprint(state_key: &str) -> String {
    digest_bytes(state_key.as_bytes())[..16].to_owned()
}

fn opt_str(object: &Object, name: &str) -> Option<String> {
    let text = py_strip(object.get(name)?.as_str()?);
    (!text.is_empty()).then(|| text.to_owned())
}

fn exact_str<'a>(object: &'a Object, name: &str) -> Option<&'a str> {
    object.get(name)?.as_str()
}

fn claude_pending_key(session_id: &str, artifact_id: &str) -> String {
    let fingerprint = &digest_bytes(artifact_id.as_bytes())[..24];
    format!("claude_pending_permission:{session_id}:{fingerprint}")
}

/// The command fingerprint both Cursor state keys are built from: the
/// normalized command's digest, truncated the way the retired
/// `_cursor_shell_command_fingerprint` truncated it.
///
/// A command the normalizer cannot read is no fingerprint at all. The retired
/// Python raised on it, so a request carrying one is invalid rather than named
/// after its unnormalized text.
fn cursor_command_fingerprint(command: &str) -> Result<String, &'static str> {
    match normalize_cursor_shell_command(command) {
        CursorShellNormalization::Command(normalized) => {
            Ok(digest_bytes(normalized.as_bytes())[..24].to_owned())
        }
        CursorShellNormalization::Unnormalizable => Err(ERROR_INVALID),
    }
}

fn cursor_pending_key(conversation_id: &str, command: &str) -> Result<String, &'static str> {
    Ok(format!(
        "{}{conversation_id}:{}",
        CURSOR_FAMILY.item_prefix,
        cursor_command_fingerprint(command)?
    ))
}

fn cursor_allow_key(conversation_id: &str, command: &str) -> Result<String, &'static str> {
    Ok(format!(
        "cursor_native_shell_allow:{conversation_id}:{}",
        cursor_command_fingerprint(command)?
    ))
}

/// The Cursor row a request names. A request that carries the command gets its
/// key derived here; one that echoes a key the resident issued is acted on as
/// given.
fn cursor_target(
    conversation_id: &str,
    command: Option<&str>,
    given: Option<&String>,
    derive: fn(&str, &str) -> Result<String, &'static str>,
) -> Result<String, &'static str> {
    match (given, command) {
        (Some(key), _) => Ok(key.clone()),
        (None, Some(command)) => derive(conversation_id, command),
        (None, None) => Err(ERROR_INVALID),
    }
}

fn notice_key(session_id: &str, tool_name: Option<&str>) -> String {
    match tool_name {
        Some(tool) => format!("claude_permission_notice:{session_id}:{tool}"),
        None => format!("claude_permission_notice:{session_id}"),
    }
}

fn dedupe(keys: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    keys.into_iter()
        .filter(|key| seen.insert(key.clone()))
        .collect()
}

struct Env<'a> {
    connection: &'a Connection,
    key: Option<zeroize::Zeroizing<Vec<u8>>>,
    key_id: Option<&'a str>,
    now: &'a str,
    /// Set by the direct hook lane, which holds a key the daemon published
    /// earlier: a row signed under another key id is left untouched and
    /// flagged here, so the daemon judges it with its current key.
    foreign_key: Option<&'a std::cell::Cell<bool>>,
}

/// Why the direct hook lane leaves a Claude permission dialog to the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectNoticeDefer {
    StoreUnavailable,
    ForeignKey,
    /// A notice is visible and this binding has no key to mark it seen.
    UnkeyedNotice,
}

/// `_peek_claude_permission_notice` followed, when it finds a notice, by
/// `_mark_claude_pending_permission_prompt_seen`, in one transaction under
/// the key the daemon bound to the direct lane.
///
/// A busy or unavailable store, or any row signed under another key id,
/// rolls everything back and defers, so the daemon's own path still runs
/// exactly as before.
pub(crate) fn claude_permission_notice_direct(
    store_path: &std::path::Path,
    key: &[u8],
    key_id: &str,
    now: &str,
    session_id: &str,
    tool_name: Option<&str>,
) -> Result<Option<Map<String, Value>>, DirectNoticeDefer> {
    direct_notice_transaction(
        store_path,
        Some((key, key_id)),
        now,
        Some(session_id),
        tool_name,
        None,
    )
}

/// Event name and the function that renders its JSON from the loaded notice.
type PromptEvent<'a> = (&'a str, &'a dyn Fn(Option<&Object>) -> Option<String>);

/// The daemon's answer to a Claude `permission_prompt` notification:
/// `_load_claude_permission_notice`, `_mark_claude_pending_permission_prompt_seen`
/// and the event it always records, in one transaction.
///
/// `key` is `None` when the binding has no integrity key, or the hook names
/// no session. A keyed session loads its notice after `BEGIN IMMEDIATE`. A
/// notice that is visible then, and no key is bound, defers so the daemon
/// still marks it. `event` renders the event's JSON text from the loaded
/// notice. Failing to write it defers like a busy store.
pub(crate) fn claude_permission_prompt_direct(
    store_path: &std::path::Path,
    key: Option<(&[u8], &str)>,
    now: &str,
    session_id: Option<&str>,
    tool_name: Option<&str>,
    event: PromptEvent<'_>,
) -> Result<Option<Map<String, Value>>, DirectNoticeDefer> {
    direct_notice_transaction(store_path, key, now, session_id, tool_name, Some(event))
}

/// A notice row for this session, read on the transaction's own connection.
fn unkeyed_notice_present(
    connection: &Connection,
    session_id: &str,
) -> Result<bool, DirectNoticeDefer> {
    if !crate::local_store_read::table_exists(connection, "sync_state")
        .map_err(|_| DirectNoticeDefer::StoreUnavailable)?
    {
        return Ok(false);
    }
    let session_key = format!("claude_permission_notice:{session_id}");
    connection
        .query_row(
            "select exists(select 1 from sync_state \
               where state_key = ?1 or (state_key >= ?2 and state_key < ?3))",
            params![
                session_key,
                format!("{session_key}:"),
                format!("{session_key};")
            ],
            |row| row.get(0),
        )
        .map_err(|_| DirectNoticeDefer::StoreUnavailable)
}

fn direct_notice_transaction(
    store_path: &std::path::Path,
    key: Option<(&[u8], &str)>,
    now: &str,
    session_id: Option<&str>,
    tool_name: Option<&str>,
    event: Option<PromptEvent<'_>>,
) -> Result<Option<Map<String, Value>>, DirectNoticeDefer> {
    let connection = Connection::open_with_flags(store_path, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(|_| DirectNoticeDefer::StoreUnavailable)?;
    // A held write lock sends the hook to the daemon, which waits for it.
    connection
        .busy_timeout(Duration::from_millis(DIRECT_BUSY_TIMEOUT_MS))
        .map_err(|_| DirectNoticeDefer::StoreUnavailable)?;
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|_| DirectNoticeDefer::StoreUnavailable)?;
    let foreign_key = std::cell::Cell::new(false);
    let env = Env {
        connection: &connection,
        key: key.map(|(bytes, _)| zeroize::Zeroizing::new(bytes.to_vec())),
        key_id: key.map(|(_, id)| id),
        now,
        foreign_key: Some(&foreign_key),
    };
    let notice = match (key, session_id) {
        (Some(_), Some(session_id)) => {
            let notice = env.claude_load_notice(session_id, tool_name);
            if let Some(notice) = &notice {
                if let (Some(artifact_id), Some(artifact_hash), Some(command)) = (
                    opt_str(notice, "artifact_id"),
                    opt_str(notice, "artifact_hash"),
                    opt_str(notice, "command"),
                ) {
                    env.claude_mark_prompt_seen(session_id, &artifact_id, &artifact_hash, &command);
                }
            }
            notice
        }
        (None, Some(session_id)) => {
            // Same connection as the write lock, so a notice committed after
            // any earlier read is visible here and is not answered unseen.
            if unkeyed_notice_present(&connection, session_id)? {
                let _ = connection.execute_batch("ROLLBACK");
                return Err(DirectNoticeDefer::UnkeyedNotice);
            }
            None
        }
        _ => None,
    };
    if foreign_key.get() {
        let _ = connection.execute_batch("ROLLBACK");
        return Err(DirectNoticeDefer::ForeignKey);
    }
    if let Some((event_name, render)) = event {
        let recorded = render(notice.as_ref()).is_some_and(|text| {
            connection
                .execute(
                    "insert into guard_events (event_name, payload_json, occurred_at) \
                     values (?1, ?2, ?3)",
                    params![event_name, text, now],
                )
                .is_ok()
        });
        if !recorded {
            let _ = connection.execute_batch("ROLLBACK");
            return Err(DirectNoticeDefer::StoreUnavailable);
        }
    }
    if connection.execute_batch("COMMIT").is_err() {
        let _ = connection.execute_batch("ROLLBACK");
        return Err(DirectNoticeDefer::StoreUnavailable);
    }
    Ok(notice)
}

fn required(value: &Option<String>) -> Result<&str, &'static str> {
    value.as_deref().ok_or(ERROR_INVALID)
}

pub(crate) mod direct_record;
mod dispatch;
mod flows;
mod store;

#[cfg(all(test, unix))]
#[path = "hook_authority_state_vectors_tests.rs"]
mod vectors;

#[cfg(all(test, unix))]
#[path = "hook_authority_state_session_ops_tests.rs"]
mod session_ops;

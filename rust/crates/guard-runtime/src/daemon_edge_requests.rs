//! `GET /v1/requests`, answered as the daemon's dashboard request list answers
//! it: the same native option check, the same store pages, and the local
//! dashboard's native business queue check.
//!
//! A local caller's pages merge the saved native business requests the
//! resident verifies, behind the store's pages.

use std::net::SocketAddr;

use serde_json::{json, Map, Value};

use super::super::http::query_value;
use super::{business, recommend, NativeReads, ReadConfig};
use crate::daemon_handler_requests::requests_list;

const MAX_STORE_CHUNKS: usize = 10_000;

/// The answer, and whether the daemon would send it with
/// `Cache-Control: no-store`.
///
/// A local caller's page also carries the saved native business requests:
/// appended once the store's pages end, continued by a native cursor, and
/// counted in the totals, as `local_request_page` merged them.
pub(super) fn list(
    query: &str,
    hosted: bool,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value, bool)> {
    let (proceed, status, body, fields) = requests_list(query).into_parts();
    if !proceed {
        return Some((status, body, false));
    }
    let cursor = fields.get("cursor")?.as_str();
    let native_cursor = !hosted && cursor.is_some_and(|c| c.starts_with(business::CURSOR_PREFIX));
    let marker = match cursor.filter(|_| !native_cursor) {
        None => Value::Null,
        Some(cursor) => match page_marker(cursor) {
            Some(marker) => marker,
            None => return Some(invalid_cursor()),
        },
    };
    let limit = fields.get("limit")?.as_u64()?;
    let harness = fields.get("harness")?.as_str();
    let include_totals = fields.get("include_totals")?.as_bool()?;
    let resolved = fields.get("status")?.as_str() == Some("resolved");
    let mut page = Map::new();
    if !native_cursor {
        page = store_page(&fields, marker, limit, config, reads)?;
        // Other harnesses cannot hold native rows, and without totals neither
        // resolved history nor an unfinished SQL page reads the native queue.
        if hosted
            || harness.is_some_and(|harness| harness != "native-business")
            || (!include_totals && (resolved || !page.get("next_cursor")?.is_null()))
        {
            return Some((200, Value::Object(page), true));
        }
    }
    let filters = json!({
        "status": fields.get("status")?,
        "harness": fields.get("harness")?,
        "search": fields.get("search")?,
    });
    let with_filters = |extra: Value| {
        let mut request = filters.clone();
        for (key, value) in extra.as_object().into_iter().flatten() {
            request[key] = value.clone();
        }
        request
    };
    let native = business::summaries(config, reads)
        .map_err(|_| business::PageError::Read)
        .and_then(|summaries| {
            if native_cursor {
                business::page(
                    &summaries,
                    with_filters(json!({"cursor": cursor, "limit": limit})),
                )
            } else if !resolved && page.get("next_cursor").is_some_and(Value::is_null) {
                // Append only after SQL pagination ends, keeping each page bounded.
                let shown = page
                    .get("items")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len);
                let room = (limit as usize).saturating_sub(shown);
                business::page(&summaries, with_filters(json!({"room": room})))
            } else {
                business::page(&summaries, with_filters(json!({"room": 0}))).map(|mut native| {
                    native.insert("items".to_owned(), Value::Array(Vec::new()));
                    native.insert("next_cursor".to_owned(), Value::Null);
                    native
                })
            }
        });
    let native = match native {
        Ok(native) => native,
        Err(business::PageError::Cursor) => return Some(invalid_cursor()),
        Err(business::PageError::Read) if native_cursor => return Some(invalid_cursor()),
        Err(business::PageError::Read) => {
            page.insert(
                "native_business_queue_error".to_owned(),
                Value::from("native_local_business_queue_read_failed"),
            );
            page.insert(
                "native_business_queue_checked".to_owned(),
                Value::Bool(true),
            );
            return Some((200, Value::Object(page), true));
        }
    };
    let native_items = native.get("items")?.clone();
    let native_next = native.get("next_cursor")?.clone();
    if native_cursor {
        page = store_page(&fields, Value::Null, 1, config, reads)?;
        page.insert("items".to_owned(), native_items);
        page.insert("next_cursor".to_owned(), native_next);
    } else if native_items
        .as_array()
        .is_some_and(|items| !items.is_empty())
        || !native_next.is_null()
    {
        let Value::Array(mut items) = page.remove("items")? else {
            return None;
        };
        items.extend(native_items.as_array()?.iter().cloned());
        page.insert("items".to_owned(), Value::Array(items));
        page.insert("next_cursor".to_owned(), native_next);
    }
    let count = native.get("count")?.as_i64()?;
    if include_totals {
        add(&mut page, "total_pending_count", count)?;
        if !resolved {
            add(&mut page, "total_count", count)?;
        }
    }
    page.insert(
        "native_business_queue_checked".to_owned(),
        Value::Bool(true),
    );
    Some((200, Value::Object(page), true))
}

fn add(page: &mut Map<String, Value>, key: &str, count: i64) -> Option<()> {
    let total = page.get(key)?.as_i64()?;
    page.insert(key.to_owned(), Value::from(total.checked_add(count)?));
    Some(())
}

/// The daemon's body for a queue position no page can continue.
fn invalid_cursor() -> (u16, Value, bool) {
    (
        400,
        json!({
            "error": "invalid_cursor",
            "recovery": {
                "code": "refresh_queue",
                "title": "Refresh the blocked action list.",
                "body": "The queue position expired. Refresh the Review Queue to continue.",
            },
        }),
        false,
    )
}

/// `_cursor_marker`: the `[last_seen_at, request_id]` a store page cursor
/// names, from its unpadded URL-safe base64 JSON.
fn page_marker(cursor: &str) -> Option<Value> {
    let decoded = base64url_decode(cursor.trim_end_matches('='))?;
    let payload: Value = serde_json::from_slice(&decoded).ok()?;
    let last_seen_at = payload.get("last_seen_at")?.as_str()?;
    let request_id = payload.get("request_id")?.as_str()?;
    Some(json!([last_seen_at, request_id]))
}

/// URL-safe base64 without padding; a length one past a multiple of four is
/// refused, and the unused low bits of the last character are ignored, as
/// `binascii` ignores them.
fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3 + 2);
    let (mut buffer, mut bits) = (0_u32, 0_u32);
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// `GET /v1/requests/{id}`. The hosted dashboard gets the stored row less its
/// private queue hint, and an unknown id gets the not-found body with the
/// local queue link; a local caller's unknown id may name a saved native
/// business request. The `bool` is whether the answer is `no-store`.
///
/// A local caller's stored row gets the read-time extension recommendation
/// and coverage; one that needs a connector-setup recommendation goes to the
/// daemon. A wait asks the daemon to hold the read, so it goes there too, as
/// does a row that may carry a temporary MCP or local tool grant offer, which
/// only the daemon attaches.
pub(super) fn detail(
    request_id: &str,
    query: &str,
    hosted: bool,
    local: Option<SocketAddr>,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value, bool)> {
    if query_value(query, "wait_ms").ok()?.is_some() {
        return None;
    }
    let cwd = config.daemon_cwd.as_deref()?;
    let approval = reads.store_call(
        config,
        "get_approval_request",
        json!({"request_id": request_id, "derive_scope": true, "cwd": cwd}),
    )?;
    if approval.is_null() {
        let local = local?;
        if hosted {
            let queue_url = business::local_url(local, "/#/inbox");
            return Some((404, business::not_found(&queue_url), false));
        }
        return business::unknown_detail(request_id, local, config, reads);
    }
    let Value::Object(mut approval) = approval else {
        return None;
    };
    if may_carry_grant_offer(&approval) {
        return None;
    }
    if !hosted {
        let approval = recommend::local_detail(approval, config, reads)?;
        return Some((200, Value::Object(approval), false));
    }
    approval.remove("extension_allow_hint");
    Some((200, Value::Object(approval), false))
}

/// `_with_approval_hints` asks the resident about a filed browser intent, or
/// about scanner evidence that names the local-tool scanner.
fn may_carry_grant_offer(approval: &Map<String, Value>) -> bool {
    approval.get("browser_intent").is_some_and(Value::is_object)
        || approval
            .get("scanner_evidence")
            .and_then(Value::as_array)
            .is_some_and(|entries| {
                entries.iter().any(|entry| {
                    entry.get("source").and_then(Value::as_str) == Some("trusted_local_tool")
                })
            })
}

/// `GET /v1/requests/{id}/resume` for a request whose resume is already
/// recorded. A request with no record yet goes to the daemon, which seeds one.
pub(super) fn resume(
    request_id: &str,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value)> {
    let not_found = || Some((404, json!({"error": "not_found"})));
    let approval = reads.store_call(
        config,
        "get_approval_request",
        json!({"request_id": request_id}),
    )?;
    if approval.is_null() {
        return not_found();
    }
    let resume = reads.store_call(
        config,
        "get_request_resume",
        json!({"request_id": request_id}),
    )?;
    resume.is_object().then_some((200, resume))
}

/// `list_approval_request_page`: every chunk of the one page.
fn store_page(
    fields: &Value,
    cursor: Value,
    limit: u64,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<Map<String, Value>> {
    // The page op resolves a relative config path from the daemon's working
    // directory, which the handshake names.
    let cwd = config.daemon_cwd.clone()?;
    let mut args = json!({
        "status": fields.get("status")?,
        "limit": limit,
        "cursor": cursor,
        "harness": fields.get("harness")?,
        "search": fields.get("search")?,
        "include_totals": fields.get("include_totals")?,
        "exclude_watch_only": false,
        "cwd": cwd,
    });
    let mut items = Vec::new();
    for _ in 0..MAX_STORE_CHUNKS {
        let Value::Object(mut chunk) =
            reads.store_call(config, "list_approval_request_page", args.clone())?
        else {
            return None;
        };
        let Value::Array(rows) = chunk.remove("items")? else {
            return None;
        };
        items.extend(rows);
        match chunk.remove("complete")? {
            Value::Bool(true) => {
                chunk.insert("items".to_owned(), Value::Array(items));
                return Some(chunk);
            }
            Value::Bool(false) => {
                args["after"] = chunk.remove("after")?;
                args["taken"] = Value::from(items.len());
            }
            _ => return None,
        }
    }
    None
}

#[cfg(all(test, unix))]
#[path = "daemon_edge_requests_tests.rs"]
mod tests;

//! Bounded v2 catalog reads (ADR 0014) for the CLI.
//!
//! The daemon's native read model owns filtering, paging, cursors and ETags.
//! These ops only walk it: `catalog_get` reads one representation,
//! `catalog_traverse` reads every page of one resource and verifies the
//! traversal is complete and consistent, and `catalog_extension` assembles
//! the legacy v1 extension object from one detail read plus its collection
//! traversals. A daemon without the v2 read model answers `unsupported`, so
//! the caller may fall back to the v1 catalog; a traversal that cannot be
//! verified answers `traversal`. A changed snapshot restarts the read once.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Instant;

use serde_json::{json, Map, Value};

use super::{failure, json_request, Request};

const CATALOG_V2_PATH: &str = "/v2/extension-controls/catalog/";
const MAX_PAGE_BYTES: usize = 262_144;
const MAX_PAGE_ITEMS: usize = 100;
/// A traversal of the largest admitted collection (4,096 rules) needs at most
/// 4,096 single-item pages; anything beyond these bounds is a daemon fault.
const MAX_TRAVERSAL_PAGES: usize = 4_096;
const MAX_TRAVERSAL_BYTES: usize = 64 * 1024 * 1024;
const SNAPSHOT_EXPIRED: &str = "catalog_snapshot_expired";

/// A failed read, already in the reply shape the caller maps.
type Failed = Value;

struct Traversal {
    snapshot_id: String,
    digest: String,
    total_count: i64,
    items: Vec<Value>,
}

pub(super) fn answer(request: &Request, addr: SocketAddr, deadline: Instant) -> Value {
    let reader = Reader {
        request,
        addr,
        deadline,
    };
    let outcome = match request.op.as_str() {
        "catalog_get" => reader.get(&request.route, "").map(Value::Object),
        "catalog_traverse" => {
            let params = string_params(request.params.as_ref());
            restart_once(|| reader.traverse_once(&request.route, &request.item_key, &params))
                .map(Traversal::into_value)
        }
        "catalog_extension" => {
            restart_once(|| reader.extension(&request.extension_id)).map(Value::Object)
        }
        _ => Err(failure("schema", "unsupported daemon client op", None)),
    };
    match outcome {
        Ok(value) => json!({ "ok": value }),
        Err(failed) => failed,
    }
}

impl Traversal {
    fn into_value(self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "native_catalog_digest": self.digest,
            "total_count": self.total_count,
            "items": self.items,
        })
    }
}

fn restart_once<T>(mut read: impl FnMut() -> Result<T, Failed>) -> Result<T, Failed> {
    match read() {
        Err(failed) if is_traversal(&failed, Some(SNAPSHOT_EXPIRED)) => read(),
        outcome => outcome,
    }
}

fn is_traversal(failed: &Value, code: Option<&str>) -> bool {
    failed.get("error").and_then(Value::as_str) == Some("traversal")
        && code.is_none_or(|code| failed.get("code").and_then(Value::as_str) == Some(code))
}

fn traversal(message: &str, code: Option<&str>) -> Failed {
    json!({"error": "traversal", "message": message, "status": null, "code": code})
}

fn schema(message: &str) -> Failed {
    failure("schema", message, None)
}

fn string_params(params: Option<&Value>) -> Vec<(String, String)> {
    params
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|text| (key.clone(), text.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default()
}

struct Reader<'a> {
    request: &'a Request,
    addr: SocketAddr,
    deadline: Instant,
}

impl Reader<'_> {
    /// One page or detail, with the daemon's own classified failures. A
    /// 404/501 that means "no v2 read model" becomes `unsupported`.
    fn sized(&self, route: &str, query: &str) -> Result<(Map<String, Value>, usize), Failed> {
        let mut path = format!("{CATALOG_V2_PATH}{route}");
        if !query.is_empty() {
            path.push('?');
            path.push_str(query);
        }
        let mut page = self.request.clone();
        page.method = "GET".to_owned();
        page.path = path;
        page.body = None;
        page.if_none_match = None;
        let reply = json_request(&page, self.addr, self.deadline, MAX_PAGE_BYTES);
        if let Some(Value::Object(map)) = reply.get("ok") {
            if reply.get("etag").and_then(Value::as_str).is_none() {
                return Err(schema(
                    "Guard daemon catalog response is missing its validator",
                ));
            }
            let size = reply.get("size").and_then(Value::as_u64).unwrap_or(0);
            return Ok((map.clone(), usize::try_from(size).unwrap_or(usize::MAX)));
        }
        Err(unsupported(reply))
    }

    fn get(&self, route: &str, query: &str) -> Result<Map<String, Value>, Failed> {
        self.sized(route, query).map(|(map, _)| map)
    }

    fn traverse_once(
        &self,
        route: &str,
        item_key: &str,
        params: &[(String, String)],
    ) -> Result<Traversal, Failed> {
        let mut items = Vec::new();
        let mut seen_items = HashSet::new();
        let mut seen_cursors = HashSet::new();
        let mut first: Option<(String, String, i64)> = None;
        let mut cursor: Option<String> = None;
        let mut consumed = 0_usize;
        for _ in 0..MAX_TRAVERSAL_PAGES {
            let mut query = vec![("limit".to_owned(), MAX_PAGE_ITEMS.to_string())];
            for (key, value) in params {
                query.retain(|(existing, _)| existing != key);
                query.push((key.clone(), value.clone()));
            }
            if let Some(cursor) = &cursor {
                query.push(("cursor".to_owned(), cursor.clone()));
            }
            query.sort();
            let (page, size) = match self.sized(route, &form_encode(&query)) {
                Ok(page) => page,
                Err(failed)
                    if failed.get("error").and_then(Value::as_str) == Some("http")
                        && failed.get("code").and_then(Value::as_str) == Some(SNAPSHOT_EXPIRED) =>
                {
                    let message = failed["message"].as_str().unwrap_or_default().to_owned();
                    let mut expired = traversal(&message, Some(SNAPSHOT_EXPIRED));
                    expired["status"] = failed["status"].clone();
                    return Err(expired);
                }
                Err(failed) => return Err(failed),
            };
            consumed = consumed.saturating_add(size);
            if consumed > MAX_TRAVERSAL_BYTES {
                return Err(traversal(
                    "Guard daemon catalog traversal exceeded its byte budget",
                    None,
                ));
            }
            let fields = page_fields(&page)?;
            let identity = (fields.snapshot_id, fields.digest, fields.total_count);
            match &first {
                None => first = Some(identity),
                Some(seen) if *seen != identity => {
                    return Err(traversal(
                        "Guard daemon catalog snapshot changed",
                        Some(SNAPSHOT_EXPIRED),
                    ))
                }
                Some(_) => {}
            }
            let empty = fields.items.is_empty();
            for item in fields.items {
                let Some(id) = item.get(item_key).and_then(Value::as_str) else {
                    return Err(traversal(
                        "Guard daemon catalog traversal returned a duplicate item",
                        None,
                    ));
                };
                if !seen_items.insert(id.to_owned()) {
                    return Err(traversal(
                        "Guard daemon catalog traversal returned a duplicate item",
                        None,
                    ));
                }
                items.push(item);
            }
            let Some(next) = fields.next_cursor else {
                let (snapshot_id, digest, total_count) = first.unwrap_or_default();
                if usize::try_from(total_count).ok() != Some(items.len()) {
                    return Err(traversal(
                        "Guard daemon catalog traversal was incomplete",
                        None,
                    ));
                }
                return Ok(Traversal {
                    snapshot_id,
                    digest,
                    total_count,
                    items,
                });
            };
            if empty || !seen_cursors.insert(next.clone()) {
                return Err(traversal(
                    "Guard daemon catalog traversal did not advance",
                    None,
                ));
            }
            cursor = Some(next);
        }
        Err(traversal(
            "Guard daemon catalog traversal exceeded its page budget",
            None,
        ))
    }

    /// The legacy v1 extension object: one detail read and every collection
    /// it declares, all from the detail's snapshot and at its declared counts.
    fn extension(&self, extension_id: &str) -> Result<Map<String, Value>, Failed> {
        let invalid = || schema("Guard daemon catalog detail schema is invalid");
        let detail = self.get(&extension_route(extension_id, None), "")?;
        let (Some(Value::Object(extension)), Some(Value::Object(collections))) =
            (detail.get("extension"), detail.get("collections"))
        else {
            return Err(invalid());
        };
        let snapshot = (
            detail.get("snapshot_id").cloned(),
            detail.get("native_catalog_digest").cloned(),
        );
        let mut result: Map<String, Value> = extension
            .iter()
            .filter(|(key, _)| !matches!(key.as_str(), "catalog_defaults" | "content_revision"))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let Some(Value::Object(defaults)) = extension.get("catalog_defaults") else {
            return Err(invalid());
        };
        let (Some(enabled), Some(activation)) =
            (defaults.get("enabled"), defaults.get("activation"))
        else {
            return Err(invalid());
        };
        result.insert("enabled".to_owned(), enabled.clone());
        result.insert("activation".to_owned(), activation.clone());
        let mut collection = |name: &str, route: &str, item_key: &str| -> Result<(), Failed> {
            let declared = collections
                .get(name)
                .and_then(Value::as_object)
                .and_then(|declared| declared.get("total_count"))
                .filter(|count| count.is_i64())
                .and_then(Value::as_i64)
                .ok_or_else(invalid)?;
            let route = extension_route(extension_id, Some(route));
            let walked = restart_once(|| self.traverse_once(&route, item_key, &[]))?;
            if (
                Some(Value::String(walked.snapshot_id)),
                Some(Value::String(walked.digest)),
            ) != snapshot
            {
                return Err(traversal(
                    "Guard daemon catalog snapshot changed",
                    Some(SNAPSHOT_EXPIRED),
                ));
            }
            if walked.total_count != declared {
                return Err(traversal(
                    "Guard daemon catalog collection does not match its detail",
                    None,
                ));
            }
            result.insert(name.to_owned(), Value::Array(walked.items));
            Ok(())
        };
        collection("permissions", "permissions", "permission_id")?;
        collection("rules", "rules", "rule_id")?;
        if collections.contains_key("mcp_tools") {
            collection("mcp_tools", "mcp-tools", "name")?;
        }
        Ok(result)
    }
}

struct PageFields {
    snapshot_id: String,
    digest: String,
    total_count: i64,
    items: Vec<Value>,
    next_cursor: Option<String>,
}

fn page_fields(page: &Map<String, Value>) -> Result<PageFields, Failed> {
    let invalid = || schema("Guard daemon catalog page schema is invalid");
    let text = |key: &str| page.get(key).and_then(Value::as_str).map(str::to_owned);
    let snapshot_id = text("snapshot_id").ok_or_else(invalid)?;
    let digest = text("native_catalog_digest").ok_or_else(invalid)?;
    let total_count = page
        .get("total_count")
        .filter(|count| count.is_i64() || count.is_u64())
        .and_then(Value::as_i64)
        .ok_or_else(invalid)?;
    let items = match page.get("items") {
        Some(Value::Array(items)) if items.iter().all(Value::is_object) => items.clone(),
        _ => return Err(invalid()),
    };
    let next_cursor = match page.get("next_cursor") {
        None | Some(Value::Null) => None,
        Some(Value::String(cursor)) => Some(cursor.clone()),
        Some(_) => return Err(invalid()),
    };
    Ok(PageFields {
        snapshot_id,
        digest,
        total_count,
        items,
        next_cursor,
    })
}

/// A 404 or 501 that means "this daemon has no v2 read model": an older
/// daemon answers a bare 404, a newer one without native support 501.
fn unsupported(reply: Value) -> Failed {
    if reply.get("error").and_then(Value::as_str) != Some("http") {
        return reply;
    }
    let status = reply.get("status").and_then(Value::as_u64);
    let code = reply.get("code").and_then(Value::as_str);
    let absent = matches!(
        (status, code),
        (Some(404), None | Some("not_found")) | (Some(501), Some("catalog_read_model_unavailable"))
    );
    if !absent {
        return reply;
    }
    let mut failed = reply;
    failed["error"] = Value::from("unsupported");
    failed["message"] = Value::from("Guard daemon does not serve the v2 catalog");
    failed
}

fn extension_route(extension_id: &str, collection: Option<&str>) -> String {
    let route = format!("extensions/{}", percent_encode(extension_id, false));
    match collection {
        Some(collection) => format!("{route}/{collection}"),
        None => route,
    }
}

/// `urlencode` over sorted pairs, as the read model's query parser expects.
fn form_encode(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                percent_encode(key, true),
                percent_encode(value, true)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn percent_encode(text: &str, plus_for_space: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(char::from(byte));
            }
            b' ' if plus_for_space => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
#[path = "daemon_client_catalog_tests.rs"]
mod tests;

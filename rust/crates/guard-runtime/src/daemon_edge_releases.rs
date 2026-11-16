//! `GET /v1/releases/index` and `GET /v1/releases/release`: one fixed-origin
//! document from the
//! public release archive, fetched under the machine's managed network policy
//! and projected by the native release-feed projector before the dashboard
//! sees a byte of it.
//!
//! The dashboard cannot reach the portal itself (`connect-src 'self'`), so
//! this route is its only transport. Nothing here reads, filters or reorders a
//! release: the projector's body is written verbatim.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use guard_command::egress_caller::policy_get_with_headers;
use serde_json::{json, Value};

use super::super::http::{parse_qs, Request};
use crate::managed_policy_load::ManagedPolicySource;
use crate::release_feed_op::{
    evaluate_release_feed_project, ReleaseFeedProjectRequest, RELEASE_FEED_REQUEST_SCHEMA,
    RELEASE_FEED_RESULT_SCHEMA,
};
use crate::supply_chain_eval_caller::CallerEgressFulfilment;

/// `RELEASE_FEED_ORIGIN`: the only host this route ever reaches.
const ORIGIN: &str = "https://hol.org";
const INDEX_PATH: &str = "/api/guard/releases/v1/index";
const DETAIL_PATH: &str = "/api/guard/releases/v1/release";
const LOCAL_PREFIX: &str = "/v1/releases/";
const LOCAL_INDEX: &str = "/v1/releases/index";
const LOCAL_DETAIL: &str = "/v1/releases/release";
/// `MAX_RELEASE_FEED_RESPONSE_BYTES`.
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
/// `RELEASE_FEED_IO_DEADLINE_SECONDS`.
const IO_DEADLINE_SECONDS: f64 = 4.0;
/// `RELEASE_FEED_FRESH_RESULT_SECONDS`.
const FRESH_RESULT: Duration = Duration::from_secs(300);
/// `MAX_CACHED_RELEASE_DOCUMENTS`.
const MAX_CACHED_DOCUMENTS: usize = 32;
/// `MAX_RELEASE_FEED_PAGE`.
const MAX_PAGE: u32 = 1_000;
/// `MAX_RELEASE_FEED_PAGE_SIZE`.
const MAX_PAGE_SIZE: u32 = 50;
/// `HOL_GUARD_RELEASE_FEED`: the rollout switch.
const ROLLOUT_ENV: &str = "HOL_GUARD_RELEASE_FEED";

const UNAVAILABLE: &str = "release_feed_capability_unavailable";
const REQUEST_INVALID: &str = "release_feed_request_invalid";
const TRANSPORT_FAILED: &str = "release_feed_transport_failed";
const UPSTREAM_ERROR: &str = "release_feed_upstream_error";
const NOT_FOUND: &str = "release_not_found";

/// One cached upstream document, keyed by its path and query.
struct Cached {
    key: String,
    body: Vec<u8>,
    etag: Option<String>,
    fetched: Instant,
}

/// `_cached_documents` under `_fetch_lock`: at most one upstream request is
/// in flight per daemon, and concurrent callers reuse its fresh result.
static CACHE: Mutex<Vec<Cached>> = Mutex::new(Vec::new());

/// What the route writes.
#[derive(Debug, PartialEq)]
pub(in crate::daemon_edge) enum Answer {
    /// The daemon's JSON error.
    Error(u16, Value),
    /// The projector's body, written verbatim with `Cache-Control: no-store`.
    Body(Vec<u8>),
}

/// Whether `path` is one this module answers.
pub(in crate::daemon_edge) fn owns(path: &str) -> bool {
    path.starts_with(LOCAL_PREFIX)
}

/// The route's answer, or `None` for a query the edge will not read the way
/// Python's `parse_qs` would.
pub(in crate::daemon_edge) fn read(request: &Request<'_>) -> Answer {
    if !rollout_enabled(std::env::var(ROLLOUT_ENV).ok().as_deref()) {
        return error(503, UNAVAILABLE);
    }
    let target = match request.path {
        LOCAL_INDEX => Kind::Index,
        LOCAL_DETAIL => Kind::Detail,
        _ => return error(404, "not_found"),
    };
    let params = parse_params(request.query);
    let target = match target_for(target, &params) {
        Ok(target) => target,
        Err(code) => return error(400, code),
    };
    project(&target, fetch)
}

/// `release_feed_rollout_enabled`.
pub(in crate::daemon_edge) fn rollout_enabled(value: Option<&str>) -> bool {
    !matches!(
        value
            .map(|text| text.trim().to_ascii_lowercase())
            .as_deref(),
        Some("off" | "0" | "false" | "disabled")
    )
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(in crate::daemon_edge) enum Kind {
    Index,
    Detail,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Index => "index",
            Self::Detail => "detail",
        }
    }
}

/// One bounded upstream read: which document, and its fixed path and query.
#[derive(Debug, PartialEq)]
pub(in crate::daemon_edge) struct Target {
    pub(in crate::daemon_edge) kind: Kind,
    pub(in crate::daemon_edge) path: &'static str,
    pub(in crate::daemon_edge) query: String,
}

/// `parse_qs(query, keep_blank_values=False)` grouped by name.
pub(in crate::daemon_edge) fn parse_params(query: &str) -> BTreeMap<String, Vec<String>> {
    let mut params: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in parse_qs(query) {
        params.entry(name).or_default().push(value);
    }
    params
}

/// The route's query checks and `release_feed_target`.
pub(in crate::daemon_edge) fn target_for(
    kind: Kind,
    params: &BTreeMap<String, Vec<String>>,
) -> Result<Target, &'static str> {
    let slug = match kind {
        Kind::Detail => match params.get("slug").map(Vec::as_slice) {
            Some([slug]) => Some(slug.as_str()),
            _ => return Err(REQUEST_INVALID),
        },
        Kind::Index => None,
    };
    let page = number(params.get("page"), 1).ok_or(REQUEST_INVALID)?;
    let page_size = number(params.get("pageSize"), MAX_PAGE_SIZE).ok_or(REQUEST_INVALID)?;
    match kind {
        Kind::Index => {
            if !(1..=MAX_PAGE).contains(&page) || !(1..=MAX_PAGE_SIZE).contains(&page_size) {
                return Err(REQUEST_INVALID);
            }
            Ok(Target {
                kind,
                path: INDEX_PATH,
                query: format!("page={page}&pageSize={page_size}"),
            })
        }
        Kind::Detail => {
            let slug = slug
                .filter(|slug| valid_slug(slug))
                .ok_or(REQUEST_INVALID)?;
            Ok(Target {
                kind,
                path: DETAIL_PATH,
                query: format!("slug={slug}"),
            })
        }
    }
}

/// `_release_feed_number`: absent is the default; present must be one value
/// of at most six ASCII digits, at least one.
fn number(values: Option<&Vec<String>>, default: u32) -> Option<u32> {
    let Some(values) = values else {
        return Some(default);
    };
    let [value] = values.as_slice() else {
        return None;
    };
    if value.is_empty() || value.len() > 6 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok().filter(|parsed| *parsed >= 1)
}

/// `^[a-z0-9][a-z0-9.-]{0,127}$`.
pub(in crate::daemon_edge) fn valid_slug(slug: &str) -> bool {
    let bytes = slug.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9')
        && bytes[1..]
            .iter()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'))
}

/// One upstream exchange: status, ETag and body, or the transport's failure.
pub(in crate::daemon_edge) type Exchange = Result<(u16, Option<String>, Vec<u8>), ()>;

/// `release_feed_projection` after the request checks, with the upstream
/// exchange supplied by `fetcher`.
pub(in crate::daemon_edge) fn project(
    target: &Target,
    fetcher: impl FnOnce(&str, Option<&str>) -> Exchange,
) -> Answer {
    let document = match document(target, fetcher) {
        Ok(document) => document,
        Err((status, code)) => return error(status, code),
    };
    let Ok(body) = String::from_utf8(document) else {
        return error(503, TRANSPORT_FAILED);
    };
    let request = ReleaseFeedProjectRequest {
        schema: RELEASE_FEED_REQUEST_SCHEMA.to_owned(),
        kind: target.kind.name().to_owned(),
        body,
    };
    let Ok(frame) = evaluate_release_feed_project(&request) else {
        return error(501, UNAVAILABLE);
    };
    validated(&frame).unwrap_or_else(|| error(501, UNAVAILABLE))
}

/// `_validated_result`: the frame's exact shape, or `None`.
fn validated(frame: &[u8]) -> Option<Answer> {
    let decoded: Value = serde_json::from_slice(frame).ok()?;
    let object = decoded.as_object()?;
    let fields = [
        "schema",
        "outcome",
        "http_status",
        "etag",
        "body",
        "error_code",
    ];
    if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) {
        return None;
    }
    if object.get("schema")?.as_str()? != RELEASE_FEED_RESULT_SCHEMA {
        return None;
    }
    let status = object.get("http_status")?.as_u64()?;
    match object.get("outcome")?.as_str()? {
        "ok" => {
            let body = object.get("body")?.as_str()?;
            if status != 200
                || !object.get("error_code")?.is_null()
                || body.len() as u64 > MAX_RESPONSE_BYTES
            {
                return None;
            }
            Some(Answer::Body(body.as_bytes().to_vec()))
        }
        "error" => {
            let code = object.get("error_code")?.as_str()?;
            let expected = match code {
                "release_feed_request_invalid" | "release_feed_body_invalid" => 400,
                "release_feed_payload_invalid" => 502,
                _ => return None,
            };
            if status != expected || !object.get("body")?.is_null() {
                return None;
            }
            Some(error(expected as u16, code))
        }
        _ => None,
    }
}

/// `fetch_release_document`: the fresh cached body, or one fetched now. A 304
/// reuses the cached body rather than restamping it.
fn document(
    target: &Target,
    fetcher: impl FnOnce(&str, Option<&str>) -> Exchange,
) -> Result<Vec<u8>, (u16, &'static str)> {
    let key = format!("{}?{}", target.path, target.query);
    let mut cache = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = Instant::now();
    let position = cache.iter().position(|entry| entry.key == key);
    if let Some(entry) = position.map(|index| &cache[index]) {
        if now.duration_since(entry.fetched) < FRESH_RESULT {
            return Ok(entry.body.clone());
        }
    }
    let etag = position.and_then(|index| cache[index].etag.clone());
    let url = format!("{ORIGIN}{key}");
    let (status, fresh_etag, body) =
        fetcher(&url, etag.as_deref()).map_err(|()| (503, TRANSPORT_FAILED))?;
    if status == 304 {
        if let Some(index) = position {
            cache[index].fetched = now;
            return Ok(cache[index].body.clone());
        }
    }
    match status {
        200 => {}
        404 => return Err((404, NOT_FOUND)),
        _ => return Err((502, UPSTREAM_ERROR)),
    }
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err((503, TRANSPORT_FAILED));
    }
    if std::str::from_utf8(&body).is_err() {
        return Err((503, TRANSPORT_FAILED));
    }
    match position {
        Some(index) => {
            cache.remove(index);
        }
        None if cache.len() >= MAX_CACHED_DOCUMENTS => {
            // Oldest insertion first: the archive index stays warm because
            // the dashboard reads it on every visit.
            cache.remove(0);
        }
        None => {}
    }
    cache.push(Cached {
        key,
        body: body.clone(),
        etag: fresh_etag,
        fetched: now,
    });
    Ok(body)
}

/// The exchange under the machine's managed network policy. No redirect is
/// followed and no Authorization, Cookie or local identifier is attached.
fn fetch(url: &str, etag: Option<&str>) -> Exchange {
    let policy =
        CallerEgressFulfilment::resolve_policy(&ManagedPolicySource::native()).map_err(|_| ())?;
    let mut headers = BTreeMap::from([
        ("Accept".to_owned(), "application/json".to_owned()),
        // Identity encoding keeps the byte bound equal to the decompressed
        // bound.
        ("Accept-Encoding".to_owned(), "identity".to_owned()),
        ("User-Agent".to_owned(), crate::daemon_edge::user_agent()),
    ]);
    if let Some(etag) = etag {
        headers.insert("If-None-Match".to_owned(), etag.to_owned());
    }
    match policy_get_with_headers(
        url,
        headers,
        IO_DEADLINE_SECONDS,
        0,
        MAX_RESPONSE_BYTES,
        &policy,
    ) {
        Ok((status, headers, body)) => Ok((status, headers.get("etag").cloned(), body)),
        // A refused destination, a timeout and a dropped connection are
        // all the same transport failure to the dashboard.
        Err(_) => Err(()),
    }
}

fn error(status: u16, code: &str) -> Answer {
    Answer::Error(status, json!({"error": code}))
}

#[cfg(test)]
pub(in crate::daemon_edge) fn reset_cache_for_tests() {
    CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clear();
}

#[cfg(all(test, unix))]
#[path = "daemon_edge_releases_tests.rs"]
mod tests;

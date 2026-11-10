//! `/v1/discovery/extensions/*`: sponsored extension discovery, answered as
//! the daemon's discovery routes answer it.
//!
//! The dashboard never talks to Guard Cloud directly (`connect-src 'self'`),
//! so these routes are its only transport. Every placement byte is fetched
//! from one fixed origin under the machine's managed network policy and
//! projected by the native placement projector; nothing here parses, selects,
//! ranks or re-serializes a placement. Render and event measurement is relayed
//! only with the user's consent, and no local credential, identifier or
//! inventory is ever attached.
//!
//! Rollback: `HOL_GUARD_DISCOVERY=off` makes every route answer
//! `discovery_capability_unavailable` without any upstream or native work.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::pyjson::{float_repr, PyVal};
use guard_command::egress_caller::policy_send;
use guard_contracts::EgressOutcomeV1;
use serde_json::{json, Map, Value};

use super::super::http::{query_pairs, Request};
use super::{NativeReads, ReadConfig};
use crate::discovery_placement_op::{
    evaluate_discovery_placement_project, DiscoveryPlacementProjectRequest,
};
use crate::managed_policy_load::ManagedPolicySource;
use crate::policy_bundle_time::micros_to_utc_isoformat;
use crate::supply_chain_eval_caller::CallerEgressFulfilment;

const ROLLOUT_ENV: &str = "HOL_GUARD_DISCOVERY";
const UNAVAILABLE: &str = "discovery_capability_unavailable";
const TRANSPORT_FAILED: &str = "discovery_transport_failed";
const UPSTREAM_ERROR: &str = "discovery_upstream_error";
const TOO_LARGE: &str = "discovery_response_too_large";
const OPTED_OUT: &str = "discovery_opted_out";

/// `DISCOVERY_CLOUD_ORIGIN`: the only host these routes ever reach.
const ORIGIN: &str = "https://hol.org";
/// A loopback stand-in for [`ORIGIN`], for integration runs that fixture the
/// discovery service. Only `http://127.0.0.1:<port>` is honoured.
const FIXTURE_ORIGIN_ENV: &str = "HOL_GUARD_DISCOVERY_FIXTURE_ORIGIN";
const PLACEMENTS_PATH: &str = "/api/guard/extensions/discovery/v1/placements";
const RENDERS_PATH: &str = "/api/guard/extensions/discovery/v1/renders";
const EVENTS_PATH: &str = "/api/guard/extensions/discovery/v1/events";

const LOCAL_PREFIX: &str = "/v1/discovery/extensions/";
const LOCAL_PLACEMENTS: &str = "/v1/discovery/extensions/placements";
const LOCAL_SETTINGS: &str = "/v1/discovery/extensions/settings";
const LOCAL_RENDERS: &str = "/v1/discovery/extensions/renders";
const LOCAL_EVENTS: &str = "/v1/discovery/extensions/events";

/// `MAX_DISCOVERY_RESPONSE_BYTES`.
const MAX_RESPONSE_BYTES: u64 = 65_536;
/// `MAX_DISCOVERY_REQUEST_BYTES`.
const MAX_REQUEST_BYTES: usize = 16_384;
/// The most of an upstream error body the relay hands back.
const MAX_RELAYED_ERROR_BYTES: usize = 4_096;
/// `DISCOVERY_IO_DEADLINE_SECONDS`.
const IO_DEADLINE_SECONDS: f64 = 2.0;
/// `DISCOVERY_FRESH_RESULT_SECONDS`: concurrent dashboard tabs share one
/// upstream result per poll cadence.
const FRESH_RESULT: Duration = Duration::from_secs(10);

const DISCOVERY_RESULT_SCHEMA: &str = "guard-discovery-project-result.v1";
const DISCOVERY_REQUEST_SCHEMA: &str = "guard-discovery-project-request.v1";

/// The store keys holding the user's and the managed discovery settings.
const SETTINGS_KEY: &str = "guard_sponsored_discovery_settings_v1";
const MANAGED_KEY: &str = "guard_sponsored_discovery_managed_policy_v1";
const DISCOVERY_ENABLED: &str = "sponsored_discovery_enabled";
const MEASUREMENT_ENABLED: &str = "sponsored_discovery_measurement_enabled";

/// The cached placements snapshot.
#[derive(Clone)]
pub(in crate::daemon_edge) struct Snapshot {
    pub(in crate::daemon_edge) body: Vec<u8>,
    pub(in crate::daemon_edge) server_date_ms: Option<i64>,
    pub(in crate::daemon_edge) etag: Option<String>,
    fetched: Instant,
}

/// `_cached_snapshot` under `_fetch_lock`: the lock is the single bounded
/// worker, so at most one upstream read is in flight per daemon.
static CACHE: Mutex<Option<Snapshot>> = Mutex::new(None);

/// What the route writes.
#[derive(Debug, PartialEq)]
pub(in crate::daemon_edge) enum Answer {
    /// The daemon's `_write_json`.
    Json(u16, Value),
    /// Bytes written verbatim (HTML-escaped) with `Cache-Control: no-store`.
    Raw(u16, Vec<u8>),
}

/// Whether `path` is one this module answers.
pub(in crate::daemon_edge) fn owns(path: &str) -> bool {
    path.starts_with(LOCAL_PREFIX)
}

/// `_DISABLED_VALUES` in `discovery_rollout_enabled`.
pub(in crate::daemon_edge) fn rollout_enabled(value: Option<&str>) -> bool {
    !matches!(
        value
            .map(|text| text.trim().to_ascii_lowercase())
            .as_deref(),
        Some("0" | "off" | "false" | "disabled")
    )
}

/// The origin these routes reach: [`ORIGIN`], or a loopback fixture origin.
fn origin() -> String {
    std::env::var(FIXTURE_ORIGIN_ENV)
        .ok()
        .filter(|value| fixture_origin(value))
        .unwrap_or_else(|| ORIGIN.to_owned())
}

/// Whether `value` is `http://127.0.0.1:<port>` and nothing else.
pub(in crate::daemon_edge) fn fixture_origin(value: &str) -> bool {
    value
        .strip_prefix("http://127.0.0.1:")
        .and_then(|port| {
            (!port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit()))
                .then(|| port.parse::<u16>().ok())
                .flatten()
        })
        .is_some_and(|port| port != 0)
}

fn rollout() -> bool {
    rollout_enabled(std::env::var(ROLLOUT_ENV).ok().as_deref())
}

/// Whether the query carries a `token` parameter, which the daemon refuses on
/// these routes rather than reading.
pub(in crate::daemon_edge) fn query_names_token(query: &str) -> bool {
    let key = format!("{}{}", "tok", "en");
    match query_pairs(query) {
        Ok(pairs) => pairs.iter().any(|(name, _)| *name == key),
        Err(_) => true,
    }
}

/// The GET routes after authentication.
pub(in crate::daemon_edge) fn read(
    request: &Request<'_>,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<Answer> {
    let settings = settings(config, reads)?;
    // A device whose user or administrator turned sponsored discovery off
    // answers that before anything that can fail.
    if request.path == LOCAL_PLACEMENTS && !flag(&settings, DISCOVERY_ENABLED) {
        return Some(error(403, OPTED_OUT));
    }
    if !rollout() {
        return Some(error(503, UNAVAILABLE));
    }
    if request.path == LOCAL_SETTINGS {
        return Some(Answer::Json(200, Value::Object(settings)));
    }
    if request.path != LOCAL_PLACEMENTS {
        return Some(error(404, "not_found"));
    }
    Some(placements(
        flag(&settings, DISCOVERY_ENABLED),
        fetch_placements,
        now_wall_ms(),
    ))
}

/// The POST routes after authentication and the body read.
pub(in crate::daemon_edge) fn write(
    request: &Request<'_>,
    payload: Option<&[(String, PyVal)]>,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<Answer> {
    if !rollout() {
        return Some(error(503, UNAVAILABLE));
    }
    let upstream = match request.path {
        LOCAL_RENDERS => Some(RENDERS_PATH),
        LOCAL_EVENTS => Some(EVENTS_PATH),
        _ => None,
    };
    if let Some(upstream) = upstream {
        let settings = settings(config, reads)?;
        // Measurement off still allows discovery but emits no render or
        // event request.
        if !flag(&settings, MEASUREMENT_ENABLED) {
            return Some(error(403, "measurement_disabled"));
        }
        let Some(payload) = payload else {
            return Some(error(400, "invalid_request"));
        };
        let raw = compact(&PyVal::Dict(payload.to_vec()));
        return Some(relay(upstream, raw, send_relay));
    }
    if request.path == LOCAL_SETTINGS {
        let empty = Vec::new();
        let update = payload.unwrap_or(&empty);
        let mut record = load_mapping(config, reads, SETTINGS_KEY)?;
        for name in [DISCOVERY_ENABLED, MEASUREMENT_ENABLED] {
            match last_value(update, name) {
                None | Some(PyVal::Null) => {}
                Some(PyVal::Bool(value)) => {
                    record.insert(name.to_owned(), Value::Bool(*value));
                }
                Some(_) => return Some(error(400, "invalid_request")),
            }
        }
        let now = micros_to_utc_isoformat(now_micros(), "+00:00")?;
        reads
            .store_write(
                config,
                "set_sync_payload",
                json!({
                    "state_key": SETTINGS_KEY,
                    "payload": Value::Object(record),
                    "now": now,
                }),
            )
            .ok()?;
        return settings(config, reads).map(|settings| Answer::Json(200, Value::Object(settings)));
    }
    Some(error(404, "not_found"))
}

/// The last value a Python dict keeps for `name`.
fn last_value<'a>(entries: &'a [(String, PyVal)], name: &str) -> Option<&'a PyVal> {
    entries
        .iter()
        .rev()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
}

fn load_mapping(config: &ReadConfig, reads: &NativeReads, key: &str) -> Option<Map<String, Value>> {
    let payload = reads.store_call(config, "get_sync_payload", json!({"state_key": key}))?;
    Some(match payload {
        Value::Object(record) => record,
        _ => Map::new(),
    })
}

/// The user's discovery preferences with the managed
/// policy applied.
fn settings(config: &ReadConfig, reads: &NativeReads) -> Option<Map<String, Value>> {
    let record = load_mapping(config, reads, SETTINGS_KEY)?;
    let managed = load_mapping(config, reads, MANAGED_KEY)?;
    Some(effective(&record, &managed))
}

pub(in crate::daemon_edge) fn effective(
    record: &Map<String, Value>,
    managed: &Map<String, Value>,
) -> Map<String, Value> {
    let mut settings = Map::new();
    for (name, default) in [(DISCOVERY_ENABLED, true), (MEASUREMENT_ENABLED, false)] {
        let value = record.get(name).and_then(Value::as_bool).unwrap_or(default);
        let managed_off = managed.get(name) == Some(&Value::Bool(false));
        settings.insert(name.to_owned(), Value::Bool(value && !managed_off));
    }
    settings.insert(
        "managed_discovery_disabled".to_owned(),
        Value::Bool(managed.get(DISCOVERY_ENABLED) == Some(&Value::Bool(false))),
    );
    settings.insert(
        "managed_measurement_disabled".to_owned(),
        Value::Bool(managed.get(MEASUREMENT_ENABLED) == Some(&Value::Bool(false))),
    );
    settings
}

fn flag(settings: &Map<String, Value>, name: &str) -> bool {
    settings.get(name) == Some(&Value::Bool(true))
}

/// One upstream read: status, ETag, Date and body, or the transport failure.
pub(in crate::daemon_edge) type Exchange =
    Result<(u16, Option<String>, Option<String>, Vec<u8>), &'static str>;

/// `discovery_placement_projection` after the gates, with the upstream read
/// supplied by `fetcher`.
pub(in crate::daemon_edge) fn placements(
    policy_allowed: bool,
    fetcher: impl FnOnce(Option<&str>) -> Exchange,
    now_wall_ms: i64,
) -> Answer {
    let snapshot = match snapshot(fetcher) {
        Ok(snapshot) => snapshot,
        Err((status, code)) => return error(status, code),
    };
    let Ok(body) = String::from_utf8(snapshot.body) else {
        return error(503, TRANSPORT_FAILED);
    };
    let request = DiscoveryPlacementProjectRequest {
        schema: DISCOVERY_REQUEST_SCHEMA.to_owned(),
        body,
        server_date_ms: snapshot.server_date_ms,
        now_wall_ms,
        policy_allowed,
    };
    let Ok(frame) = evaluate_discovery_placement_project(&request) else {
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
    if object.get("schema")?.as_str()? != DISCOVERY_RESULT_SCHEMA {
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
            Some(Answer::Raw(200, body.as_bytes().to_vec()))
        }
        "error" => {
            let code = object.get("error_code")?.as_str()?;
            let expected = match code {
                "discovery_request_invalid" | "discovery_body_invalid" => 400,
                "discovery_snapshot_invalid" => 503,
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

/// `fetch_discovery_snapshot`: the fresh cached snapshot, or one read now. A
/// 304 reuses the original body and server date; it never restamps the
/// eligibility observation.
fn snapshot(
    fetcher: impl FnOnce(Option<&str>) -> Exchange,
) -> Result<Snapshot, (u16, &'static str)> {
    let mut cache = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = Instant::now();
    if let Some(cached) = cache.as_ref() {
        if now.duration_since(cached.fetched) < FRESH_RESULT {
            return Ok(cached.clone());
        }
    }
    let etag = cache.as_ref().and_then(|cached| cached.etag.clone());
    let (status, fresh_etag, date, body) = fetcher(etag.as_deref()).map_err(|code| (503, code))?;
    if status == 304 {
        if let Some(cached) = cache.as_mut() {
            cached.fetched = now;
            return Ok(cached.clone());
        }
    }
    if status != 200 {
        return Err((503, UPSTREAM_ERROR));
    }
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err((503, TOO_LARGE));
    }
    if std::str::from_utf8(&body).is_err() {
        return Err((503, TRANSPORT_FAILED));
    }
    let fresh = Snapshot {
        body,
        server_date_ms: date.as_deref().and_then(http_date_ms),
        etag: fresh_etag,
        fetched: now,
    };
    *cache = Some(fresh.clone());
    Ok(fresh)
}

fn headers(extra: &[(&str, &str)]) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::from([
        ("Accept".to_owned(), "application/json".to_owned()),
        // Identity encoding keeps the byte bound equal to the decompressed
        // bound.
        ("Accept-Encoding".to_owned(), "identity".to_owned()),
        ("Cache-Control".to_owned(), "no-store".to_owned()),
        (
            "User-Agent".to_owned(),
            format!("hol-guard/{}", crate::PACKAGE_VERSION),
        ),
    ]);
    for (name, value) in extra {
        headers.insert((*name).to_owned(), (*value).to_owned());
    }
    headers
}

/// The placements read under the machine's managed network policy. No
/// redirect is followed and no Authorization, Cookie or local identifier is
/// attached.
fn fetch_placements(etag: Option<&str>) -> Exchange {
    let policy = CallerEgressFulfilment::resolve_policy(&ManagedPolicySource::native())
        .map_err(|_| TRANSPORT_FAILED)?;
    let extra: Vec<(&str, &str)> = etag
        .map(|etag| ("If-None-Match", etag))
        .into_iter()
        .collect();
    match policy_send(
        "GET",
        &format!("{}{PLACEMENTS_PATH}", origin()),
        headers(&extra),
        None,
        IO_DEADLINE_SECONDS,
        0,
        MAX_RESPONSE_BYTES,
        &policy,
    ) {
        Ok((status, headers, body)) => Ok((
            status,
            headers.get("etag").cloned(),
            headers.get("date").cloned(),
            body,
        )),
        Err(outcome) => Err(failure_code(&outcome)),
    }
}

fn failure_code(outcome: &EgressOutcomeV1) -> &'static str {
    match outcome {
        EgressOutcomeV1::Error { message } if message == "response too large" => TOO_LARGE,
        _ => TRANSPORT_FAILED,
    }
}

/// One relay exchange: the status and body, or the transport failure.
pub(in crate::daemon_edge) type RelayExchange = Result<(u16, Vec<u8>), &'static str>;

/// `relay_discovery_measurement`: a consented render or event body sent to the
/// fixed origin.
pub(in crate::daemon_edge) fn relay(
    upstream: &str,
    raw: String,
    sender: impl FnOnce(&str, String) -> RelayExchange,
) -> Answer {
    if raw.len() > MAX_REQUEST_BYTES {
        return error(400, "discovery_request_invalid");
    }
    match sender(upstream, raw) {
        Err(code) => error(503, code),
        Ok((200, body)) => Answer::Raw(200, body),
        Ok((status, _)) if (200..300).contains(&status) => error(503, UPSTREAM_ERROR),
        Ok((status, body)) if body.len() <= MAX_RELAYED_ERROR_BYTES => Answer::Raw(status, body),
        Ok((status, _)) => Answer::Raw(status, br#"{"error":"relay_failed"}"#.to_vec()),
    }
}

fn send_relay(upstream: &str, raw: String) -> RelayExchange {
    let policy = CallerEgressFulfilment::resolve_policy(&ManagedPolicySource::native())
        .map_err(|_| TRANSPORT_FAILED)?;
    match policy_send(
        "POST",
        &format!("{}{upstream}", origin()),
        headers(&[("Content-Type", "application/json")]),
        Some(raw),
        IO_DEADLINE_SECONDS,
        0,
        MAX_RESPONSE_BYTES,
        &policy,
    ) {
        Ok((status, _, body)) => Ok((status, body)),
        Err(outcome) => Err(failure_code(&outcome)),
    }
}

/// `json.dumps(value, separators=(",", ":"))`: ASCII-only, key order kept,
/// a repeated key collapsed to its first position and last value.
pub(in crate::daemon_edge) fn compact(value: &PyVal) -> String {
    let mut out = String::new();
    write_compact(value, &mut out);
    out
}

fn write_compact(value: &PyVal, out: &mut String) {
    match value {
        PyVal::Null => out.push_str("null"),
        PyVal::Bool(true) => out.push_str("true"),
        PyVal::Bool(false) => out.push_str("false"),
        PyVal::Int(digits) => out.push_str(digits),
        PyVal::Float(number) => out.push_str(&float_repr(*number)),
        PyVal::Str(text) => write_string(text, out),
        PyVal::List(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_compact(item, out);
            }
            out.push(']');
        }
        PyVal::Dict(entries) => {
            let mut order: Vec<&str> = Vec::new();
            let mut latest: BTreeMap<&str, &PyVal> = BTreeMap::new();
            for (key, item) in entries {
                if latest.insert(key, item).is_none() {
                    order.push(key);
                }
            }
            out.push('{');
            for (index, key) in order.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_compact(latest[key], out);
            }
            out.push('}');
        }
    }
}

fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            ' '..='~' => out.push(character),
            _ => {
                let mut units = [0u16; 2];
                for unit in character.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
}

/// `_parse_http_date_ms` for the forms an HTTP `Date` header takes:
/// `[Day, ]DD Mon YYYY HH:MM[:SS] ZONE`.
pub(in crate::daemon_edge) fn http_date_ms(value: &str) -> Option<i64> {
    let text = value.trim();
    let text = match text.split_once(',') {
        Some((_, rest)) => rest.trim(),
        None => text,
    };
    let parts: Vec<&str> = text.split_whitespace().collect();
    let [day, month, year, time, zone] = parts.as_slice() else {
        return None;
    };
    let day: u32 = day.parse().ok()?;
    let month = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ]
    .iter()
    .position(|name| month.eq_ignore_ascii_case(name))? as u32
        + 1;
    let mut year: i64 = year.parse().ok()?;
    if year < 100 {
        year += if year > 68 { 1900 } else { 2000 };
    }
    let clock: Vec<&str> = time.split(':').collect();
    let (hour, minute, second): (i64, i64, i64) = match clock.as_slice() {
        [hour, minute] => (hour.parse().ok()?, minute.parse().ok()?, 0),
        [hour, minute, second] => (
            hour.parse().ok()?,
            minute.parse().ok()?,
            second.parse().ok()?,
        ),
        _ => return None,
    };
    if !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 61 {
        return None;
    }
    let offset_seconds: i64 = match zone.to_ascii_uppercase().as_str() {
        "GMT" | "UT" | "UTC" | "Z" => 0,
        signed if signed.len() == 5 && (signed.starts_with('+') || signed.starts_with('-')) => {
            let hours: i64 = signed[1..3].parse().ok()?;
            let minutes: i64 = signed[3..5].parse().ok()?;
            let magnitude = hours * 3600 + minutes * 60;
            if signed.starts_with('-') {
                -magnitude
            } else {
                magnitude
            }
        }
        _ => return None,
    };
    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second - offset_seconds;
    seconds.checked_mul(1000)
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day_of_year =
        (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn now_wall_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as i64)
}

fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_micros() as i64)
}

fn error(status: u16, code: &str) -> Answer {
    Answer::Json(status, json!({"error": code}))
}

#[cfg(test)]
pub(in crate::daemon_edge) fn reset_cache_for_tests() {
    *CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
}

#[cfg(all(test, unix))]
#[path = "daemon_edge_discovery_tests.rs"]
mod tests;

//! Native discovery placement validation and lease projection.
//!
//! The daemon's I/O-only adapter fetches a fixed-origin snapshot from Guard
//! Cloud and hands the raw bytes here. This module is the only place a
//! placement becomes renderable: it validates the untrusted payload against
//! the `guard.extensions.discovery.v1` contract (structure, bounds, safe
//! plain text, temporal invariants), projects a conservative remaining lease,
//! and re-serializes a data-only projection. It never fetches, never writes
//! catalog/policy/trust state, and never executes anything derived from the
//! payload. No validated native capability means no paid fallback.

use serde::Deserialize;
use serde_json::{json, Map, Value};

pub const DISCOVERY_PLACEMENT_FEATURE: &str = "discovery-placement-projection-v1";
pub const DISCOVERY_PROJECT_REQUEST_SCHEMA: &str = "guard-discovery-project-request.v1";
pub const DISCOVERY_PROJECT_RESULT_SCHEMA: &str = "guard-discovery-project-result.v1";
pub const DISCOVERY_SNAPSHOT_SCHEMA: &str = "guard.extensions.discovery.v1";
/// Maximum candidates in one snapshot (10 always + 5 time-slot + 4 sponsored).
pub const MAX_DISCOVERY_PLACEMENTS: usize = 19;
/// Absolute snapshot lease, measured from the Cloud eligibility observation.
pub const MAX_DISCOVERY_LEASE_MS: i64 = 30_000;
/// A server observation further in the future than this is rejected.
const FUTURE_TOLERANCE_MS: i64 = 5_000;
/// Maximum upstream JSON nesting depth accepted by the validator.
const MAX_JSON_DEPTH: usize = 12;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryPlacementProjectRequest {
    pub schema: String,
    /// Raw upstream JSON text (the adapter already bounded its size).
    pub body: String,
    /// Server `Date` header (epoch ms) captured from the HTTP response, when
    /// present: the trusted response-time anchor for future-observation
    /// checks. Local clocks alone are not trusted.
    pub server_date_ms: Option<i64>,
    /// Current local wall clock (epoch ms) at projection time.
    pub now_wall_ms: i64,
    /// Effective local sponsorship policy: false empties paid content.
    pub policy_allowed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoveryError {
    Request,
    Body,
    Snapshot,
}

impl DiscoveryError {
    fn code(self) -> &'static str {
        match self {
            Self::Request => "discovery_request_invalid",
            Self::Body => "discovery_body_invalid",
            Self::Snapshot => "discovery_snapshot_invalid",
        }
    }

    fn http_status(self) -> u16 {
        match self {
            Self::Request | Self::Body => 400,
            Self::Snapshot => 503,
        }
    }
}

fn error_frame(error: DiscoveryError) -> Value {
    json!({
        "schema": DISCOVERY_PROJECT_RESULT_SCHEMA,
        "outcome": "error",
        "http_status": error.http_status(),
        "etag": Value::Null,
        "body": Value::Null,
        "error_code": error.code(),
    })
}

/// Strict UTC ISO-8601 parser for the Cloud wire format
/// (`YYYY-MM-DDTHH:MM:SS[.fff]Z`). Returns epoch milliseconds.
fn parse_utc_iso_ms(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() != 20 && bytes.len() != 24 {
        return None;
    }
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[bytes.len() - 1] != b'Z'
    {
        return None;
    }
    let digits_at = |range: std::ops::Range<usize>| -> Option<[u8; 4]> {
        let mut out = [0u8; 4];
        for (index, position) in range.enumerate() {
            let byte = bytes.get(position).copied()?;
            if !byte.is_ascii_digit() {
                return None;
            }
            out[index] = byte;
        }
        Some(out)
    };
    let year = digits_at(0..4)?;
    let month = digits_at(5..7)?;
    let day = digits_at(8..10)?;
    let hour = digits_at(11..13)?;
    let minute = digits_at(14..16)?;
    let second = digits_at(17..19)?;
    let millis = if bytes.len() == 24 {
        if bytes[19] != b'.' {
            return None;
        }
        digits_at(20..23)?
    } else {
        [b'0'; 4]
    };
    let number = |group: [u8; 4], len: usize| -> i64 {
        let mut value: i64 = 0;
        for byte in group.iter().take(len.max(1)) {
            value = value * 10 + i64::from(byte - b'0');
        }
        value
    };
    let year = number(year, 4);
    let month = number(month, 2);
    let day = number(day, 2);
    let hour = number(hour, 2);
    let minute = number(minute, 2);
    let second = number(second, 2);
    let millisecond = if bytes.len() == 24 {
        number(millis, 3)
    } else {
        0
    };
    let valid_month = (1..=12).contains(&month);
    let valid_day = (1..=31).contains(&day);
    if !valid_month || !valid_day || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    // Days-from-civil (Howard Hinnant's algorithm), valid for the supported
    // Gregorian range; leap-day validity is checked against the month.
    let is_leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month = [
        31,
        if is_leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let month_index = usize::try_from(month - 1).ok()?;
    if day > days_in_month[month_index] {
        return None;
    }
    let years = if month <= 2 { year - 1 } else { year };
    let era = if years >= 0 { years } else { years - 399 } / 400;
    let year_of_era = years - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(((days * 24 + hour) * 60 * 60 + minute * 60 + second) * 1000 + millisecond)
}

fn json_depth(value: &Value) -> usize {
    match value {
        Value::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        Value::Array(items) => 1 + items.iter().map(json_depth).max().unwrap_or(0),
        _ => 1,
    }
}

fn is_uuid_like(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

fn is_extension_id(value: &str) -> bool {
    let (namespace, rest) = match value.split_once('.') {
        Some(parts) => parts,
        None => return false,
    };
    if !matches!(namespace, "command" | "mcp") {
        return false;
    }
    let mut chars = rest.chars();
    match chars.next() {
        Some(first) if first.is_ascii_lowercase() || first.is_ascii_digit() => {}
        _ => return false,
    }
    let allowed =
        |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-');
    rest.len() >= 3 && rest.len() <= 132 && rest.chars().all(allowed)
}

/// Plain-text bound shared by creative fields and creative versions: no
/// C0/C1 controls, no bidi/format marks, no line/paragraph separators, and
/// no markup-significant code points. Mirrors the Cloud contract's stricter
/// creative class (see points-portal discovery contracts).
fn is_safe_text(value: &str) -> bool {
    value.chars().all(|c| {
        !matches!(c,
            '\u{0000}'..='\u{001f}'
                | '\u{007f}'..='\u{009f}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
                | '<'
                | '>')
    })
}

fn field_str<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

fn validate_creative(object: &Map<String, Value>) -> Result<(), DiscoveryError> {
    let creative = object
        .get("creative")
        .and_then(Value::as_object)
        .ok_or(DiscoveryError::Snapshot)?;
    if creative.len() != 3 {
        return Err(DiscoveryError::Snapshot);
    }
    for (key, limit) in [("headline", 80usize), ("body", 160), ("brandName", 64)] {
        let value = field_str(creative, key).ok_or(DiscoveryError::Snapshot)?;
        if value.is_empty() || value.chars().count() > limit || !is_safe_text(value) {
            return Err(DiscoveryError::Snapshot);
        }
    }
    Ok(())
}

fn validate_placement(
    object: &Map<String, Value>,
    generated_ms: i64,
    seen_ids: &mut Vec<String>,
) -> Result<i64, DiscoveryError> {
    const PLACEMENT_FIELDS: [&str; 9] = [
        "publicPlacementId",
        "extensionId",
        "product",
        "slotIndex",
        "windowIndex",
        "startsAt",
        "endsAt",
        "creativeVersion",
        "creative",
    ];
    if object.len() != PLACEMENT_FIELDS.len()
        || !PLACEMENT_FIELDS.iter().all(|key| object.contains_key(*key))
    {
        return Err(DiscoveryError::Snapshot);
    }
    let public_id = field_str(object, "publicPlacementId").ok_or(DiscoveryError::Snapshot)?;
    if !is_uuid_like(public_id) || seen_ids.iter().any(|seen| seen == public_id) {
        return Err(DiscoveryError::Snapshot);
    }
    seen_ids.push(public_id.to_owned());
    let extension_id = field_str(object, "extensionId").ok_or(DiscoveryError::Snapshot)?;
    if !is_extension_id(extension_id) {
        return Err(DiscoveryError::Snapshot);
    }
    let product = field_str(object, "product").ok_or(DiscoveryError::Snapshot)?;
    if !matches!(product, "always" | "time_slot" | "sponsored") {
        return Err(DiscoveryError::Snapshot);
    }
    let slot_index = object
        .get("slotIndex")
        .and_then(Value::as_i64)
        .ok_or(DiscoveryError::Snapshot)?;
    let slot_max = match product {
        "always" => 9,
        "time_slot" => 4,
        _ => 3,
    };
    if !(0..=slot_max).contains(&slot_index) {
        return Err(DiscoveryError::Snapshot);
    }
    let window = match object.get("windowIndex") {
        Some(Value::Number(number)) => {
            let window_index = number.as_i64().ok_or(DiscoveryError::Snapshot)?;
            if !(0..=11).contains(&window_index) {
                return Err(DiscoveryError::Snapshot);
            }
            Some(window_index)
        }
        Some(Value::Null) => None,
        _ => return Err(DiscoveryError::Snapshot),
    };
    match (product, window) {
        ("time_slot", Some(_)) => {}
        ("time_slot", None) | (_, Some(_)) => return Err(DiscoveryError::Snapshot),
        _ => {}
    }
    if product == "time_slot" {
        // The two-hour UTC window at the observation must match the carried
        // window index; a stale prior-window placement is not renderable.
        // Window index = floor(UTC hour / 2) over the 12 daily windows.
        let utc_hour = generated_ms / 3_600_000 % 24;
        let expected = utc_hour / 2;
        if window != Some(expected) {
            return Err(DiscoveryError::Snapshot);
        }
    }
    let starts = parse_utc_iso_ms(field_str(object, "startsAt").ok_or(DiscoveryError::Snapshot)?)
        .ok_or(DiscoveryError::Snapshot)?;
    let ends = parse_utc_iso_ms(field_str(object, "endsAt").ok_or(DiscoveryError::Snapshot)?)
        .ok_or(DiscoveryError::Snapshot)?;
    if ends <= starts || starts > generated_ms || ends <= generated_ms {
        return Err(DiscoveryError::Snapshot);
    }
    let creative_version = field_str(object, "creativeVersion").ok_or(DiscoveryError::Snapshot)?;
    if creative_version.is_empty()
        || creative_version.chars().count() > 64
        || !is_safe_text(creative_version)
    {
        return Err(DiscoveryError::Snapshot);
    }
    validate_creative(object)?;
    Ok(ends)
}

fn validate_offer(object: &Map<String, Value>) -> Result<(), DiscoveryError> {
    const OFFER_FIELDS: [&str; 6] = [
        "product",
        "availability",
        "indicativeAmountCents",
        "currency",
        "checkedAt",
        "quoteRequired",
    ];
    if object.len() != OFFER_FIELDS.len()
        || !OFFER_FIELDS.iter().all(|key| object.contains_key(*key))
    {
        return Err(DiscoveryError::Snapshot);
    }
    if object.get("quoteRequired") != Some(&Value::Bool(true)) {
        return Err(DiscoveryError::Snapshot);
    }
    let product = field_str(object, "product").ok_or(DiscoveryError::Snapshot)?;
    if !matches!(product, "always" | "time_slot" | "sponsored") {
        return Err(DiscoveryError::Snapshot);
    }
    let availability = field_str(object, "availability").ok_or(DiscoveryError::Snapshot)?;
    if !matches!(availability, "open" | "sold_out" | "unknown") {
        return Err(DiscoveryError::Snapshot);
    }
    let amount_null = matches!(object.get("indicativeAmountCents"), Some(Value::Null));
    let currency = field_str(object, "currency");
    let checked = field_str(object, "checkedAt");
    if availability == "unknown" {
        if !amount_null || currency.is_some() || checked.is_some() {
            return Err(DiscoveryError::Snapshot);
        }
        return Ok(());
    }
    if amount_null || currency.is_none() || checked.is_none() {
        return Err(DiscoveryError::Snapshot);
    }
    let amount = object
        .get("indicativeAmountCents")
        .and_then(Value::as_i64)
        .ok_or(DiscoveryError::Snapshot)?;
    if !(1..=100_000_000).contains(&amount) {
        return Err(DiscoveryError::Snapshot);
    }
    let currency = currency.unwrap_or_default();
    if currency.len() != 3 || !currency.chars().all(|c| c.is_ascii_lowercase()) {
        return Err(DiscoveryError::Snapshot);
    }
    parse_utc_iso_ms(checked.unwrap_or_default()).ok_or(DiscoveryError::Snapshot)?;
    Ok(())
}

fn validate_snapshot(
    snapshot: &Map<String, Value>,
    request: &DiscoveryPlacementProjectRequest,
) -> Result<i64, DiscoveryError> {
    const SNAPSHOT_FIELDS: [&str; 9] = [
        "schemaVersion",
        "snapshotId",
        "state",
        "enabled",
        "reasonCode",
        "generatedAt",
        "leaseExpiresAt",
        "placements",
        "offers",
    ];
    if snapshot.len() != SNAPSHOT_FIELDS.len()
        || !SNAPSHOT_FIELDS
            .iter()
            .all(|key| snapshot.contains_key(*key))
    {
        return Err(DiscoveryError::Snapshot);
    }
    if field_str(snapshot, "schemaVersion") != Some(DISCOVERY_SNAPSHOT_SCHEMA) {
        return Err(DiscoveryError::Snapshot);
    }
    if !is_uuid_like(field_str(snapshot, "snapshotId").unwrap_or_default()) {
        return Err(DiscoveryError::Snapshot);
    }
    let state = field_str(snapshot, "state").ok_or(DiscoveryError::Snapshot)?;
    let enabled = matches!(snapshot.get("enabled"), Some(Value::Bool(true)));
    let reason = match snapshot.get("reasonCode") {
        Some(Value::Null) => None,
        Some(Value::String(code)) => Some(code.as_str()),
        _ => return Err(DiscoveryError::Snapshot),
    };
    if !matches!(state, "ready" | "unavailable") {
        return Err(DiscoveryError::Snapshot);
    }
    match reason {
        None | Some("disabled" | "source_unavailable" | "invalid_snapshot" | "rate_limited") => {}
        _ => return Err(DiscoveryError::Snapshot),
    }
    if state == "unavailable" {
        if enabled {
            return Err(DiscoveryError::Snapshot);
        }
        let terminal = matches!(
            reason,
            Some("source_unavailable" | "invalid_snapshot" | "rate_limited")
        );
        if !terminal {
            return Err(DiscoveryError::Snapshot);
        }
    } else if enabled != (reason.is_none()) || (!enabled && reason != Some("disabled")) {
        return Err(DiscoveryError::Snapshot);
    }

    let generated =
        parse_utc_iso_ms(field_str(snapshot, "generatedAt").ok_or(DiscoveryError::Snapshot)?)
            .ok_or(DiscoveryError::Snapshot)?;
    let lease =
        parse_utc_iso_ms(field_str(snapshot, "leaseExpiresAt").ok_or(DiscoveryError::Snapshot)?)
            .ok_or(DiscoveryError::Snapshot)?;
    if lease <= generated || lease - generated > MAX_DISCOVERY_LEASE_MS {
        return Err(DiscoveryError::Snapshot);
    }
    // A server observation unreasonably in the future is rejected. The HTTP
    // Date header is the trusted anchor when present; the local wall clock is
    // only a secondary bound.
    if let Some(server_date) = request.server_date_ms {
        if generated > server_date + FUTURE_TOLERANCE_MS {
            return Err(DiscoveryError::Snapshot);
        }
    }
    if generated > request.now_wall_ms + FUTURE_TOLERANCE_MS {
        return Err(DiscoveryError::Snapshot);
    }

    let placements = snapshot
        .get("placements")
        .and_then(Value::as_array)
        .ok_or(DiscoveryError::Snapshot)?;
    if placements.len() > MAX_DISCOVERY_PLACEMENTS {
        return Err(DiscoveryError::Snapshot);
    }
    if !enabled && !placements.is_empty() {
        return Err(DiscoveryError::Snapshot);
    }
    let mut earliest_item_end: Option<i64> = None;
    let mut seen_ids = Vec::new();
    for placement in placements {
        let object = placement.as_object().ok_or(DiscoveryError::Snapshot)?;
        let ends = validate_placement(object, generated, &mut seen_ids)?;
        earliest_item_end = Some(match earliest_item_end {
            Some(current) => current.min(ends),
            None => ends,
        });
    }

    let offers = snapshot
        .get("offers")
        .and_then(Value::as_array)
        .ok_or(DiscoveryError::Snapshot)?;
    if offers.len() != 3 {
        return Err(DiscoveryError::Snapshot);
    }
    let mut products: Vec<&str> = Vec::with_capacity(3);
    for offer in offers {
        let object = offer.as_object().ok_or(DiscoveryError::Snapshot)?;
        validate_offer(object)?;
        products.push(field_str(object, "product").unwrap_or_default());
    }
    let distinct =
        products[0] != products[1] && products[0] != products[2] && products[1] != products[2];
    if products.iter().any(|product| product.is_empty()) || !distinct {
        return Err(DiscoveryError::Snapshot);
    }
    if state == "unavailable"
        && offers.iter().any(|offer| {
            let object = offer.as_object();
            field_str(object.unwrap_or(&Map::new()), "availability") != Some("unknown")
        })
    {
        return Err(DiscoveryError::Snapshot);
    }

    Ok(match earliest_item_end {
        Some(item_end) => lease.min(item_end),
        None => lease,
    })
}

/// Validate the upstream snapshot and project the Local response body.
/// Returns the resident result frame as encoded bytes; the Python adapter
/// writes `body` verbatim and never interprets placements.
pub fn evaluate_discovery_placement_project(
    request: &DiscoveryPlacementProjectRequest,
) -> Result<Vec<u8>, String> {
    let frame = match evaluate_discovery_placement_frame(request) {
        Ok(frame) => frame,
        Err(error) => error_frame(error),
    };
    serde_json::to_vec(&frame).map_err(|error| error.to_string())
}

fn evaluate_discovery_placement_frame(
    request: &DiscoveryPlacementProjectRequest,
) -> Result<Value, DiscoveryError> {
    if request.schema != DISCOVERY_PROJECT_REQUEST_SCHEMA {
        return Err(DiscoveryError::Request);
    }
    if request.body.len() > 131_072 || request.now_wall_ms <= 0 {
        return Err(DiscoveryError::Request);
    }
    let parsed: Value = match serde_json::from_str(&request.body) {
        Ok(parsed) => parsed,
        Err(_) => return Err(DiscoveryError::Body),
    };
    if json_depth(&parsed) > MAX_JSON_DEPTH {
        return Err(DiscoveryError::Body);
    }
    let snapshot = match parsed.as_object() {
        Some(object) => object,
        None => return Err(DiscoveryError::Body),
    };
    let authority_end = validate_snapshot(snapshot, request)?;

    // The projection removes items that ended while the snapshot was cached;
    // it can never extend the upstream lease.
    let mut projected = snapshot.clone();
    let remaining_ms = (authority_end - request.now_wall_ms).clamp(0, MAX_DISCOVERY_LEASE_MS);
    if !request.policy_allowed {
        projected.insert("enabled".to_owned(), Value::Bool(false));
        projected.insert(
            "reasonCode".to_owned(),
            Value::String("disabled".to_owned()),
        );
        projected.insert("placements".to_owned(), Value::Array(Vec::new()));
    } else if remaining_ms == 0 {
        projected.insert("placements".to_owned(), Value::Array(Vec::new()));
    } else if let Some(placements) = snapshot.get("placements").and_then(Value::as_array) {
        let kept: Vec<Value> = placements
            .iter()
            .filter(|placement| {
                placement
                    .as_object()
                    .and_then(|object| field_str(object, "endsAt"))
                    .and_then(parse_utc_iso_ms)
                    .is_some_and(|ends| ends > request.now_wall_ms)
            })
            .cloned()
            .collect();
        projected.insert("placements".to_owned(), Value::Array(kept));
    }
    let projection = json!({
        "snapshot": projected,
        "remainingLeaseMs": if request.policy_allowed { remaining_ms } else { 0 },
        "policyAllowed": request.policy_allowed,
    });
    let body = serde_json::to_string(&projection).map_err(|_| DiscoveryError::Body)?;
    Ok(json!({
        "schema": DISCOVERY_PROJECT_RESULT_SCHEMA,
        "outcome": "ok",
        "http_status": 200,
        "etag": Value::Null,
        "body": body,
        "error_code": Value::Null,
    }))
}

#[cfg(test)]
#[path = "discovery_placement_op_tests.rs"]
mod discovery_placement_op_tests;

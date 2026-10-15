//! `consume_native_review_approval` — spends the chronologically latest
//! matching five-minute allow of a verified harness-native Accept.
//!
//! A resolved inbox row is not a permanent capability: it is bound to the
//! newly computed request identity and consumed at most once, in the same
//! write transaction the `guard_store` op already holds. Same-instant
//! decisions are one logical resolution set; any conflict, any matching row
//! with an unusable timestamp, or any binding outside the native-review
//! grammar refuses. Timestamp spellings outside `YYYY-MM-DD[T ]HH:MM[:SS[.f]]`
//! plus `Z` or a numeric offset are refused too (fail closed).
//!
//! Parity vectors recorded from the original Python implementation live in
//! `testdata/guard_store/native_review_consume_vectors.json`.

use std::sync::OnceLock;

use guard_contracts::{canonical_utc_timestamp, utc_timestamp_micros};
use regex::Regex;
use rusqlite::Connection;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_all, StoreResult};

const WINDOW_MICROS: i64 = 5 * 60 * 1_000_000;
const EVENT_NAME: &str = "native-review.once-consumed";

fn binding_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        // Extension-bound reviews append a lowercase SHA256 policy-domain digest.
        Regex::new(r"^native-review-v4:[0-9a-f]{64}(?::[a-z0-9_-]{1,128}){4}(?::[0-9a-f]{64})?$")
            .expect("native review binding pattern")
    })
}

fn digits(bytes: &[u8], at: &mut usize, count: usize) -> Option<u32> {
    let slice = bytes.get(*at..*at + count)?;
    *at += count;
    slice.iter().try_fold(0u32, |acc, byte| {
        byte.is_ascii_digit()
            .then(|| acc * 10 + u32::from(byte - b'0'))
    })
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn expect(bytes: &[u8], at: &mut usize, byte: u8) -> Option<()> {
    (bytes.get(*at) == Some(&byte)).then(|| *at += 1)
}

fn parse_aware(text: &str) -> Option<()> {
    let bytes = text.as_bytes();
    let mut at = 0;
    let year = digits(bytes, &mut at, 4)?;
    expect(bytes, &mut at, b'-')?;
    let month = digits(bytes, &mut at, 2)?;
    expect(bytes, &mut at, b'-')?;
    let day = digits(bytes, &mut at, 2)?;
    if year == 0 || !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return None;
    }
    matches!(bytes.get(at), Some(b'T' | b' ')).then(|| at += 1)?;
    let hour = digits(bytes, &mut at, 2)?;
    expect(bytes, &mut at, b':')?;
    let minute = digits(bytes, &mut at, 2)?;
    let mut second = 0;
    if expect(bytes, &mut at, b':').is_some() {
        second = digits(bytes, &mut at, 2)?;
        if expect(bytes, &mut at, b'.').is_some() {
            let start = at;
            while bytes.get(at).is_some_and(u8::is_ascii_digit) {
                at += 1;
            }
            (at > start).then_some(())?;
        }
    }
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    if expect(bytes, &mut at, b'Z').is_none() {
        matches!(bytes.get(at), Some(b'+' | b'-')).then(|| at += 1)?;
        let offset_hour = digits(bytes, &mut at, 2)?;
        let mut offset_minute = 0;
        if expect(bytes, &mut at, b':').is_some() || at < bytes.len() {
            offset_minute = digits(bytes, &mut at, 2)?;
        }
        if offset_hour > 23 || offset_minute > 59 {
            return None;
        }
    }
    (at == bytes.len()).then_some(())
}

/// Instant in microseconds plus CPython's `isoformat()` spelling of its UTC form.
fn instant(value: Option<&str>) -> Option<(i64, String)> {
    let text = value?;
    parse_aware(text)?;
    let micros = utc_timestamp_micros(text)?;
    let canonical = canonical_utc_timestamp(text)?;
    let iso = canonical
        .strip_suffix(".000000+00:00")
        .map_or(canonical.clone(), |head| format!("{head}+00:00"));
    Some((micros, iso))
}

pub(crate) fn consume(connection: &Connection, args: &Args) -> StoreResult<Value> {
    matching_decision(connection, args, "allow", true)
}

pub(crate) fn matching_block(connection: &Connection, args: &Args) -> StoreResult<Value> {
    // A refusal cannot grant execution. Keep it for the retry window so repeated
    // attempts do not re-open the question the user has already answered.
    matching_decision(connection, args, "block", false)
}

fn matching_decision(
    connection: &Connection,
    args: &Args,
    action: &str,
    spend: bool,
) -> StoreResult<Value> {
    let (harness, artifact_id, artifact_name) = (
        args.str("harness")?,
        args.str("artifact_id")?,
        args.str("artifact_name")?,
    );
    let (artifact_hash, launch_target) = (args.str("artifact_hash")?, args.str("launch_target")?);
    let workspace = args.opt_str("workspace")?;
    let Some((current, current_iso)) = instant(Some(args.str("now")?)) else {
        return Ok(json!(false));
    };
    if !binding_pattern().is_match(artifact_hash) {
        return Ok(json!(false));
    }
    let rows = query_all(
        connection,
        "select request_id, resolved_at, resolution_action, resolution_scope \
         from approval_requests \
         where status = 'resolved' and harness = ? and artifact_id = ? and artifact_name = ? \
           and artifact_hash = ? and launch_target = ? and workspace is ?",
        &[
            Value::from(harness),
            Value::from(artifact_id),
            Value::from(artifact_name),
            Value::from(artifact_hash),
            Value::from(launch_target),
            workspace.map_or(Value::Null, Value::from),
        ],
    )?;
    let mut resolved = Vec::with_capacity(rows.len());
    for row in &rows {
        // An unusable timestamp on any matching row means the latest decision
        // cannot be established, so no older allow is reused.
        let Some((micros, iso)) = instant(row.get("resolved_at").and_then(Value::as_str)) else {
            return Ok(json!(false));
        };
        resolved.push((micros, iso, row));
    }
    let Some(approved_at) = resolved.iter().map(|(micros, _, _)| *micros).max() else {
        return Ok(json!(false));
    };
    let latest: Vec<_> = resolved
        .iter()
        .filter(|(micros, _, _)| *micros == approved_at)
        .collect();
    // Same-instant decisions are one logical resolution set. Any conflict is
    // ambiguous and refuses rather than relying on SQLite row order.
    let allowed = latest.iter().all(|(_, _, row)| {
        row.get("resolution_action").and_then(Value::as_str) == Some(action)
            && matches!(
                row.get("resolution_scope").and_then(Value::as_str),
                Some("once" | "artifact")
            )
    });
    let elapsed = current - approved_at;
    if !allowed || !(0..=WINDOW_MICROS).contains(&elapsed) {
        return Ok(json!(false));
    }
    if !spend {
        return Ok(json!(true));
    }
    let request_id = latest
        .iter()
        .filter_map(|(_, _, row)| row.get("request_id").and_then(Value::as_str))
        .min()
        .unwrap_or_default();
    // All equivalent decisions at this instant are spent as one capability.
    let approved_iso = &latest[0].1;
    let effect_key = hex::encode(Sha256::digest(
        format!("native-review-once-v3\0{artifact_hash}\0{approved_iso}").as_bytes(),
    ));
    let inserted = exec(
        connection,
        "insert or ignore into guard_continuation_effects \
         (effect_key, request_id, evidence_id, event_name, created_at) \
         values (?, ?, ?, ?, ?)",
        &[
            Value::from(effect_key),
            Value::from(request_id),
            Value::from(artifact_hash),
            Value::from(EVENT_NAME),
            Value::from(current_iso),
        ],
    )?;
    Ok(json!(inserted == 1))
}

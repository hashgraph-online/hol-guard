//! Record bridge-ingress and native-worker capture rows when a private,
//! unexpired marker enables the opt-in diagnostics.

use std::path::Path;

use crate::binding_capture_crypto::{seal_receipt, CaptureSession};
use crate::binding_capture_fs::{append_row, load_capture_config};
use crate::binding_capture_json::{self as json, Json};
use crate::binding_capture_receipt::receipt_projection;
use crate::binding_capture_record::base_row;

const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
const TRANSPORT_FIELDS: [&str; 3] = ["guard_remaining_seconds", "guard_remaining_ms", "hook_env"];

fn payload_object(text: &str) -> Option<Json> {
    if text.len() > MAX_PAYLOAD_BYTES {
        return None;
    }
    json::parse_object(text.as_bytes())
}

fn seal_and_append(
    session: &CaptureSession,
    guard_home: &Path,
    mut row: Vec<(String, Json)>,
    now: f64,
) -> bool {
    let Some(mac) = session.row_hmac(&Json::Obj(row.clone()), now) else {
        return false;
    };
    row.push(("row_mac".to_owned(), Json::Str(mac)));
    append_row(session, guard_home, &Json::Obj(row), now)
}

/// Fingerprint the raw and forwarded ingress payloads (`record_bridge_ingress`).
pub(crate) fn record_bridge_ingress(
    guard_home: &Path,
    raw_payload: &str,
    forwarded_payload: Option<&str>,
    event_name: &str,
    harness: &str,
    now: f64,
) -> bool {
    if harness != "codex" {
        return false;
    }
    let Some(session) = load_capture_config(guard_home, now) else {
        return false;
    };
    let (Some(raw), Some(forwarded)) = (
        payload_object(raw_payload),
        payload_object(forwarded_payload.unwrap_or(raw_payload)),
    ) else {
        return false;
    };
    let Json::Obj(entries) = forwarded else {
        return false;
    };
    // Daemon admission removes transport fields before native review.
    let forwarded = Json::Obj(
        entries
            .into_iter()
            .filter(|(key, _)| !TRANSPORT_FIELDS.contains(&key.as_str()))
            .collect(),
    );
    let (Some(raw_mac), Some(forwarded_mac)) = (
        session.payload_hmac("raw", &raw, now),
        session.payload_hmac("forwarded", &forwarded, now),
    ) else {
        return false;
    };
    let Some(mut row) = base_row(&session, "bridge_ingress", harness, event_name, &raw) else {
        return false;
    };
    row.push(("raw_payload_hmac_sha256".to_owned(), Json::Str(raw_mac)));
    row.push((
        "forwarded_payload_hmac_sha256".to_owned(),
        Json::Str(forwarded_mac),
    ));
    seal_and_append(&session, guard_home, row, now)
}

/// Seal the validated native-edge receipt with the forwarded payload digest.
pub(crate) fn record_native_worker(
    guard_home: &Path,
    payload: &str,
    harness: &str,
    event_name: &str,
    receipt: &str,
    now: f64,
) -> bool {
    if harness != "codex" {
        return false;
    }
    let Some(session) = load_capture_config(guard_home, now) else {
        return false;
    };
    let Some(payload) = payload_object(payload) else {
        return false;
    };
    let Some(fingerprint) = session.payload_hmac("forwarded", &payload, now) else {
        return false;
    };
    let Some(projection) = json::parse(receipt).and_then(|value| receipt_projection(&value)) else {
        return false;
    };
    let Some(mut row) = base_row(&session, "native_worker", harness, event_name, &payload) else {
        return false;
    };
    let row_event = row
        .iter()
        .find(|(key, _)| key == "event_name")
        .map(|(_, value)| value.clone());
    if projection.get("event_name") != row_event.as_ref()
        || projection.get("harness").and_then(Json::as_str) != Some(harness)
    {
        return false;
    }
    row.push((
        "forwarded_payload_hmac_sha256".to_owned(),
        Json::Str(fingerprint),
    ));
    row.push((
        "decision_scope".to_owned(),
        Json::Str("native_edge".to_owned()),
    ));
    let Some(sealed) = seal_receipt(&session, &Json::Obj(row.clone()), &projection, now) else {
        return false;
    };
    row.push(("sealed_receipt".to_owned(), sealed));
    seal_and_append(&session, guard_home, row, now)
}

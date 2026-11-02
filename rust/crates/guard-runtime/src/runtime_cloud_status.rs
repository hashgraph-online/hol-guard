//! `runtime_cloud_status` runner-authority kind: the Guard Cloud status copy of
//! the local runtime snapshot. Ported from the approval center's
//! `_build_runtime_proof_status`, `_build_cloud_sync_health` and
//! `_runtime_cloud_state_label`/`_runtime_cloud_state_detail`.
//!
//! Python still reads the store and resolves the shared cloud state and its
//! repair flags, then ships:
//!
//! - `connect_state`: the latest connect state, or `null` when there is none;
//! - `cloud_state` and the boolean flags `sync_configured`,
//!   `oauth_repair_required`, `connect_retry_required`,
//!   `connect_retry_refresh_race` and `shared_proof_recorded`;
//! - `pending_events`, the count of events not yet uploaded;
//! - `event_summary`, the stored Guard events v1 summary;
//! - `synced_at`, the `synced_at` values of the event, sync and runtime
//!   session summaries;
//! - `policy_ack`: the stored policy bundle acknowledgement, the synced
//!   bundle's `bundle_hash` and `bundle_version`, and this machine's
//!   `device_id`, each `null` when it is missing;
//! - `sync_url`, the configured sync URL, or `null` when sync is off.
//!
//! The answer carries `proof_status` (without the proof fields the caller
//! already holds), `cloud_state_label`, `cloud_state_detail`,
//! `cloud_sync_health`, `cloud_policy_last_ack_at` and the Guard pages on the
//! sync URL's origin: `dashboard_url`, `inbox_url`, `fleet_url` and
//! `connect_url`.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use crate::daemon_lifecycle_text::py_strip;
use crate::guard_product_copy::guard_urls;
use crate::policy_bundle_time::from_isoformat;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const STALE_AFTER_MICROS: i64 = 24 * 60 * 60 * 1_000_000;
const REFRESH_RACE_PROOF_DETAIL: &str = "Local Guard remains available. The first shared Guard \
     Cloud proof stalled after a refresh-token race. Run hol-guard connect once on this machine \
     when you want shared proof restored.";

struct Flags {
    sync_configured: bool,
    oauth_repair_required: bool,
    connect_retry_required: bool,
    connect_retry_refresh_race: bool,
    shared_proof_recorded: bool,
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    dispatch_at(args, now_micros())
}

fn dispatch_at(args: &Value, now: i64) -> KindResult {
    let flag = |key: &str| args.get(key).and_then(Value::as_bool).ok_or(ERR_INVALID);
    let flags = Flags {
        sync_configured: flag("sync_configured")?,
        oauth_repair_required: flag("oauth_repair_required")?,
        connect_retry_required: flag("connect_retry_required")?,
        connect_retry_refresh_race: flag("connect_retry_refresh_race")?,
        shared_proof_recorded: flag("shared_proof_recorded")?,
    };
    let cloud_state = args
        .get("cloud_state")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let connect_state = match args.get("connect_state") {
        Some(Value::Object(state)) => Some(state),
        Some(Value::Null) => None,
        _ => return Err(ERR_INVALID),
    };
    let pending_events = args
        .get("pending_events")
        .and_then(Value::as_u64)
        .ok_or(ERR_INVALID)?;
    let event_summary = args
        .get("event_summary")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    let synced_at = args
        .get("synced_at")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    let policy_ack = args
        .get("policy_ack")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    let last_ack_at = policy_last_ack_at(policy_ack)?;
    let urls = match args.get("sync_url") {
        Some(Value::String(url)) => guard_urls(Some(url.as_str())),
        Some(Value::Null) => guard_urls(None),
        _ => return Err(ERR_INVALID),
    };
    Ok(json!({
        "proof_status": proof_status(connect_state),
        "cloud_state_label": cloud_state_label(cloud_state),
        "cloud_state_detail": cloud_state_detail(cloud_state, &flags),
        "cloud_sync_health": sync_health(
            cloud_state,
            &flags,
            pending_events,
            event_summary,
            synced_at,
            now,
        ),
        "cloud_policy_last_ack_at": last_ack_at,
        "dashboard_url": urls.dashboard,
        "inbox_url": urls.inbox,
        "fleet_url": urls.fleet,
        "connect_url": urls.connect,
    }))
}

/// `_cloud_policy_last_ack_at`: the acknowledgement's `appliedAt` when it
/// records this device syncing the current bundle at a parseable time.
fn policy_last_ack_at(policy_ack: &Map<String, Value>) -> Result<Option<&str>, &'static str> {
    let nullable_text = |key: &str| match policy_ack.get(key) {
        Some(Value::String(value)) => Ok(Some(value.as_str())),
        Some(Value::Null) => Ok(None),
        _ => Err(ERR_INVALID),
    };
    let acknowledgement = policy_ack
        .get("acknowledgement")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    let bundle_hash = nullable_text("bundle_hash")?.filter(|value| !value.is_empty());
    let bundle_version = nullable_text("bundle_version")?.filter(|value| !value.is_empty());
    let device_id = nullable_text("device_id")?;
    let (Some(bundle_hash), Some(bundle_version), Some(device_id)) =
        (bundle_hash, bundle_version, device_id)
    else {
        return Ok(None);
    };
    let field = |key: &str| acknowledgement.get(key).and_then(Value::as_str);
    let applied_at = text(acknowledgement, "appliedAt");
    let acknowledged = field("bundleHash") == Some(bundle_hash)
        && field("bundleVersion") == Some(bundle_version)
        && field("deviceId") == Some(device_id)
        && field("status") == Some("synced");
    Ok(applied_at
        .filter(|value| acknowledged && from_isoformat(&value.replace('Z', "+00:00")).is_some()))
}

/// `_optional_string`: a non-empty string, unstripped.
fn text<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn proof_status(connect_state: Option<&Map<String, Value>>) -> Value {
    let Some(state) = connect_state else {
        return proof_payload("not_connected", None);
    };
    let status = text(state, "status");
    let milestone = text(state, "milestone");
    let first_synced = state
        .get("proof")
        .and_then(Value::as_object)
        .and_then(|proof| text(proof, "first_synced_at"))
        .is_some();
    let name = if status == Some("retry_required") || milestone == Some("first_sync_failed") {
        if refresh_race(text(state, "reason")) {
            "stalled"
        } else {
            "failed"
        }
    } else if milestone == Some("first_sync_pending") {
        "pending"
    } else if milestone == Some("expired") || status == Some("expired") {
        "expired"
    } else if milestone == Some("waiting_for_browser") || status == Some("waiting") {
        "waiting"
    } else if milestone == Some("first_sync_succeeded") || first_synced {
        "synced"
    } else if milestone == Some("sync_not_available") {
        "sync_unavailable"
    } else {
        "not_connected"
    };
    proof_payload(name, text(state, "request_id"))
}

/// `connect_retry_refresh_race_from_reason`.
fn refresh_race(reason: Option<&str>) -> bool {
    reason.is_some_and(|reason| reason.to_lowercase().contains("already consumed"))
}

fn proof_payload(state: &str, request_id: Option<&str>) -> Value {
    let (label, detail) = match state {
        "synced" => (
            "First proof synced",
            "This device completed its first Guard Cloud proof sync.",
        ),
        "sync_unavailable" => (
            "Local connected, cloud sync gated",
            "Local Guard is connected. Shared cloud sync needs a paid Guard plan.",
        ),
        "failed" => (
            "First proof needs retry",
            "Guard Cloud sign-in on this machine needs repair. Run hol-guard connect again.",
        ),
        "stalled" => ("First proof stalled", REFRESH_RACE_PROOF_DETAIL),
        "pending" => (
            "First proof pending",
            "Browser sign-in finished. Local Guard will retry the first proof sync \
             automatically while the daemon is running, or you can run hol-guard sync now.",
        ),
        "expired" => (
            "Sign-in expired",
            "The sign-in link expired. Run hol-guard connect again.",
        ),
        "waiting" => (
            "Waiting for browser sign-in",
            "Open the sign-in link to register this local Guard device.",
        ),
        _ => (
            "Cloud proof not started",
            "Connect Guard Cloud to sync this device proof.",
        ),
    };
    json!({
        "state": state,
        "label": label,
        "detail": detail,
        "request_id": request_id,
    })
}

fn cloud_state_label(cloud_state: &str) -> &'static str {
    match cloud_state {
        "paired_waiting" | "paired_active" => "Connected",
        _ => "Local only",
    }
}

fn cloud_state_detail(cloud_state: &str, flags: &Flags) -> &'static str {
    if flags.oauth_repair_required {
        return "Guard Cloud sign-in on this machine is incomplete. Run hol-guard connect again \
                to repair local authorization and resume sync.";
    }
    if flags.connect_retry_refresh_race {
        return "Local Guard remains available. The first shared Guard Cloud proof stalled \
                after a refresh-token race. Run hol-guard connect once when you want shared \
                proof restored.";
    }
    if flags.connect_retry_required {
        // `resolve_guard_cloud_repair_detail`.
        return if flags.shared_proof_recorded {
            "Guard Cloud connection on this machine needs repair before shared proof can \
             resume. Run hol-guard connect again."
        } else {
            "Guard Cloud connection on this machine needs repair before the first shared \
             proof can land. Run hol-guard connect again."
        };
    }
    match cloud_state {
        "paired_waiting" => {
            "This machine is connected to Guard Cloud. Local Guard will finish the first shared \
             proof automatically while the daemon is running."
        }
        "paired_active" => {
            "This machine is connected to Guard Cloud. Open Home, Inbox, or Fleet in the portal \
             to continue with shared review and proof."
        }
        _ => {
            "Guard is running locally. Guard Cloud is optional; connect it for shared review, \
             sync, and team memory."
        }
    }
}

fn sync_health(
    cloud_state: &str,
    flags: &Flags,
    pending_events: u64,
    event_summary: &Map<String, Value>,
    synced_at: &[Value],
    now: i64,
) -> Value {
    let last_synced = latest_sync_timestamp(synced_at);
    let state = if flags.oauth_repair_required || flags.connect_retry_required {
        "failed"
    } else if !flags.sync_configured {
        "disabled"
    } else if event_summary.get("status").and_then(Value::as_str) == Some("failed") {
        "failed"
    } else if event_summary.get("sync_skipped") == Some(&Value::Bool(true))
        && event_summary.get("sync_reason").and_then(Value::as_str)
            == Some("guard_events_endpoint_unavailable")
    {
        "degraded"
    } else if last_synced
        .is_some_and(|(instant, _)| now.saturating_sub(instant) > STALE_AFTER_MICROS)
    {
        "stale"
    } else if pending_events > 0 || cloud_state == "paired_waiting" {
        "pending"
    } else {
        "healthy"
    };
    let label = match state {
        "healthy" => "Cloud sync healthy",
        "failed" => "Cloud sync needs attention",
        "degraded" => "Cloud sync degraded",
        "disabled" => "Cloud optional",
        "stale" => "Cloud sync stale",
        _ => "Cloud sync pending",
    };
    json!({
        "state": state,
        "label": label,
        "detail": sync_health_detail(state, pending_events, flags),
        "pending_events": pending_events,
        "last_synced_at": last_synced.map(|(_, value)| value),
        "next_retry_after": event_summary.get("next_retry_after").cloned().unwrap_or(Value::Null),
    })
}

fn sync_health_detail(state: &str, pending_events: u64, flags: &Flags) -> String {
    let detail = match state {
        "healthy" => "Guard Cloud has the latest local proof from this machine.",
        "failed" if flags.connect_retry_refresh_race => {
            "Local Guard remains available. The first shared Guard Cloud proof stalled after a \
             refresh-token race. Run hol-guard connect once to mint a fresh Cloud refresh token."
        }
        "failed" if flags.oauth_repair_required || flags.connect_retry_required => {
            "Guard Cloud authorization on this machine needs repair. Run hol-guard connect again \
             to restore sync."
        }
        "failed" => {
            "Guard Cloud did not accept the last upload. Guard will retry automatically, or run \
             hol-guard sync to try again now."
        }
        "degraded" => {
            "Cloud accepted legacy sync, but v1 Guard event ingest is unavailable. Review local \
             protection health separately."
        }
        "disabled" => {
            "Local Guard is active. Cloud sync is optional and currently off; connect it for \
             shared team proof."
        }
        "stale" => {
            "Cloud has not seen fresh local proof recently. Keep this runtime open or run sync \
             again."
        }
        _ if pending_events == 1 => "One local proof event is queued for the next Cloud sync.",
        _ if pending_events > 1 => {
            return format!(
                "{pending_events} local proof events are queued for the next Cloud sync."
            )
        }
        _ => "Waiting for the first shared Cloud proof from this machine.",
    };
    detail.to_owned()
}

/// `_latest_sync_timestamp`: the latest parseable value, first one on a tie,
/// with its instant.
fn latest_sync_timestamp(values: &[Value]) -> Option<(i64, &str)> {
    let mut latest: Option<(i64, &str)> = None;
    for value in values.iter().filter_map(Value::as_str) {
        if py_strip(value).is_empty() {
            continue;
        }
        let Some(instant) = instant(value) else {
            continue;
        };
        if latest.is_none_or(|(best, _)| instant > best) {
            latest = Some((instant, value));
        }
    }
    latest
}

/// `_parse_timestamp` as UTC microseconds; a naive timestamp is UTC.
fn instant(value: &str) -> Option<i64> {
    from_isoformat(&value.replace('Z', "+00:00"))?.utc_micros()
}

fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_micros()).ok())
        .unwrap_or_default()
}

#[cfg(test)]
#[path = "runtime_cloud_status_tests.rs"]
mod tests;

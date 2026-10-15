//! `PackagePosture` — resident op owning the local supply-chain posture that
//! `local_supply_chain.py` used to derive in Python: connection state, signed
//! bundle freshness, health, and the cloud-managed policy projection.
//!
//! The caller hydrates only what it alone can read (the sync payloads, the
//! configured risk actions and the package-manager shim status). The runtime
//! decides the status, the health, the refresh schedule and every field of the
//! reported posture; callers never recompute any of it.

use guard_command::local_supply_chain::ecosystem_support_matrix;
use guard_contracts::{
    PackagePostureRequestV1, SupplyChainEvalResultV1, PACKAGE_AUTHORITY_REQUEST_SCHEMA,
    PACKAGE_AUTHORITY_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};

use crate::context_digest::python_strip;
use crate::package_authority_op::request_digest;
use crate::policy_bundle_time::{from_isoformat, micros_to_utc_isoformat};

const MICROS_PER_SECOND: i64 = 1_000_000;
const DEFAULT_BUNDLE_REFRESH_INTERVAL_SECONDS: i64 = 15 * 60;
const STALE_REFRESH_GRACE_SECONDS: i64 = 5 * 60;

fn invalid() -> String {
    "native_package_posture_invalid".to_owned()
}

/// Python `_string_value`: the string itself when it is not blank.
fn string_value(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|text| !python_strip(text).is_empty())
}

fn text(value: Option<&Value>) -> Value {
    string_value(value).map_or(Value::Null, |text| json!(text))
}

/// Python `_int_value`: `isinstance(value, int)`, which includes booleans.
fn int_value(value: Option<&Value>) -> Value {
    match value {
        Some(number @ Value::Number(n)) if n.is_i64() || n.is_u64() => number.clone(),
        Some(flag @ Value::Bool(_)) => flag.clone(),
        _ => Value::Null,
    }
}

/// Python `_parse_timestamp`: UTC microseconds, `None` when unparsable.
fn parse_timestamp(value: &str) -> Option<i64> {
    let stripped = python_strip(value);
    if stripped.is_empty() {
        return None;
    }
    let normalized = match stripped.strip_suffix('Z') {
        Some(prefix) => format!("{prefix}+00:00"),
        None => stripped.to_owned(),
    };
    from_isoformat(&normalized)?.utc_micros()
}

fn snapshot_now(now: Option<&str>) -> i64 {
    now.and_then(parse_timestamp).unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_micros() as i64)
    })
}

fn posture_status(
    request: &PackagePostureRequestV1,
    summary: &Map<String, Value>,
    bundle: &Map<String, Value>,
    expires_at: Option<i64>,
    now: i64,
) -> String {
    if !request.credentials_present {
        return "not_connected".to_owned();
    }
    if request.workspace_id.is_none() {
        return "workspace_required".to_owned();
    }
    if summary.is_empty() && bundle.is_empty() {
        return "sync_required".to_owned();
    }
    if expires_at.is_some_and(|expires| expires <= now) {
        return "expired".to_owned();
    }
    if let Some(status) = string_value(summary.get("status")) {
        return status.to_owned();
    }
    if !bundle.is_empty() {
        return "synced".to_owned();
    }
    "degraded".to_owned()
}

fn posture_detail(status: &str) -> &'static str {
    match status {
        "not_connected" => "Local package protection is active. Guard Cloud is optional and adds live package intelligence, synced policy, and cross-device evidence.",
        "workspace_required" => "Finish Guard Cloud pairing to fetch workspace-specific supply-chain bundles.",
        "sync_required" => "Run `hol-guard supply-chain sync` to fetch the latest signed bundle.",
        "expired" => "The cached signed bundle expired. Run `hol-guard supply-chain sync` before the next install.",
        "synced" => "Signed supply-chain bundle is ready for local install protection.",
        "degraded" => "Supply-chain protection is degraded. Refresh the signed bundle before trusting new installs.",
        _ => "Supply-chain protection status is available.",
    }
}

fn posture_health_status(status: &str, next_refresh_at: Option<i64>, now: i64) -> &'static str {
    match status {
        "expired" => "stale",
        "not_connected" => "local",
        "workspace_required" | "sync_required" | "degraded" => "degraded",
        "synced" => {
            let grace = STALE_REFRESH_GRACE_SECONDS * MICROS_PER_SECOND;
            if next_refresh_at.is_some_and(|next| next.saturating_add(grace) <= now) {
                "stale"
            } else {
                "protected"
            }
        }
        _ => "degraded",
    }
}

/// The explicit `next_refresh_at`, else the sync time plus the default interval.
fn next_refresh_at(summary: &Map<String, Value>, synced_at: Option<&str>) -> Option<i64> {
    if let Some(explicit) = string_value(summary.get("next_refresh_at")).and_then(parse_timestamp) {
        return Some(explicit);
    }
    let synced = parse_timestamp(synced_at?)?;
    Some(synced.saturating_add(DEFAULT_BUNDLE_REFRESH_INTERVAL_SECONDS * MICROS_PER_SECOND))
}

fn iso(micros: Option<i64>) -> Value {
    micros
        .and_then(|value| micros_to_utc_isoformat(value, "+00:00"))
        .map_or(Value::Null, Value::String)
}

fn first_text(candidates: &[Option<&Value>]) -> Value {
    candidates
        .iter()
        .find_map(|candidate| string_value(*candidate))
        .map_or(Value::Null, |text| json!(text))
}

fn object(value: &Value) -> Result<&Map<String, Value>, String> {
    value.as_object().ok_or_else(invalid)
}

fn posture(request: &PackagePostureRequestV1) -> Result<Value, String> {
    let summary = object(&request.summary)?;
    let entitlement = object(&request.entitlement)?;
    let remote_policy = object(&request.remote_policy)?;
    let bundle = object(&request.bundle_payload)?;
    if !request.package_manager_protection.is_object() {
        return Err(invalid());
    }
    let now = snapshot_now(request.now.as_deref());
    let expires_at_text = string_value(bundle.get("expiresAt"));
    let expires_at = expires_at_text.and_then(parse_timestamp);
    let status = posture_status(request, summary, bundle, expires_at, now);
    let synced_at = string_value(summary.get("synced_at"));
    let next_refresh = next_refresh_at(summary, synced_at);
    let supported_ecosystems = match summary.get("ecosystem_support") {
        Some(Value::Array(items)) if !items.is_empty() => Value::Array(items.clone()),
        _ => Value::Array(ecosystem_support_matrix()),
    };
    let remote_text = |snake: &str, camel: &str| {
        string_value(remote_policy.get(camel)).or_else(|| string_value(remote_policy.get(snake)))
    };
    let remote_package_script = remote_text("package_script_action", "packageScriptAction");
    let remote_cloud_advisory = remote_text("cloud_advisory_action", "cloudAdvisoryAction");
    let managed_by_cloud = !remote_policy.is_empty();
    let workspace = request.workspace_id.as_deref();
    let workspace_value = workspace.map_or(Value::Null, |id| json!(id));
    let action = |remote: Option<&str>, configured: &Option<String>| match remote {
        Some(action) => json!(action),
        None => configured
            .as_ref()
            .map_or(Value::Null, |action| json!(action)),
    };
    Ok(json!({
        "status": status,
        "health_status": posture_health_status(&status, next_refresh, now),
        "detail": posture_detail(&status),
        "connection": {
            "logged_in": request.credentials_present,
            "paired": workspace.is_some(),
            "workspace_id": workspace_value,
        },
        "bundle": {
            "bundle_version": first_text(&[
                summary.get("bundle_version"),
                entitlement.get("bundle_version"),
                bundle.get("bundleVersion"),
            ]),
            "feed_snapshot_hash": first_text(&[
                summary.get("feed_snapshot_hash"),
                bundle.get("feedSnapshotHash"),
            ]),
            "policy_hash": first_text(&[
                summary.get("policy_hash"),
                entitlement.get("policy_hash"),
                bundle.get("policyHash"),
            ]),
            "synced_at": text(summary.get("synced_at")),
            "next_refresh_at": iso(next_refresh),
            "expires_at": expires_at_text.map_or(Value::Null, |text| json!(text)),
            "tier": first_text(&[
                summary.get("tier"),
                entitlement.get("tier"),
                bundle.get("tier"),
            ]),
            "workspace_id": match first_text(&[
                summary.get("workspace_id"),
                entitlement.get("workspace_id"),
            ]) {
                Value::Null => workspace_value,
                value => value,
            },
            "advisory_count": int_value(summary.get("advisory_count")),
            "package_count": int_value(summary.get("package_count")),
        },
        "policy": {
            "security_level": request.security_level,
            "cloud_advisory_action": action(remote_cloud_advisory, &request.config_cloud_advisory_action),
            "package_script_action": action(remote_package_script, &request.config_package_script_action),
            "managed_by_cloud": managed_by_cloud,
            "remote_policy_active": !remote_policy.is_empty(),
            "team_policy_active": false,
            "managed_label": if managed_by_cloud { json!("Guard Cloud sync") } else { Value::Null },
            "managed_updated_at": text(remote_policy.get("updatedAt")),
        },
        "supported_ecosystems": supported_ecosystems,
        "package_manager_protection": request.package_manager_protection,
    }))
}

pub(crate) fn evaluate_package_posture(
    request: &PackagePostureRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != PACKAGE_AUTHORITY_REQUEST_SCHEMA {
        return Err("native_package_posture_schema_mismatch".to_owned());
    }
    if request.request_id.is_empty() || request.guard_home.is_empty() {
        return Err(invalid());
    }
    crate::encode_response(&SupplyChainEvalResultV1 {
        schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload: Some(posture(request)?),
    })
}

#[cfg(test)]
#[path = "package_posture_op_tests.rs"]
mod tests;

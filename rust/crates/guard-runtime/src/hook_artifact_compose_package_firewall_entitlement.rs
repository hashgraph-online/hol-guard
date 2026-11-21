//! `package_firewall_entitlement` — resolve what Cloud access a home proves.
//!
//! The caller reads the store rows; the entitlement they add up to is decided
//! here, by the same resolver the package authority edge already runs, so the
//! control plane and the package edge cannot drift apart. Nothing in the query
//! is a verdict: a malformed clock or a row of the wrong shape is refused
//! rather than read as an allow.

use guard_command::local_supply_chain::{
    parse_timestamp, resolve_package_firewall_entitlement_from_facts,
    PackageFirewallEntitlementFacts, Timestamp,
};
use guard_contracts::PackageFirewallEntitlementQueryV1;
use serde_json::Value;

fn row(value: &Value, field: &str) -> Result<Option<Value>, String> {
    match value {
        Value::Null => Ok(None),
        Value::Object(_) => Ok(Some(value.clone())),
        _ => Err(format!("{field} must be an object or null")),
    }
}

fn resolved_now(now: Option<&String>) -> Result<Timestamp, String> {
    match now {
        None => Ok(Timestamp::now_utc()),
        Some(text) => {
            parse_timestamp(text).ok_or_else(|| "now must be an ISO-8601 instant".to_owned())
        }
    }
}

pub(crate) fn package_firewall_entitlement(
    query: &PackageFirewallEntitlementQueryV1,
) -> Result<Value, String> {
    let facts = PackageFirewallEntitlementFacts {
        bundle_payload: row(&query.bundle_payload, "bundle_payload")?,
        oauth_payload: row(&query.oauth_payload, "oauth_payload")?,
        oauth_health: row(&query.oauth_health, "oauth_health")?,
        connect_state: row(&query.connect_state, "connect_state")?,
        has_cloud_sync_profile: query.has_cloud_sync_profile,
    };
    let now = resolved_now(query.now.as_ref())?;
    Ok(Value::Object(
        resolve_package_firewall_entitlement_from_facts(&facts, &now),
    ))
}

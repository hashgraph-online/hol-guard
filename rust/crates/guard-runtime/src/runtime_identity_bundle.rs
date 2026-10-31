//! Runtime advisories read from the cached, signed supply-chain bundle.
//!
//! The caller hands over the stored bundle response with its sync context;
//! nothing here reads the store. The bundle is accepted only when the shared
//! cached-bundle check passes (workspace scope, payload hash, signature, key
//! state, freshness and rollback), so a bundle with a bad signature, another
//! workspace's scope or an older version than the last sync never supplies
//! advisories. A recorded sync must name this workspace and a bundle version,
//! as package evaluation requires. Unknown target kinds, malformed entries,
//! repeated advisory ids and entries past the request bounds are skipped and
//! counted rather than guessed at or allowed to fail the assessment.
//!
//! A bundle verified only against its own advertised keyring (no recorded
//! sync keyring anchored it) can report a runtime affected but never clear
//! one, the same limit package evaluation puts on such a bundle.

use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use guard_command::supply_chain_bundle::{
    load_supply_chain_bundle_response, SupplyChainBundleError,
};
use guard_command::supply_chain_bundle_cache_trust::{
    cached_supply_chain_bundle_key_valid_until, cached_supply_chain_bundle_valid_until,
    validate_cached_supply_chain_bundle, CachedBundleRejection,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{
    parse_intervals, AdvisoryInput, PlatformInput, RangeInput, MAX_ADVISORIES,
    MAX_ARTIFACT_ADVISORY_PAIRS, MAX_RANGES,
};

pub(crate) const FEATURE: &str = "runtime-identity-assess-bundle-v1";
const SECTION_KEY: &str = "runtimeAdvisories";
const SECTION_SCHEMA: &str = "runtime-advisories.v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CachedBundleInput {
    response: Value,
    workspace_id: String,
    #[serde(default)]
    sync_keyring: Option<Value>,
    /// The recorded `supply_chain_bundle_entitlement` sync payload, if any.
    #[serde(default)]
    entitlement: Option<Value>,
    #[serde(default)]
    now: Option<f64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Section {
    schema_version: String,
    ruleset_version: String,
    entries: Vec<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    advisory_id: String,
    normalized_severity: String,
    known_exploited: bool,
    include_prerelease: bool,
    backport_build_ids: Vec<String>,
    ranges: Vec<Range>,
    target: Target,
    title: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Range {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Target {
    #[serde(rename_all = "camelCase")]
    Runtime {
        family: String,
        vendor: String,
        platforms: Vec<PlatformInput>,
        version_scheme: String,
    },
    #[serde(rename_all = "camelCase")]
    BundledComponent {
        component: String,
        host: Host,
        platforms: Vec<PlatformInput>,
        version_scheme: String,
    },
}

#[derive(Debug, Deserialize)]
struct Host {
    family: String,
    vendor: String,
}

/// The room a request leaves for bundled advisories: the caller's own
/// advisories and artifacts count against the same bounds.
pub(crate) struct Budget<'a> {
    pub(crate) artifacts: usize,
    pub(crate) supplied: &'a [AdvisoryInput],
}

impl Budget<'_> {
    fn capacity(&self) -> usize {
        MAX_ADVISORIES
            .min(MAX_ARTIFACT_ADVISORY_PAIRS / self.artifacts.max(1))
            .saturating_sub(self.supplied.len())
    }
}

/// The advisories the cached bundle supplies, and a report of where they came
/// from. Advisories are empty unless the source state is `verified`.
pub(crate) fn bundle_advisories(
    input: Option<&CachedBundleInput>,
    budget: &Budget<'_>,
) -> (Vec<AdvisoryInput>, Value) {
    let Some(input) = input else {
        return (Vec::new(), source("absent", None, None));
    };
    evaluate(input, input.now, budget)
}

/// Launch admission keeps an expired bundle's rules for positive matches only:
/// PRD retains stale affected verdicts while stale absence stays unknown. The
/// bundle is re-checked as of its own expiry, so scope, payload hash,
/// signature, key state and rollback are still enforced; only freshness is
/// relaxed, and the report stays `stale` so callers never clear on it. A
/// grace key that vouched for it must still be valid now; the report's
/// `valid_until` is that key's expiry, or null when no grace key bounds it.
/// Seconds since the Unix epoch, on every platform.
pub(crate) fn now_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |elapsed| elapsed.as_secs_f64())
}

pub(crate) fn launch_bundle_advisories(input: Option<&CachedBundleInput>) -> LaunchAdvisories {
    let budget = Budget {
        artifacts: 1,
        supplied: &[],
    };
    let (advisories, source) = bundle_advisories(input, &budget);
    let current = LaunchAdvisories { advisories, source };
    let (Some(input), Some("bundle_expired")) = (input, current.source["reason"].as_str()) else {
        return current;
    };
    let Ok(typed) = load_supply_chain_bundle_response(&input.response) else {
        return current;
    };
    let Ok(expired_at) = typed.bundle.expires_at_timestamp() else {
        return current;
    };
    let key_until = cached_supply_chain_bundle_key_valid_until(&typed, input.sync_keyring.as_ref());
    let now = input.now.unwrap_or_else(now_seconds);
    if key_until.is_some_and(|until| now > until) {
        return current;
    }
    let (advisories, mut source) = evaluate(input, Some(expired_at), &budget);
    if source["state"] != "verified" {
        return current;
    }
    source["state"] = json!("stale");
    source["reason"] = json!("bundle_expired");
    source["expired_at"] = json!(expired_at);
    source["valid_until"] = json!(key_until);
    LaunchAdvisories { advisories, source }
}

/// Bundle rules verified once and reused across launch checks.
#[derive(Debug)]
pub(crate) struct LaunchAdvisories {
    pub(super) advisories: Vec<AdvisoryInput>,
    pub(crate) source: Value,
}

#[cfg(test)]
impl LaunchAdvisories {
    /// Advisories in request form, as if taken from a bundle reported by
    /// `source`.
    pub(crate) fn for_tests(advisories: Value, source: Value) -> Self {
        Self {
            advisories: serde_json::from_value(advisories).expect("advisories"),
            source,
        }
    }
}

impl CachedBundleInput {
    pub(crate) fn new(
        response: Value,
        workspace_id: String,
        sync_keyring: Option<Value>,
        entitlement: Option<Value>,
    ) -> Self {
        Self {
            response,
            workspace_id,
            sync_keyring,
            entitlement,
            now: None,
        }
    }
}

fn evaluate(
    input: &CachedBundleInput,
    now: Option<f64>,
    budget: &Budget<'_>,
) -> (Vec<AdvisoryInput>, Value) {
    let synced_version = match synced_bundle_version(input) {
        Ok(version) => version,
        Err(reason) => return (Vec::new(), source("invalid", Some(reason), None)),
    };
    let typed = match load_supply_chain_bundle_response(&input.response) {
        Ok(typed) => typed,
        Err(_) => {
            return (
                Vec::new(),
                source("invalid", Some("bundle_malformed"), None),
            )
        }
    };
    let anchored = match validate_cached_supply_chain_bundle(
        &typed,
        &input.workspace_id,
        now,
        input.sync_keyring.as_ref(),
        synced_version.as_deref(),
    ) {
        Ok(anchored) => anchored,
        Err(rejection) => {
            let (state, reason) = rejection_state(&rejection);
            return (Vec::new(), source(state, Some(reason), None));
        }
    };
    let bundle_version = typed.bundle.bundle_version.as_str();
    let valid_until = cached_supply_chain_bundle_valid_until(&typed, input.sync_keyring.as_ref());
    let verified = |reason: Option<&str>, extra: Value| {
        let mut report = source("verified", reason, Some(bundle_version));
        report["anchored"] = json!(anchored);
        report["valid_until"] = json!(valid_until);
        if let (Some(report), Value::Object(extra)) = (report.as_object_mut(), extra) {
            report.extend(extra);
        }
        report
    };
    let Some(raw) = typed.signed_bundle.get(SECTION_KEY) else {
        return (
            Vec::new(),
            with_coverage(verified(Some("section_absent"), json!({}))),
        );
    };
    let Ok(section) = Section::deserialize(raw) else {
        return (
            Vec::new(),
            source(
                "unsupported",
                Some("section_malformed"),
                Some(bundle_version),
            ),
        );
    };
    if section.schema_version != SECTION_SCHEMA {
        return (
            Vec::new(),
            source(
                "unsupported",
                Some("schema_unsupported"),
                Some(bundle_version),
            ),
        );
    }
    let mut usable_entries: Vec<AdvisoryInput> = section
        .entries
        .iter()
        .filter_map(|raw| Entry::deserialize(raw).ok().map(advisory_input))
        .filter(usable)
        .collect();
    // When the bounds force a cut, the most severe entries are kept.
    usable_entries.sort_by_key(|advisory| std::cmp::Reverse(importance(advisory)));
    let mut seen: BTreeSet<String> = budget
        .supplied
        .iter()
        .map(|advisory| advisory.advisory_id.clone())
        .collect();
    let unique: Vec<AdvisoryInput> = usable_entries
        .into_iter()
        .filter(|advisory| seen.insert(advisory.advisory_id.clone()))
        .collect();
    let truncated = unique.len().saturating_sub(budget.capacity());
    let advisories: Vec<AdvisoryInput> = unique.into_iter().take(budget.capacity()).collect();
    let report = verified(
        (truncated > 0).then_some("section_truncated"),
        json!({
            "ruleset_version": section.ruleset_version,
            "entries": advisories.len(),
            "entries_skipped": section.entries.len() - advisories.len(),
            "entries_truncated": truncated,
        }),
    );
    (advisories, with_coverage(report))
}

/// Mirrors package evaluation: a recorded sync must belong to this workspace
/// and name the version it synced, or the cache cannot be checked for rollback.
fn synced_bundle_version(input: &CachedBundleInput) -> Result<Option<String>, &'static str> {
    let Some(entitlement) = input.entitlement.as_ref().filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    if entitlement.get("workspace_id").and_then(Value::as_str) != Some(&input.workspace_id) {
        return Err("sync_record_scope_mismatch");
    }
    entitlement
        .get("bundle_version")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|version| !version.is_empty())
        .map(|version| Some(version.to_owned()))
        .ok_or("sync_record_invalid")
}

fn importance(advisory: &AdvisoryInput) -> (bool, u8) {
    let severity = match advisory.severity.as_deref() {
        Some("critical") => 4,
        Some("high") => 3,
        Some("medium" | "moderate") => 2,
        Some("low") => 1,
        _ => 0,
    };
    (advisory.known_exploited, severity)
}

fn advisory_input(entry: Entry) -> AdvisoryInput {
    let (family, vendor, platforms, version_scheme, bundled_component) = match entry.target {
        Target::Runtime {
            family,
            vendor,
            platforms,
            version_scheme,
        } => (family, vendor, platforms, version_scheme, None),
        Target::BundledComponent {
            component,
            host,
            platforms,
            version_scheme,
        } => (
            host.family,
            host.vendor,
            platforms,
            version_scheme,
            Some(component),
        ),
    };
    AdvisoryInput {
        advisory_id: entry.advisory_id,
        family,
        vendor: Some(vendor),
        version_scheme,
        ranges: entry
            .ranges
            .into_iter()
            .map(|range| RangeInput {
                introduced: range.introduced,
                fixed: range.fixed,
                last_affected: range.last_affected,
            })
            .collect(),
        include_prerelease: entry.include_prerelease,
        backport_build_ids: entry.backport_build_ids,
        platforms,
        bundled_component,
        severity: Some(entry.normalized_severity),
        known_exploited: entry.known_exploited,
        title: Some(entry.title),
    }
}

/// A signed entry this build cannot evaluate is skipped, never allowed to
/// fail the whole assessment.
fn usable(advisory: &AdvisoryInput) -> bool {
    advisory.ranges.len() <= MAX_RANGES
        && advisory.backport_build_ids.len() <= MAX_RANGES
        && advisory.platforms.len() <= MAX_RANGES
        && parse_intervals(advisory).is_ok()
}

fn rejection_state(rejection: &CachedBundleRejection) -> (&'static str, &'static str) {
    match rejection {
        CachedBundleRejection::Scope(_) => ("invalid", "scope_rejected"),
        CachedBundleRejection::Bundle(error) => match error {
            // An expired bundle was well formed but is too old to trust;
            // its signature is not checked once freshness fails.
            SupplyChainBundleError::Expired(_) => ("stale", "bundle_expired"),
            SupplyChainBundleError::Rollback(_) => ("invalid", "bundle_rollback"),
            SupplyChainBundleError::Signature(_) => ("invalid", "signature_invalid"),
            SupplyChainBundleError::PayloadHash(_) => ("invalid", "payload_hash_mismatch"),
            SupplyChainBundleError::Keyring(_) => ("invalid", "keyring_rejected"),
            SupplyChainBundleError::Malformed(_) => ("invalid", "bundle_malformed"),
        },
    }
}

fn source(state: &str, reason: Option<&str>, bundle_version: Option<&str>) -> Value {
    with_coverage(json!({
        "state": state,
        "reason": reason,
        "bundle_version": bundle_version,
        "anchored": false,
        "valid_until": null,
        "ruleset_version": null,
        "entries": 0,
        "entries_skipped": 0,
        "entries_truncated": 0,
    }))
}

/// Adds the coverage a report gives callers: whether advisories were
/// available, and if not, why. Callers relay these rather than deciding.
fn with_coverage(mut report: Value) -> Value {
    let state = report["state"].as_str().unwrap_or("invalid").to_owned();
    let entries = report["entries"].as_u64().unwrap_or(0);
    let available = state == "verified" && entries > 0;
    let reason = match (available, state.as_str()) {
        (true, _) if report["anchored"] != true => {
            Some("runtime_advisory_bundle_unanchored".to_owned())
        }
        (true, _) => None,
        (false, "verified") => Some("runtime_advisories_not_in_bundle".to_owned()),
        (false, state) => Some(format!("runtime_advisory_bundle_{state}")),
    };
    report["advisories_available"] = json!(available);
    report["coverage_reason"] = json!(reason);
    report
}

#[cfg(test)]
#[path = "runtime_identity_bundle_tests.rs"]
mod tests;

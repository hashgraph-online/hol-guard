//! `temporary_mcp_grant` — the bounded grants a routine browser MCP capability
//! may carry.
//!
//! A queued browser call offers the approval card a short grant (15m, 1h or
//! 5h) for the exact call, its category or the whole server, but only when the
//! call's projected risk is the routine category of its intent and nothing
//! else. The intent arrives as the approval request filed it, so it is
//! untrusted: anything that is not such an intent answers "no grant" rather
//! than failing. For one pick the op returns the selector the grant is filed
//! under and the moment it runs out; a pick the card does not offer is refused
//! by code, never widened to fit.
//!
//! An intent that names its driver identity and site also offers the site
//! targets of `browser_site_grant.rs` (BP-T060), under the tiers of
//! `browser_grant_eligibility.rs` (BP-T061): a shared-profile call may carry a
//! `session-site` grant and nothing else.
//!
//! Two shapes share the kind:
//! - `{"browser_intents": [intent, ...]}` answers `{"approvals": [...]}`, one
//!   card payload or `null` per intent, in order.
//! - `{"browser_intent": intent, "selection": {...}}` answers
//!   `{"selection": ..., "refusal": ...}` for one pick.

use serde_json::{json, Map, Value};

use crate::browser_grant_eligibility::{grant_tier, surface_clean, GrantTier, SHARED_PROFILE_RISK};
use crate::browser_site_grant::{
    is_site_target, site_scope, site_selector, site_targets, SiteScope, SESSION_BOUND_SECONDS,
    SESSION_DURATION,
};
use crate::context_digest::python_strip;
use crate::mcp_tool_policy_grants::{category_for, exact_grant_selector, scope_grant_selector};
use crate::runner_authority_op::KindResult;

const ERR_INVALID: &str = "native_temporary_mcp_grant_invalid";
/// The most intents one read may ask about; a queue page is far smaller.
const MAX_INTENTS: usize = 4096;
/// `TEMPORARY_MCP_GRANT_TARGETS`.
const TARGETS: [&str; 3] = ["exact", "category", "server"];
/// `TEMPORARY_MCP_GRANT_DURATIONS` and their `_DURATION_SECONDS`.
const DURATIONS: [(&str, i64); 3] = [("15m", 900), ("1h", 3600), ("5h", 18000)];
/// `_HARD_RISK_EXCLUSIONS` — the shapes no grant covers, carried on the card so
/// the surface can say so. A shared-profile card offers `session-site`, so its
/// list leaves out `browser_shared_profile` (see `Eligibility::exclusions`).
const HARD_RISK_EXCLUSIONS: [&str; 11] = [
    "browser_guard_origin",
    "browser_transfer",
    "browser_privileged",
    "browser_sensitive_surface",
    "browser_shared_profile",
    "secret_access",
    "filesystem_access",
    "command_execution",
    "destructive_mutation",
    "privileged_system_mutation",
    "tool_schema_mismatch",
];

/// A routine browser capability that may carry a bounded grant.
struct Eligibility {
    server_identity_hash: String,
    server_name: String,
    category: &'static str,
    target_label: Option<String>,
    site: Option<SiteScope>,
    tier: GrantTier,
    surface_clean: bool,
}

impl Eligibility {
    /// The exclusions this card names: a `SharedSession` card can cover the
    /// shared-profile risk with `session-site`, so it does not list it.
    fn exclusions(&self) -> Vec<&'static str> {
        HARD_RISK_EXCLUSIONS
            .into_iter()
            .filter(|risk| self.tier != GrantTier::SharedSession || *risk != SHARED_PROFILE_RISK)
            .collect()
    }

    fn targets(&self) -> Vec<&'static str> {
        let mut targets = TARGETS.to_vec();
        targets.extend(self.site.as_ref().map(site_targets).unwrap_or_default());
        targets.retain(|target| self.tier.allows(target, self.surface_clean));
        targets
    }

    fn durations(&self) -> Vec<&'static str> {
        let mut durations = vec!["once", "15m", "1h", "5h"];
        if self.targets().contains(&"session-site") {
            durations.push(SESSION_DURATION);
        }
        durations
    }
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args.as_object().ok_or(ERR_INVALID)?;
    if let Some(intents) = fields.get("browser_intents") {
        let intents = intents.as_array().ok_or(ERR_INVALID)?;
        if intents.len() > MAX_INTENTS || fields.len() != 1 {
            return Err(ERR_INVALID);
        }
        let approvals: Vec<Value> = intents
            .iter()
            .map(|intent| approval(Some(intent)).unwrap_or(Value::Null))
            .collect();
        return Ok(json!({ "approvals": approvals }));
    }
    let pick = fields
        .get("selection")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    let (selection, refusal) = match eligibility(fields.get("browser_intent")) {
        None => (Value::Null, json!("temporary_mcp_approval_ineligible")),
        Some(found) => match select(&found, pick)? {
            Ok(selection) => (selection, Value::Null),
            Err(code) => (Value::Null, json!(code)),
        },
    };
    Ok(json!({ "selection": selection, "refusal": refusal }))
}

/// `temporary_mcp_approval_payload`: the card payload for one filed intent.
pub(crate) fn approval(intent: Option<&Value>) -> Option<Value> {
    let found = eligibility(intent)?;
    Some(json!({
        "version": 1,
        "eligible": true,
        "server_name": found.server_name,
        "server_identity_hash": found.server_identity_hash,
        "category": found.category,
        "target_label": found.target_label,
        "allowed_targets": found.targets(),
        "allowed_durations": found.durations(),
        "hard_risk_exclusions": found.exclusions(),
    }))
}

/// `eligibility_from_browser_intent`: the routine category must be claimed,
/// and nothing beyond it but the informational external-domain flag and, for
/// a `session-site` grant only, the shared-profile risk. An intent that leaves
/// no target to offer offers nothing.
fn eligibility(intent: Option<&Value>) -> Option<Eligibility> {
    let filed = intent?;
    let intent = filed.as_object()?;
    let server_identity_hash = nonempty(intent, "mcp_server_identity_hash");
    let server_name = nonempty(intent, "mcp_server_name");
    let category = nonempty(intent, "intent").and_then(|named| category_for(&named));
    let (Some(server_identity_hash), Some(server_name), Some(category)) =
        (server_identity_hash, server_name, category)
    else {
        return None;
    };
    let risk_categories: Vec<&str> = intent
        .get("risk_categories")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let tier = grant_tier(category, &risk_categories)?;
    let target_label =
        nonempty(intent, "target_domain").or_else(|| nonempty(intent, "target_origin"));
    let found = Eligibility {
        server_identity_hash,
        server_name,
        category,
        target_label,
        site: site_scope(filed),
        tier,
        surface_clean: surface_clean(intent),
    };
    (!found.targets().is_empty()).then_some(found)
}

/// `parse_temporary_mcp_grant_selection` and the selector
/// `temporary_mcp_grant_decision` files it under. The outer error is a
/// malformed request; the inner one is a pick the card refuses.
fn select(
    found: &Eligibility,
    pick: &Map<String, Value>,
) -> Result<Result<Value, &'static str>, &'static str> {
    let text = |key: &str| match pick.get(key) {
        Some(Value::String(text)) => Ok(text.as_str()),
        _ => Err(ERR_INVALID),
    };
    let (now, artifact_id, artifact_hash) =
        (text("now")?, text("artifact_id")?, text("artifact_hash")?);
    let target = pick
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !found.targets().contains(&target) {
        return Ok(Err("invalid_mcp_grant_target"));
    }
    let duration = pick
        .get("duration")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let session =
        (duration == SESSION_DURATION && target == "session-site").then_some(SESSION_BOUND_SECONDS);
    let Some(seconds) = DURATIONS
        .iter()
        .find_map(|(name, seconds)| (*name == duration).then_some(*seconds))
        .or(session)
    else {
        return Ok(Err("invalid_mcp_grant_duration"));
    };
    let Some(expires_at) =
        crate::guard_store_json::add_seconds_utc_isoformat(now, seconds * 1_000_000)
    else {
        return Ok(Err("invalid_mcp_grant_timestamp"));
    };
    let artifact_id = match (target, found.site.as_ref()) {
        (site_target, Some(site)) if is_site_target(site_target) => {
            match site_selector(site, site_target, found.category) {
                Some(selector) => selector,
                None => return Ok(Err("invalid_mcp_grant_target")),
            }
        }
        ("exact", _) => exact_grant_selector(artifact_id, artifact_hash),
        ("category", _) => scope_grant_selector(&found.server_identity_hash, Some(found.category)),
        _ => scope_grant_selector(&found.server_identity_hash, None),
    };
    Ok(Ok(json!({
        "target": target,
        "duration": duration,
        "expires_at": expires_at,
        "server_name": found.server_name,
        "server_identity_hash": found.server_identity_hash,
        "category": found.category,
        "artifact_id": artifact_id,
    })))
}

/// `_nonempty_string`.
fn nonempty(fields: &Map<String, Value>, key: &str) -> Option<String> {
    let text = python_strip(fields.get(key)?.as_str()?);
    (!text.is_empty()).then(|| text.to_owned())
}

#[cfg(test)]
#[path = "temporary_mcp_grant_tests.rs"]
mod tests;

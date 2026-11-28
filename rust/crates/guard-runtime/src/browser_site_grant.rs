//! Site grants for browser drivers (BP-T060, PRD 5.5).
//!
//! A site grant covers the routine actions of one driver identity on one site,
//! whichever of that driver's profiled tools performs them. It is filed under
//! `browser-grant:v2:<driver_identity_hash>:...`, so it ends when the driver
//! identity hash changes (see `browser_driver_ledger.rs`), and it names the
//! site by digest:
//!
//! | target          | selector suffix                                   |
//! | --------------- | ------------------------------------------------- |
//! | `site-category` | `site:<origin_digest>:category:<category>`        |
//! | `site`          | `site:<origin_digest>`                            |
//! | `site-group`    | `group:<site_group_digest>`                       |
//! | `session-site`  | `session:<session_ref_digest>:site:<origin_digest>` |
//!
//! The scope is read from the filed browser intent: `driver_identity_hash`,
//! `target_origin`, and when present `site_group` and `session_ref_digest`.
//! The hook fills `driver_identity_hash` only for a tool the driver profile
//! maps, so an unprofiled tool carries none and no site target is offered for
//! it or covers it. An intent without these fields offers only the older
//! `exact`, `category` and `server` targets.

use serde_json::{Map, Value};

use crate::browser_session_schema::is_digest;
use crate::context_digest::python_strip;

const SELECTOR_PREFIX: &str = "browser-grant:v2";
/// The site targets, most specific first.
pub(crate) const SITE_TARGETS: [&str; 4] = ["session-site", "site-category", "site", "site-group"];
/// `session` is offered for `session-site` only. Until session-end expiry
/// lands, the grant is also bounded by the longest timed duration.
pub(crate) const SESSION_DURATION: &str = "session";
pub(crate) const SESSION_BOUND_SECONDS: i64 = 5 * 60 * 60;
const MAX_ORIGIN_CHARS: usize = 512;

/// Where a browser intent acts, as a site grant names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SiteScope {
    pub driver_identity_hash: String,
    pub origin_digest: String,
    pub site_group_digest: Option<String>,
    pub session_ref_digest: Option<String>,
}

fn text<'a>(intent: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    let value = python_strip(intent.get(key)?.as_str()?);
    (!value.is_empty()).then_some(value)
}

fn named_digest(value: &str) -> Option<String> {
    (value.len() <= MAX_ORIGIN_CHARS && value.bytes().all(|byte| byte.is_ascii_graphic()))
        .then(|| guard_policy_snapshot::digest_bytes(value.as_bytes()))
}

/// The site scope of a filed intent, or none when it lacks a driver identity
/// hash or a target origin.
pub(crate) fn site_scope(intent: &Value) -> Option<SiteScope> {
    let intent = intent.as_object()?;
    let driver_identity_hash = text(intent, "driver_identity_hash").filter(|d| is_digest(d))?;
    let origin_digest = named_digest(text(intent, "target_origin")?)?;
    Some(SiteScope {
        driver_identity_hash: driver_identity_hash.to_owned(),
        origin_digest,
        site_group_digest: text(intent, "site_group").and_then(named_digest),
        session_ref_digest: text(intent, "session_ref_digest")
            .filter(|d| is_digest(d))
            .map(str::to_owned),
    })
}

/// The site targets a scope can be granted under.
pub(crate) fn site_targets(scope: &SiteScope) -> Vec<&'static str> {
    SITE_TARGETS
        .into_iter()
        .filter(|target| match *target {
            "session-site" => scope.session_ref_digest.is_some(),
            "site-group" => scope.site_group_digest.is_some(),
            _ => true,
        })
        .collect()
}

pub(crate) fn is_site_target(target: &str) -> bool {
    SITE_TARGETS.contains(&target)
}

/// The selector a site grant of `target` is filed under.
pub(crate) fn site_selector(scope: &SiteScope, target: &str, category: &str) -> Option<String> {
    let SiteScope {
        driver_identity_hash: driver,
        origin_digest: origin,
        ..
    } = scope;
    let suffix = match target {
        "site-category" => format!("site:{origin}:category:{category}"),
        "site" => format!("site:{origin}"),
        "site-group" => format!("group:{}", scope.site_group_digest.as_ref()?),
        "session-site" => format!(
            "session:{}:site:{origin}",
            scope.session_ref_digest.as_ref()?
        ),
        _ => return None,
    };
    Some(format!("{SELECTOR_PREFIX}:{driver}:{suffix}"))
}

/// Whether a site grant of `target`, filed for `grant`, covers a routine call
/// with scope `candidate`: the same driver identity always, then the same
/// origin, site group or session and origin, and for `site-category` the same
/// category.
pub(crate) fn site_covers(
    target: &str,
    grant: (&SiteScope, &str),
    candidate: (&SiteScope, &str),
) -> bool {
    let ((grant, grant_category), (candidate, candidate_category)) = (grant, candidate);
    if grant.driver_identity_hash != candidate.driver_identity_hash {
        return false;
    }
    let same_origin = grant.origin_digest == candidate.origin_digest;
    match target {
        "site-category" => same_origin && grant_category == candidate_category,
        "site" => same_origin,
        "site-group" => {
            grant.site_group_digest.is_some()
                && grant.site_group_digest == candidate.site_group_digest
        }
        "session-site" => {
            same_origin
                && grant.session_ref_digest.is_some()
                && grant.session_ref_digest == candidate.session_ref_digest
        }
        _ => false,
    }
}

#[cfg(test)]
#[path = "browser_site_grant_tests.rs"]
mod tests;

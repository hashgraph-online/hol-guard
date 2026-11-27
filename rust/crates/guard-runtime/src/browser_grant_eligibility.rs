//! BP-T061: which grants a filed browser intent may carry.
//!
//! Two tiers:
//! - `Routine`: the call's risk is its routine category, plus at most the
//!   informational external-domain flag. Every target may be offered, as
//!   before; the site targets also need a clean surface (below).
//! - `SharedSession`: the same, except the call also runs in a shared or
//!   remote-debugging profile (`browser_shared_profile`). Only `session-site`
//!   may be offered, and only with a clean surface.
//!
//! A clean surface means the filed intent names no sensitive surface flag, no
//! password or payment element and no input that looks like a secret or a
//! payment detail. The hook fills `element` and `input` with the shape of
//! `BrowserActionV2` (`is_password`, `is_payment`, `preview_class`). A field
//! present in any other shape is read as unclean, never as absent.
//!
//! Transfer, privileged, sensitive-surface, Guard-origin and every other
//! hard-excluded risk fails both tiers, because neither tier allows a risk
//! beyond those named above.

use serde_json::{Map, Value};

use crate::mcp_tool_policy_grants::risks_allow_grant;

/// The risk a shared or remote-debugging profile adds to a call.
pub(crate) const SHARED_PROFILE_RISK: &str = "browser_shared_profile";
/// The input preview classes no site grant covers.
const UNSAFE_PREVIEW_CLASSES: [&str; 2] = ["looks_like_secret", "looks_like_payment"];
/// The grant targets that predate site grants. They keep today's rule and
/// never see a surface check.
const LEGACY_TARGETS: [&str; 3] = ["exact", "category", "server"];

/// How far a filed intent may be granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrantTier {
    Routine,
    SharedSession,
}

impl GrantTier {
    /// Whether a grant of `target` may be offered for, or cover, a call of
    /// this tier whose surface is `surface_clean`.
    pub(crate) fn allows(self, target: &str, surface_clean: bool) -> bool {
        match self {
            Self::Routine => LEGACY_TARGETS.contains(&target) || surface_clean,
            Self::SharedSession => target == "session-site" && surface_clean,
        }
    }
}

/// The tier of a call whose routine category is `category` and whose
/// projected risks are `risks`, or none when no grant may cover it.
pub(crate) fn grant_tier<S: AsRef<str>>(category: &str, risks: &[S]) -> Option<GrantTier> {
    if risks_allow_grant(category, risks) {
        return Some(GrantTier::Routine);
    }
    let shared = risks
        .iter()
        .any(|risk| risk.as_ref() == SHARED_PROFILE_RISK);
    let rest: Vec<&str> = risks
        .iter()
        .map(AsRef::as_ref)
        .filter(|risk| *risk != SHARED_PROFILE_RISK)
        .collect();
    (shared && risks_allow_grant(category, &rest)).then_some(GrantTier::SharedSession)
}

/// Whether the filed intent names no sensitive surface, no password or
/// payment element and no secret- or payment-looking input.
pub(crate) fn surface_clean(intent: &Map<String, Value>) -> bool {
    let flags_clean = match intent.get("sensitive_surface_flags") {
        None | Some(Value::Null) => true,
        Some(Value::Array(flags)) => flags.is_empty(),
        Some(_) => false,
    };
    let element_clean = match intent.get("element") {
        None | Some(Value::Null) => true,
        Some(Value::Object(element)) => ["is_password", "is_payment"]
            .iter()
            .all(|key| matches!(element.get(*key), None | Some(Value::Bool(false)))),
        Some(_) => false,
    };
    let input_clean = match intent.get("input") {
        None | Some(Value::Null) => true,
        Some(Value::Object(input)) => match input.get("preview_class") {
            None | Some(Value::Null) => true,
            Some(Value::String(class)) => !UNSAFE_PREVIEW_CLASSES.contains(&class.as_str()),
            Some(_) => false,
        },
        Some(_) => false,
    };
    flags_clean && element_clean && input_clean
}

#[cfg(test)]
#[path = "browser_grant_eligibility_tests.rs"]
mod tests;

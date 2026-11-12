//! Saved consent scopes for version 2 cloud action requests.
//!
//! - `exact`: the exact call, bound to the action identity (as version 1).
//! - `resource`: this action on this connection and resource.
//! - `bounded`: this action on this connection when a stored fact selector
//!   definitely matches. An unknown fact never satisfies it.
//!
//! Consent only answers a review. Resource and bounded scopes do not answer a
//! re-approval unless the facts say the change can be undone; permanent or
//! unknown reversibility needs exact consent.

use guard_contracts::{ActionFactsV2, FactSelectorV2, FactSubjectV2, Match3, ReversibilityV2};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::cloud_action::{is_sha256_hex, ConsentKind};
use crate::cloud_action_binding::{valid_action_id, valid_label};
use crate::cloud_action_canonical::{canonical_bytes, domain_digest};
use crate::effect_decision::GuardAction;

const SELECTOR_DOMAIN: &str = "guard.cloud-action-consent-selector.v2";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedConsentV2 {
    consent_id: String,
    kind: ConsentKind,
    scope: ConsentScopeV2,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum ConsentScopeV2 {
    Exact {
        action_identity_sha256: String,
    },
    Resource {
        action_id: String,
        connection_id: String,
        resource_id: String,
    },
    Bounded {
        action_id: String,
        connection_id: String,
        selector: Box<FactSelectorV2>,
        selector_sha256: String,
    },
}

/// Digest a bounded consent stores beside its selector, over the selector's
/// canonical JSON.
pub fn consent_selector_digest(selector: &FactSelectorV2) -> Option<String> {
    let value = serde_json::to_value(selector).ok()?;
    let bytes = canonical_bytes(&value).ok()?;
    Some(domain_digest(SELECTOR_DOMAIN, &[&bytes]))
}

pub(crate) fn validate_consent(saved: &SavedConsentV2) -> Result<(), &'static str> {
    let ok = valid_label(&saved.consent_id)
        && match &saved.scope {
            ConsentScopeV2::Exact {
                action_identity_sha256,
            } => is_sha256_hex(action_identity_sha256),
            ConsentScopeV2::Resource {
                action_id,
                connection_id,
                resource_id,
            } => {
                valid_action_id(action_id) && valid_label(connection_id) && valid_label(resource_id)
            }
            ConsentScopeV2::Bounded {
                action_id,
                connection_id,
                selector,
                selector_sha256,
            } => {
                valid_action_id(action_id)
                    && valid_label(connection_id)
                    && selector.validate().is_ok()
                    && consent_selector_digest(selector).as_deref() == Some(selector_sha256)
            }
        };
    ok.then_some(()).ok_or("invalid_request")
}

pub(crate) struct ConsentContext<'a> {
    pub(crate) identity: &'a str,
    pub(crate) action_id: &'a str,
    pub(crate) connection_id: &'a str,
    pub(crate) resource_id: Option<&'a str>,
    pub(crate) subject: &'a FactSubjectV2<'a>,
    pub(crate) action: GuardAction,
}

pub(crate) struct AppliedConsent<'a> {
    pub(crate) consent_id: &'a str,
    kind: ConsentKind,
    scope: &'static str,
}

impl AppliedConsent<'_> {
    pub(crate) fn kind_str(&self) -> &'static str {
        match self.kind {
            ConsentKind::Once => "once",
            ConsentKind::Always => "always",
        }
    }

    pub(crate) fn scope_str(&self) -> &'static str {
        self.scope
    }

    pub(crate) fn reason_code(&self) -> &'static str {
        match self.kind {
            ConsentKind::Once => "saved_consent_once",
            ConsentKind::Always => "saved_consent_always",
        }
    }
}

/// Whether a scope wider than the exact call may answer this decision.
fn broad_scope_allowed(action: GuardAction, facts: &ActionFactsV2) -> bool {
    action != GuardAction::RequireReapproval
        || matches!(
            facts.reversibility.known(),
            Some(ReversibilityV2::Reversible | ReversibilityV2::Recoverable)
        )
}

/// The strongest consent that covers this call: `always` before `once`, then
/// the narrowest scope.
pub(crate) fn find_consent<'a>(
    saved: &'a [SavedConsentV2],
    context: &ConsentContext<'_>,
) -> Option<AppliedConsent<'a>> {
    let broad = broad_scope_allowed(context.action, context.subject.facts);
    saved
        .iter()
        .filter_map(|consent| {
            let (rank, scope) = match &consent.scope {
                ConsentScopeV2::Exact {
                    action_identity_sha256,
                } => (action_identity_sha256 == context.identity).then_some((2, "exact"))?,
                ConsentScopeV2::Resource {
                    action_id,
                    connection_id,
                    resource_id,
                } => (broad
                    && action_id == context.action_id
                    && connection_id == context.connection_id
                    && Some(resource_id.as_str()) == context.resource_id)
                    .then_some((1, "resource"))?,
                ConsentScopeV2::Bounded {
                    action_id,
                    connection_id,
                    selector,
                    ..
                } => (broad
                    && action_id == context.action_id
                    && connection_id == context.connection_id
                    && selector.matches(context.subject) == Match3::Yes)
                    .then_some((0, "bounded"))?,
            };
            Some(((consent.kind == ConsentKind::Always, rank), consent, scope))
        })
        .max_by_key(|(key, _, _)| *key)
        .map(|(_, consent, scope)| AppliedConsent {
            consent_id: &consent.consent_id,
            kind: consent.kind,
            scope,
        })
}

/// The choices a review offers. Allow once and Always allow are always both
/// present for the exact call; a resource scope is added when it could apply.
pub(crate) fn consent_options(
    has_resource: bool,
    action: GuardAction,
    facts: &ActionFactsV2,
) -> Vec<Value> {
    let mut options = vec![
        json!({"kind": "once", "scope": "exact"}),
        json!({"kind": "always", "scope": "exact"}),
    ];
    if has_resource && broad_scope_allowed(action, facts) {
        options.push(json!({"kind": "once", "scope": "resource"}));
        options.push(json!({"kind": "always", "scope": "resource"}));
    }
    options
}

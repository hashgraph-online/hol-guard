//! Saved consent scopes for version 2 cloud action requests.
//!
//! - `exact`: the exact call, bound to the action identity (as version 1).
//! - `resource`: this action on this connection and resource.
//! - `bounded`: this action on this connection when a stored fact selector
//!   definitely matches. An unknown fact never satisfies it.
//!
//! Consent only answers a review. Resource and bounded scopes do not answer a
//! re-approval unless the facts say the change can be undone; permanent or
//! unknown reversibility needs exact consent. They also never answer a call in
//! a session that saw an injection signal, or an outbound call in a session
//! that read untrusted or sensitive content (or keeps no journal), so text an
//! agent read cannot ride a standing permission out of the account.
//!
//! A review offers bounded Always allow choices built from the call's own
//! known facts, with the selector and its digest, so the host stores exactly
//! what the evaluator will match.

use guard_contracts::{ActionClassV2, FactSelectorV2, FactSubjectV2, Match3, ReversibilityV2};
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

/// Record or recipient counts a bounded offer rounds up to.
const BOUND_TIERS: [u64; 9] = [1, 5, 10, 25, 50, 100, 250, 500, 1000];

/// The smallest tier that covers `count`, if any does.
fn covering_tier(count: u64) -> Option<u64> {
    BOUND_TIERS.iter().copied().find(|tier| *tier >= count)
}

/// Whether a scope wider than the exact call may answer this decision.
fn broad_scope_allowed(action: GuardAction, subject: &FactSubjectV2<'_>) -> bool {
    let facts = subject.facts;
    let undoable = action != GuardAction::RequireReapproval
        || matches!(
            facts.reversibility.known(),
            Some(ReversibilityV2::Reversible | ReversibilityV2::Recoverable)
        );
    undoable && !tainted(subject)
}

/// Whether the call can carry data or value out of the account. An update or
/// execute counts unless its audience is known to be internal.
fn outbound(subject: &FactSubjectV2<'_>) -> bool {
    let facts = subject.facts;
    facts.class.is_egress()
        || (matches!(facts.class, ActionClassV2::Update | ActionClassV2::Execute)
            && facts.audience.external.known() != Some(&false))
}

/// A call known to reach outside never gets a bounded offer, so no bounded
/// consent answers it either, whatever its selector left open.
fn reaches_outside(subject: &FactSubjectV2<'_>) -> bool {
    subject.facts.audience.external.known() == Some(&true)
}

fn tainted(subject: &FactSubjectV2<'_>) -> bool {
    match subject.session {
        Some(session) if session.injection_signal_seen => true,
        Some(session) => {
            outbound(subject) && (session.untrusted_content_seen || session.sensitive_data_seen)
        }
        None => outbound(subject),
    }
}

/// The strongest consent that covers this call: `always` before `once`, then
/// the narrowest scope.
pub(crate) fn find_consent<'a>(
    saved: &'a [SavedConsentV2],
    context: &ConsentContext<'_>,
) -> Option<AppliedConsent<'a>> {
    let broad = broad_scope_allowed(context.action, context.subject);
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
                    && !reaches_outside(context.subject)
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
/// present for the exact call; a resource scope is added when it could apply,
/// and bounded Always allow choices when the facts can bound the call.
pub(crate) fn consent_options(
    has_resource: bool,
    action: GuardAction,
    subject: &FactSubjectV2<'_>,
) -> Vec<Value> {
    let mut options = vec![
        json!({"kind": "once", "scope": "exact"}),
        json!({"kind": "always", "scope": "exact"}),
    ];
    if broad_scope_allowed(action, subject) {
        if has_resource {
            options.push(json!({"kind": "once", "scope": "resource"}));
            options.push(json!({"kind": "always", "scope": "resource"}));
        }
        options.extend(bounded_offers(subject));
    }
    options
}

/// Up to two bounded Always allow choices: the smallest tier that covers this
/// call and the next wider one. Each pins the provider, class, object and
/// reversibility. An outbound call also pins its recipient domains, its record
/// tier and, when known, a byte cap. A payment, a call known to reach outside,
/// an outbound call not known to stay inside, and a call whose bounding facts
/// are unknown or larger than the widest tier get none.
fn bounded_offers(subject: &FactSubjectV2<'_>) -> Vec<Value> {
    let facts = subject.facts;
    // No selector bounds an amount, so a payment never gets a standing choice.
    if matches!(facts.class, ActionClassV2::Pay) {
        return Vec::new();
    }
    // A call known to reach outside gets none, and an outbound call must be
    // known to stay inside: the selector then pins `external: false`.
    if reaches_outside(subject) {
        return Vec::new();
    }
    let internal = match facts.audience.external.known() {
        Some(true) => return Vec::new(),
        Some(false) => true,
        None if outbound(subject) => return Vec::new(),
        None => false,
    };
    let (Some(object), Some(reversibility)) = (facts.object.known(), facts.reversibility.known())
    else {
        return Vec::new();
    };
    let mut base = FactSelectorV2 {
        providers: Some(vec![subject.provider.to_owned()]),
        classes: Some(vec![facts.class]),
        objects: Some(vec![*object]),
        reversibility: Some(vec![*reversibility]),
        external: internal.then_some(false),
        ..FactSelectorV2::default()
    };
    let count = if facts.class.is_egress() {
        let Some(domains) = facts.audience.recipient_domains.known() else {
            return Vec::new();
        };
        if domains.is_empty() {
            return Vec::new();
        }
        base.recipient_domains = Some(domains.clone());
        // An outbound consent also caps what it carries: the records at the
        // tier that covers this call, and the bytes when they are known. A
        // call that does not say how many records it carries gets none.
        let Some(&records) = facts.record_count.known() else {
            return Vec::new();
        };
        let Some(tier) = covering_tier(records) else {
            return Vec::new();
        };
        base.max_record_count = Some(tier);
        if let Some(&bytes) = facts.byte_count.known() {
            let Some(cap) = bytes.checked_next_power_of_two() else {
                return Vec::new();
            };
            base.max_byte_count = Some(cap);
        }
        facts.recipient_count.known()
    } else {
        facts.record_count.known()
    };
    let Some(&count) = count else {
        return Vec::new();
    };
    BOUND_TIERS
        .iter()
        .copied()
        .skip_while(|tier| *tier < count)
        .take(2)
        .filter_map(|tier| {
            let mut selector = base.clone();
            if facts.class.is_egress() {
                selector.max_recipient_count = Some(tier);
            } else {
                selector.max_record_count = Some(tier);
            }
            selector.validate().ok()?;
            let digest = consent_selector_digest(&selector)?;
            Some(json!({
                "kind": "always",
                "scope": "bounded",
                "selector": selector,
                "selector_sha256": digest,
            }))
        })
        .collect()
}

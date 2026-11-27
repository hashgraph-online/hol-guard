//! The provider decide step (PRD 6.6, BP-T123).
//!
//! Applies cached provider signals to Guard's own decision for one action. It reads the provider
//! store and the session's [`NoiseLedger`] and nothing else: no network, no waiting on the worker.
//! A subject with no cached answer simply has no provider effect, and the worker is asked for one
//! elsewhere.
//!
//! For the connected providers whose compiled manifest declares the capability:
//!
//! - A signal counts as fresh only when the provider is still `connected`, the stored state is
//!   `fresh` and it has not expired. Signals from any other provider are ignored.
//! - The fresh signals go through [`NoiseLedger::admit_subject`] in card order with each provider's
//!   effect level for the capability, so `ok` is a finding, unverified `caution` is a finding,
//!   verified `caution` is reviewed inside the caps, `danger` is reviewed (or blocked under
//!   `enforce`), and `observe` only writes would-have-reviewed receipts. The strongest fresh verdict
//!   wins and the subject raises at most one provider-caused review.
//! - A fresh `danger` under `tighten` or `enforce` suspends grants for the subject.
//! - A provider with no fresh answer is listed as unavailable. With "Require a fresh check" on for
//!   the capability, that also reviews the action.
//!
//! The result is the stronger of Guard's decision and the provider effect, so for any signal set
//! the decision is never weaker than the decision with no provider.

use std::collections::BTreeMap;

use guard_contracts::{
    ProviderCapabilityV1, ProviderConnectionStateV1, ProviderEffectLevelV1, ProviderVerdictV1,
};
use guard_provider_integrations::compose::{compose, ProviderRow};
use guard_provider_integrations::noise::{
    apply, BaselineDecision, NoiseLedger, NoiseSignal, ProviderEffect,
};
use rusqlite::Connection;

use crate::provider_integration_store::{
    capability_settings, provider_connection, signals_for_subject, CapabilitySetting,
    ProviderStoreResult, StoredSignal,
};

/// A connected provider whose compiled manifest declares the capability being decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecideProvider<'a> {
    pub provider_id: &'a str,
    /// `provider.publisher.verified` from the compiled manifest.
    pub verified: bool,
}

/// One decision the hook or relay path asks about.
#[derive(Debug, Clone, Copy)]
pub struct DecideRequest<'a> {
    /// Guard's own decision for the action, before provider evidence.
    pub baseline: BaselineDecision,
    pub capability: ProviderCapabilityV1,
    pub subject_digest: &'a str,
    pub providers: &'a [DecideProvider<'a>],
    pub now_ms: u64,
}

/// One provider's cached answer, as the card lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAnswer {
    pub provider_id: String,
    pub verdict: ProviderVerdictV1,
    pub reason_codes: Vec<String>,
    pub fresh: bool,
    pub verified: bool,
    /// The signal version the noise caps count.
    pub revision: u64,
}

/// What the provider signals did to the decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderDecision {
    /// Never weaker than the request's `baseline`.
    pub decision: BaselineDecision,
    /// The noise ledger's effect for the subject.
    pub effect: ProviderEffect,
    /// The provider whose answer leads the card, when one is fresh and not `unknown`.
    pub deciding_provider: Option<String>,
    /// Show the one Browser-area notice that a provider is quiet-capped for the session.
    pub quiet_cap_notice: bool,
    /// A fresh `danger` under `tighten` or `enforce`: grants do not apply to the subject.
    pub suspend_grants: bool,
    /// Every cached answer from the given providers, in card order.
    pub answers: Vec<ProviderAnswer>,
    /// Providers with no fresh answer, for the `provider_unavailable` finding.
    pub unavailable: Vec<String>,
    /// Providers with "Require a fresh check" on and no fresh answer. Each reviews the action.
    pub fresh_check_required: Vec<String>,
}

impl ProviderDecision {
    fn unchanged(baseline: BaselineDecision) -> Self {
        Self {
            decision: baseline,
            effect: ProviderEffect::None,
            deciding_provider: None,
            quiet_cap_notice: false,
            suspend_grants: false,
            answers: Vec::new(),
            unavailable: Vec::new(),
            fresh_check_required: Vec::new(),
        }
    }
}

struct Candidate<'a> {
    provider: DecideProvider<'a>,
    setting: CapabilitySetting,
    signal: Option<StoredSignal>,
    fresh: bool,
}

fn is_fresh(state: Option<ProviderConnectionStateV1>, signal: &StoredSignal, now_ms: u64) -> bool {
    state == Some(ProviderConnectionStateV1::Connected)
        && signal.signal.state.is_fresh()
        && now_ms >= signal.signal.observed_at_ms
        && now_ms < signal.signal.expires_at_ms
}

fn candidates<'a>(
    connection: &Connection,
    request: &DecideRequest<'a>,
) -> ProviderStoreResult<Vec<Candidate<'a>>> {
    let mut cached: BTreeMap<String, StoredSignal> =
        signals_for_subject(connection, request.capability, request.subject_digest)?
            .into_iter()
            .map(|signal| (signal.signal.provider_id.clone(), signal))
            .collect();
    let mut seen = Vec::new();
    let mut candidates = Vec::new();
    for provider in request.providers {
        if seen.contains(&provider.provider_id) {
            continue;
        }
        seen.push(provider.provider_id);
        let state =
            provider_connection(connection, provider.provider_id)?.map(|stored| stored.state);
        let setting = capability_settings(connection, provider.provider_id)?
            .get(&request.capability)
            .copied()
            .unwrap_or_default();
        let signal = cached.remove(provider.provider_id);
        let fresh = signal
            .as_ref()
            .is_some_and(|signal| is_fresh(state, signal, request.now_ms));
        candidates.push(Candidate {
            provider: *provider,
            setting,
            signal,
            fresh,
        });
    }
    Ok(candidates)
}

/// Apply the cached provider signals for one subject to Guard's decision and record what the
/// session's noise caps count. A store error is returned; the caller then keeps `baseline`, which is
/// what the decision would be with no provider.
pub fn decide(
    connection: &Connection,
    ledger: &mut NoiseLedger,
    request: &DecideRequest<'_>,
) -> ProviderStoreResult<ProviderDecision> {
    if request.providers.is_empty() {
        return Ok(ProviderDecision::unchanged(request.baseline));
    }
    let candidates = candidates(connection, request)?;
    let rows: Vec<ProviderRow<'_>> = candidates
        .iter()
        .filter_map(|candidate| {
            candidate.signal.as_ref().map(|signal| ProviderRow {
                provider_id: candidate.provider.provider_id,
                verdict: signal.signal.verdict,
                fresh: candidate.fresh,
                verified: candidate.provider.verified,
            })
        })
        .collect();
    let composition = compose(&rows);
    let by_id: BTreeMap<&str, &Candidate<'_>> = candidates
        .iter()
        .map(|candidate| (candidate.provider.provider_id, candidate))
        .collect();
    let fresh_check_required: Vec<String> = candidates
        .iter()
        .filter(|candidate| !candidate.fresh && candidate.setting.require_fresh)
        .map(|candidate| candidate.provider.provider_id.to_owned())
        .collect();
    // A missing fresh check reviews the action whatever the answers say, so a provider row that
    // joins that review rides on it and is not counted against the caution caps.
    let guard_reviews_anyway =
        request.baseline != BaselineDecision::Allow || !fresh_check_required.is_empty();
    let mut noise = Vec::new();
    let mut answers = Vec::new();
    for row in &composition.ordered {
        let candidate = by_id[row.provider_id];
        let Some(signal) = candidate.signal.as_ref() else {
            continue;
        };
        noise.push(NoiseSignal {
            provider_id: row.provider_id,
            subject_digest: request.subject_digest,
            signal_version: signal.revision,
            verdict: signal.signal.verdict,
            fresh: candidate.fresh,
            verified: candidate.provider.verified,
            effect: candidate.setting.effect_level,
            guard_reviews_anyway,
        });
        answers.push(ProviderAnswer {
            provider_id: row.provider_id.to_owned(),
            verdict: signal.signal.verdict,
            reason_codes: signal.signal.reason_codes.clone(),
            fresh: candidate.fresh,
            verified: candidate.provider.verified,
            revision: signal.revision,
        });
    }
    let outcome = ledger.admit_subject(&noise);
    let suspend_grants = candidates.iter().any(|candidate| {
        candidate.fresh
            && candidate.setting.effect_level != ProviderEffectLevelV1::Observe
            && candidate
                .signal
                .as_ref()
                .is_some_and(|signal| signal.signal.verdict == ProviderVerdictV1::Danger)
    });
    let unavailable: Vec<String> = candidates
        .iter()
        .filter(|candidate| !candidate.fresh)
        .map(|candidate| candidate.provider.provider_id.to_owned())
        .collect();
    let mut decision = apply(request.baseline, outcome.effect);
    if !fresh_check_required.is_empty() {
        decision = decision.max(BaselineDecision::Review);
    }
    Ok(ProviderDecision {
        decision,
        effect: outcome.effect,
        deciding_provider: composition.deciding.map(|row| row.provider_id.to_owned()),
        quiet_cap_notice: outcome.quiet_cap_notice,
        suspend_grants,
        answers,
        unavailable,
        fresh_check_required,
    })
}

#[cfg(test)]
#[path = "provider_integration_decide_tests.rs"]
mod tests;

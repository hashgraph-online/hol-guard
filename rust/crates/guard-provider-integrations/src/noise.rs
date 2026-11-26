//! Provider noise caps (PRD 6.12).
//!
//! A provider adds evidence. Left alone it would also add prompts, so the resident runs every fresh
//! signal through a per-session [`NoiseLedger`] before the signal may touch a decision:
//!
//! - `ok` is a finding and `unknown` (or any signal that is not fresh) has no effect.
//! - Under the `observe` effect level, `caution` and `danger` are would-have-reviewed receipts.
//! - `caution` from an unverified provider is a finding only.
//! - `caution` from a verified provider raises at most one review per subject per signal version,
//!   and at most [`PROVIDER_CAUTION_REVIEWS_PER_SESSION`] per provider per session. Past the session
//!   cap it is a finding, and the first capped signal asks for one Browser-area notice.
//! - `danger` is never capped: it is reviewed under `tighten` and blocks under `enforce`.
//! - When Guard reviews the action anyway the provider row rides on that review and costs nothing.
//!
//! The ledger can only add a review or a block on top of Guard's own decision. [`apply`] takes the
//! stronger of the two, so no signal sequence can produce an allow Guard would not have given.

use std::collections::{BTreeMap, BTreeSet};

use guard_contracts::{
    ProviderEffectLevelV1, ProviderVerdictV1, PROVIDER_CAUTION_REVIEWS_PER_SESSION,
    PROVIDER_CAUTION_REVIEWS_PER_SUBJECT_VERSION,
};

/// One fresh-or-not provider answer about the action being decided.
#[derive(Debug, Clone, Copy)]
pub struct NoiseSignal<'a> {
    pub provider_id: &'a str,
    pub subject_digest: &'a str,
    /// Changes whenever the provider's answer changes or is refreshed after expiry.
    pub signal_version: u64,
    pub verdict: ProviderVerdictV1,
    pub fresh: bool,
    /// `provider.publisher.verified`, set by maintainers only.
    pub verified: bool,
    pub effect: ProviderEffectLevelV1,
    /// Guard raises a review or block for this action without the provider.
    pub guard_reviews_anyway: bool,
}

/// What a signal may do to the action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProviderEffect {
    /// Nothing to show.
    None,
    /// A finding on the card or receipt, no decision change.
    Finding,
    /// A finding plus a would-have-reviewed receipt (`observe`).
    WouldHaveReviewed,
    /// The provider row joins a review Guard raises anyway. Not provider-caused, not counted.
    RidesOnGuardReview,
    /// A provider-caused review.
    Review,
    /// A provider-caused block (`danger` under `enforce`).
    Block,
}

/// The ledger's answer for one signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoiseOutcome {
    pub effect: ProviderEffect,
    /// Show the one Browser-area notice that this provider is quiet-capped for the session.
    pub quiet_cap_notice: bool,
}

impl NoiseOutcome {
    const fn of(effect: ProviderEffect) -> Self {
        Self {
            effect,
            quiet_cap_notice: false,
        }
    }
}

/// Guard's own decision for an action, before provider evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BaselineDecision {
    Allow,
    Review,
    Block,
}

/// Guard's decision with the provider's effect applied. Provider evidence only tightens.
pub fn apply(baseline: BaselineDecision, effect: ProviderEffect) -> BaselineDecision {
    let provider = match effect {
        ProviderEffect::Block => BaselineDecision::Block,
        ProviderEffect::Review => BaselineDecision::Review,
        _ => BaselineDecision::Allow,
    };
    baseline.max(provider)
}

/// Per-session counters for provider-caused `caution` reviews. Held by the resident, never sent
/// anywhere. Each provider holds at most the session cap of subject entries.
#[derive(Debug, Default)]
pub struct NoiseLedger {
    reviewed: BTreeMap<String, BTreeMap<(String, u64), u32>>,
    capped: BTreeSet<String>,
}

impl NoiseLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Provider-caused `caution` reviews raised for `provider_id` this session.
    pub fn caution_reviews(&self, provider_id: &str) -> u32 {
        self.reviewed
            .get(provider_id)
            .map_or(0, |subjects| subjects.values().sum())
    }

    /// Decide what `signal` may do and record it.
    pub fn admit(&mut self, signal: &NoiseSignal<'_>) -> NoiseOutcome {
        if !signal.fresh {
            return NoiseOutcome::of(ProviderEffect::None);
        }
        match signal.verdict {
            ProviderVerdictV1::Unknown => NoiseOutcome::of(ProviderEffect::None),
            ProviderVerdictV1::Ok => NoiseOutcome::of(ProviderEffect::Finding),
            ProviderVerdictV1::Danger => NoiseOutcome::of(Self::danger(signal)),
            ProviderVerdictV1::Caution => self.caution(signal),
        }
    }

    fn danger(signal: &NoiseSignal<'_>) -> ProviderEffect {
        match signal.effect {
            ProviderEffectLevelV1::Observe => ProviderEffect::WouldHaveReviewed,
            ProviderEffectLevelV1::Enforce => ProviderEffect::Block,
            ProviderEffectLevelV1::Tighten if signal.guard_reviews_anyway => {
                ProviderEffect::RidesOnGuardReview
            }
            ProviderEffectLevelV1::Tighten => ProviderEffect::Review,
        }
    }

    /// Several providers answered about one subject. Every signal is weighed against the caps
    /// without recording anything; only the strongest effect is recorded, so the subject raises at
    /// most one provider-caused review whatever the provider count. Ties go to a verified
    /// provider, then to the earlier signal, so the caller passes signals in card order.
    pub fn admit_subject(&mut self, signals: &[NoiseSignal<'_>]) -> NoiseOutcome {
        // A review already raised for one of these answers covers the subject: another provider's
        // `caution` about the same subject does not ask again.
        let subject_reviewed = signals.iter().any(|signal| {
            signal.verdict == ProviderVerdictV1::Caution && self.reviews_for(signal) > 0
        });
        let effect = |ledger: &Self, signal: &NoiseSignal<'_>| match ledger.preview(signal) {
            ProviderEffect::Review if subject_reviewed => ProviderEffect::Finding,
            effect => effect,
        };
        let winner = signals
            .iter()
            .enumerate()
            .max_by(|(left_index, left), (right_index, right)| {
                effect(self, left)
                    .cmp(&effect(self, right))
                    .then_with(|| left.verified.cmp(&right.verified))
                    .then_with(|| right_index.cmp(left_index))
            })
            .map(|(_, signal)| *signal);
        match winner {
            Some(signal) if effect(self, &signal) == ProviderEffect::Finding => {
                NoiseOutcome::of(ProviderEffect::Finding)
            }
            Some(signal) => self.admit(&signal),
            None => NoiseOutcome::of(ProviderEffect::None),
        }
    }

    fn reviews_for(&self, signal: &NoiseSignal<'_>) -> u32 {
        self.reviewed
            .get(signal.provider_id)
            .and_then(|subjects| {
                subjects.get(&(signal.subject_digest.to_owned(), signal.signal_version))
            })
            .copied()
            .unwrap_or(0)
    }

    /// What [`NoiseLedger::admit`] would return for `signal`, without recording it.
    pub fn preview(&self, signal: &NoiseSignal<'_>) -> ProviderEffect {
        if !signal.fresh {
            return ProviderEffect::None;
        }
        match signal.verdict {
            ProviderVerdictV1::Unknown => ProviderEffect::None,
            ProviderVerdictV1::Ok => ProviderEffect::Finding,
            ProviderVerdictV1::Danger => Self::danger(signal),
            ProviderVerdictV1::Caution => match self.caution_gate(signal) {
                CautionGate::Effect(effect) => effect,
                CautionGate::SessionCapped => ProviderEffect::Finding,
                CautionGate::Admit => ProviderEffect::Review,
            },
        }
    }

    fn caution_gate(&self, signal: &NoiseSignal<'_>) -> CautionGate {
        if signal.effect == ProviderEffectLevelV1::Observe {
            return CautionGate::Effect(ProviderEffect::WouldHaveReviewed);
        }
        if !signal.verified {
            return CautionGate::Effect(ProviderEffect::Finding);
        }
        if signal.guard_reviews_anyway {
            return CautionGate::Effect(ProviderEffect::RidesOnGuardReview);
        }
        if self.reviews_for(signal) >= PROVIDER_CAUTION_REVIEWS_PER_SUBJECT_VERSION {
            return CautionGate::Effect(ProviderEffect::Finding);
        }
        if self.caution_reviews(signal.provider_id) >= PROVIDER_CAUTION_REVIEWS_PER_SESSION {
            return CautionGate::SessionCapped;
        }
        CautionGate::Admit
    }

    fn caution(&mut self, signal: &NoiseSignal<'_>) -> NoiseOutcome {
        match self.caution_gate(signal) {
            CautionGate::Effect(effect) => NoiseOutcome::of(effect),
            CautionGate::SessionCapped => NoiseOutcome {
                effect: ProviderEffect::Finding,
                quiet_cap_notice: self.capped.insert(signal.provider_id.to_owned()),
            },
            CautionGate::Admit => {
                *self
                    .reviewed
                    .entry(signal.provider_id.to_owned())
                    .or_default()
                    .entry((signal.subject_digest.to_owned(), signal.signal_version))
                    .or_insert(0) += 1;
                NoiseOutcome::of(ProviderEffect::Review)
            }
        }
    }
}

enum CautionGate {
    Effect(ProviderEffect),
    SessionCapped,
    Admit,
}

#[cfg(test)]
#[path = "noise_tests.rs"]
mod tests;

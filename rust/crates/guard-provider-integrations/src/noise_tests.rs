use std::collections::BTreeMap;

use guard_contracts::{
    ProviderEffectLevelV1 as Level, ProviderVerdictV1 as V, PROVIDER_CAUTION_REVIEWS_PER_SESSION,
};

use super::*;

const PROVIDER: &str = "provider.exampleshield";

fn signal(subject: &'static str, verdict: V) -> NoiseSignal<'static> {
    NoiseSignal {
        provider_id: PROVIDER,
        subject_digest: subject,
        signal_version: 1,
        verdict,
        fresh: true,
        verified: true,
        effect: Level::Tighten,
        guard_reviews_anyway: false,
    }
}

fn effect(ledger: &mut NoiseLedger, signal: NoiseSignal<'_>) -> ProviderEffect {
    ledger.admit(&signal).effect
}

#[test]
fn ok_is_a_finding_and_unknown_or_stale_has_no_effect() {
    let mut ledger = NoiseLedger::new();
    assert_eq!(
        effect(&mut ledger, signal("a", V::Ok)),
        ProviderEffect::Finding
    );
    assert_eq!(
        effect(&mut ledger, signal("a", V::Unknown)),
        ProviderEffect::None
    );
    for verdict in [V::Ok, V::Caution, V::Danger, V::Unknown] {
        let mut stale = signal("a", verdict);
        stale.fresh = false;
        assert_eq!(
            effect(&mut ledger, stale),
            ProviderEffect::None,
            "{verdict:?}"
        );
    }
    assert_eq!(ledger.caution_reviews(PROVIDER), 0);
}

#[test]
fn unverified_caution_is_a_finding_only() {
    let mut ledger = NoiseLedger::new();
    for subject in ["a", "b", "c", "d", "e"] {
        let mut unverified = signal(subject, V::Caution);
        unverified.verified = false;
        assert_eq!(effect(&mut ledger, unverified), ProviderEffect::Finding);
    }
    assert_eq!(ledger.caution_reviews(PROVIDER), 0);
}

#[test]
fn verified_caution_asks_once_per_subject_and_signal_version() {
    let mut ledger = NoiseLedger::new();
    assert_eq!(
        effect(&mut ledger, signal("a", V::Caution)),
        ProviderEffect::Review
    );
    assert_eq!(
        effect(&mut ledger, signal("a", V::Caution)),
        ProviderEffect::Finding
    );
    let mut changed = signal("a", V::Caution);
    changed.signal_version = 2;
    assert_eq!(effect(&mut ledger, changed), ProviderEffect::Review);
    assert_eq!(effect(&mut ledger, changed), ProviderEffect::Finding);
    assert_eq!(ledger.caution_reviews(PROVIDER), 2);
}

#[test]
fn the_session_cap_turns_further_cautions_into_findings_with_one_notice() {
    let mut ledger = NoiseLedger::new();
    for subject in ["a", "b", "c"] {
        assert_eq!(
            effect(&mut ledger, signal(subject, V::Caution)),
            ProviderEffect::Review
        );
    }
    assert_eq!(
        ledger.admit(&signal("d", V::Caution)),
        NoiseOutcome {
            effect: ProviderEffect::Finding,
            quiet_cap_notice: true
        }
    );
    assert_eq!(
        ledger.admit(&signal("e", V::Caution)),
        NoiseOutcome {
            effect: ProviderEffect::Finding,
            quiet_cap_notice: false
        }
    );
    let mut other = signal("d", V::Caution);
    other.provider_id = "provider.otherwatch";
    assert_eq!(effect(&mut ledger, other), ProviderEffect::Review);
}

#[test]
fn danger_is_never_capped() {
    let mut ledger = NoiseLedger::new();
    for subject in ["a", "b", "c"] {
        effect(&mut ledger, signal(subject, V::Caution));
    }
    for _ in 0..10 {
        assert_eq!(
            effect(&mut ledger, signal("a", V::Danger)),
            ProviderEffect::Review
        );
        let mut unverified = signal("z", V::Danger);
        unverified.verified = false;
        assert_eq!(effect(&mut ledger, unverified), ProviderEffect::Review);
    }
    let mut enforced = signal("a", V::Danger);
    enforced.effect = Level::Enforce;
    assert_eq!(effect(&mut ledger, enforced), ProviderEffect::Block);
}

#[test]
fn observe_writes_would_have_reviewed_receipts_only() {
    let mut ledger = NoiseLedger::new();
    for verdict in [V::Caution, V::Danger] {
        let mut observed = signal("a", verdict);
        observed.effect = Level::Observe;
        assert_eq!(
            effect(&mut ledger, observed),
            ProviderEffect::WouldHaveReviewed
        );
    }
    assert_eq!(ledger.caution_reviews(PROVIDER), 0);
}

#[test]
fn a_review_guard_raises_anyway_is_not_counted() {
    let mut ledger = NoiseLedger::new();
    for subject in ["a", "b", "c", "d", "e"] {
        let mut riding = signal(subject, V::Caution);
        riding.guard_reviews_anyway = true;
        assert_eq!(
            effect(&mut ledger, riding),
            ProviderEffect::RidesOnGuardReview
        );
    }
    assert_eq!(ledger.caution_reviews(PROVIDER), 0);
    assert_eq!(
        effect(&mut ledger, signal("a", V::Caution)),
        ProviderEffect::Review
    );
}

#[test]
fn apply_only_tightens() {
    use BaselineDecision::{Allow, Block, Review};
    for baseline in [Allow, Review, Block] {
        for effect in [
            ProviderEffect::None,
            ProviderEffect::Finding,
            ProviderEffect::WouldHaveReviewed,
            ProviderEffect::RidesOnGuardReview,
            ProviderEffect::Review,
            ProviderEffect::Block,
        ] {
            assert!(
                apply(baseline, effect) >= baseline,
                "{baseline:?} {effect:?}"
            );
        }
    }
    assert_eq!(apply(Allow, ProviderEffect::Finding), Allow);
    assert_eq!(apply(Allow, ProviderEffect::Review), Review);
    assert_eq!(apply(Review, ProviderEffect::Block), Block);
}

/// A small deterministic generator so the property runs without an extra dependency.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[(self.next() % items.len() as u64) as usize]
    }
}

#[test]
fn no_signal_sequence_exceeds_the_caps_or_loosens_a_decision() {
    const PROVIDERS: [&str; 3] = ["provider.a", "provider.b", "provider.fixture-c"];
    const SUBJECTS: [&str; 6] = ["s1", "s2", "s3", "s4", "s5", "s6"];
    const VERDICTS: [V; 4] = [V::Ok, V::Caution, V::Danger, V::Unknown];
    const LEVELS: [Level; 3] = [Level::Observe, Level::Tighten, Level::Enforce];
    const BASELINES: [BaselineDecision; 3] = [
        BaselineDecision::Allow,
        BaselineDecision::Review,
        BaselineDecision::Block,
    ];
    let mut random = XorShift(0x9e37_79b9_7f4a_7c15);
    for _ in 0..2000 {
        let mut ledger = NoiseLedger::new();
        let mut caution_reviews: BTreeMap<&str, u32> = BTreeMap::new();
        let mut per_subject: BTreeMap<(&str, &str, u64), u32> = BTreeMap::new();
        let mut notices: BTreeMap<&str, u32> = BTreeMap::new();
        for _ in 0..60 {
            let baseline = random.pick(&BASELINES);
            let signal = NoiseSignal {
                provider_id: random.pick(&PROVIDERS),
                subject_digest: random.pick(&SUBJECTS),
                signal_version: random.next() % 3,
                verdict: random.pick(&VERDICTS),
                fresh: random.next() % 5 != 0,
                verified: random.next() % 3 != 0,
                effect: random.pick(&LEVELS),
                guard_reviews_anyway: baseline != BaselineDecision::Allow,
            };
            let outcome = ledger.admit(&signal);
            let decided = apply(baseline, outcome.effect);
            assert!(decided >= baseline, "{signal:?} loosened {baseline:?}");
            if signal.verdict != V::Danger {
                assert!(
                    outcome.effect < ProviderEffect::Review || signal.verdict == V::Caution,
                    "{signal:?} raised {outcome:?}"
                );
                assert_ne!(outcome.effect, ProviderEffect::Block, "{signal:?}");
            }
            if signal.verdict == V::Caution && outcome.effect == ProviderEffect::Review {
                assert!(signal.verified && signal.fresh && baseline == BaselineDecision::Allow);
                *caution_reviews.entry(signal.provider_id).or_default() += 1;
                *per_subject
                    .entry((
                        signal.provider_id,
                        signal.subject_digest,
                        signal.signal_version,
                    ))
                    .or_default() += 1;
            }
            if outcome.quiet_cap_notice {
                *notices.entry(signal.provider_id).or_default() += 1;
            }
        }
        assert!(caution_reviews
            .values()
            .all(|count| *count <= PROVIDER_CAUTION_REVIEWS_PER_SESSION));
        assert!(per_subject.values().all(|count| *count <= 1));
        assert!(notices.values().all(|count| *count <= 1));
        for (provider, count) in caution_reviews {
            assert_eq!(ledger.caution_reviews(provider), count);
        }
    }
}

const OTHER: &str = "provider.otherwatch";

#[test]
fn a_stale_reviewed_answer_does_not_cover_another_providers_fresh_caution() {
    let mut ledger = NoiseLedger::new();
    let first = signal("s", V::Caution);
    assert_eq!(
        ledger.admit_subject(&[first]).effect,
        ProviderEffect::Review
    );
    let other = NoiseSignal {
        provider_id: OTHER,
        ..signal("s", V::Caution)
    };
    assert_eq!(
        ledger.admit_subject(&[first, other]).effect,
        ProviderEffect::Finding,
        "a fresh reviewed answer covers the subject"
    );
    let expired = NoiseSignal {
        fresh: false,
        ..first
    };
    assert_eq!(
        ledger.admit_subject(&[expired, other]).effect,
        ProviderEffect::Review
    );
}

#[test]
fn subject_admission_keeps_the_session_cap_notice() {
    let mut ledger = NoiseLedger::new();
    let subjects = ["c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7"];
    let cap = PROVIDER_CAUTION_REVIEWS_PER_SESSION as usize;
    assert!(subjects.len() > cap + 1);
    for subject in &subjects[..cap] {
        assert_eq!(
            ledger.admit_subject(&[signal(subject, V::Caution)]).effect,
            ProviderEffect::Review
        );
    }
    assert_eq!(
        ledger.admit_subject(&[signal(subjects[cap], V::Caution)]),
        NoiseOutcome {
            effect: ProviderEffect::Finding,
            quiet_cap_notice: true
        }
    );
    assert_eq!(
        ledger.admit_subject(&[signal(subjects[cap + 1], V::Caution)]),
        NoiseOutcome {
            effect: ProviderEffect::Finding,
            quiet_cap_notice: false
        }
    );
}

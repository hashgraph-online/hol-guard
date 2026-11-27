use guard_contracts::{
    ProviderEffectLevelV1 as Level, ProviderVerdictV1 as V, PROVIDER_OVERRIDE_WINDOW_MS,
};

use super::*;
use crate::noise::{apply, BaselineDecision, NoiseLedger, NoiseSignal};

const PROVIDER: &str = "provider.exampleshield";
const REASON: &str = "lookalike_domain";
const DAY: u64 = 24 * 60 * 60 * 1000;

fn three_allows(ledger: &mut OverrideLedger, start: u64) {
    for step in 0..3 {
        ledger.record_allow_through(PROVIDER, REASON, start + step * DAY);
    }
}

#[test]
fn three_allow_throughs_in_seven_days_offer_the_quiet_choice() {
    let mut ledger = OverrideLedger::new();
    ledger.record_allow_through(PROVIDER, REASON, 0);
    ledger.record_allow_through(PROVIDER, REASON, DAY);
    assert!(!ledger.offers_quiet(PROVIDER, REASON, DAY));
    ledger.record_allow_through(PROVIDER, REASON, 2 * DAY);
    assert!(ledger.offers_quiet(PROVIDER, REASON, 2 * DAY));
    assert!(!ledger.offers_quiet(PROVIDER, "other_reason", 2 * DAY));
    assert!(!ledger.offers_quiet("provider.otherwatch", REASON, 2 * DAY));
}

#[test]
fn allows_older_than_seven_days_do_not_count() {
    let mut ledger = OverrideLedger::new();
    three_allows(&mut ledger, 0);
    assert!(ledger.offers_quiet(PROVIDER, REASON, 2 * DAY));
    assert!(!ledger.offers_quiet(PROVIDER, REASON, PROVIDER_OVERRIDE_WINDOW_MS));
    assert_eq!(
        ledger.allow_throughs(PROVIDER, REASON, PROVIDER_OVERRIDE_WINDOW_MS + DAY),
        1
    );
    ledger.record_allow_through(PROVIDER, REASON, 20 * DAY);
    assert_eq!(ledger.allow_throughs(PROVIDER, REASON, 20 * DAY), 1);
}

#[test]
fn quieting_is_never_automatic() {
    let mut ledger = OverrideLedger::new();
    for step in 0..10 {
        ledger.record_allow_through(PROVIDER, REASON, step);
    }
    assert!(!ledger.is_quieted(PROVIDER, REASON));
    assert_eq!(
        ledger.effect_level(PROVIDER, &[REASON], Level::Tighten),
        Level::Tighten
    );

    let mut fresh = OverrideLedger::new();
    assert_eq!(
        fresh.accept(PROVIDER, REASON, 0),
        Err(OverrideRefusal::NotOffered)
    );
    assert_eq!(fresh.quieted().count(), 0);
}

#[test]
fn accepting_sets_observe_for_that_reason_only() {
    let mut ledger = OverrideLedger::new();
    three_allows(&mut ledger, 0);
    assert_eq!(ledger.accept(PROVIDER, REASON, 2 * DAY), Ok(()));
    assert_eq!(
        ledger.accept(PROVIDER, REASON, 2 * DAY),
        Err(OverrideRefusal::AlreadyQuieted)
    );
    assert!(!ledger.offers_quiet(PROVIDER, REASON, 2 * DAY));
    assert_eq!(
        ledger.effect_level(PROVIDER, &[REASON], Level::Enforce),
        Level::Observe
    );
    assert_eq!(
        ledger.effect_level(PROVIDER, &[REASON, "credential_form"], Level::Tighten),
        Level::Tighten
    );
    assert_eq!(
        ledger.effect_level("provider.otherwatch", &[REASON], Level::Tighten),
        Level::Tighten
    );
    assert_eq!(
        ledger.effect_level(PROVIDER, &[], Level::Tighten),
        Level::Tighten
    );
    assert_eq!(
        ledger.quieted().collect::<Vec<_>>(),
        [&(PROVIDER.to_owned(), REASON.to_owned())]
    );
}

#[test]
fn undo_restores_the_configured_level_and_resets_the_count() {
    let mut ledger = OverrideLedger::new();
    three_allows(&mut ledger, 0);
    ledger.accept(PROVIDER, REASON, 2 * DAY).unwrap();
    assert!(ledger.undo(PROVIDER, REASON));
    assert!(!ledger.undo(PROVIDER, REASON));
    assert_eq!(
        ledger.effect_level(PROVIDER, &[REASON], Level::Enforce),
        Level::Enforce
    );
    assert_eq!(ledger.quieted().count(), 0);
    assert!(!ledger.offers_quiet(PROVIDER, REASON, 2 * DAY));
}

#[test]
fn a_quieted_reason_never_goes_below_guards_own_decision() {
    let mut ledger = OverrideLedger::new();
    three_allows(&mut ledger, 0);
    ledger.accept(PROVIDER, REASON, 2 * DAY).unwrap();
    for verdict in [V::Caution, V::Danger] {
        for baseline in [
            BaselineDecision::Allow,
            BaselineDecision::Review,
            BaselineDecision::Block,
        ] {
            let mut noise = NoiseLedger::new();
            let outcome = noise.admit(&NoiseSignal {
                provider_id: PROVIDER,
                subject_digest: "subject",
                signal_version: 1,
                verdict,
                fresh: true,
                verified: true,
                effect: ledger.effect_level(PROVIDER, &[REASON], Level::Enforce),
                guard_reviews_anyway: baseline != BaselineDecision::Allow,
            });
            assert_eq!(
                apply(baseline, outcome.effect),
                baseline,
                "{verdict:?} {baseline:?}"
            );
        }
    }
}

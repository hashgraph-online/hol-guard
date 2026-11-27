//! Conformance checks 4 and 5: a quiet provider adds no prompt, and a noisy one stays inside the
//! session caps (PRD 6.12).

use guard_command::provider_integration_compile::CompiledProviderIntegrationV1;
use guard_contracts::{
    ProviderEffectLevelV1, ProviderVerdictV1, PROVIDER_CAUTION_REVIEWS_PER_SESSION,
    PROVIDER_CAUTION_REVIEWS_PER_SUBJECT_VERSION,
};

use super::{verdict_name, ConformanceCheck, CONFORMANCE_CHECKS};
use crate::noise::{apply, BaselineDecision, NoiseLedger, NoiseSignal, ProviderEffect};

/// The answers check 4 tries: `ok`, `unknown`, and a failure, which never produces a fresh signal.
const QUIET_ANSWERS: [(ProviderVerdictV1, bool); 3] = [
    (ProviderVerdictV1::Ok, true),
    (ProviderVerdictV1::Unknown, true),
    (ProviderVerdictV1::Unknown, false),
];

const LEVELS: [ProviderEffectLevelV1; 3] = [
    ProviderEffectLevelV1::Observe,
    ProviderEffectLevelV1::Tighten,
    ProviderEffectLevelV1::Enforce,
];

fn subject(index: usize) -> String {
    format!("conformance-subject-{index}")
}

pub(super) fn check_no_added_prompt(
    compiled: &CompiledProviderIntegrationV1,
    corpus: &[BaselineDecision],
) -> ConformanceCheck {
    let mut problems = Vec::new();
    if corpus.is_empty() {
        problems.push("the benign browser corpus is empty".to_owned());
    }
    for (verdict, fresh) in QUIET_ANSWERS {
        for level in LEVELS {
            let mut ledger = NoiseLedger::new();
            let changed = corpus
                .iter()
                .enumerate()
                .filter(|(index, baseline)| {
                    let subject = subject(*index);
                    let outcome = ledger.admit(&NoiseSignal {
                        provider_id: &compiled.id,
                        subject_digest: &subject,
                        signal_version: 1,
                        verdict,
                        fresh,
                        verified: compiled.verified,
                        effect: level,
                        guard_reviews_anyway: **baseline != BaselineDecision::Allow,
                    });
                    apply(**baseline, outcome.effect) != **baseline
                })
                .count();
            if changed > 0 {
                problems.push(format!(
                    "{changed} corpus row(s) changed with the provider answering {}{}",
                    verdict_name(verdict),
                    if fresh { "" } else { " after a failure" }
                ));
            }
        }
    }
    ConformanceCheck::new(CONFORMANCE_CHECKS[3], problems)
}

pub(super) fn check_bounded_prompt(
    compiled: &CompiledProviderIntegrationV1,
    rows: usize,
) -> ConformanceCheck {
    let mut problems = Vec::new();
    // Worst case: the publisher is verified and the subjects are asked about twice.
    let mut ledger = NoiseLedger::new();
    let mut per_subject = vec![0u32; rows];
    let mut reviews = 0u32;
    for _ in 0..2 {
        for (index, count) in per_subject.iter_mut().enumerate() {
            let subject = subject(index);
            let outcome = ledger.admit(&NoiseSignal {
                provider_id: &compiled.id,
                subject_digest: &subject,
                signal_version: 1,
                verdict: ProviderVerdictV1::Caution,
                fresh: true,
                verified: true,
                effect: ProviderEffectLevelV1::Tighten,
                guard_reviews_anyway: false,
            });
            if outcome.effect == ProviderEffect::Review {
                reviews += 1;
                *count += 1;
            }
        }
    }
    if reviews > PROVIDER_CAUTION_REVIEWS_PER_SESSION {
        problems.push(format!(
            "{reviews} provider-caused reviews in one session, over {PROVIDER_CAUTION_REVIEWS_PER_SESSION}"
        ));
    }
    if per_subject
        .iter()
        .any(|count| *count > PROVIDER_CAUTION_REVIEWS_PER_SUBJECT_VERSION)
    {
        problems.push("a subject was reviewed twice for the same answer".to_owned());
    }
    ConformanceCheck::new(CONFORMANCE_CHECKS[4], problems)
}

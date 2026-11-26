use guard_contracts::{ProviderEffectLevelV1, ProviderVerdictV1 as V};

use super::*;
use crate::noise::{NoiseLedger, NoiseSignal, ProviderEffect};

fn row(provider_id: &'static str, verdict: V) -> ProviderRow<'static> {
    ProviderRow {
        provider_id,
        verdict,
        fresh: true,
        verified: true,
    }
}

fn signal(row: &ProviderRow<'static>) -> NoiseSignal<'static> {
    NoiseSignal {
        provider_id: row.provider_id,
        subject_digest: "subject",
        signal_version: 1,
        verdict: row.verdict,
        fresh: row.fresh,
        verified: row.verified,
        effect: ProviderEffectLevelV1::Tighten,
        guard_reviews_anyway: false,
    }
}

fn ids(composition: &Composition<'_>) -> Vec<&'static str> {
    composition
        .shown
        .iter()
        .map(|row| match row.provider_id {
            "provider.alpha" => "alpha",
            "provider.bravo" => "bravo",
            "provider.charlie" => "charlie",
            "provider.delta" => "delta",
            other => panic!("unexpected {other}"),
        })
        .collect()
}

fn four() -> Vec<ProviderRow<'static>> {
    vec![
        row("provider.delta", V::Caution),
        row("provider.alpha", V::Ok),
        row("provider.charlie", V::Danger),
        row("provider.bravo", V::Caution),
    ]
}

#[test]
fn four_providers_sort_by_verdict_then_id_and_fold_into_n_more() {
    let composition = compose(&four());
    assert_eq!(ids(&composition), ["charlie", "bravo", "delta"]);
    assert_eq!(composition.more, 1);
    assert_eq!(
        composition.deciding,
        Some(row("provider.charlie", V::Danger))
    );
}

#[test]
fn the_order_never_depends_on_arrival_order() {
    let rows = four();
    let expected = compose(&rows);
    for rotation in 0..rows.len() {
        let mut rotated = rows.clone();
        rotated.rotate_left(rotation);
        assert_eq!(compose(&rotated), expected, "rotation {rotation}");
        rotated.reverse();
        assert_eq!(compose(&rotated), expected, "reversed rotation {rotation}");
    }
}

#[test]
fn an_ok_never_cancels_a_danger() {
    for rows in [
        vec![
            row("provider.alpha", V::Ok),
            row("provider.bravo", V::Danger),
        ],
        vec![
            row("provider.bravo", V::Danger),
            row("provider.alpha", V::Ok),
        ],
    ] {
        assert_eq!(
            compose(&rows).deciding.map(|row| row.verdict),
            Some(V::Danger)
        );
    }
}

#[test]
fn only_a_fresh_answer_decides_but_a_stale_one_is_listed() {
    let mut stale = row("provider.alpha", V::Danger);
    stale.fresh = false;
    let composition = compose(&[stale, row("provider.bravo", V::Caution)]);
    assert_eq!(
        composition.deciding,
        Some(row("provider.bravo", V::Caution))
    );
    assert_eq!(
        composition.shown,
        [row("provider.bravo", V::Caution), stale]
    );

    let unknown_only = compose(&[stale, row("provider.charlie", V::Unknown)]);
    assert_eq!(unknown_only.deciding, None);
    assert_eq!(unknown_only.shown.len(), 2);
    assert_eq!(compose(&[]).deciding, None);
}

#[test]
fn one_subject_raises_at_most_one_provider_review_whatever_the_count() {
    let mut ledger = NoiseLedger::new();
    let rows: Vec<ProviderRow<'static>> = [
        "provider.alpha",
        "provider.bravo",
        "provider.charlie",
        "provider.delta",
    ]
    .into_iter()
    .map(|id| row(id, V::Caution))
    .collect();
    let mut reviews = 0;
    for _ in 0..5 {
        let signals: Vec<_> = compose(&rows).ordered.iter().map(signal).collect();
        if ledger.admit_subject(&signals).effect == ProviderEffect::Review {
            reviews += 1;
        }
    }
    assert_eq!(reviews, 1);
}

#[test]
fn a_verified_caution_leads_an_unverified_one() {
    let mut unverified = row("provider.alpha", V::Caution);
    unverified.verified = false;
    let verified = row("provider.bravo", V::Caution);
    for rows in [[unverified, verified], [verified, unverified]] {
        let composition = compose(&rows);
        assert_eq!(composition.deciding, Some(verified));
        assert_eq!(composition.shown, [verified, unverified]);
        let signals: Vec<_> = composition.ordered.iter().map(signal).collect();
        assert_eq!(
            NoiseLedger::new().admit_subject(&signals).effect,
            ProviderEffect::Review
        );
    }
}

#[test]
fn a_provider_at_its_session_cap_does_not_hide_another_with_reviews_left() {
    let mut ledger = NoiseLedger::new();
    let capped = row("provider.alpha", V::Caution);
    for index in 0..guard_contracts::PROVIDER_CAUTION_REVIEWS_PER_SESSION {
        let subject = format!("other-{index}");
        let filler = NoiseSignal {
            subject_digest: &subject,
            ..signal(&capped)
        };
        assert_eq!(ledger.admit(&filler).effect, ProviderEffect::Review);
    }
    let rows = [capped, row("provider.bravo", V::Caution)];
    let signals: Vec<_> = compose(&rows).ordered.iter().map(signal).collect();
    assert_eq!(
        ledger.admit_subject(&signals).effect,
        ProviderEffect::Review
    );
    assert_eq!(ledger.caution_reviews("provider.bravo"), 1);
    assert_eq!(
        ledger.caution_reviews("provider.alpha"),
        guard_contracts::PROVIDER_CAUTION_REVIEWS_PER_SESSION
    );
    assert_eq!(ledger.admit_subject(&[]).effect, ProviderEffect::None);
}

#[test]
fn a_danger_is_reviewed_after_another_providers_caution_was() {
    let mut ledger = NoiseLedger::new();
    let caution = row("provider.alpha", V::Caution);
    assert_eq!(
        ledger.admit_subject(&[signal(&caution)]).effect,
        ProviderEffect::Review
    );
    let rows = [caution, row("provider.bravo", V::Danger)];
    let signals: Vec<_> = compose(&rows).ordered.iter().map(signal).collect();
    assert_eq!(
        ledger.admit_subject(&signals).effect,
        ProviderEffect::Review
    );
    assert_eq!(
        ledger.admit_subject(&signals).effect,
        ProviderEffect::Review
    );
}

#[test]
fn a_hidden_row_still_has_its_effect() {
    let ids = [
        "provider.alpha",
        "provider.bravo",
        "provider.charlie",
        "provider.delta",
        "provider.echo",
        "provider.foxtrot",
        "provider.golf",
        "provider.hotel",
    ];
    assert!(ids.len() > PROVIDER_CARD_MAX_ROWS);
    let rows: Vec<ProviderRow<'static>> = ids.iter().map(|id| row(id, V::Danger)).collect();
    let composition = compose(&rows);
    let hidden = *composition.ordered.last().unwrap();
    assert!(!composition.shown.contains(&hidden));
    let signals: Vec<_> = composition
        .ordered
        .iter()
        .map(|row| NoiseSignal {
            effect: if *row == hidden {
                ProviderEffectLevelV1::Enforce
            } else {
                ProviderEffectLevelV1::Observe
            },
            ..signal(row)
        })
        .collect();
    assert_eq!(
        NoiseLedger::new().admit_subject(&signals).effect,
        ProviderEffect::Block
    );
}

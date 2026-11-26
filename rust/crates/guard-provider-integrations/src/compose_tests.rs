use guard_contracts::{ProviderEffectLevelV1, ProviderVerdictV1 as V};

use super::*;
use crate::noise::{NoiseLedger, NoiseSignal, ProviderEffect};

fn row(provider_id: &'static str, verdict: V) -> ProviderRow<'static> {
    ProviderRow {
        provider_id,
        verdict,
        fresh: true,
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
        let deciding = compose(&rows).deciding.unwrap();
        let outcome = ledger.admit(&NoiseSignal {
            provider_id: deciding.provider_id,
            subject_digest: "subject",
            signal_version: 1,
            verdict: deciding.verdict,
            fresh: deciding.fresh,
            verified: true,
            effect: ProviderEffectLevelV1::Tighten,
            guard_reviews_anyway: false,
        });
        if outcome.effect == ProviderEffect::Review {
            reviews += 1;
        }
    }
    assert_eq!(reviews, 1);
}

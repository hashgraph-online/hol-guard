//! Several providers on one subject (PRD 6.12, "Several providers").
//!
//! For one subject the strongest fresh verdict wins and produces at most one review, whatever the
//! provider count. An `ok` from one provider never cancels a `danger` from another. The card lists
//! the rows sorted by verdict, strongest first, then by provider id, shows up to
//! [`PROVIDER_CARD_MAX_ROWS`] and folds the rest into "N more". The order depends only on the
//! verdict and the id, so a paid listing or the order answers arrived in never moves a row.

use guard_contracts::{ProviderVerdictV1, PROVIDER_CARD_MAX_ROWS};

/// One provider's latest answer about the subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderRow<'a> {
    pub provider_id: &'a str,
    pub verdict: ProviderVerdictV1,
    /// Only a fresh answer may decide. A stale or unavailable one is still listed.
    pub fresh: bool,
}

impl ProviderRow<'_> {
    /// The strength used for the decision and the order: a stale answer counts as `unknown`.
    fn strength(&self) -> u8 {
        if self.fresh {
            self.verdict.strength()
        } else {
            ProviderVerdictV1::Unknown.strength()
        }
    }
}

/// The card's provider section for one subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Composition<'a> {
    /// The strongest fresh row, the one that goes through the noise caps. `None` when no row is
    /// fresh with a verdict other than `unknown`.
    pub deciding: Option<ProviderRow<'a>>,
    /// Up to [`PROVIDER_CARD_MAX_ROWS`] rows, in card order.
    pub shown: Vec<ProviderRow<'a>>,
    /// How many rows the "N more" line stands for.
    pub more: usize,
}

/// Compose every provider's answer about one subject.
pub fn compose<'a>(rows: &[ProviderRow<'a>]) -> Composition<'a> {
    let mut ordered: Vec<ProviderRow<'a>> = rows.to_vec();
    ordered.sort_by(|left, right| {
        right
            .strength()
            .cmp(&left.strength())
            .then_with(|| left.provider_id.cmp(right.provider_id))
            .then_with(|| right.fresh.cmp(&left.fresh))
            .then_with(|| right.verdict.strength().cmp(&left.verdict.strength()))
    });
    let deciding = ordered
        .first()
        .copied()
        .filter(|row| row.strength() > ProviderVerdictV1::Unknown.strength());
    let more = ordered.len().saturating_sub(PROVIDER_CARD_MAX_ROWS);
    ordered.truncate(PROVIDER_CARD_MAX_ROWS);
    Composition {
        deciding,
        shown: ordered,
        more,
    }
}

#[cfg(test)]
#[path = "compose_tests.rs"]
mod tests;

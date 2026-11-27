//! Provider override accounting (PRD 6.12).
//!
//! When a person keeps allowing actions a provider asked about for the same reason, the provider is
//! adding prompts nobody acts on. After [`PROVIDER_OVERRIDE_OFFER_THRESHOLD`] allow-throughs of one
//! provider and reason code inside [`PROVIDER_OVERRIDE_WINDOW_MS`], the card offers "Stop asking for
//! this reason from <provider>". Accepting quiets that reason code: its effect level becomes
//! `observe`, so the provider still writes would-have-reviewed receipts but raises no review.
//!
//! - Quieting is never automatic. [`OverrideLedger::accept`] refuses a reason that is not on offer.
//! - Quieting never goes below Guard's own decision. It lowers only the provider's effect level, and
//!   [`crate::noise::apply`] still takes the stronger of Guard's decision and the provider's.
//! - Every quieted reason is listed ([`OverrideLedger::quieted`]) and [`OverrideLedger::undo`]
//!   restores the configured level.
//!
//! The ledger holds provider ids, reason codes and times only. It never holds a URL, a subject or
//! anything the provider said beyond its declared reason code.

use std::collections::{BTreeMap, BTreeSet};

use guard_contracts::{
    ProviderEffectLevelV1, PROVIDER_OVERRIDE_OFFER_THRESHOLD, PROVIDER_OVERRIDE_WINDOW_MS,
};

/// One provider and one of its declared reason codes.
pub type OverrideKey = (String, String);

/// Why [`OverrideLedger::accept`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverrideRefusal {
    /// The reason has not reached the threshold inside the window.
    NotOffered,
    /// The reason is already quieted.
    AlreadyQuieted,
}

/// Allow-through times and quieted reasons. Held by the resident.
#[derive(Debug, Default, Clone)]
pub struct OverrideLedger {
    allows: BTreeMap<OverrideKey, Vec<u64>>,
    quieted: BTreeSet<OverrideKey>,
}

fn key(provider_id: &str, reason_code: &str) -> OverrideKey {
    (provider_id.to_owned(), reason_code.to_owned())
}

impl OverrideLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that the person allowed an action a provider-caused review held for `reason_code`.
    /// Times older than the window are dropped, so each entry stays bounded by the allows of the
    /// last seven days.
    pub fn record_allow_through(&mut self, provider_id: &str, reason_code: &str, now_ms: u64) {
        let times = self
            .allows
            .entry(key(provider_id, reason_code))
            .or_default();
        times.retain(|time| in_window(*time, now_ms));
        times.push(now_ms);
    }

    /// Allow-throughs of this provider and reason inside the window ending at `now_ms`.
    pub fn allow_throughs(&self, provider_id: &str, reason_code: &str, now_ms: u64) -> u32 {
        self.allows
            .get(&key(provider_id, reason_code))
            .map_or(0, |times| {
                times
                    .iter()
                    .filter(|time| in_window(**time, now_ms))
                    .count() as u32
            })
    }

    /// Whether the card offers "Stop asking for this reason from <provider>".
    pub fn offers_quiet(&self, provider_id: &str, reason_code: &str, now_ms: u64) -> bool {
        !self.is_quieted(provider_id, reason_code)
            && self.allow_throughs(provider_id, reason_code, now_ms)
                >= PROVIDER_OVERRIDE_OFFER_THRESHOLD
    }

    /// The person accepted the offer. Refused unless the offer is showing.
    pub fn accept(
        &mut self,
        provider_id: &str,
        reason_code: &str,
        now_ms: u64,
    ) -> Result<(), OverrideRefusal> {
        if self.is_quieted(provider_id, reason_code) {
            return Err(OverrideRefusal::AlreadyQuieted);
        }
        if !self.offers_quiet(provider_id, reason_code, now_ms) {
            return Err(OverrideRefusal::NotOffered);
        }
        self.quieted.insert(key(provider_id, reason_code));
        Ok(())
    }

    /// Restore the configured level for this reason. Returns whether it was quieted. The
    /// allow-through count starts again, so the offer needs three fresh allows to return.
    pub fn undo(&mut self, provider_id: &str, reason_code: &str) -> bool {
        let key = key(provider_id, reason_code);
        self.allows.remove(&key);
        self.quieted.remove(&key)
    }

    pub fn is_quieted(&self, provider_id: &str, reason_code: &str) -> bool {
        self.quieted.contains(&key(provider_id, reason_code))
    }

    /// Every quieted reason, for the Integrations page list with undo.
    pub fn quieted(&self) -> impl Iterator<Item = &OverrideKey> {
        self.quieted.iter()
    }

    /// The effect level a signal with these reason codes runs under. Only a signal whose every
    /// reason is quieted runs at `observe`; one reason that is not quieted keeps the configured
    /// level, so quieting one reason never silences another. A signal with no reason code is never
    /// quieted.
    pub fn effect_level(
        &self,
        provider_id: &str,
        reason_codes: &[&str],
        configured: ProviderEffectLevelV1,
    ) -> ProviderEffectLevelV1 {
        let all_quieted = !reason_codes.is_empty()
            && reason_codes
                .iter()
                .all(|reason| self.is_quieted(provider_id, reason));
        if all_quieted {
            ProviderEffectLevelV1::Observe
        } else {
            configured
        }
    }
}

fn in_window(time_ms: u64, now_ms: u64) -> bool {
    time_ms <= now_ms && now_ms - time_ms < PROVIDER_OVERRIDE_WINDOW_MS
}

#[cfg(test)]
#[path = "overrides_tests.rs"]
mod tests;

//! The provider enrichment worker's pacing and failure handling (PRD 6.7, BP-T122).
//!
//! The worker is the only caller of the provider client, and the hook path never waits on it. This
//! module owns the part of the worker that decides whether a lookup may go out and what a finished
//! exchange does to the provider's standing:
//!
//! - A per-provider token bucket refills at the manifest's `max_requests_per_minute` and holds at
//!   most a tenth of a minute's requests, so a burst never runs ahead of the declared rate by more
//!   than that.
//! - A failed lookup is not retried for the same subject for [`NEGATIVE_CACHE_MS`].
//! - Five consecutive failures open the provider's circuit for [`CIRCUIT_OPEN_MS`]. When that time
//!   has passed, one probe lookup is let through and every other lookup still waits until it is
//!   recorded (or until [`PROBE_TIMEOUT_MS`] passes without a result). A failed probe opens the
//!   circuit again at once; an answer closes it and resets the count.
//! - A `401` or `403` moves the stored connection to `key_invalid`. Calls stop until the user
//!   connects again, which writes `connected` back; the connection state in the store is the
//!   record, so a restart does not forget it. Only the change to `key_invalid` is reported, so
//!   several `401`s in flight raise one notice.
//! - A cached answer is refreshed at a jittered point late in its lifetime ([`refresh_at`]), so
//!   answers cached together do not all refresh in the same instant.
//!
//! Nothing here performs I/O other than the connection-state write, and every time is passed in.

use std::collections::BTreeMap;

use guard_contracts::{ProviderCapabilityV1, ProviderConnectionStateV1};
use rusqlite::Connection;

use crate::provider_integration_store::{
    provider_connection, set_connection_state, ProviderStoreResult,
};

/// How long a failed lookup keeps the same subject from being asked again.
pub const NEGATIVE_CACHE_MS: u64 = 60 * 1000;
/// Consecutive failures that open a provider's circuit.
pub const CIRCUIT_FAILURES: u32 = 5;
/// How long an open circuit stops every lookup for the provider.
pub const CIRCUIT_OPEN_MS: u64 = 5 * 60 * 1000;
/// Subjects held in one provider's negative cache. A full cache drops its oldest entry first.
pub const NEGATIVE_CACHE_SUBJECTS: usize = 1024;
/// How long a half-open circuit waits for its probe's result before it lets another probe out.
pub const PROBE_TIMEOUT_MS: u64 = 60 * 1000;

const MINUTE_MS: u64 = 60 * 1000;

/// Whether a lookup may be sent now, and if not, why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Send it. A token has been taken.
    Send,
    /// The stored connection is not `connected` (for example `key_invalid`), so no call is made.
    NotConnected(ProviderConnectionStateV1),
    /// The provider's circuit is open until this time.
    CircuitOpen { until_ms: u64 },
    /// This subject failed recently; it may be asked again from this time.
    RecentlyFailed { until_ms: u64 },
    /// The provider's request budget is spent for now.
    RateLimited,
}

/// How one exchange ended, as the worker counts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeOutcome {
    /// The provider answered, whatever the verdict.
    Answered,
    /// `401` or `403`: the key is no longer accepted.
    Unauthorized,
    /// `429`: the provider asked Guard to slow down.
    RateLimited,
    /// Any other failure: transport, timeout, a refused destination, another status, or a body the
    /// manifest cannot map.
    Failed,
}

/// What [`ProviderWorker::record`] changed that the caller must surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Recorded {
    /// The connection moved to `key_invalid` just now. The caller raises the one dashboard notice.
    pub key_invalidated: bool,
    /// The provider's circuit opened just now.
    pub circuit_opened: bool,
}

/// Token bucket in thousandths of a request, so refill needs no floating point. `remainder` keeps
/// the part of a thousandth that has accrued but not yet been added, so frequent refills do not
/// lose it and the bucket refills at the declared rate for any `per_minute`.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    milli_tokens: u64,
    remainder: u64,
    at_ms: u64,
}

const MILLI: u64 = 1000;

fn bucket_capacity(per_minute: u64) -> u64 {
    (per_minute / 10).max(1) * MILLI
}

impl Bucket {
    fn full(per_minute: u64, now_ms: u64) -> Self {
        Self {
            milli_tokens: bucket_capacity(per_minute),
            remainder: 0,
            at_ms: now_ms,
        }
    }

    fn refill(&mut self, per_minute: u64, now_ms: u64) {
        let capacity = bucket_capacity(per_minute);
        let elapsed = now_ms.saturating_sub(self.at_ms);
        let accrued = elapsed
            .saturating_mul(per_minute)
            .saturating_mul(MILLI)
            .saturating_add(self.remainder);
        self.milli_tokens = self
            .milli_tokens
            .saturating_add(accrued / MINUTE_MS)
            .min(capacity);
        self.remainder = if self.milli_tokens == capacity {
            0
        } else {
            accrued % MINUTE_MS
        };
        self.at_ms = self.at_ms.max(now_ms);
    }

    fn empty(&mut self, now_ms: u64) {
        self.milli_tokens = 0;
        self.remainder = 0;
        self.at_ms = now_ms;
    }

    fn take(&mut self) -> bool {
        if self.milli_tokens < MILLI {
            return false;
        }
        self.milli_tokens -= MILLI;
        true
    }
}

#[derive(Debug)]
struct ProviderPace {
    bucket: Bucket,
    consecutive_failures: u32,
    open_until_ms: Option<u64>,
    /// The half-open circuit's probe: its lookup key and when it was admitted.
    probe: Option<((ProviderCapabilityV1, String), u64)>,
    failed: BTreeMap<(ProviderCapabilityV1, String), u64>,
}

impl ProviderPace {
    fn new(per_minute: u64, now_ms: u64) -> Self {
        Self {
            bucket: Bucket::full(per_minute, now_ms),
            consecutive_failures: 0,
            open_until_ms: None,
            probe: None,
            failed: BTreeMap::new(),
        }
    }

    fn remember_failure(&mut self, key: (ProviderCapabilityV1, String), now_ms: u64) {
        self.failed.retain(|_, until| *until > now_ms);
        if self.failed.len() >= NEGATIVE_CACHE_SUBJECTS && !self.failed.contains_key(&key) {
            if let Some(oldest) = self
                .failed
                .iter()
                .min_by_key(|(_, until)| **until)
                .map(|(key, _)| key.clone())
            {
                self.failed.remove(&oldest);
            }
        }
        self.failed
            .insert(key, now_ms.saturating_add(NEGATIVE_CACHE_MS));
    }
}

/// The worker's in-memory pacing state for every provider. Held by the resident; lost on restart,
/// which only means a fresh bucket and a closed circuit.
#[derive(Debug, Default)]
pub struct ProviderWorker {
    providers: BTreeMap<String, ProviderPace>,
}

impl ProviderWorker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decide whether a lookup for `subject_digest` may be sent now. `state` is the stored
    /// connection state and `per_minute` the manifest's `max_requests_per_minute`. Only
    /// [`Admission::Send`] takes a token.
    pub fn admit(
        &mut self,
        now_ms: u64,
        provider_id: &str,
        state: ProviderConnectionStateV1,
        per_minute: u64,
        capability: ProviderCapabilityV1,
        subject_digest: &str,
    ) -> Admission {
        if state != ProviderConnectionStateV1::Connected {
            return Admission::NotConnected(state);
        }
        let pace = self
            .providers
            .entry(provider_id.to_owned())
            .or_insert_with(|| ProviderPace::new(per_minute, now_ms));
        let key = (capability, subject_digest.to_owned());
        let half_open = match pace.open_until_ms {
            Some(until_ms) if now_ms < until_ms => return Admission::CircuitOpen { until_ms },
            Some(until_ms) => {
                // Half-open: one probe at a time. The failure count stays at the threshold, so a
                // failed probe opens the circuit again at once.
                if pace
                    .probe
                    .as_ref()
                    .is_some_and(|(_, at)| now_ms < at.saturating_add(PROBE_TIMEOUT_MS))
                {
                    return Admission::CircuitOpen { until_ms };
                }
                true
            }
            None => false,
        };
        if let Some(until_ms) = pace
            .failed
            .get(&key)
            .copied()
            .filter(|until| now_ms < *until)
        {
            return Admission::RecentlyFailed { until_ms };
        }
        pace.bucket.refill(per_minute, now_ms);
        if !pace.bucket.take() {
            return Admission::RateLimited;
        }
        if half_open {
            pace.probe = Some((key, now_ms));
        }
        Admission::Send
    }

    /// Count how a sent lookup ended. A `401` or `403` writes `key_invalid` to the stored
    /// connection.
    pub fn record(
        &mut self,
        connection: &Connection,
        now_ms: u64,
        provider_id: &str,
        capability: ProviderCapabilityV1,
        subject_digest: &str,
        outcome: ExchangeOutcome,
    ) -> ProviderStoreResult<Recorded> {
        let mut recorded = Recorded::default();
        let key = (capability, subject_digest.to_owned());
        if let Some(pace) = self.providers.get_mut(provider_id) {
            if pace.probe.as_ref().is_some_and(|(probe, _)| *probe == key) {
                pace.probe = None;
            }
        }
        if outcome == ExchangeOutcome::Unauthorized {
            let already_invalid = provider_connection(connection, provider_id)?
                .is_some_and(|stored| stored.state == ProviderConnectionStateV1::KeyInvalid);
            let written = set_connection_state(
                connection,
                provider_id,
                ProviderConnectionStateV1::KeyInvalid,
                now_ms,
            )?;
            recorded.key_invalidated = written && !already_invalid;
            return Ok(recorded);
        }
        let Some(pace) = self.providers.get_mut(provider_id) else {
            return Ok(recorded);
        };
        match outcome {
            ExchangeOutcome::Answered => {
                pace.consecutive_failures = 0;
                pace.open_until_ms = None;
                pace.probe = None;
                pace.failed.remove(&key);
            }
            ExchangeOutcome::RateLimited | ExchangeOutcome::Failed => {
                if outcome == ExchangeOutcome::RateLimited {
                    pace.bucket.empty(now_ms);
                }
                pace.remember_failure(key, now_ms);
                pace.consecutive_failures = pace.consecutive_failures.saturating_add(1);
                if pace.consecutive_failures >= CIRCUIT_FAILURES {
                    pace.open_until_ms = Some(now_ms.saturating_add(CIRCUIT_OPEN_MS));
                    recorded.circuit_opened = true;
                }
            }
            ExchangeOutcome::Unauthorized => unreachable!("handled above"),
        }
        Ok(recorded)
    }

    /// Forget a provider's pacing, for example after it is disconnected or connected again.
    pub fn forget(&mut self, provider_id: &str) {
        self.providers.remove(provider_id);
    }
}

/// When to refresh an answer observed at `observed_at_ms` that expires at `expires_at_ms`: a point
/// between three quarters and nine tenths of its lifetime, placed by `jitter` (any random `u32`).
/// Always before expiry, never before observation.
pub fn refresh_at(observed_at_ms: u64, expires_at_ms: u64, jitter: u32) -> u64 {
    let lifetime = u128::from(expires_at_ms.saturating_sub(observed_at_ms));
    let earliest = lifetime * 3 / 4;
    let width = lifetime * 9 / 10 - earliest;
    let offset = earliest + width * u128::from(jitter) / u128::from(u32::MAX);
    observed_at_ms.saturating_add(u64::try_from(offset).unwrap_or(u64::MAX))
}

#[cfg(test)]
#[path = "provider_integration_worker_tests.rs"]
mod tests;

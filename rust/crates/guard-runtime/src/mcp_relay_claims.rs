//! Saved-approval claims the resident decided, held until the relay asks to
//! spend them.
//!
//! The Python proxy drains the child stream and re-checks the catalog
//! authority before it claims a saved allow or a one-shot approval
//! (`_allow_and_forward`, `runtime_mcp.py`). The resident cannot see the
//! child stream, so a decision that would claim holds its context here under
//! a ticket and the relay, once its own drain found the catalog unchanged,
//! sends that ticket back to spend the claim. A ticket names this holder's
//! epoch, is taken once, and expires, so a relay can only claim for a call
//! this resident decided, and never twice.

use serde::Deserialize;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Decisions awaiting their claim; a decision without a free slot defers.
const MAX_HELD_CLAIMS: usize = 64;
/// The relay asks right after its drain; an older claim is never spent.
pub(crate) const CLAIM_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct McpRelayClaimRequestV1 {
    pub(crate) guard_home: String,
    pub(crate) ticket: String,
}

struct Held<T> {
    seq: u64,
    held_at: Instant,
    context: T,
}

struct State<T> {
    next_seq: u64,
    held: VecDeque<Held<T>>,
}

pub(crate) struct HeldClaims<T> {
    epoch: String,
    state: Mutex<State<T>>,
}

impl<T> Default for HeldClaims<T> {
    fn default() -> Self {
        static HOLDERS: AtomicU64 = AtomicU64::new(0);
        let started = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        Self {
            // Distinct from forward tickets, so neither holder takes the other's.
            epoch: format!(
                "claim-{:x}-{started:x}-{:x}",
                std::process::id(),
                HOLDERS.fetch_add(1, Ordering::Relaxed)
            ),
            state: Mutex::new(State {
                next_seq: 1,
                held: VecDeque::new(),
            }),
        }
    }
}

impl<T> HeldClaims<T> {
    /// Hold one decision's claim context; `None` when it cannot be held.
    pub(crate) fn hold(&self, context: T, now: Instant) -> Option<String> {
        let mut state = self.state.lock().ok()?;
        state
            .held
            .retain(|held| now.saturating_duration_since(held.held_at) < CLAIM_TTL);
        if state.held.len() >= MAX_HELD_CLAIMS {
            return None;
        }
        let seq = state.next_seq;
        state.next_seq = state.next_seq.saturating_add(1);
        state.held.push_back(Held {
            seq,
            held_at: now,
            context,
        });
        Some(format!("{}:{seq}", self.epoch))
    }

    /// Take a ticket's context once; a foreign, expired, malformed or already
    /// taken ticket yields nothing.
    pub(crate) fn take(&self, ticket: &str, now: Instant) -> Option<T> {
        let seq = ticket
            .strip_prefix(self.epoch.as_str())?
            .strip_prefix(':')?
            .parse::<u64>()
            .ok()?;
        let mut state = self.state.lock().ok()?;
        let index = state.held.iter().position(|held| held.seq == seq)?;
        let held = state.held.remove(index)?;
        (now.saturating_duration_since(held.held_at) < CLAIM_TTL).then_some(held.context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ticket_is_taken_once() {
        let claims = HeldClaims::<u8>::default();
        let now = Instant::now();
        let ticket = claims.hold(7, now).expect("held");
        assert_eq!(claims.take(&ticket, now), Some(7));
        assert_eq!(claims.take(&ticket, now), None);
    }

    #[test]
    fn an_expired_or_foreign_ticket_yields_nothing() {
        let claims = HeldClaims::<u8>::default();
        let other = HeldClaims::<u8>::default();
        let now = Instant::now();
        let ticket = claims.hold(1, now).expect("held");
        assert_eq!(other.take(&ticket, now), None);
        assert_eq!(claims.take("1", now), None);
        assert_eq!(claims.take(&ticket, now + CLAIM_TTL), None);
        assert_eq!(claims.take(&ticket, now), None, "an expired ticket is gone");
    }

    #[test]
    fn a_full_holder_refuses() {
        let claims = HeldClaims::<usize>::default();
        let now = Instant::now();
        for value in 0..MAX_HELD_CLAIMS {
            assert!(claims.hold(value, now).is_some());
        }
        assert!(claims.hold(0, now).is_none());
        assert!(
            claims.hold(0, now + CLAIM_TTL).is_some(),
            "expired slots free"
        );
    }
}

//! One-use claims on the approval grants that authorize a publication inverse.
//!
//! The authorization is claimed before any file comparison, so restoring old
//! bytes cannot replay a proof whose first attempted use observed a different
//! generation. The registry lives in the resident because a claim has to
//! outlive the one process step that made it. A claim grants no journal
//! retirement or native completion; it only records that one grant was spent
//! on one subject, owner operation and process.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_CLAIMS: usize = 128;
const CLAIMED: &str = "publication_inverse_authorization_claimed";
const CAPACITY: &str = "publication_inverse_authorization_capacity";
const INVALID: &str = "publication_inverse_authorization_invalid";

#[derive(Clone, PartialEq, Eq)]
struct Claim {
    subject: String,
    operation_id: String,
    owner_pid: u64,
    deadline: String,
    retirement: Instant,
}

#[derive(Default)]
pub(crate) struct Claims {
    claims: Mutex<BTreeMap<String, Claim>>,
}

/// A claim's identity as the caller presents it.
pub(crate) struct Presented<'a> {
    pub(crate) grant_id: &'a str,
    pub(crate) subject: &'a str,
    pub(crate) operation_id: &'a str,
    pub(crate) owner_pid: u64,
    /// The caller's deadline, opaque: stored on claim, compared exactly on redeem.
    pub(crate) deadline: &'a str,
}

fn seconds(value: f64) -> Duration {
    if value.is_finite() && value > 0.0 {
        Duration::try_from_secs_f64(value).unwrap_or(Duration::MAX)
    } else {
        Duration::ZERO
    }
}

impl Claims {
    /// Spend `grant_id` on this subject, owner operation and process until the
    /// grant's retirement, `retirement_seconds` from `now`.
    pub(crate) fn claim(
        &self,
        presented: &Presented<'_>,
        retirement_seconds: f64,
        now: Instant,
    ) -> Result<(), &'static str> {
        let mut claims = self.claims.lock().map_err(|_| INVALID)?;
        claims.retain(|_, claim| claim.retirement > now);
        if claims.contains_key(presented.grant_id) {
            return Err(CLAIMED);
        }
        if claims.len() >= MAX_CLAIMS {
            return Err(CAPACITY);
        }
        claims.insert(
            presented.grant_id.to_owned(),
            Claim {
                subject: presented.subject.to_owned(),
                operation_id: presented.operation_id.to_owned(),
                owner_pid: presented.owner_pid,
                deadline: presented.deadline.to_owned(),
                retirement: now.checked_add(seconds(retirement_seconds)).unwrap_or(now),
            },
        );
        Ok(())
    }

    /// Whether this exact claim is still held.
    pub(crate) fn check(
        &self,
        presented: &Presented<'_>,
        now: Instant,
    ) -> Result<(), &'static str> {
        let claims = self.claims.lock().map_err(|_| INVALID)?;
        let held = claims.get(presented.grant_id).is_some_and(|claim| {
            claim.retirement > now
                && claim.subject == presented.subject
                && claim.operation_id == presented.operation_id
                && claim.owner_pid == presented.owner_pid
                && claim.deadline == presented.deadline
        });
        if held {
            Ok(())
        } else {
            Err(INVALID)
        }
    }
}

/// The answer a `publication_inverse_claim` request gets: `ok`, or the
/// refusal code. `action` is `claim` or `check`.
pub(crate) fn answer(action: &str, presented: &Presented<'_>, retirement_seconds: f64) -> String {
    let now = Instant::now();
    let outcome = match action {
        "claim" => registry().claim(presented, retirement_seconds, now),
        "check" => registry().check(presented, now),
        _ => Err(INVALID),
    };
    outcome.map_or_else(|code| code.to_owned(), |()| "ok".to_owned())
}

/// The resident's registry; every request kind shares it.
pub(crate) fn registry() -> &'static Claims {
    static CLAIMS: std::sync::OnceLock<Claims> = std::sync::OnceLock::new();
    CLAIMS.get_or_init(Claims::default)
}

#[cfg(test)]
#[path = "publication_inverse_claims_tests.rs"]
mod tests;

//! Configuration directories' lifecycle locks, taken inside an owner that
//! already holds its Guard home: `codex_install_transaction` entered under an
//! owner this thread holds.
//!
//! A directory is locked unless the caller already holds it under a lease
//! (`HeldDirectory`). Once the locks are held the owner refuses a pending
//! runtime transition and recovers an interrupted hook publication, journaled
//! under it, before the work runs.

use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::Value;

use super::lease;
use super::lock_files::{configuration_identity, lifecycle_lock_path};
use super::owned::{pending, recover, Owner};
use super::owned_locks::{lock_directory, Failure, Limit, LIFECYCLE_DEADLINE};
use super::Budget;

const LOCK_INVALID: &str = "codex_lifecycle_lock_invalid: lifecycle lock changed during ownership";

/// A configuration directory the caller's process already holds, named by its
/// lock identity, with the lease that holds it.
pub(crate) struct HeldDirectory {
    identity: String,
    lease: String,
}

impl HeldDirectory {
    /// The directories a request names under `held_dirs`, each
    /// `{identity, lease}`.
    pub(crate) fn parse(value: Option<&Value>) -> Option<Vec<Self>> {
        let Some(items) = value else {
            return Some(Vec::new());
        };
        if items.is_null() {
            return Some(Vec::new());
        }
        items
            .as_array()?
            .iter()
            .map(|item| {
                Some(Self {
                    identity: item.get("identity")?.as_str()?.to_owned(),
                    lease: item.get("lease")?.as_str()?.to_owned(),
                })
            })
            .collect()
    }
}

/// Run `work` as `owner`, holding the lifecycle lock of each of `directories`:
/// the caller's own where `held` names it, else one taken here within `wait`.
pub(crate) fn within<T>(
    owner: &mut Owner,
    budget: &Budget,
    directories: &[&Path],
    held: &[HeldDirectory],
    wait: Duration,
    work: impl FnOnce(&mut Owner) -> Result<T, Failure>,
) -> Result<T, Failure> {
    let deadline = Instant::now() + wait;
    let mut locks = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for directory in directories {
        let identity = configuration_identity(directory);
        if seen.contains(&identity) {
            continue;
        }
        if owner.holds(&identity) {
            seen.push(identity);
            continue;
        }
        match held.iter().find(|held| held.identity == identity) {
            Some(known) => {
                // The lease must hold this directory's lock file, not another one's.
                let expected = lifecycle_lock_path(&identity).ok();
                if !expected.is_some_and(|path| lease::held_at(&known.lease, &path)) {
                    return Err(Failure::Runtime(LOCK_INVALID.to_owned()));
                }
                if Instant::now() >= deadline {
                    return Err(Failure::Timeout(LIFECYCLE_DEADLINE));
                }
            }
            None => {
                locks.push(lock_directory(
                    directory,
                    Limit::Until(deadline),
                    Some(deadline),
                )?);
                // A lock that woke just after the shared deadline is not used.
                if Instant::now() >= deadline {
                    return Err(Failure::Timeout(LIFECYCLE_DEADLINE));
                }
            }
        }
        seen.push(identity);
    }
    if pending(owner.guard_home()) {
        return Err(Failure::Transition("pending_transition"));
    }
    recover(owner, budget)?;
    work(owner)
}

//! `codex_install_transaction`: one owner of a Guard home's mutations.
//!
//! A mutation that must not interleave with another owner runs under
//! `with_owned`. The owner takes, in order, the lifecycle lock of each Codex
//! configuration directory it will write (sorted by canonical identity, each
//! waiting no longer than the deadline) and the Guard home's installation
//! lock; journals `begin`; refuses while `managed/runtime-transition.json`
//! exists or is a link; recovers an interrupted Codex publication; runs the
//! work; journals `committed` or `failed`; and releases the locks. The lock
//! files are never removed: unlinking a held lock would split ownership.
//!
//! `owned_ops` exposes the same transaction to a client whose work is still a
//! sequence of native calls: the resident holds the locks under leases for the
//! client process, so a client that dies releases them.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde_json::{json, Value};

use super::inspect::{resolve_lenient, sha256_hex};
use super::journal;
use super::lock_files::configuration_identity;
use super::owned_locks::{lock_directory, lock_install, Failure, Held, Limit};
use super::publication_commit;
use super::Budget;

/// The transaction the journal lines belong to.
pub(crate) struct Owner {
    pub(super) operation_id: String,
    target_id: String,
    actor: String,
    process_identity: String,
    pub(super) pid: u32,
    pub(super) thread: u64,
    guard_home: PathBuf,
    target: PathBuf,
    dropped: u64,
    /// Identities of the lifecycle directories this owner took exclusively.
    exclusive: Vec<String>,
}

impl Owner {
    /// Whether this owner already holds the lifecycle lock of `identity`.
    pub(super) fn holds(&self, identity: &str) -> bool {
        self.exclusive.iter().any(|held| held == identity)
    }

    /// Append mutation identities in order. A journal that cannot be written
    /// is counted, never allowed to replace the transaction's own error.
    pub(super) fn record(&mut self, mutations: &[Value]) {
        let identity = journal::Owner {
            operation_id: &self.operation_id,
            config_target_id: &self.target_id,
            actor: &self.actor,
            pid: u64::from(self.pid),
            process_identity: &self.process_identity,
        };
        match journal::append_all(&self.guard_home, &identity, mutations, self.dropped) {
            Ok(dropped) => self.dropped = dropped,
            Err(_) => self.dropped += u64::try_from(mutations.len()).unwrap_or(u64::MAX),
        }
    }

    /// Journal the `mutation` records an answer's `events` carry.
    pub(crate) fn record_events(&mut self, answer: &Value) {
        let mutations: Vec<Value> = answer
            .get("events")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|event| event.get("mutation").cloned())
            .collect();
        if !mutations.is_empty() {
            self.record(&mutations);
        }
    }

    /// `record_codex_mutation(operation, target, None, None)`.
    pub(super) fn mark(&mut self, operation: &str) {
        let marker = json!({
            "operation": operation,
            "path": self.target.to_string_lossy(),
            "before_present": false,
            "after_present": false,
            "before_digest": null,
            "after_digest": null,
        });
        self.record(&[marker]);
    }

    /// The transaction's id, which a publication it runs names as its owner.
    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub(crate) fn guard_home(&self) -> &Path {
        &self.guard_home
    }

    pub(super) fn dropped(&self) -> u64 {
        self.dropped
    }

    pub(super) fn target_id(&self) -> &str {
        &self.target_id
    }
}

/// What starts one owned mutation.
pub(crate) struct Spec<'a> {
    pub(crate) guard_home: &'a Path,
    /// The file or directory the mutation concerns; the journal names it.
    pub(crate) target: &'a Path,
    pub(crate) actor: &'a str,
    pub(crate) process_identity: &'a str,
    pub(crate) pid: u32,
    pub(crate) thread: u64,
    pub(crate) deadline: Instant,
    /// Lifecycle directories to lock; the caller leaves out those it holds.
    pub(crate) lock_dirs: Vec<PathBuf>,
    /// Lifecycle directories that exclude a competitor: taken first, they
    /// refuse as busy after the short grace instead of waiting.
    pub(crate) exclusive_dirs: Vec<PathBuf>,
    pub(crate) check_pending: bool,
    pub(crate) recover: bool,
}

/// The locks one owner holds, in the order it took them.
pub(super) type Locks = Vec<Held>;

fn random_hex() -> Result<String, Failure> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| Failure::Transition("native_transition_invalid"))?;
    Ok(hex::encode(bytes))
}

/// `assert_transition_mutation_allowed`.
pub(super) fn pending(home: &Path) -> bool {
    fs::symlink_metadata(home.join("managed").join("runtime-transition.json")).is_ok()
}

/// `recover_hook_publication`, journaled under this owner.
pub(crate) fn recover(owner: &mut Owner, budget: &Budget) -> Result<(), Failure> {
    let mut args = serde_json::Map::new();
    args.insert(
        "home".to_owned(),
        Value::String(owner.guard_home.to_string_lossy().into_owned()),
    );
    let answer = publication_commit::dispatch("publication_recover", &args, budget)
        .map_err(|_| Failure::Transition("native_transition_invalid"))?;
    owner.record_events(&answer);
    match answer.get("error") {
        Some(fault) => Err(Failure::Fault(fault.clone())),
        None => Ok(()),
    }
}

/// The checks an owner makes once it holds its locks.
fn admit(owner: &mut Owner, spec: &Spec<'_>, budget: &Budget) -> Result<(), Failure> {
    if spec.check_pending && pending(&owner.guard_home) {
        return Err(Failure::Transition("pending_transition"));
    }
    if spec.recover {
        recover(owner, budget)?;
    }
    Ok(())
}

/// Take the locks and journal `begin`. The owner is refused, with `failed`
/// journaled and every lock released, when a transition is pending or the
/// interrupted publication cannot be recovered.
pub(super) fn begin(spec: &Spec<'_>, budget: &Budget) -> Result<(Locks, Owner), Failure> {
    let home = resolve_lenient(spec.guard_home);
    let mut locks: Locks = Vec::new();
    let mut directories: Vec<(String, &Path)> = spec
        .lock_dirs
        .iter()
        .map(|directory| (configuration_identity(directory), directory.as_path()))
        .collect();
    directories.sort();
    directories.dedup_by(|a, b| a.0 == b.0);
    let mut exclusive: Vec<(String, &Path)> = spec
        .exclusive_dirs
        .iter()
        .map(|directory| (configuration_identity(directory), directory.as_path()))
        .collect();
    exclusive.sort();
    exclusive.dedup_by(|a, b| a.0 == b.0);
    let mut taken = Vec::new();
    for (identity, directory) in exclusive {
        locks.push(lock_directory(directory, Limit::Grace, None)?);
        taken.push(identity);
    }
    for (_, directory) in directories {
        let held = lock_directory(directory, Limit::Until(spec.deadline), Some(spec.deadline))?;
        locks.push(held);
    }
    locks.push(lock_install(&home, spec.deadline)?);
    let mut owner = Owner {
        operation_id: random_hex()?,
        target_id: sha256_hex(resolve_lenient(spec.target).to_string_lossy().as_bytes()),
        actor: spec.actor.to_owned(),
        process_identity: spec.process_identity.to_owned(),
        pid: spec.pid,
        thread: spec.thread,
        guard_home: home,
        target: spec.target.to_path_buf(),
        dropped: 0,
        exclusive: taken,
    };
    owner.mark("begin");
    if let Err(failure) = admit(&mut owner, spec, budget) {
        owner.mark("failed");
        return Err(failure);
    }
    Ok((locks, owner))
}

/// Run `work` as the sole owner of the Guard home's mutations.
pub(crate) fn with_owned<T>(
    spec: &Spec<'_>,
    budget: &Budget,
    work: impl FnOnce(&mut Owner) -> Result<T, Failure>,
) -> Result<T, Failure> {
    let (locks, mut owner) = begin(spec, budget)?;
    let result = work(&mut owner);
    owner.mark(if result.is_ok() {
        "committed"
    } else {
        "failed"
    });
    drop(locks);
    result
}

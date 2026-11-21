//! The `owned_*` ops: one installation transaction asked for over several
//! native calls.
//!
//! `owned_begin` takes the locks, journals `begin`, and answers an owner token
//! that the caller's later calls carry. The locks live under leases for the
//! caller's process, so a client that exits releases them and its owner is
//! forgotten. `owned_call` is the single-call form: it runs one publication op
//! as the owner and ends the transaction itself.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use super::lease;
use super::lock_files::configuration_identity;
use super::owned::{begin, recover, with_owned, Owner, Spec};
use super::owned_locks::{lock_directory, Failure, Limit};
use super::publication_commit;
use super::Budget;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const MAX_OWNERS: usize = 64;
const MAX_DIRS: usize = 16;
const MAX_WAIT: Duration = Duration::from_secs(600);
const INVALID: Failure = Failure::Transition("native_transition_invalid");

const LOCK_MESSAGE: &str = "codex_lifecycle_lock_invalid: lifecycle lock changed during ownership";

struct Entry {
    owner: Owner,
    leases: Vec<String>,
}

static OWNERS: Mutex<Option<HashMap<String, Entry>>> = Mutex::new(None);

/// Forget the owners whose locks were reaped with their client process. An
/// owner that lost any lock gives up the rest too: a lock it still holds would
/// otherwise stay held with nobody left to end it.
fn prune(owners: &mut HashMap<String, Entry>) {
    owners.retain(|_, entry| {
        if entry.leases.iter().all(|lease| lease::held(lease)) {
            return true;
        }
        entry.leases.iter().for_each(|lease| lease::release(lease));
        false
    });
}

fn text<'a>(args: &'a Map<String, Value>, key: &str) -> Result<&'a str, &'static str> {
    args.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)
}

fn number(args: &Map<String, Value>, key: &str) -> Result<u64, &'static str> {
    args.get(key).and_then(Value::as_u64).ok_or(ERR_INVALID)
}

fn pid(args: &Map<String, Value>) -> Result<u32, &'static str> {
    u32::try_from(number(args, "client_pid")?).map_err(|_| ERR_INVALID)
}

fn deadline(args: &Map<String, Value>) -> Result<Instant, &'static str> {
    let wait = Duration::from_millis(number(args, "deadline_ms")?).min(MAX_WAIT);
    Ok(Instant::now() + wait)
}

fn directories(args: &Map<String, Value>) -> Result<Vec<PathBuf>, &'static str> {
    let Some(list) = args.get("dirs") else {
        return Ok(Vec::new());
    };
    let list = list.as_array().ok_or(ERR_INVALID)?;
    if list.len() > MAX_DIRS {
        return Err(ERR_INVALID);
    }
    list.iter()
        .map(|item| item.as_str().map(PathBuf::from).ok_or(ERR_INVALID))
        .collect()
}

fn flag(args: &Map<String, Value>, key: &str) -> bool {
    args.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// The transaction a request names. `lock_dirs` borrows from `dirs`.
fn spec<'a>(args: &'a Map<String, Value>, dirs: &'a [PathBuf]) -> Result<Spec<'a>, &'static str> {
    Ok(Spec {
        guard_home: Path::new(text(args, "guard_home")?),
        target: Path::new(text(args, "target")?),
        actor: text(args, "actor")?,
        process_identity: text(args, "process_identity")?,
        pid: pid(args)?,
        thread: number(args, "thread")?,
        deadline: deadline(args)?,
        lock_dirs: dirs.to_vec(),
        exclusive_dirs: Vec::new(),
        check_pending: flag(args, "check_pending"),
        recover: flag(args, "recover"),
    })
}

fn adopt_all(locks: Vec<super::owned_locks::Held>, pid: u32) -> Result<Vec<String>, Failure> {
    let mut leases = Vec::new();
    for held in locks {
        match lease::adopt(held.file, held.path, pid) {
            Ok(token) => leases.push(token),
            Err(_) => {
                leases.iter().for_each(|token| lease::release(token));
                return Err(INVALID);
            }
        }
    }
    Ok(leases)
}

fn token() -> Result<String, &'static str> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| ERR_INVALID)?;
    Ok(hex::encode(bytes))
}

/// `owned_locks`: lifecycle locks for `dirs`, in canonical order. Without
/// `wait` a busy lock refuses after the grace that lets an exited owner go.
fn locks(args: &Map<String, Value>) -> KindResult {
    let pid = pid(args)?;
    let wait = flag(args, "wait");
    let limit_at = if wait || args.contains_key("deadline_ms") {
        Some(deadline(args)?)
    } else {
        None
    };
    let mut dirs: Vec<(String, PathBuf)> = directories(args)?
        .into_iter()
        .map(|directory| (configuration_identity(&directory), directory))
        .collect();
    dirs.sort();
    dirs.dedup_by(|a, b| a.0 == b.0);
    let mut held = Vec::new();
    for (_, directory) in &dirs {
        let limit = match (wait, limit_at) {
            (true, Some(until)) => Limit::Until(until),
            _ => Limit::Grace,
        };
        match lock_directory(directory, limit, limit_at) {
            Ok(lock) => held.push(lock),
            Err(failure) => return Ok(failure.to_json()),
        }
    }
    match adopt_all(held, pid) {
        Ok(leases) => Ok(json!({ "ok": true, "leases": leases })),
        Err(failure) => Ok(failure.to_json()),
    }
}

fn start(args: &Map<String, Value>, budget: &Budget) -> KindResult {
    let dirs = directories(args)?;
    let spec = spec(args, &dirs)?;
    let (held, owner) = match begin(&spec, budget) {
        Ok(started) => started,
        Err(failure) => return Ok(failure.to_json()),
    };
    let leases = match adopt_all(held, spec.pid) {
        Ok(leases) => leases,
        Err(failure) => return Ok(failure.to_json()),
    };
    let id = token()?;
    let answer = json!({
        "ok": true,
        "owner": id,
        "operation_id": owner.operation_id,
        "config_target_id": owner.target_id(),
        "leases": leases,
    });
    let mut guard = OWNERS.lock().unwrap_or_else(PoisonError::into_inner);
    let owners = guard.get_or_insert_with(HashMap::new);
    prune(owners);
    if owners.len() >= MAX_OWNERS {
        leases.iter().for_each(|lease| lease::release(lease));
        return Ok(INVALID.to_json());
    }
    owners.insert(id, Entry { owner, leases });
    Ok(answer)
}

/// Run `act` on the live owner a request names.
fn with_entry(args: &Map<String, Value>, act: impl FnOnce(&mut Entry) -> Value) -> KindResult {
    let id = text(args, "owner")?;
    let mut guard = OWNERS.lock().unwrap_or_else(PoisonError::into_inner);
    let owners = guard.get_or_insert_with(HashMap::new);
    prune(owners);
    match owners.get_mut(id) {
        Some(entry) => Ok(act(entry)),
        None => Ok(json!({ "ok": true, "recorded": false })),
    }
}

fn record(args: &Map<String, Value>) -> KindResult {
    let mutations = args
        .get("mutations")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .clone();
    let (pid, thread) = (pid(args)?, number(args, "thread")?);
    with_entry(args, |entry| {
        if entry.owner.pid != pid || entry.owner.thread != thread {
            return json!({ "ok": true, "recorded": false });
        }
        entry.owner.record(&mutations);
        json!({ "ok": true, "recorded": true, "dropped_events": entry.owner.dropped() })
    })
}

/// `owned_recover`: recover as the owner. An owner the resident no longer
/// knows lost its locks (its client exited or its lock files changed), so the
/// caller must not go on as though it still held them.
fn recovered(args: &Map<String, Value>, budget: &Budget) -> KindResult {
    let id = text(args, "owner")?;
    let mut guard = OWNERS.lock().unwrap_or_else(PoisonError::into_inner);
    let owners = guard.get_or_insert_with(HashMap::new);
    prune(owners);
    Ok(match owners.get_mut(id) {
        Some(entry) => match recover(&mut entry.owner, budget) {
            Ok(()) => json!({ "ok": true, "recorded": true }),
            Err(failure) => failure.to_json(),
        },
        None => Failure::Runtime(LOCK_MESSAGE.to_owned()).to_json(),
    })
}

fn end(args: &Map<String, Value>) -> KindResult {
    let committed = flag(args, "committed");
    let id = text(args, "owner")?;
    let mut guard = OWNERS.lock().unwrap_or_else(PoisonError::into_inner);
    let owners = guard.get_or_insert_with(HashMap::new);
    prune(owners);
    // `ended: false` tells the caller its owner was already gone, so it can
    // release the leases it still holds by token.
    let Some(mut entry) = owners.remove(id) else {
        return Ok(json!({ "ok": true, "ended": false }));
    };
    entry
        .owner
        .mark(if committed { "committed" } else { "failed" });
    entry.leases.iter().for_each(|lease| lease::release(lease));
    Ok(json!({ "ok": true, "ended": true }))
}

/// `owned_call`: one publication op as the owner, journaled and ended here.
fn call(args: &Map<String, Value>, budget: &Budget) -> KindResult {
    let dirs = directories(args)?;
    let spec = spec(args, &dirs)?;
    let inner = args
        .get("call")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    let name = text(inner, "op")?;
    let done = with_owned(&spec, budget, |owner| {
        let answer = publication_commit::dispatch(name, inner, budget).map_err(|_| INVALID)?;
        owner.record_events(&answer);
        match answer.get("error") {
            Some(fault) => Err(Failure::Fault(fault.clone())),
            None => Ok(answer.get("value").cloned().unwrap_or(Value::Null)),
        }
    });
    Ok(match done {
        Ok(value) => json!({ "ok": true, "value": value }),
        Err(failure) => failure.to_json(),
    })
}

/// Run `work` as the live owner `token` names, for the client process and
/// thread that began it. The entry leaves the registry while the work runs, so
/// a long mutation does not hold every other client's owned ops, and goes back
/// when it ends. An owner this resident no longer knows, or one begun by
/// another process or thread, lost the locks the caller thinks it holds.
pub(crate) fn with_registered<T>(
    token: &str,
    pid: u32,
    thread: u64,
    work: impl FnOnce(&mut Owner) -> Result<T, Failure>,
) -> Result<T, Failure> {
    let mut entry = {
        let mut guard = OWNERS.lock().unwrap_or_else(PoisonError::into_inner);
        let owners = guard.get_or_insert_with(HashMap::new);
        prune(owners);
        match owners.get(token) {
            Some(known) if known.owner.pid == pid && known.owner.thread == thread => {}
            _ => return Err(Failure::Runtime(LOCK_MESSAGE.to_owned())),
        }
        match owners.remove(token) {
            Some(entry) => entry,
            None => return Err(Failure::Runtime(LOCK_MESSAGE.to_owned())),
        }
    };
    let result = work(&mut entry.owner);
    let mut guard = OWNERS.lock().unwrap_or_else(PoisonError::into_inner);
    guard
        .get_or_insert_with(HashMap::new)
        .insert(token.to_owned(), entry);
    result
}

pub(super) fn dispatch(op: &str, args: &Map<String, Value>, budget: &Budget) -> KindResult {
    match op {
        "owned_locks" => locks(args),
        "owned_begin" => start(args, budget),
        "owned_record" => record(args),
        "owned_recover" => recovered(args, budget),
        "owned_end" => end(args),
        "owned_call" => call(args, budget),
        _ => Err(ERR_INVALID),
    }
}

//! What the process table says about a home's daemons once retirement has
//! done what it may.
//!
//! An unreadable process table is read again, a bounded number of times,
//! before it counts against a start. A process the inventory names as this
//! home's daemon but that Guard cannot prove is its own (its start marker,
//! its owner and its command line together) is never signalled. It is left
//! running, journaled as `leftover_left_alone`, and a start skips its port,
//! so it no longer makes every later start refuse until someone repairs the
//! home by hand.

use std::thread;

use crate::daemon_edge::lifecycle;

use super::host::{self, Caller};
use super::retire::Deadline;

/// Reads of the process table before an unreadable answer counts.
const INVENTORY_READS: usize = 3;
/// How much of a leftover's command line a refusal quotes.
const COMMAND_IN_MESSAGE_BYTES: usize = 160;
const LEFTOVER_EVENT: &str = "leftover_left_alone";

/// A process the inventory names as this home's daemon that Guard cannot
/// prove is its own, and why.
#[derive(Debug)]
pub(super) struct Leftover {
    pub(super) pid: i64,
    pub(super) port: i64,
    reason: &'static str,
}

#[cfg(test)]
pub(super) static FOREIGN_OWNER_FOR_TEST: std::sync::Mutex<Vec<i64>> =
    std::sync::Mutex::new(Vec::new());

/// Answers `read` once it answers, after at most `INVENTORY_READS` reads with
/// a short pause between them, and never pauses past `deadline`.
pub(super) fn settled<T>(deadline: Deadline, mut read: impl FnMut() -> Option<T>) -> Option<T> {
    for attempt in 1..=INVENTORY_READS {
        if let Some(answer) = read() {
            return Some(answer);
        }
        if attempt == INVENTORY_READS || deadline.passed() {
            break;
        }
        let pause = deadline
            .remaining()
            .map_or(host::POLL_INTERVAL, |left| left.min(host::POLL_INTERVAL));
        thread::sleep(pause);
    }
    None
}

/// This home's daemons as `(pid, port)`, or `None` when the process table
/// still cannot prove them after bounded reads.
pub(super) fn inventory(caller: &Caller, deadline: Deadline) -> Option<Vec<(i64, i64)>> {
    settled(deadline, || host::daemon_inventory(caller))
}

/// `_guard_daemon_pid_identity_for_retirement`: the generation and owner an
/// inventoried process must keep, when it runs as this user.
pub(super) fn identity_for_retirement(pid: i64) -> Option<(String, String)> {
    #[cfg(test)]
    if FOREIGN_OWNER_FOR_TEST
        .lock()
        .is_ok_and(|pids| pids.contains(&pid))
    {
        return None;
    }
    let marker = host::start_marker(pid)?;
    let owner = host::owner_marker(pid)?;
    let own = host::own_owner_marker()?;
    host::same_text(&owner, &own).then_some((marker, owner))
}

/// Why Guard cannot prove that the running process `pid` is this home's
/// daemon, or `None` when it can, and so may retire it.
fn unproven(caller: &Caller, pid: i64) -> Option<&'static str> {
    if host::start_marker(pid).is_none() {
        return Some("unreadable_start_marker");
    }
    if identity_for_retirement(pid).is_none() {
        return Some("foreign_owner");
    }
    match host::command_identity(caller, pid, Some(&caller.guard_home)) {
        Some(true) => None,
        Some(false) => Some("foreign_command"),
        None => Some("unreadable_command"),
    }
}

/// `unproven`, read again within `deadline` while the start marker or the
/// command line cannot be read, so a daemon of Guard's own whose identity
/// was unreadable for a moment is not taken for a leftover. A proven
/// mismatch is final at once.
fn settled_proof(caller: &Caller, pid: i64, deadline: Deadline) -> Option<&'static str> {
    let mut unreadable = None;
    let proof = settled(deadline, || match unproven(caller, pid) {
        Some(reason) if reason.starts_with("unreadable_") => {
            unreadable = Some(reason);
            None
        }
        proof => Some(proof),
    });
    proof.unwrap_or(unreadable)
}

/// The running inventory split into the leftovers Guard must leave alone,
/// and whether it also names a daemon Guard could prove and retire.
fn classify(caller: &Caller, deadline: Deadline) -> Option<(Vec<Leftover>, bool)> {
    let mut leftovers = Vec::new();
    let mut provable = false;
    for (pid, port) in inventory(caller, deadline)? {
        if host::pid_is_proven_dead(pid) {
            continue;
        }
        match settled_proof(caller, pid, deadline) {
            Some(reason) => leftovers.push(Leftover { pid, port, reason }),
            None => provable = true,
        }
    }
    Some((leftovers, provable))
}

/// `Some(leftovers)` when every daemon the inventory still names is one Guard
/// cannot prove is its own, so retirement has done all it may; `None` when
/// the table cannot be read, or names a daemon Guard can prove and has not
/// stopped yet.
pub(super) fn only_unproven(caller: &Caller, deadline: Deadline) -> Option<Vec<Leftover>> {
    let (leftovers, provable) = classify(caller, deadline)?;
    (!provable).then_some(leftovers)
}

/// The leftovers running now; none when the table cannot be read.
fn running(caller: &Caller, deadline: Deadline) -> Vec<Leftover> {
    classify(caller, deadline)
        .map(|(leftovers, _)| leftovers)
        .unwrap_or_default()
}

/// Journals each leftover a start leaves running, naming the starter.
fn record(caller: &Caller, leftovers: &[Leftover]) {
    for leftover in leftovers {
        let Ok(pid) = u32::try_from(leftover.pid) else {
            continue;
        };
        let details = lifecycle::Details {
            reason: Some(leftover.reason),
            port: u16::try_from(leftover.port).ok().filter(|port| *port > 0),
            by_pid: u32::try_from(caller.own_pid).ok().filter(|pid| *pid > 0),
            by_parent_pid: u32::try_from(caller.parent_pid).ok().filter(|pid| *pid > 0),
            ..lifecycle::Details::default()
        };
        lifecycle::record_details(&caller.guard_home, pid, LEFTOVER_EVENT, &details);
    }
}

/// The `candidates` a launch may use: a leftover's port is skipped, and each
/// leftover is journaled. The refusal names every leftover, with its pid and
/// command, when they hold every candidate.
pub(super) fn free_ports(
    caller: &Caller,
    candidates: Vec<i64>,
    deadline: Deadline,
) -> Result<Vec<i64>, String> {
    let held = running(caller, deadline);
    if held.is_empty() {
        return Ok(candidates);
    }
    record(caller, &held);
    let free: Vec<i64> = candidates
        .into_iter()
        .filter(|port| !held.iter().any(|leftover| leftover.port == *port))
        .collect();
    if free.is_empty() {
        return Err(every_port_held_message(&held));
    }
    Ok(free)
}

/// The refusal when leftovers hold every port a start could use.
fn every_port_held_message(leftovers: &[Leftover]) -> String {
    let named: Vec<String> = leftovers
        .iter()
        .map(|leftover| {
            format!(
                "pid {} on port {} ({})",
                leftover.pid,
                leftover.port,
                command_summary(leftover.pid)
            )
        })
        .collect();
    format!(
        "Every Guard daemon port is held by a process Guard cannot prove is its own, and it was left running: {}.",
        named.join("; ")
    )
}

fn command_summary(pid: i64) -> String {
    let Some(command) = host::command_for_pid(pid) else {
        return "command unreadable".to_owned();
    };
    if command.len() <= COMMAND_IN_MESSAGE_BYTES {
        return command;
    }
    let mut end = COMMAND_IN_MESSAGE_BYTES;
    while !command.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &command[..end])
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::time::{Duration, Instant};

    use super::{settled, Deadline, INVENTORY_READS};

    #[test]
    fn an_unreadable_table_is_read_again_before_it_counts() {
        let reads = Cell::new(0);
        let answer = settled(Deadline(None), || {
            reads.set(reads.get() + 1);
            (reads.get() == INVENTORY_READS).then_some(7)
        });
        assert_eq!(answer, Some(7));
        assert_eq!(reads.get(), INVENTORY_READS);
    }

    #[test]
    fn a_table_that_stays_unreadable_counts_after_bounded_reads() {
        let reads = Cell::new(0);
        let answer: Option<()> = settled(Deadline(None), || {
            reads.set(reads.get() + 1);
            None
        });
        assert_eq!(answer, None);
        assert_eq!(reads.get(), INVENTORY_READS);
    }

    #[test]
    fn a_passed_deadline_stops_the_reads() {
        let reads = Cell::new(0);
        let started = Instant::now();
        let answer: Option<()> = settled(Deadline(Some(started)), || {
            reads.set(reads.get() + 1);
            None
        });
        assert_eq!(answer, None);
        assert_eq!(reads.get(), 1);
        assert!(started.elapsed() < Duration::from_millis(50));
    }
}

//! The wall-clock budget every grep include walk in one evaluation shares,
//! and the answers those walks have already reached.
//!
//! `search_scope_walk` owns the walk; this module decides how long it may
//! run and remembers what it found, so a command read again under another
//! spelling is not walked twice.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// The wall clock every include walk in one evaluation may spend between
/// them.
///
/// The whole native evaluation runs inside half a second, and the entry count
/// an include walk is held to does not bound the time those entries take: a directory read costs
/// what the host's filesystem charges for it, which on a loaded machine is
/// not what it costs on an idle one. Spending the evaluation's remaining
/// budget there fails the evaluation, and a failed evaluation blocks, so this
/// walk stops on the clock as well.
///
/// One evaluation asks this question once per recursive root, and a command
/// is read again for every spelling a rewrite reaches, so a clock started
/// afresh for each walk would bound no single evaluation. The budget is the
/// submission's: every include walk inside it is charged the time it took,
/// and the next one gets only what is left. Only the walks are charged. The
/// readings that answer before them are bounded on their own, and charging
/// their time here would withhold the narrowing from any command read on a
/// loaded machine, however small the tree it names. The repeated spellings
/// pay nothing, because a root and glob set already walked is answered from
/// [`INCLUDE_SCOPE_ANSWERS`] rather than walked again, so the budget bounds
/// the distinct trees a submission names. Expiring only withholds the
/// narrowing and leaves the answer the readings above already reached.
const INCLUDE_SCOPE_BUDGET: Duration = Duration::from_millis(75);
/// How far into the evaluation an include walk may still run.
///
/// The budget above charges only the walks, so on its own it would let a walk
/// start after the earlier readings had already spent most of the
/// evaluation. Past this point a walk is not started and a running one stops,
/// which leaves half the evaluation for everything after the walks.
const INCLUDE_SCOPE_CEILING: Duration = Duration::from_millis(250);

thread_local! {
    /// When the include walks of the evaluation running on this thread must
    /// stop whatever they have spent, and the time they have spent so far.
    /// Unset outside an evaluation -- a test driving the walk directly --
    /// where each walk gets the budget to itself.
    static INCLUDE_SCOPE_SPENT: std::cell::Cell<Option<(Instant, Duration)>> =
        const { std::cell::Cell::new(None) };
    /// What the include walks of this evaluation have already answered.
    ///
    /// A rewrite hands the same command back under several spellings, and
    /// each of them resolves the same operand to the same directory and the
    /// same globs. Without this the evaluation pays for that tree once per
    /// spelling and runs the shared budget out on work it has already done.
    static INCLUDE_SCOPE_ANSWERS: std::cell::RefCell<HashMap<IncludeScopeKey, bool>> =
        std::cell::RefCell::new(HashMap::new());
    /// How many evaluations are open on this thread.
    ///
    /// One submission reaches the evaluation entry point many times over: the
    /// command itself, then the envelope it is read inside once per
    /// projection -- a git-config isolation, a virtualenv activation, an
    /// environment prefix, each inner command of a process substitution, a
    /// redirect rewrite. Those are not separate submissions and must not get
    /// budgets of their own, so only the outermost opens the budget.
    static INCLUDE_SCOPE_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// What an include walk is decided by: the directory it starts at, the globs
/// that select the files below it, and the home the sensitive-path readings
/// are relative to. Two walks that agree on all three inspect the same
/// entries and reach the same answer.
pub(super) type IncludeScopeKey = (PathBuf, String, Option<String>);

/// Open the shared include-walk budget for the submission beginning now.
///
/// The returned guard ends the submission where it is dropped. A nested
/// evaluation of the same submission takes a guard too, and that guard
/// neither refills the budget nor ends the submission: the outermost one
/// does both, which is what makes the budget the submission's own.
///
/// The answers of the previous submission are dropped with it, because a
/// tree is read again when the next one asks: what is in it may have changed
/// since.
#[must_use]
pub(crate) fn begin_include_scope_budget() -> IncludeScopeBudget {
    let depth = INCLUDE_SCOPE_DEPTH.with(|depth| {
        let entered = depth.get() + 1;
        depth.set(entered);
        entered
    });
    if depth == 1 {
        INCLUDE_SCOPE_SPENT.with(|spent| {
            spent.set(Some((
                Instant::now() + INCLUDE_SCOPE_CEILING,
                Duration::ZERO,
            )));
        });
        INCLUDE_SCOPE_ANSWERS.with(|answers| answers.borrow_mut().clear());
    }
    IncludeScopeBudget
}

/// The open submission, which ends where this is dropped.
pub(crate) struct IncludeScopeBudget;

impl Drop for IncludeScopeBudget {
    fn drop(&mut self) {
        let left = INCLUDE_SCOPE_DEPTH.with(|depth| {
            let left = depth.get().saturating_sub(1);
            depth.set(left);
            left
        });
        if left == 0 {
            INCLUDE_SCOPE_SPENT.with(|spent| spent.set(None));
            INCLUDE_SCOPE_ANSWERS.with(|answers| answers.borrow_mut().clear());
        }
    }
}

/// Put the thread back where it is outside an evaluation, for a test that
/// reads the unopened budget on a thread an earlier test may have used.
#[cfg(test)]
fn clear_include_scope_budget() {
    INCLUDE_SCOPE_DEPTH.with(|depth| depth.set(0));
    INCLUDE_SCOPE_SPENT.with(|spent| spent.set(None));
    INCLUDE_SCOPE_ANSWERS.with(|answers| answers.borrow_mut().clear());
}

/// When an include walk starting now has to stop: what is left of the
/// evaluation's shared budget, never past its ceiling, or a budget of its own
/// outside one.
fn include_scope_deadline() -> Instant {
    let deadline = Instant::now() + include_scope_remaining();
    INCLUDE_SCOPE_SPENT
        .with(std::cell::Cell::get)
        .map_or(deadline, |(ceiling, _)| deadline.min(ceiling))
}

/// What the include walks of the open evaluation have left to spend.
fn include_scope_remaining() -> Duration {
    INCLUDE_SCOPE_SPENT
        .with(std::cell::Cell::get)
        .map_or(INCLUDE_SCOPE_BUDGET, |(_, spent)| {
            INCLUDE_SCOPE_BUDGET.saturating_sub(spent)
        })
}

/// Charge an include walk's time to the open evaluation; outside one there
/// is nothing to charge.
fn charge_include_scope(elapsed: Duration) {
    INCLUDE_SCOPE_SPENT.with(|spent| {
        if let Some((ceiling, total)) = spent.get() {
            spent.set(Some((ceiling, total.saturating_add(elapsed))));
        }
    });
}

/// `walk`'s answer for `key`, walked at most once per evaluation and charged
/// to that evaluation's budget. `walk` is handed the instant it must stop by.
pub(super) fn charged_include_walk(
    key: IncludeScopeKey,
    walk: impl FnOnce(Instant) -> bool,
) -> bool {
    if let Some(answer) = INCLUDE_SCOPE_ANSWERS.with(|answers| answers.borrow().get(&key).copied())
    {
        return answer;
    }
    let started = Instant::now();
    let answer = walk(include_scope_deadline());
    charge_include_scope(started.elapsed());
    INCLUDE_SCOPE_ANSWERS.with(|answers| {
        answers.borrow_mut().insert(key, answer);
    });
    answer
}

#[cfg(test)]
#[path = "search_scope_budget_tests.rs"]
mod tests;

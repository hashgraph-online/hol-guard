//! The include walk's budget is the evaluation's, not each walk's.

use super::{
    begin_include_scope_budget, charge_include_scope, clear_include_scope_budget,
    include_scope_deadline, include_scope_remaining, INCLUDE_SCOPE_BUDGET, INCLUDE_SCOPE_CEILING,
};
use std::time::{Duration, Instant};

/// Every include walk inside one evaluation spends from the same budget.
///
/// A submission is read again for every spelling a rewrite reaches, so a
/// budget handed out afresh to each walk would let the walks together spend
/// several times the budget below and fail the evaluation they were meant to
/// leave room for. Charging every walk to one budget is what bounds their
/// total.
#[test]
fn walks_in_one_evaluation_share_one_budget() {
    clear_include_scope_budget();
    let _budget = begin_include_scope_budget();
    assert_eq!(include_scope_remaining(), INCLUDE_SCOPE_BUDGET);
    charge_include_scope(INCLUDE_SCOPE_BUDGET / 3);
    assert_eq!(
        include_scope_remaining(),
        INCLUDE_SCOPE_BUDGET - INCLUDE_SCOPE_BUDGET / 3,
        "a second include walk in the same evaluation was given a budget of its own"
    );
    charge_include_scope(INCLUDE_SCOPE_BUDGET);
    assert_eq!(include_scope_remaining(), Duration::ZERO);
    assert!(
        include_scope_deadline() <= Instant::now(),
        "a spent budget still let another include walk run"
    );
}

/// Time the evaluation spends before its first include walk is not charged.
///
/// The readings that answer before an include walk are bounded on their own.
/// A budget that ran from the start of the evaluation charged them too, so a
/// loaded machine withheld the narrowing from a grep over a tree of a few
/// files and the command came back for review.
#[test]
fn time_before_the_first_walk_is_not_charged() {
    clear_include_scope_budget();
    let _budget = begin_include_scope_budget();
    std::thread::sleep(INCLUDE_SCOPE_BUDGET + Duration::from_millis(10));
    assert_eq!(include_scope_remaining(), INCLUDE_SCOPE_BUDGET);
    assert!(
        include_scope_deadline() > Instant::now(),
        "the evaluation's earlier readings spent the include walk's budget"
    );
}

/// No include walk runs past the evaluation's ceiling, budget or not.
///
/// Charging only the walks would otherwise let a walk start after the
/// earlier readings had spent most of the evaluation and fail it.
#[test]
fn no_walk_runs_past_the_ceiling() {
    clear_include_scope_budget();
    let _budget = begin_include_scope_budget();
    std::thread::sleep(INCLUDE_SCOPE_CEILING + Duration::from_millis(10));
    assert_eq!(include_scope_remaining(), INCLUDE_SCOPE_BUDGET);
    assert!(
        include_scope_deadline() <= Instant::now(),
        "an include walk could start past the evaluation's ceiling"
    );
}

/// A walk driven outside an evaluation gets the budget to itself.
///
/// The proofs are exercised directly by tests and by callers that never
/// enter `evaluate_pre_tool`, where no budget has been opened. Those walks
/// are bounded by the same budget rather than stopping at once.
#[test]
fn a_walk_outside_an_evaluation_is_bounded_on_its_own() {
    clear_include_scope_budget();
    charge_include_scope(INCLUDE_SCOPE_BUDGET);
    let before = Instant::now();
    let deadline = include_scope_deadline();
    assert!(
        deadline > before,
        "a walk with no evaluation budget was handed an expired deadline"
    );
    assert!(
        deadline <= Instant::now() + INCLUDE_SCOPE_BUDGET,
        "a walk with no evaluation budget outlasts the budget"
    );
}

/// A projection spends from the budget its submission opened.
///
/// An envelope evaluates each projection of a submission -- a git-config
/// isolation, an environment prefix, an inner command of a process
/// substitution -- by calling the evaluation entry point again. Refilling
/// the budget there would hand every projection the whole budget, which is
/// the same unbounded total that a budget per walk used to give.
#[test]
fn a_projection_joins_the_budget_its_submission_opened() {
    clear_include_scope_budget();
    let submission = begin_include_scope_budget();
    let step = INCLUDE_SCOPE_BUDGET / 5;
    charge_include_scope(step);
    {
        let _projection = begin_include_scope_budget();
        assert_eq!(
            include_scope_remaining(),
            INCLUDE_SCOPE_BUDGET - step,
            "a projection was handed a budget of its own"
        );
        charge_include_scope(step);
    }
    assert_eq!(
        include_scope_remaining(),
        INCLUDE_SCOPE_BUDGET - step * 2,
        "a projection's return ended the submission that was still open"
    );
    drop(submission);
    let _next = begin_include_scope_budget();
    assert_eq!(
        include_scope_remaining(),
        INCLUDE_SCOPE_BUDGET,
        "the next submission inherited the budget the one before it spent"
    );
}

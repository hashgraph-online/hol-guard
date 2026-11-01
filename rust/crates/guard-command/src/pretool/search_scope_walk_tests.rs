//! The include walk's clock is the evaluation's, not each walk's.

use super::{
    begin_include_scope_budget, clear_include_scope_budget, include_scope_deadline,
    INCLUDE_SCOPE_BUDGET,
};
use std::time::Instant;

/// Every include walk inside one evaluation stops at the same moment.
///
/// A submission is read again for every spelling a rewrite reaches, so a
/// clock handed out afresh to each walk would let the walks together spend
/// several times the budget below and fail the evaluation they were meant to
/// leave room for. Starting the clock once is what bounds their total.
#[test]
fn walks_in_one_evaluation_share_a_deadline() {
    clear_include_scope_budget();
    begin_include_scope_budget();
    let first = include_scope_deadline();
    let second = include_scope_deadline();
    assert_eq!(
        first, second,
        "a second include walk in the same evaluation was given a clock of its own"
    );
    assert!(
        first <= Instant::now() + INCLUDE_SCOPE_BUDGET,
        "the shared clock outlasts the budget it was started with"
    );
}

/// A walk driven outside an evaluation gets the budget to itself.
///
/// The proofs are exercised directly by tests and by callers that never
/// enter `evaluate_pre_tool`, where no clock has been started. Those walks
/// are bounded by the same budget rather than stopping at once.
#[test]
fn a_walk_outside_an_evaluation_is_bounded_on_its_own() {
    clear_include_scope_budget();
    let before = Instant::now();
    let deadline = include_scope_deadline();
    assert!(
        deadline > before,
        "a walk with no evaluation clock was handed an expired deadline"
    );
    assert!(
        deadline <= Instant::now() + INCLUDE_SCOPE_BUDGET,
        "a walk with no evaluation clock outlasts the budget"
    );
}

//! The include walk's budget is the evaluation's, not each walk's.

use super::{
    advice_walk_deadline, begin_include_scope_budget, begin_submission_budget,
    charge_include_scope, clear_include_scope_budget, include_scope_deadline,
    include_scope_remaining, submission_walk_stop, ADVICE_GRACE, INCLUDE_SCOPE_BUDGET,
    INCLUDE_SCOPE_CEILING,
};
use crate::pretool::git_probe::HOOK_RESERVE;
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

/// The walk that words a decided review stops a little past the include
/// ceiling inside an evaluation, and has no clock outside one.
#[test]
fn the_advice_walk_stops_soon_after_the_include_ceiling() {
    clear_include_scope_budget();
    assert_eq!(advice_walk_deadline(), None);
    let opened = Instant::now();
    let budget = begin_include_scope_budget();
    let deadline = advice_walk_deadline().expect("an open evaluation sets the advice clock");
    assert!(deadline >= opened + INCLUDE_SCOPE_CEILING + ADVICE_GRACE);
    assert!(deadline <= Instant::now() + INCLUDE_SCOPE_CEILING + ADVICE_GRACE);
    drop(budget);
    assert_eq!(advice_walk_deadline(), None);
}

/// A walk held only to its entry count stops where the hook's deadline
/// leaves the reserve a Git probe keeps, and runs unclocked without one.
///
/// Only the outermost reading of a submission records the deadline, as it
/// opens the budget, and the record ends with the submission.
#[test]
fn the_hook_deadline_stops_a_counted_walk_before_its_reserve() {
    clear_include_scope_budget();
    assert_eq!(submission_walk_stop(), None);
    let deadline = Instant::now() + Duration::from_secs(1);
    let submission = begin_submission_budget(Some(deadline));
    assert_eq!(submission_walk_stop(), Some(deadline - HOOK_RESERVE));
    {
        let _projection = begin_submission_budget(Some(deadline + Duration::from_secs(9)));
        assert_eq!(
            submission_walk_stop(),
            Some(deadline - HOOK_RESERVE),
            "a projection moved the deadline its submission was given"
        );
    }
    drop(submission);
    assert_eq!(submission_walk_stop(), None);
    let _unclocked = begin_submission_budget(None);
    assert_eq!(submission_walk_stop(), None);
}

/// `rg -g '*.ts*' .` over a large checkout walks the tree to show that the
/// glob selects no sensitive file. That walk ran on past the hook's deadline,
/// so the hook failed without a review the user could approve. It now stops
/// where the deadline leaves the reserve, and the command keeps its review.
#[test]
fn an_rg_glob_walk_stops_where_the_hook_deadline_leaves_its_reserve() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!("guard-rg-glob-deadline-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let project = root.join("home/storefront");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(project.join("src/app.ts"), "export const a = 1;\n").unwrap();
    std::fs::write(project.join("src/view.tsx"), "export const b = 2;\n").unwrap();
    let home = std::fs::canonicalize(root.join("home")).unwrap();
    let project = std::fs::canonicalize(project).unwrap();
    let (home, cwd) = (home.to_str().unwrap(), project.to_str().unwrap());
    let proven = || {
        crate::pretool::search_scope::rg_glob_scope_proven(
            &["."],
            &["*.ts*"],
            Some(home),
            Some(cwd),
        )
    };
    clear_include_scope_budget();
    let spent = begin_submission_budget(Some(Instant::now() + HOOK_RESERVE / 2));
    let late = proven();
    drop(spent);
    let roomy = begin_submission_budget(Some(Instant::now() + Duration::from_secs(60)));
    let in_time = proven();
    drop(roomy);
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        !late,
        "the glob walk ran into the time the hook keeps for the extension check"
    );
    assert!(
        in_time,
        "a walk with time left did not prove a plain source tree"
    );
}

//! A saved allow claimed while sibling approvals move its authority revision.

use super::*;

/// Resolves against a store whose first claim refuses and whose later lookups
/// offer `later`, returning the evaluation and the rows it tried to claim.
fn resolve_after_a_sibling_approval(
    first: Value,
    later: Option<Value>,
) -> (PackageRequestEvaluation, Vec<Value>) {
    resolve_after_sibling_approvals(first, later, 1, false)
}

/// Resolves against a store whose first `refusals` claims refuse, and whose
/// later lookups offer `later`, one revision newer each time when `moves`.
fn resolve_after_sibling_approvals(
    first: Value,
    later: Option<Value>,
    refusals: u32,
    moves: bool,
) -> (PackageRequestEvaluation, Vec<Value>) {
    let store = SavedApprovalStore {
        home: PathBuf::from("/tmp/guard-home"),
        decision: Some(first),
        claim_succeeds: true,
        claimed: RefCell::new(Vec::new()),
        looked_up: RefCell::new(Vec::new()),
        lookup_error: None,
        events: RefCell::new(Vec::new()),
        lookup_calls: RefCell::new(0),
        fail_lookup_after: None,
        later_decision: later,
        refused_claims: RefCell::new(refusals),
        later_revision_moves: moves,
    };
    let seams = Seams;
    let resolved = apply_stored_package_policy_override(
        &evaluation(),
        &store,
        &artifact(),
        ARTIFACT_HASH,
        Path::new("/tmp/proj"),
        NOW,
        None,
        None,
        true,
        &seams,
        &seams,
        &seams,
        &seams,
    )
    .evaluation;
    let claimed = store
        .claimed
        .borrow()
        .iter()
        .map(|(row, _)| row.clone())
        .collect();
    (resolved, claimed)
}

fn saved_row(decision_id: i64, revision: i64) -> Value {
    json!({
        "decision_id": decision_id,
        "action": "allow",
        "artifact_hash": ARTIFACT_HASH,
        "_approval_authority_revision": revision,
    })
}

#[test]
fn a_claim_refused_for_a_moved_revision_reads_the_saved_allow_again() {
    // A sibling approval moved the authority revision between this request
    // reading its saved allow and claiming it.
    let (resolved, claims) =
        resolve_after_a_sibling_approval(saved_row(7, 4), Some(saved_row(7, 5)));
    assert_eq!(claims, vec![saved_row(7, 4), saved_row(7, 5)]);
    assert_eq!(resolved.policy_action().as_deref(), Some("allow"));
    assert_eq!(resolved.value["saved_approval_decision_id"], json!(7));
}

#[test]
fn a_full_bulk_approval_of_siblings_landing_before_the_claim_still_allows() {
    // Guard settles up to eight Cloud Review jobs at once. Each of the seven
    // siblings moves the revision twice before this request's claim: once
    // when its allow is stored and once when its own install claims it.
    let (resolved, claims) =
        resolve_after_sibling_approvals(saved_row(7, 1), Some(saved_row(7, 2)), 14, true);
    let revisions: Vec<i64> = (1..=15).collect();
    assert_eq!(
        claims,
        revisions
            .iter()
            .map(|revision| saved_row(7, *revision))
            .collect::<Vec<_>>()
    );
    assert_eq!(resolved.policy_action().as_deref(), Some("allow"));
}

#[test]
fn the_rereads_stop_at_the_budget_when_the_revision_keeps_moving() {
    let (resolved, claims) =
        resolve_after_sibling_approvals(saved_row(7, 1), Some(saved_row(7, 2)), 40, true);
    assert_eq!(claims.len(), 16);
    assert_eq!(resolved.policy_action().as_deref(), Some("review"));
}

#[test]
fn a_claim_refused_at_an_unmoved_revision_is_not_tried_again() {
    let (resolved, claims) = resolve_after_a_sibling_approval(saved_row(7, 4), None);
    assert_eq!(claims, vec![saved_row(7, 4)]);
    assert_eq!(resolved.policy_action().as_deref(), Some("review"));
}

#[test]
fn a_different_row_at_the_new_revision_is_not_claimed_in_its_place() {
    let (resolved, claims) =
        resolve_after_a_sibling_approval(saved_row(7, 4), Some(saved_row(8, 5)));
    assert_eq!(claims, vec![saved_row(7, 4)]);
    assert_eq!(resolved.policy_action().as_deref(), Some("review"));
}

#[test]
fn a_block_read_after_a_refused_claim_keeps_the_review() {
    let mut block = saved_row(7, 5);
    block["action"] = json!("block");
    let (resolved, claims) = resolve_after_a_sibling_approval(saved_row(7, 4), Some(block));
    assert_eq!(claims, vec![saved_row(7, 4)]);
    assert_eq!(resolved.policy_action().as_deref(), Some("review"));
}

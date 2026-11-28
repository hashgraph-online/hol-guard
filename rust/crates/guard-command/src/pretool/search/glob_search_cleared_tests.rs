use super::surely_matches;

#[test]
fn a_match_answers_before_the_listing_budget_runs_out() {
    // More entries than the listing budget, every one a match: the first
    // entry read already proves that `*.rs` names something, so a directory
    // too large to list in full still answers yes.
    let root = tempfile::Builder::new()
        .prefix("guard-sure-match")
        .tempdir()
        .expect("temp root");
    for index in 0..=super::MAX_SURE_MATCH_ENTRIES {
        std::fs::write(root.path().join(format!("module_{index}.rs")), "").expect("fixture file");
    }
    assert!(surely_matches(root.path(), "*.rs"));
    assert!(!surely_matches(root.path(), "*.py"));
}

use super::native_check_budget_ms;

#[test]
fn the_native_check_leaves_time_to_queue_a_timed_out_review() {
    // A short hook budget keeps three quarters for the check.
    assert_eq!(native_check_budget_ms(Some(1_240)), 930);
    assert_eq!(native_check_budget_ms(Some(750)), 563);
    // A long one keeps all but half a second.
    assert_eq!(native_check_budget_ms(Some(2_191)), 1_691);
    assert_eq!(native_check_budget_ms(Some(60_000)), 8_500);
    assert_eq!(native_check_budget_ms(None), 8_500);
}

#[test]
fn a_tiny_budget_still_gives_the_check_some_time() {
    assert_eq!(native_check_budget_ms(Some(1)), 1);
    assert_eq!(native_check_budget_ms(Some(4)), 3);
    assert_eq!(native_check_budget_ms(Some(0)), 0);
}

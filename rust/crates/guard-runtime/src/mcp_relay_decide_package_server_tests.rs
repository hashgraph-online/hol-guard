use super::super::package_leg::EVALUATION_ABSENT;
use super::*;

#[test]
fn a_package_defer_hands_the_server_off() {
    assert!(hands_server_off(EVALUATION_ABSENT));
    assert!(hands_server_off("mcp_relay_package_policy_failed"));
}

#[test]
fn a_defer_outside_the_package_lane_never_hands_the_server_off() {
    assert!(!hands_server_off("mcp_relay_policy_need"));
    assert!(!hands_server_off("mcp_relay_saved_policy_unverifiable"));
}

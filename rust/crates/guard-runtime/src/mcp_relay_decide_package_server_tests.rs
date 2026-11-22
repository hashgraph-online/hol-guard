use super::super::ask::PACKAGE_PROMPT;
use super::super::package_leg::EVALUATION_ABSENT;
use super::*;

#[test]
fn a_degraded_integrity_miss_is_refused_without_handing_the_server_off() {
    assert!(DAEMON_AUTHORITY.starts_with(PACKAGE_DEFER_PREFIX));
    assert!(!hands_server_off(DAEMON_AUTHORITY));
}

#[test]
fn every_other_package_defer_still_hands_the_server_off() {
    assert!(hands_server_off(EVALUATION_ABSENT));
    assert!(hands_server_off(PACKAGE_PROMPT));
    assert!(hands_server_off("mcp_relay_package_policy_failed"));
}

#[test]
fn a_defer_outside_the_package_lane_never_hands_the_server_off() {
    assert!(!hands_server_off("mcp_relay_policy_need"));
    assert!(!hands_server_off("mcp_relay_saved_policy_unverifiable"));
}

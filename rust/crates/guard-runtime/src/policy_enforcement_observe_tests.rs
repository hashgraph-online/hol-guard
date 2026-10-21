//! Observe mode keeps a warning visible without turning a floor into a block.

use super::*;

#[test]
fn observe_keeps_only_a_warn_floor_over_a_proven_allow_silent() {
    for (floor, intrinsic, expected) in [
        ("warn", "allow", "native_policy_warning"),
        ("review", "allow", "native_policy_observed_floor"),
        ("block", "warn", "native_policy_observed_floor"),
    ] {
        let mut observed_snapshot = snapshot(policy(floor));
        observed_snapshot.mode = "observe".into();
        let result = apply_pre_tool_policy(
            &observed_snapshot,
            &Value::Object(Map::new()),
            generic_result(intrinsic),
        )
        .unwrap();
        assert_eq!(result.decision, "allow", "{floor} over {intrinsic}");
        assert_eq!(result.reason_code, expected, "{floor} over {intrinsic}");
    }
}

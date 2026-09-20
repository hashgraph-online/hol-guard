//! Probe an exact benchmark request and its compiled policy without transport.
use super::*;

#[test]
#[ignore = "explicit local policy diagnostic; fixture path required"]
fn native_posttool_policy_component_diagnostic() {
    let path = std::env::var("HOL_GUARD_POLICY_DIAGNOSTIC_FIXTURE").unwrap();
    let bytes = std::fs::read(path).unwrap();
    assert!(bytes.len() <= 1024 * 1024);
    let fixture: Value = serde_json::from_slice(&bytes).unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert!(!cases.is_empty() && cases.len() <= 8);
    for case in cases {
        let request: NativeHookRequestV1 = serde_json::from_value(case["request"].clone()).unwrap();
        let policy: EffectiveNativePolicyV3 =
            serde_json::from_value(case["effective_policy"].clone()).unwrap();
        assert_eq!(request.event_name, "PostToolUse");
        let intrinsic = guard_hook_core::review_post_tool(&request);
        let intrinsic_json = serde_json::to_value(&intrinsic).unwrap();
        let result = apply_post_tool_policy(
            &snapshot(policy),
            &request,
            GuardHookPayloadKindV2::Inline,
            intrinsic,
        )
        .unwrap();
        println!(
            "{}",
            json!({
                "schema":"guard.native-posttool-policy-diagnostic.v1",
                "name":case["name"], "intrinsic":intrinsic_json, "after_policy":result,
                "scope":"actual scanner plus compiled policy join; no store, socket or installed qualification",
            })
        );
    }
}

use super::*;
use serde_json::Value;

fn request(home: &str, action: &str) -> HookPolicyFenceWindowRequestV1 {
    HookPolicyFenceWindowRequestV1 {
        schema: REQUEST_SCHEMA.to_owned(),
        request_id: format!("fence-{action}"),
        guard_home: home.to_owned(),
        action: action.to_owned(),
        admitted: None,
        waited_ms: None,
    }
}

#[test]
fn a_window_closes_once_the_last_waiter_leaves() {
    let home = "/synthetic/fence-window";
    let enter = request(home, "enter");
    let _: Value = serde_json::from_slice(&evaluate(&enter).expect("enter")).expect("response");
    let mut second = request(home, "enter");
    second.request_id = "fence-second".to_owned();
    let _: Value = serde_json::from_slice(&evaluate(&second).expect("enter")).expect("response");
    let mut leave = request(home, "leave");
    leave.request_id = "fence-leave-one".to_owned();
    leave.admitted = Some(true);
    let first: Value = serde_json::from_slice(&evaluate(&leave).expect("leave")).expect("response");
    assert!(first["result"]["window_event"].is_null());
    leave.request_id = "fence-leave-two".to_owned();
    leave.admitted = Some(false);
    let last: Value = serde_json::from_slice(&evaluate(&leave).expect("leave")).expect("response");
    assert_eq!(last["result"]["window_event"]["event_name"], EVENT_NAME);
    assert_eq!(
        last["result"]["window_event"]["payload"]["absorbed_calls"],
        1
    );
    assert_eq!(
        last["result"]["window_event"]["payload"]["exhausted_calls"],
        1
    );
}

#[test]
fn a_direct_wait_without_daemon_window_is_one_event() {
    let mut request = request("/synthetic/direct-fence", "absorb_direct");
    request.waited_ms = Some(450);
    let output: Value =
        serde_json::from_slice(&evaluate(&request).expect("absorb")).expect("response");
    assert_eq!(
        output["result"]["window_event"]["payload"]["absorbed_calls"],
        1
    );
    assert_eq!(
        output["result"]["window_event"]["payload"]["exhausted_calls"],
        0
    );
}

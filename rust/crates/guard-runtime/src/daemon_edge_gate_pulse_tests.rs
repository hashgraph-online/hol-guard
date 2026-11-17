use super::*;

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => unreachable!(),
    }
}

#[test]
fn the_caller_asks_for_the_yid_app_at_the_top_level_or_in_the_gate() {
    assert!(wants_pulse(&object(json!({"approval_gate_pulse": true}))));
    assert!(wants_pulse(&object(
        json!({"approval_gate": {"pulse": true}})
    )));
    assert!(!wants_pulse(&object(json!({"approval_gate_pulse": "yes"}))));
    assert!(!wants_pulse(&object(json!({"approval_password": "pw"}))));
}

#[test]
fn only_a_pulse_required_refusal_starts_a_yid_request() {
    let refusal = |error: &str| Gate::Refused(403, object(json!({"error": error, "message": "m"})));
    assert!(needs_pulse(&refusal("approval_gate_pulse_required")));
    assert!(!needs_pulse(&refusal("approval_gate_required")));
    assert!(!needs_pulse(&Gate::Passed(None)));
}

#[test]
fn a_pending_request_answers_202_with_what_the_dashboard_polls() {
    let request = object(json!({
        "status": "pending",
        "request_id": "pr_1",
        "match_code": "42",
        "decide_by": "2026-11-13T12:00:00Z",
    }));
    assert_eq!(
        pending(&request),
        Gate::Refused(
            202,
            object(json!({
                "pulse_request_id": "pr_1",
                "pulse_match_code": "42",
                "pulse_decide_by": "2026-11-13T12:00:00Z",
                "error": "approval_gate_pulse_pending",
                "message": PENDING_MESSAGE,
            }))
        )
    );
}

#[test]
fn a_pulse_request_id_replaces_the_password_and_code() {
    let input = wire_input(&object(json!({
        "approval_password": "pw",
        "approval_totp_code": "123456",
        "approval_pulse_request_id": "pr_1",
    })))
    .unwrap();
    assert_eq!(input.pulse_request_id.as_deref(), Some("pr_1"));
    assert_eq!(input.password, None);
    assert_eq!(input.totp_code, None);
    let input = wire_input(&object(json!({"approval_password": "pw"}))).unwrap();
    assert_eq!(input.password.as_deref(), Some("pw"));
    assert_eq!(input.pulse_request_id, None);
}

#[test]
fn the_public_config_reports_pulse_and_hides_the_command_unless_told() {
    let base = json!({
        "enabled": true, "configured": true, "cooldown_seconds": 0,
        "cooldown_active": false, "fail_closed": true, "strict_all_decisions": false,
        "totp_enabled": false, "totp_pending": false,
    });
    let config = super::super::public_config(&object(base.clone())).unwrap();
    assert_eq!(config["pulse_enabled"], json!(false));
    assert_eq!(config["pulse_cooldown_seconds"], json!(0));
    assert_eq!(config["pulse_show_command"], json!(false));
    let mut on = object(base);
    on.insert("pulse_enabled".to_owned(), json!(true));
    on.insert("pulse_cooldown_seconds".to_owned(), json!(300));
    on.insert("pulse_show_command".to_owned(), json!(true));
    let config = super::super::public_config(&on).unwrap();
    assert_eq!(config["pulse_enabled"], json!(true));
    assert_eq!(config["pulse_cooldown_seconds"], json!(300));
    assert_eq!(config["pulse_show_command"], json!(true));
}

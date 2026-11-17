use super::*;

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => unreachable!(),
    }
}

#[test]
fn a_save_names_exactly_its_settings() {
    let save = |settings: Value| {
        save_change(&object(
            json!({"settings": settings, "approval_pulse_request_id": "r"}),
        ))
    };
    let none = save(json!({"receipt_redaction_level": "none"}));
    assert_eq!(
        none,
        json!({"kind": "save", "settings": {"receipt_redaction_level": "none"}})
    );
    assert_eq!(
        none,
        save(json!({"receipt_redaction_level": "none"})),
        "a resubmit names the same change"
    );
    assert_ne!(
        none,
        save(json!({"receipt_redaction_level": "strict"})),
        "another change is named differently"
    );
    // How the save is approved is not part of the change.
    assert_eq!(
        save_change(&object(
            json!({"settings": {"a": 1}, "approval_password": "pw"})
        )),
        save_change(&object(
            json!({"settings": {"a": 1}, "approval_gate_pulse": true})
        )),
    );
}

#[test]
fn the_proof_comes_from_the_gate_unless_one_is_offered_at_the_top_level() {
    let gate = json!({"password": "pw", "pulse_show_command": true});
    let payload = object(json!({"settings": {"approval_gate": gate.clone()}}));
    assert_eq!(
        save_gate_input(&payload, Some(&gate)),
        object(json!({"approval_gate": gate}))
    );
    let payload = object(json!({"settings": {}, "approval_password": "top"}));
    assert_eq!(save_gate_input(&payload, None), payload);
    assert_eq!(
        save_gate_input(&object(json!({"settings": {}})), None),
        Map::new()
    );
}

#[test]
fn the_dashboard_pulse_fields_are_carried_from_the_top_level() {
    let gate = json!({"pulse_show_command": true});
    let payload = object(json!({
        "settings": {"approval_gate": gate.clone()},
        "approval_gate_pulse": true,
        "approval_pulse_request_id": "azr_1",
        "unrelated": 1,
    }));
    assert_eq!(
        save_gate_input(&payload, Some(&gate)),
        object(json!({
            "approval_gate": gate,
            "approval_gate_pulse": true,
            "approval_pulse_request_id": "azr_1",
        }))
    );
}

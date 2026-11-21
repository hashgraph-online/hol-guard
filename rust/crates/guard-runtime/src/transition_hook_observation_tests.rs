use super::*;

const OPERATION: &str = "1b4e28ba-2fa1-41d2-883f-0016d3cca427";
const REQUEST: &str = "transition-hook-0123456789abcdef0123456789abcdef";

fn payload(probe: Value) -> Value {
    json!({"hook_event_name": "PreToolUse", PROBE_FIELD: probe})
}

fn probe_fields() -> Value {
    json!({"schema": PROBE_SCHEMA, "operation_id": OPERATION, "request_id": REQUEST})
}

#[test]
fn only_a_complete_canonical_probe_is_read() {
    assert_eq!(probe(&payload(probe_fields())), Some((OPERATION, REQUEST)));
    assert_eq!(probe(&json!({"hook_event_name": "PreToolUse"})), None);
    assert_eq!(probe(&payload(Value::from("probe"))), None);

    let mut extra = probe_fields();
    extra["note"] = Value::from("x");
    let mut missing = probe_fields();
    missing.as_object_mut().unwrap().remove("schema");
    for bad in [extra, missing] {
        assert_eq!(probe(&payload(bad)), None);
    }
    for (field, value) in [
        ("schema", Value::from("hol-guard.transition-hook-probe.v2")),
        ("operation_id", Value::from(OPERATION.to_uppercase())),
        ("operation_id", Value::from(OPERATION.replace('-', ""))),
        ("operation_id", Value::from(format!("{{{OPERATION}}}"))),
        ("operation_id", Value::from(7)),
        ("request_id", Value::from("transition-hook-0123")),
        (
            "request_id",
            Value::from("transition-hook-0123456789ABCDEF0123456789abcdef"),
        ),
        ("request_id", Value::from(format!("{REQUEST}\n"))),
        ("request_id", Value::Null),
    ] {
        let mut fields = probe_fields();
        fields[field] = value.clone();
        assert_eq!(probe(&payload(fields)), None, "{field}={value}");
    }
}

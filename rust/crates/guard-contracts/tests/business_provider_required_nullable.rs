use guard_contracts::BusinessProviderV1;
use serde_json::{json, Value};

fn provider(state: &str) -> Value {
    json!({
        "service": "google_gmail",
        "account_binding": "a".repeat(64),
        "tenant_binding": "b".repeat(64),
        "identity_state": state,
        "tool_identity_digest": "c".repeat(64),
        "tool_schema_digest": "d".repeat(64)
    })
}

#[test]
fn missing_binding_is_rejected_for_every_identity_state() {
    for state in ["known", "unknown", "unsupported"] {
        for field in ["account_binding", "tenant_binding"] {
            let mut value = provider(state);
            value.as_object_mut().unwrap().remove(field);
            let error = serde_json::from_value::<BusinessProviderV1>(value).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("missing field `{field}`")),
                "{state}.{field}: {error}"
            );
        }
    }
}

#[test]
fn explicit_null_and_present_bindings_round_trip_without_losing_keys() {
    for state in ["unknown", "unsupported"] {
        for account_null in [false, true] {
            for tenant_null in [false, true] {
                let mut value = provider(state);
                if account_null {
                    value["account_binding"] = Value::Null;
                }
                if tenant_null {
                    value["tenant_binding"] = Value::Null;
                }
                let decoded: BusinessProviderV1 = serde_json::from_value(value.clone()).unwrap();
                assert_eq!(decoded.account_binding.is_none(), account_null);
                assert_eq!(decoded.tenant_binding.is_none(), tenant_null);
                assert_eq!(serde_json::to_value(decoded).unwrap(), value);
            }
        }
    }
}

#[test]
fn removing_a_null_binding_does_not_decode_as_explicit_unknown_identity() {
    for field in ["account_binding", "tenant_binding"] {
        let mut value = provider("unknown");
        value["account_binding"] = Value::Null;
        value["tenant_binding"] = Value::Null;
        assert!(serde_json::from_value::<BusinessProviderV1>(value.clone()).is_ok());
        value.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<BusinessProviderV1>(value).is_err());
    }
}

#[test]
fn non_string_non_null_bindings_are_rejected() {
    for field in ["account_binding", "tenant_binding"] {
        for invalid in [json!(false), json!(0), json!([]), json!({})] {
            let mut value = provider("unknown");
            value[field] = invalid;
            assert!(serde_json::from_value::<BusinessProviderV1>(value).is_err());
        }
    }
}

#[test]
fn duplicate_binding_keys_are_rejected_even_when_one_value_is_null() {
    for field in ["account_binding", "tenant_binding"] {
        for initial in [Value::Null, json!("a".repeat(64))] {
            let mut value = provider("unknown");
            value[field] = initial;
            let encoded = serde_json::to_string(&value).unwrap();
            for extra in ["null", "\"duplicate\""] {
                let duplicated = encoded.replacen(
                    &format!("\"{field}\":"),
                    &format!("\"{field}\":{extra},\"{field}\":"),
                    1,
                );
                let error = serde_json::from_str::<BusinessProviderV1>(&duplicated).unwrap_err();
                assert!(error.to_string().contains("duplicate field"), "{error}");
            }
        }
    }
}

#[test]
fn unknown_fields_stay_rejected_when_bindings_are_explicitly_null() {
    let mut value = provider("unknown");
    value["account_binding"] = Value::Null;
    value["tenant_binding"] = Value::Null;
    value["identity_override"] = json!(true);
    let error = serde_json::from_value::<BusinessProviderV1>(value).unwrap_err();
    assert!(error.to_string().contains("unknown field"), "{error}");
}

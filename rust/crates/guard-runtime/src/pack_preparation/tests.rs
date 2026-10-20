use super::*;
fn request() -> Value {
    let engine = guard_command::source_cli::compiler_info()["implementation_digest"].clone();
    json!({"profile":"remote","engine":engine,"now":1500,"selected":[],"retained":[],"validate_only":true,
        "release_data":json!({"engine":engine,"issued_at":1000,"expires_at":2000}).to_string()})
}
#[test]
fn preflight_has_no_filesystem_capability_and_preserves_errors() {
    let mut input = request();
    assert_eq!(evaluate(&input).unwrap(), json!({"validated":true}));
    input["now"] = json!(2000);
    assert!(evaluate(&input)
        .unwrap_err()
        .contains("fresh authenticated"));
    input["now"] = json!(1500);
    input["engine"] = json!("0".repeat(64));
    assert!(evaluate(&input)
        .unwrap_err()
        .contains("different native engine"));
}
#[test]
fn selection_ids_are_strict_and_bounded() {
    for id in [
        "command.",
        "command.Foo",
        "command.a..b",
        "command.a/-b",
        "command.a-",
    ] {
        let mut input = request();
        input["selected"] = json!([id]);
        assert!(evaluate(&input).unwrap_err().contains("selection invalid"));
    }
    let mut input = request();
    input["selected"] = json!((0..=MAX_SELECTED)
        .map(|i| format!("command.pack-{i}"))
        .collect::<Vec<_>>());
    assert!(evaluate(&input).unwrap_err().contains("admission budget"));
}

#[test]
fn target_metadata_selection_and_legacy_are_native_and_io_free() {
    let mut input = json!({"operation":"target-metadata", "controls":[
        {"kind":"extension", "id":"command.present", "extension_present":true},
        {"kind":"permission", "id":"command.owner.permission.run", "permission_present":true},
        {"kind":"extension", "id":"invalid/target"}
    ]});
    assert_eq!(evaluate(&input).unwrap(), json!({"catalog_refs":[]}));
    input["controls"][1]["permission_present"] = json!(false);
    assert_eq!(evaluate(&input).unwrap(), json!({"authority":"installed"}));
    input["installed"] = Value::Null;
    input["committed"] = json!(false);
    assert_eq!(evaluate(&input).unwrap(), json!({"catalog_refs":[]}));
    input["committed"] = json!(true);
    input["directory"] = json!("unused");
    assert_eq!(evaluate(&input).unwrap(), json!({"authority":"remote"}));
}

fn reference(kind: &str, length: u64, expanded: u64) -> Value {
    json!({"sha256":"a".repeat(64),"length":length,"expanded_length":expanded,"kind":kind,
        "location":{"tag":"t","asset":"a"}})
}

#[test]
fn transfer_budget_is_cumulative_and_charged_from_authenticated_lengths() {
    let spent = |response: &Value| response["budget"]["spent"].as_u64().unwrap();
    let first = transfer::account(&json!({}), json!({"need":reference("data", 100, 100)})).unwrap();
    assert_eq!(first["budget"], json!({"spent":100,"rounds":1}));
    // Concatenation parts are materialized in the same transfer.
    let second = transfer::account(&first, json!({"need":reference("concat", 10, 400)})).unwrap();
    assert_eq!(second["budget"], json!({"spent":510,"rounds":2}));
    let archives = json!({"need_archives":[{"length":7},{"length":9}]});
    assert_eq!(spent(&transfer::account(&second, archives).unwrap()), 526);
    let batch =
        json!({"needs":[{"need":reference("data", 5, 5)},{"need_archives":[{"length":4}]}]});
    assert_eq!(spent(&transfer::account(&json!({}), batch).unwrap()), 9);
    // Responses that request no transfer carry no budget.
    let done = transfer::account(&second, json!({"selected":[]})).unwrap();
    assert!(done.get("budget").is_none());
}

#[test]
fn transfer_budget_fails_closed_at_bytes_rounds_and_malformed_state() {
    let need = json!({"need":reference("data", 1, 1)});
    let limit = 512 * 1024 * 1024;
    let at_limit = json!({"budget":{"spent":limit - 1,"rounds":0}});
    assert!(transfer::account(&at_limit, need.clone()).is_ok());
    let over = json!({"budget":{"spent":limit,"rounds":0}});
    assert_eq!(
        transfer::account(&over, need.clone()).unwrap_err(),
        "pack_transfer_budget_exceeded"
    );
    let last = json!({"budget":{"spent":0,"rounds":8191}});
    assert!(transfer::account(&last, need.clone()).is_ok());
    let rounds = json!({"budget":{"spent":0,"rounds":8192}});
    assert_eq!(
        transfer::account(&rounds, need.clone()).unwrap_err(),
        "pack_transfer_budget_exceeded"
    );
    let wrapped = json!({"budget":{"spent":u64::MAX,"rounds":u64::MAX}});
    assert!(transfer::account(&wrapped, need.clone()).is_err());
    for budget in [json!({"spent":-1,"rounds":0}), json!({"spent":0}), json!(7)] {
        let input = json!({ "budget": budget });
        assert_eq!(
            transfer::account(&input, need.clone()).unwrap_err(),
            "pack_transfer_request_invalid"
        );
    }
    for malformed in [
        json!({"need":{"kind":"data"}}),
        json!({"need_archives":[{"length":"7"}]}),
        json!({"need":reference("concat", u64::MAX, 1)}),
    ] {
        assert!(transfer::account(&json!({}), malformed).is_err());
    }
}

#[test]
fn unavailable_policy_is_a_typed_response_and_offline_never_requests_transfers() {
    let input = json!({"profile":"remote"});
    assert_eq!(
        respond(&input, Err(Failure::Unavailable)).unwrap(),
        json!({"unavailable":UNAVAILABLE})
    );
    let response = respond(&input, Err(Failure::Need(reference("data", 3, 3)))).unwrap();
    assert_eq!(response["budget"], json!({"spent":3,"rounds":1}));
    assert_eq!(
        respond(&input, Err(Failure::Revoked("command.x".into(), 9))).unwrap(),
        json!({"revoked":"command.x","epoch":9})
    );
    assert_eq!(
        respond(&input, Err("pack preparation metadata invalid".into())).unwrap_err(),
        "pack preparation metadata invalid"
    );
    let offline = json!({"profile":"committed-subset"});
    for failure in [
        Failure::Need(reference("data", 3, 3)),
        Failure::Batch(vec![json!({"need":reference("data", 3, 3)})]),
        Failure::Archives(json!([{"length":3}])),
    ] {
        assert_eq!(
            respond(&offline, Err(failure)).unwrap_err(),
            "offline subset cannot fetch uncached policy"
        );
    }
    // Unavailability is reported, not fetched, even for a committed subset.
    assert_eq!(
        respond(&offline, Err(Failure::Unavailable)).unwrap(),
        json!({"unavailable":UNAVAILABLE})
    );
}

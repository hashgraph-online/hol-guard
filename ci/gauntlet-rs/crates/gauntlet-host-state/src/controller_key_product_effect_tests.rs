use super::*;
use serde_json::json;

#[test]
fn kernel_effect_readback_requires_host_pins_known_writers_and_exact_surface() {
    let pin = HostEffectEventsPin {
        run_id: "a".repeat(16),
        host_key_record_sha256: "b".repeat(64),
        terminal_sha256: "c".repeat(64),
        report_sha256: "d".repeat(64),
        journal_sha256: "e".repeat(64),
        journal_bytes: 100,
        events: 12,
        unknown_writers: 1,
        raw_sha256: "f".repeat(64),
    };
    let value = json!({"schema":"hol-gauntlet-staging-kernel-bound-effect.v1","run_id":pin.run_id,
        "role":"success","surface":"provider-home","final_sha256":"59cae128f1e25176c5c65014eca5ecf8a6ad57360b867f2d5b22837ca4712d74",
        "final_bytes":24,"device":8,"inode":10,"close_writes":2,"writers":[{"pid":42,"start_ticks":123}],
        "outside_journal_sha256":pin.journal_sha256,"held_final_file_checked":true,"physical_owner_uid":10001,
        "event_view_owner_uid":10004,"idmap_kernel_verified":true,"guard_causality_verified":false,"execution_eligible":false,
        "kernel_observed_cgroup":format!("/holgauntletrust{}.slice/hol-product-cell-{}.service",pin.run_id,"b".repeat(32)),
        "kernel_product_pid":41,"kernel_product_start_ticks":122,"outside_report_sha256":pin.report_sha256,"continuously_observed":false});
    let read = |v: &Value| validate(v.to_string().as_bytes(), &pin, "success", "provider-home");
    assert_eq!(read(&value).unwrap(), value);
    for (field, change) in [
        ("outside_report_sha256", json!("0".repeat(64))),
        ("outside_journal_sha256", json!("0".repeat(64))),
        ("idmap_kernel_verified", json!(false)),
        ("guard_causality_verified", json!(true)),
        ("execution_eligible", json!(true)),
        ("surface", json!("provider-remote")),
        ("writers", json!([])),
        ("close_writes", json!(13)),
        (
            "kernel_observed_cgroup",
            json!("/system.slice/other.service"),
        ),
        ("final_bytes", json!(25)),
    ] {
        let mut changed = value.clone();
        changed[field] = change;
        assert!(read(&changed).is_err(), "{field}");
    }
    let mut changed = value.clone();
    let duplicate = changed["writers"][0].clone();
    changed["writers"].as_array_mut().unwrap().push(duplicate);
    assert!(read(&changed).is_err());
    changed = value.clone();
    changed["caller_expected_cgroup"] = json!("/system.slice/other.service");
    assert!(read(&changed).is_err());
    let mut v2 = value.clone();
    v2["schema"] = json!("hol-gauntlet-staging-kernel-bound-effect.v2");
    v2["file_handle"] = json!({"kind":1,"bytes":"0123456789abcdef"});
    v2["file_generation_verified"] = json!(true);
    assert!(read(&v2).is_ok());
    for (field, change) in [
        ("file_handle", Value::Null),
        ("file_generation_verified", json!(false)),
        (
            "schema",
            json!("hol-gauntlet-staging-kernel-bound-effect.v1"),
        ),
    ] {
        let mut bad = v2.clone();
        bad[field] = change;
        assert!(read(&bad).is_err());
    }
    signed_relation_cases(v2, &pin);
}

fn signed_relation_cases(mut value: Value, pin: &HostEffectEventsPin) {
    let key = HostKeyPinRecord {
        pins: crate::HostControllerKeyPins {
            job_id: pin.run_id.clone(),
            source_sha: "1".repeat(40),
            deployment_digest: "2".repeat(64),
            worker_generation: "3".repeat(64),
            started_marker_sha256: "4".repeat(64),
            controller_key_pin_sha256: "5".repeat(64),
            controller_public_key_hex: "6".repeat(64),
        },
        raw_sha256: pin.host_key_record_sha256.clone(),
    };
    // The explicit signed mode must not silently accept an older response.
    let read = |v: &Value| {
        validate_signed(
            v.to_string().as_bytes(),
            pin,
            "success",
            "provider-home",
            &key,
        )
    };
    assert!(read(&value).is_err());
    value["schema"] = json!("hol-gauntlet-staging-signed-kernel-bound-effect.v1");
    value["signed_control_relation"] = json!({
        "schema":"hol-gauntlet-staging-signed-product-relation.v1","run_id":pin.run_id,
        "signed_session_id":"success","source_sha":key.pins.source_sha,"record_sha256":"7".repeat(64),
        "controller_public_key_hex":key.pins.controller_public_key_hex,"product_pid":41,"product_start_ticks":122,
        "task_mounts_matched":3,"namespaces_matched":6,"argv_sha256":"8".repeat(64),"mountinfo_sha256":"9".repeat(64),
        "outside_control_key_matched":true,"guard_causality_verified":false,"execution_eligible":false});
    assert_eq!(read(&value).unwrap(), value);
    assert!(validate(
        value.to_string().as_bytes(),
        pin,
        "success",
        "provider-home"
    )
    .is_err());
    for (field, change) in [
        ("run_id", json!("0".repeat(16))),
        ("source_sha", json!("0".repeat(40))),
        ("controller_public_key_hex", json!("0".repeat(64))),
        ("signed_session_id", json!("boundary")),
        ("product_pid", json!(42)),
        ("product_start_ticks", json!(123)),
        ("record_sha256", json!("unknown")),
        ("task_mounts_matched", json!(2)),
        ("namespaces_matched", json!(7)),
        ("outside_control_key_matched", json!(false)),
        ("guard_causality_verified", json!(true)),
        ("execution_eligible", json!(true)),
    ] {
        let mut bad = value.clone();
        bad["signed_control_relation"][field] = change;
        assert!(read(&bad).is_err(), "{field}");
    }
    let mut missing_generation = value.clone();
    missing_generation["file_handle"] = Value::Null;
    assert!(read(&missing_generation).is_err());
    let mut extra = value.clone();
    extra["signed_control_relation"]["passed"] = json!(true);
    assert!(read(&extra).is_err());
}

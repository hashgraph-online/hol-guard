use serde_json::{json, Value};

use super::dispatch;

fn compare(stage: &str, fields: Value) -> Result<Value, String> {
    let mut request = json!({"op": "publication_runtime_compare", "stage": stage});
    for (key, value) in fields.as_object().unwrap() {
        request[key] = value.clone();
    }
    let answer = dispatch(&request).map_err(|error| error.to_string())?;
    match answer.get("error") {
        Some(error) => Err(error.to_string()),
        None => Ok(answer["value"].clone()),
    }
}

fn capabilities(protocol: i64, version: &str) -> Value {
    json!({"protocol_version": protocol, "runtime_version": version, "rule_digest": "rd", "build_sha": "sha"})
}

fn manifest(version: &str) -> Value {
    json!({"package_version": version, "rule_digest": "rd", "source_sha": "sha"})
}

#[test]
fn only_a_clean_zero_exit_passes_the_probe() {
    let probe = |code: i64, flag: &str| {
        let mut fields = json!({"returncode": code, "timed_out": false, "containment_failed": false, "output_limit_exceeded": false});
        if flag != "returncode" {
            fields[flag] = json!(true);
        }
        compare("probe", fields)
    };
    assert!(probe(0, "returncode").is_ok());
    for (code, flag) in [
        (1, "returncode"),
        (0, "timed_out"),
        (0, "containment_failed"),
        (0, "output_limit_exceeded"),
    ] {
        assert!(probe(code, flag)
            .unwrap_err()
            .contains("authority_repair_native_inspection_failed"));
    }
    assert!(compare("probe", json!({})).is_err());
}

#[test]
fn capabilities_must_carry_the_protocol_and_match_the_manifest() {
    let check = |capabilities: Value, manifest: Value| {
        compare(
            "capabilities",
            json!({"capabilities": capabilities, "protocol": 1, "manifest": manifest}),
        )
    };
    assert!(check(capabilities(1, "1.0"), manifest("1.0")).is_ok());
    assert!(
        check(capabilities(1, "9.9"), Value::Null).is_ok(),
        "no manifest, nothing to match"
    );
    for bad in [Value::Null, capabilities(2, "1.0")] {
        assert!(check(bad, manifest("1.0"))
            .unwrap_err()
            .contains("native_protocol_mismatch"));
    }
    let mut other = capabilities(1, "1.0");
    other["build_sha"] = json!("else");
    for bad in [capabilities(1, "2.0"), other] {
        assert!(check(bad, manifest("1.0"))
            .unwrap_err()
            .contains("native_manifest_capabilities_mismatch"));
    }
}

#[test]
fn only_auto_mode_holds_the_runtime_to_the_package_version() {
    let check = |mode: &str, version: Value| {
        compare(
            "version",
            json!({"mode": mode, "version": version, "runtime_version": "1.0"}),
        )
    };
    assert!(check("auto", json!("1.0")).is_ok());
    assert!(check("auto", Value::Null).is_ok());
    assert!(check("force", json!("2.0")).is_ok());
    assert!(check("auto", json!("2.0"))
        .unwrap_err()
        .contains("native_version_mismatch"));
}

#[test]
fn a_changed_or_missing_generation_is_refused() {
    let check = |before: Value, after: Value| {
        compare("generation", json!({"before": before, "after": after}))
    };
    assert!(check(json!([10, 20, 30]), json!([10, 20, 30])).is_ok());
    for after in [
        json!([10, 21, 30]),
        json!([11, 20, 30]),
        json!([10, 20, 31]),
        Value::Null,
    ] {
        assert!(check(json!([10, 20, 30]), after)
            .unwrap_err()
            .contains("native_runtime_generation_changed"));
    }
}

#[test]
fn an_unknown_stage_is_refused() {
    assert!(compare("other", json!({}))
        .unwrap_err()
        .contains("files_invalid"));
}

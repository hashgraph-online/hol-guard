use super::*;

#[test]
fn offline_parity_compares_full_native_evidence_and_rejects_real_differences() {
    let mut baseline = compiled().program;
    baseline["authoring_semantics_digest"] = serde_json::json!("a".repeat(64));
    baseline.as_object_mut().unwrap().remove("program_digest");
    baseline["program_digest"] = serde_json::json!(digest_canonical_bytes(
        PROGRAM_DOMAIN,
        &serde_json::to_vec(&baseline).unwrap()
    ));
    let mut request = serde_json::json!({
        "schema":"guard.command-extension-parity.v1",
        "baseline_program":baseline,
        "build":{"schema":"guard.command-extension-build.v1","base":"packaged",
            "sources":[serde_json::from_slice::<Value>(EXAMPLE).unwrap()],
            "trust":serde_json::from_slice::<Value>(TRUST).unwrap()},
        "cases":[{"id":"git-reset","payload":{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}},
            "controls":[],"managed_controls":[]}]
    });
    let result = compare_programs(&serde_json::to_vec(&request).unwrap()).unwrap();
    assert_eq!(result["ok"], true, "{result}");
    for rule in request["baseline_program"]["rules"].as_array_mut().unwrap() {
        rule["rule_version"] = serde_json::json!("9.9.9");
    }
    let baseline = &mut request["baseline_program"];
    baseline.as_object_mut().unwrap().remove("program_digest");
    baseline["program_digest"] = serde_json::json!(digest_canonical_bytes(
        PROGRAM_DOMAIN,
        &serde_json::to_vec(baseline).unwrap()
    ));
    let result = compare_programs(&serde_json::to_vec(&request).unwrap()).unwrap();
    assert_eq!(result["ok"], false);
    assert_ne!(
        result["cases"][0]["baseline"],
        result["cases"][0]["candidate"]
    );
}

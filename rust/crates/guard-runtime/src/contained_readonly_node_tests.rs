use super::*;

#[test]
fn only_an_indented_option_line_offers_the_wasm_option() {
    let help = b"Options:\n  --disable-wasm-trap-handler  disable trap-handler-based WebAssembly bound checks\n";
    assert!(offers_wasm_trap_option(help));
    assert!(offers_wasm_trap_option(b"\t--disable-wasm-trap-handler"));
    // Unindented, a longer option, or one carried in prose is not it.
    assert!(!offers_wasm_trap_option(b"--disable-wasm-trap-handler\n"));
    assert!(!offers_wasm_trap_option(
        b"  --disable-wasm-trap-handler-for-workers\n"
    ));
    assert!(!offers_wasm_trap_option(
        b"  see --disable-wasm-trap-handler\n"
    ));
    assert!(!offers_wasm_trap_option(
        b"  --disable-wasm-trap-handler\r\n"
    ));
    assert!(!offers_wasm_trap_option(b""));
}

#[test]
fn only_an_outright_allow_or_a_transform_runs_vitest_route_lets_the_help_run() {
    let response = |value: Value| -> Map<String, Value> {
        let Value::Object(response) = value else {
            unreachable!()
        };
        response
    };
    let outright = response(json!({ "decision": "allow", "policy_action": "allow" }));
    assert!(allowed(&outright, false));
    assert!(allowed(&outright, true));
    // The transform image runs under Vitest's route, so a run that starts
    // one may read the help as that route; no other run may.
    let vitest = response(json!({
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": VITEST_ROUTE.0,
        "required_execution_profile": VITEST_ROUTE.1,
    }));
    assert!(allowed(&vitest, true));
    assert!(!allowed(&vitest, false));
    let mut observed = vitest.clone();
    observed.insert("observe_mode".to_owned(), Value::Bool(true));
    assert!(!allowed(&observed, true));
    for refused in [
        json!({ "decision": "allow", "policy_action": "require-reapproval" }),
        json!({ "decision": "deny", "policy_action": "allow" }),
        json!({ "decision": "allow", "policy_action": "allow", "observe_mode": true }),
        json!({
            "decision": "deny",
            "policy_action": "sandbox-required",
            "reason_code": "native_node_test_readonly_containment_required",
            "required_execution_profile": NODE_TEST_PROFILE,
        }),
        json!({}),
    ] {
        assert!(!allowed(&response(refused.clone()), false));
        assert!(!allowed(&response(refused), true));
    }
}

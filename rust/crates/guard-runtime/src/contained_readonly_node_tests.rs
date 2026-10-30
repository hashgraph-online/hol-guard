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
fn only_an_outright_allow_lets_the_help_run() {
    let response = |value: Value| -> Map<String, Value> {
        let Value::Object(response) = value else {
            unreachable!()
        };
        response
    };
    assert!(allowed(&response(
        json!({ "decision": "allow", "policy_action": "allow" })
    )));
    for refused in [
        json!({ "decision": "allow", "policy_action": "require-reapproval" }),
        json!({ "decision": "deny", "policy_action": "allow" }),
        json!({ "decision": "allow", "policy_action": "allow", "observe_mode": true }),
        json!({}),
    ] {
        assert!(!allowed(&response(refused)));
    }
}

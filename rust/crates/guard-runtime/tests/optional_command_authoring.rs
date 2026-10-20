//! The normal runtime compiles authored optional metadata without embedding it.

use serde_json::{json, Value};
use std::ffi::OsString;
use std::io::Write;
use std::process::{Command, Stdio};

/// The runtime binary this test drives.
///
/// CI runs the runtime tests from a nextest archive, which can be restored
/// from cache and unpacked somewhere other than the build directory
/// `CARGO_BIN_EXE_*` was baked against. Nextest exports the unpacked path, so
/// prefer it and fall back to the build path under plain `cargo test`.
fn runtime_binary() -> OsString {
    [
        "NEXTEST_BIN_EXE_hol-guard-runtime",
        "NEXTEST_BIN_EXE_hol_guard_runtime",
    ]
    .into_iter()
    .find_map(std::env::var_os)
    .unwrap_or_else(|| env!("CARGO_BIN_EXE_hol-guard-runtime").into())
}

fn compiler(operation: &str, input: &[u8]) -> Value {
    let mut child = Command::new(runtime_binary())
        .arg(operation)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn optional_command_metadata_is_authored_and_default_off_outside_core() {
    let built = compiler("export-built", &[]);
    assert!(built["catalog"]
        .as_array()
        .unwrap()
        .iter()
        .all(|entry| entry["extension_id"] != "command.agentbridge"));
    let source: Value = serde_json::from_slice(include_bytes!(
        "../../../../contributions/command-sources/command.agentbridge.json"
    ))
    .unwrap();
    let mut trust = compiler("export-trust", &[]);
    trust["classes"]["external"] = json!(["command.agentbridge"]);
    let input = serde_json::to_vec(&json!({
        "schema":"guard.command-extension-build.v1",
        "sources":[source], "trust":trust, "base":"packaged",
        "validation_base":{"catalog":built["catalog"], "programs":[]}
    }))
    .unwrap();
    let authored = compiler("compile", &input);
    let optional = authored["catalog"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["extension_id"] == "command.agentbridge")
        .unwrap();
    assert_eq!(optional["trust_class"], "external");
    assert_eq!(optional["activation"], "opt-in");
    assert_eq!(optional["enabled"], false);
    assert_eq!(optional["rules"].as_array().unwrap().len(), 2);
    assert_ne!(
        authored["program"]["program_digest"],
        built["program"]["program_digest"]
    );
}

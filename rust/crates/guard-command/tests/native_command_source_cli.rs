use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Output, Stdio};

fn invoke(arguments: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_guard-command-source"))
        .args(arguments)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn request() -> Vec<u8> {
    let source: Value =
        serde_json::from_slice(include_bytes!("fixtures/command-source-example.v1.json")).unwrap();
    let trust: Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/extensions/trust-class-map.v1.json"
    )))
    .unwrap();
    serde_json::to_vec(&json!({
        "schema":"guard.command-extension-build.v1",
        "sources":[source], "trust":trust, "base":"packaged"
    }))
    .unwrap()
}

#[test]
fn offline_cli_compiles_deterministically_and_checks_exact_identity() {
    let input = request();
    let first = invoke(&["compile"], &input);
    assert!(first.status.success(), "{first:?}");
    let second = invoke(&["compile"], &input);
    assert!(second.status.success());
    assert_eq!(first.stdout, second.stdout);
    let compiled: Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(
        compiled["catalog_projection_kind"],
        "addition-only-not-release-catalog"
    );
    let digest = compiled["program"]["program_digest"].as_str().unwrap();
    assert!(invoke(&["check", digest], &input).status.success());
    let stale = invoke(&["check", &"0".repeat(64)], &input);
    assert_eq!(stale.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&stale.stdout).unwrap()["code"],
        "command_source_generated_program_stale"
    );
    assert!(invoke(&["validate"], &input).status.success());
}

#[test]
fn checked_in_schemas_are_exact_native_projections() {
    for (argument, expected) in [
        (
            "schema",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../contracts/extensions/command-extension-source.v1.schema.json"
            ))
            .as_slice(),
        ),
        (
            "descriptor-schema",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../contracts/extensions/contribution.v2.schema.json"
            ))
            .as_slice(),
        ),
    ] {
        let output = invoke(&[argument], b"");
        assert!(output.status.success());
        assert_eq!(output.stdout, expected, "{argument} schema drift");
    }
}

#[test]
fn malformed_build_inputs_produce_structured_failure_without_artifacts() {
    for input in [b"{}".as_slice(), b"{\"schema\":1,\"schema\":2}", b"{} {}"] {
        let output = invoke(&["compile"], input);
        assert_eq!(output.status.code(), Some(2));
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["ok"], false);
        assert!(result.get("program").is_none());
        assert!(result["code"]
            .as_str()
            .unwrap()
            .starts_with("command_source_"));
    }
}

#[test]
fn portable_fixtures_use_native_policy_and_report_failed_expectations() {
    let mut fixtures: Value =
        serde_json::from_slice(include_bytes!("fixtures/command-source-behavior.v1.json")).unwrap();
    fixtures["build"] = serde_json::from_slice(&request()).unwrap();
    let output = invoke(&["test"], &serde_json::to_vec(&fixtures).unwrap());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["target_commands_executed"], 0);
    assert_eq!(
        result["scope"],
        "offline-simulation-not-authenticated-receipts"
    );
    fixtures["cases"][0]["expected_action"] = json!("allow");
    let output = invoke(&["test"], &serde_json::to_vec(&fixtures).unwrap());
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["ok"],
        false
    );
    fixtures["cases"][0]["rule_id"] = json!("command.missing.rule");
    assert_eq!(
        invoke(&["test"], &serde_json::to_vec(&fixtures).unwrap())
            .status
            .code(),
        Some(2)
    );
}

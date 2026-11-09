//! `hol-guard-runtime cloud-action` serves Guard Cloud's hosted action
//! evaluator from the runtime the wheel already ships.

use serde_json::Value;
use std::ffi::OsString;
use std::io::Write;
use std::process::{Command, Output, Stdio};

const BINDINGS: &str =
    include_str!("../../guard-command/tests/fixtures/cloud-action/binding-set.json");
const REQUEST: &str = include_str!("../../guard-command/tests/fixtures/cloud-action/request.json");

/// See `optional_command_authoring.rs`: nextest archives move the binary.
fn runtime_binary() -> OsString {
    [
        "NEXTEST_BIN_EXE_hol-guard-runtime",
        "NEXTEST_BIN_EXE_hol_guard_runtime",
    ]
    .into_iter()
    .find_map(std::env::var_os)
    .unwrap_or_else(|| env!("CARGO_BIN_EXE_hol-guard-runtime").into())
}

fn invoke(arguments: &[&str], input: Vec<u8>) -> Output {
    let mut child = Command::new(runtime_binary())
        .arg("cloud-action")
        .args(arguments)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    // A process that exits at startup never reads this, so a write error is fine.
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    output
}

fn request_line() -> Vec<u8> {
    let set = guard_command::cloud_action_binding::load_binding_set(BINDINGS.as_bytes()).unwrap();
    let mut request: Value = serde_json::from_str(REQUEST).unwrap();
    request["binding_set_digest"] = set.digest.into();
    let mut line = request.to_string().into_bytes();
    line.push(b'\n');
    line
}

#[test]
fn the_runtime_answers_cloud_action_requests_one_line_each() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bindings.json");
    std::fs::write(&path, BINDINGS).unwrap();
    let mut input = request_line();
    input.extend(b"not json\n");
    input.extend(request_line());

    let output = invoke(&["--binding-set", path.to_str().unwrap()], input);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert_eq!(lines[0]["action"], "review");
    assert_eq!(lines[0]["request_id"], "req-0001");
    assert_eq!(lines[1]["action"], "block");
    assert_eq!(lines[1]["dispatch_permitted"], false);
    assert_eq!(lines[1]["error"]["code"], "malformed");
    assert_eq!(lines[2]["action"], "review");
}

#[test]
fn a_bad_startup_stops_before_answering() {
    for (arguments, code) in [
        (vec![], "usage"),
        (
            vec!["--binding-set", "/nonexistent/bindings.json"],
            "binding_set_unreadable",
        ),
    ] {
        let output = invoke(&arguments, request_line());
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!("hol-guard-runtime cloud-action: {code}")),
            "{stderr}"
        );
    }
}

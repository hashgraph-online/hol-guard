use guard_command::cloud_action_binding::load_binding_set;
use serde_json::{json, Value};
use std::ffi::OsString;
use std::io::Write;
use std::process::{Command, Output, Stdio};

const BINDINGS: &str = include_str!("fixtures/cloud-action/binding-set.json");
const REQUEST: &str = include_str!("fixtures/cloud-action/request.json");
const LINE_CAP: usize = 4 * 1024 * 1024;

fn binary() -> OsString {
    [
        "NEXTEST_BIN_EXE_guard-cloud-action",
        "NEXTEST_BIN_EXE_guard_cloud_action",
    ]
    .into_iter()
    .find_map(std::env::var_os)
    .unwrap_or_else(|| env!("CARGO_BIN_EXE_guard-cloud-action").into())
}

fn invoke(arguments: &[&str], environment: &[(&str, &str)], input: Vec<u8>) -> Output {
    let mut child = Command::new(binary())
        .args(arguments)
        .env_clear()
        .envs(environment.iter().copied())
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

struct Fixture {
    _directory: tempfile::TempDir,
    path: String,
}

fn binding_file(contents: &str) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bindings.json");
    std::fs::write(&path, contents).unwrap();
    Fixture {
        path: path.to_str().unwrap().into(),
        _directory: directory,
    }
}

fn request_line() -> Vec<u8> {
    let set = load_binding_set(BINDINGS.as_bytes()).unwrap();
    let mut request: Value = serde_json::from_str(REQUEST).unwrap();
    request["binding_set_digest"] = set.digest.into();
    let mut line = request.to_string().into_bytes();
    line.push(b'\n');
    line
}

fn results(output: &Output) -> Vec<Value> {
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn error_code(result: &Value) -> &str {
    assert_eq!(result["action"], "block", "{result}");
    assert_eq!(result["dispatch_permitted"], false, "{result}");
    result["error"]["code"].as_str().unwrap()
}

#[test]
fn a_bad_startup_stops_the_process_before_it_answers_anything() {
    let good = binding_file(BINDINGS);
    let key = "11".repeat(32);
    let missing_capability = binding_file(&BINDINGS.replacen("\"egress-pinned\", ", "", 1));
    let malformed = binding_file("{");
    let cases: [(Vec<&str>, &str); 8] = [
        (vec![], "usage"),
        (vec!["--binding-set"], "usage"),
        (vec!["--bind", &good.path], "usage"),
        (
            vec!["--binding-set", "/nonexistent/bindings.json"],
            "binding_set_unreadable",
        ),
        (
            vec!["--binding-set", &malformed.path],
            "binding_set_malformed",
        ),
        (
            vec!["--binding-set", &missing_capability.path],
            "binding_missing_required_capability",
        ),
        (
            vec![
                "--binding-set",
                &good.path,
                "--activation-public-key",
                "not-hex",
            ],
            "activation_key_invalid",
        ),
        (
            vec![
                "--binding-set",
                &good.path,
                "--activation-public-key",
                &key[2..],
            ],
            "activation_key_invalid",
        ),
    ];
    for (arguments, code) in cases {
        let output = invoke(&arguments, &[], request_line());
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}");
        assert!(
            stderr(&output).contains(code),
            "{arguments:?}: {}",
            stderr(&output)
        );
    }
}

#[test]
fn a_bad_environment_key_also_stops_the_process() {
    let good = binding_file(BINDINGS);
    let output = invoke(
        &[],
        &[
            ("GUARD_CLOUD_ACTION_BINDING_SET", &good.path),
            ("GUARD_CLOUD_ACTION_ACTIVATION_PUBLIC_KEY", "abcd"),
        ],
        request_line(),
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

#[test]
fn it_answers_one_result_per_line_and_survives_an_oversize_line() {
    let good = binding_file(BINDINGS);
    let mut input = request_line();
    input.extend(vec![b'x'; LINE_CAP + 1]);
    input.push(b'\n');
    input.extend(b"\n");
    input.extend(b"not json\n");
    input.extend(vec![b'y'; 3 * LINE_CAP]);
    input.push(b'\n');
    input.extend(request_line());
    let output = invoke(&["--binding-set", &good.path], &[], input);
    assert!(output.status.success(), "{}", stderr(&output));
    let lines = results(&output);
    assert_eq!(lines.len(), 6, "{lines:?}");
    assert_eq!(lines[0]["action"], "review");
    assert_eq!(lines[0]["request_id"], "req-0001");
    assert_eq!(error_code(&lines[1]), "limit");
    assert_eq!(error_code(&lines[2]), "malformed");
    assert_eq!(error_code(&lines[3]), "malformed");
    assert_eq!(error_code(&lines[4]), "limit");
    assert_eq!(lines[5]["action"], "review");
}

#[test]
fn the_line_cap_is_exact_and_an_unterminated_last_line_is_answered() {
    let good = binding_file(BINDINGS);
    let mut at_cap = vec![b'x'; LINE_CAP];
    at_cap.push(b'\n');
    let mut input = at_cap;
    input.extend(vec![b'x'; LINE_CAP + 1]);
    let output = invoke(&["--binding-set", &good.path], &[], input);
    let lines = results(&output);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(error_code(&lines[0]), "malformed");
    assert_eq!(error_code(&lines[1]), "limit");

    let mut unterminated = request_line();
    unterminated.pop();
    let output = invoke(&["--binding-set", &good.path], &[], unterminated);
    let lines = results(&output);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["action"], "review");
}

#[test]
fn startup_values_come_from_the_environment_and_flags_override_them() {
    let good = binding_file(BINDINGS);
    let environment = [("GUARD_CLOUD_ACTION_BINDING_SET", good.path.as_str())];
    let output = invoke(&[], &environment, request_line());
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(results(&output)[0]["action"], "review");

    let broken = binding_file("{");
    let environment = [("GUARD_CLOUD_ACTION_BINDING_SET", broken.path.as_str())];
    let output = invoke(&["--binding-set", &good.path], &environment, request_line());
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(results(&output)[0]["action"], "review");
}

#[test]
fn the_activation_key_reaches_the_evaluator() {
    let good = binding_file(BINDINGS);
    let mut request: Value = serde_json::from_slice(&request_line()).unwrap();
    request["activation"] = json!({"payload": {}, "signature": "AAAA"});
    let mut line = request.to_string().into_bytes();
    line.push(b'\n');

    let without_key = invoke(&["--binding-set", &good.path], &[], line.clone());
    assert_eq!(
        error_code(&results(&without_key)[0]),
        "activation_key_unavailable"
    );

    let key = "11".repeat(32);
    let with_key = invoke(
        &["--binding-set", &good.path, "--activation-public-key", &key],
        &[],
        line,
    );
    assert_eq!(error_code(&results(&with_key)[0]), "activation_invalid");
}

use serde_json::{json, Value};

use super::dispatch;

fn probe(command: Value, env: Value, timeout: u64) -> Value {
    let cwd = std::env::temp_dir();
    dispatch(&json!({
        "command": command,
        "cwd": cwd,
        "env": env,
        "timeout_seconds": timeout,
    }))
    .unwrap()
}

#[test]
fn a_program_that_is_not_there_is_not_found_without_running() {
    let home = tempfile::tempdir().unwrap();
    let absent = home.path().join("absent-cli");
    assert_eq!(
        probe(json!([absent, "--help"]), json!({}), 5),
        json!({
            "command": [absent, "--help"],
            "ok": false,
            "return_code": null,
            "stdout": "",
            "stderr": "command not found",
        })
    );
    let bare = probe(
        json!(["absent-cli", "--help"]),
        json!({"PATH": home.path()}),
        5,
    );
    assert_eq!(bare["stderr"], "command not found");
    let no_path = probe(json!(["sh", "--help"]), json!({}), 5);
    assert_eq!(no_path["stderr"], "command not found");
}

#[cfg(unix)]
#[test]
fn a_cli_answers_its_exit_status_and_trimmed_output_from_the_sent_environment() {
    let answer = probe(
        json!([
            "sh",
            "-c",
            "printf ' %s \\n' \"$PROBE_VALUE\"; printf 'warn\\n' >&2; exit 3"
        ]),
        json!({"PATH": "/bin:/usr/bin", "PROBE_VALUE": "sent"}),
        5,
    );
    assert_eq!(
        answer,
        json!({
            "command": ["sh", "-c", "printf ' %s \\n' \"$PROBE_VALUE\"; printf 'warn\\n' >&2; exit 3"],
            "ok": false,
            "return_code": 3,
            "stdout": "sent",
            "stderr": "warn",
        })
    );
    let ok = probe(json!(["/bin/sh", "-c", "echo $HOME"]), json!({}), 5);
    assert_eq!(ok["ok"], true);
    assert_eq!(ok["stdout"], "", "the resident's own HOME is never passed");
}

#[cfg(unix)]
#[test]
fn a_cli_that_overruns_keeps_what_it_wrote_and_says_it_timed_out() {
    let answer = probe(
        json!(["/bin/sh", "-c", "echo started; exec sleep 30"]),
        json!({}),
        1,
    );
    assert_eq!(answer["timed_out"], true);
    assert_eq!(answer["ok"], false);
    assert_eq!(answer["return_code"], Value::Null);
    assert_eq!(answer["stdout"], "started");
}

#[cfg(unix)]
#[test]
fn a_cli_ended_by_a_signal_is_not_reported_as_missing() {
    let answer = probe(json!(["/bin/sh", "-c", "kill -9 $$"]), json!({}), 5);
    assert_eq!(answer["ok"], false);
    assert_eq!(answer["stderr"], "command did not exit normally");
}

#[test]
fn a_malformed_probe_request_is_refused() {
    let cwd = std::env::temp_dir();
    let request = |command: Value, cwd: Value, env: Value, timeout: Value| json!({"command": command, "cwd": cwd, "env": env, "timeout_seconds": timeout});
    for args in [
        request(json!([]), json!(cwd), json!({}), json!(5)),
        request(json!([""]), json!(cwd), json!({}), json!(5)),
        request(json!(["cli", 1]), json!(cwd), json!({}), json!(5)),
        request(json!(["cli"]), json!("relative"), json!({}), json!(5)),
        request(json!(["cli"]), json!(cwd), json!({"A=B": "x"}), json!(5)),
        request(json!(["cli"]), json!(cwd), json!({"A": 1}), json!(5)),
        request(json!(["cli"]), json!(cwd), json!({}), json!(0)),
        request(json!(["cli"]), json!(cwd), json!({}), json!(61)),
        request(json!(["cli"]), json!(cwd), json!({}), json!(1.5)),
        json!({"command": ["cli"], "cwd": cwd, "env": {}}),
    ] {
        assert!(dispatch(&args).is_err(), "{args}");
    }
}

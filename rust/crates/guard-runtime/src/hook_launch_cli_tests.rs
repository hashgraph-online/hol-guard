use super::*;

fn request(text: &str) -> Request {
    serde_json::from_str(text).expect("request parses")
}

#[cfg(unix)]
fn launch(command: &[&str], input: &str, timeout_millis: u64, extra: &str) -> Value {
    let dir = std::env::temp_dir();
    let body = json!({
        "op": "launch",
        "command": command,
        "input_text": input,
        "cwd": dir.to_string_lossy(),
        "environment": { "PATH": std::env::var("PATH").unwrap_or_default() },
        "timeout_millis": timeout_millis,
    });
    let mut body = body;
    if !extra.is_empty() {
        let extra: Value = serde_json::from_str(extra).unwrap();
        for (key, value) in extra.as_object().unwrap() {
            body[key] = value.clone();
        }
    }
    answer(request(&body.to_string()), Arc::new(AtomicBool::new(false)))
}

#[test]
fn unknown_fields_and_ops_are_refused() {
    assert!(serde_json::from_str::<Request>(r#"{"op":"launch","bogus":1}"#).is_err());
    assert!(serde_json::from_str::<Request>(r#"{"op":"spawn_anything"}"#).is_err());
    assert!(
        serde_json::from_str::<Request>(r#"{"op":"system_executable","filename":"a","x":1}"#)
            .is_err()
    );
}

#[test]
fn a_request_line_ends_at_the_first_newline() {
    let mut reader = std::io::Cursor::new(b"{\"a\":1}\nrest".to_vec());
    assert_eq!(read_line(&mut reader).unwrap(), b"{\"a\":1}");
    let mut rest = Vec::new();
    reader.read_to_end(&mut rest).unwrap();
    assert_eq!(rest, b"rest");
}

#[test]
fn an_oversize_request_line_is_refused() {
    let mut reader = std::io::repeat(b'a');
    assert_eq!(
        read_line(&mut reader),
        Err("hook_launch_request_too_large".to_owned())
    );
}

#[test]
fn a_malformed_request_is_refused() {
    let reader = std::io::Cursor::new(b"not json\n".to_vec());
    assert_eq!(
        run_command(reader),
        Err("hook_launch_request_invalid".to_owned())
    );
}

#[test]
fn the_guard_command_builders_answer_the_isolated_contract() {
    let answer = answer(
        request(
            r#"{"op":"guard_cli_command","python":"/usr/bin/python3","package_root":"/pkg","guard_args":["guard","check"]}"#,
        ),
        Arc::new(AtomicBool::new(false)),
    );
    let command = answer["command"].as_array().unwrap();
    assert_eq!(command[0], "/usr/bin/python3");
    assert_eq!(command[1], "-I");
    assert_eq!(command[2], "-c");
    assert_eq!(command[4], "guard");
    assert_eq!(command[5], "check");
    let daemon = super::answer(
        request(
            r#"{"op":"daemon_start_command","python":"/usr/bin/python3","package_root":"/pkg","guard_home":"/g","home_dir":"/h"}"#,
        ),
        Arc::new(AtomicBool::new(false)),
    );
    let command = daemon["command"].as_array().unwrap();
    assert_eq!(command.len(), 4);
    assert!(command[3]
        .as_str()
        .unwrap()
        .contains("schedule_guard_daemon_recovery"));
}

#[test]
fn a_system_executable_must_be_a_bare_filename() {
    for name in ["", ".", "..", "a/b", "a\\b", "C:cmd.exe"] {
        assert_eq!(
            system_executable(name),
            Err("Windows system executable must be a filename".to_owned()),
            "{name}"
        );
    }
}

#[test]
fn a_private_runtime_directory_error_is_an_answer() {
    let answer = answer(
        request(
            r#"{"op":"private_runtime_cwd","manifest_path":"/definitely/not/here/manifest.json"}"#,
        ),
        Arc::new(AtomicBool::new(false)),
    );
    assert_eq!(
        answer["error"],
        "managed Codex hook runtime directory is unavailable"
    );
}

#[cfg(unix)]
#[test]
fn a_launch_answers_the_child_output_and_exit() {
    let answer = launch(&["/bin/cat"], "ping", 5000, "");
    assert_eq!(answer["returncode"], 0);
    assert_eq!(answer["stdout"], "ping");
    assert_eq!(answer["timed_out"], false);
    assert_eq!(answer["containment_failed"], false);
    assert_eq!(answer["capture_incomplete"], false);
}

#[cfg(unix)]
#[test]
fn the_spawn_kernel_keeps_the_raw_bytes_the_decoded_text_replaced() {
    let dir = std::env::temp_dir();
    let outcome = run_isolated_hook_process_extended(
        &["/usr/bin/printf".to_owned(), "\\377 raw".to_owned()],
        "",
        &dir,
        &BTreeMap::new(),
        Some(5.0),
        None,
        None,
        None,
        &LaunchExtras::default(),
    );
    assert_eq!(outcome.stdout_raw, b"\xff raw");
    assert_eq!(outcome.result.stdout, "\u{fffd} raw");
}

#[cfg(unix)]
#[test]
fn a_launch_past_its_deadline_is_killed_and_reported() {
    let started = std::time::Instant::now();
    let answer = launch(&["/bin/sleep", "10"], "", 400, "");
    assert_eq!(answer["timed_out"], true);
    assert_eq!(answer["returncode"], Value::Null);
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

#[cfg(unix)]
#[test]
fn a_set_stop_flag_launches_nothing() {
    let body = json!({
        "op": "launch",
        "command": ["/bin/echo", "x"],
        "cwd": "/",
        "environment": {},
        "timeout_millis": 5000,
    });
    let stop = Arc::new(AtomicBool::new(true));
    let answer = answer(request(&body.to_string()), stop);
    assert_eq!(answer["returncode"], Value::Null);
    assert_eq!(answer["stdout"], "");
}

#[cfg(unix)]
#[test]
fn a_stop_signal_ends_a_running_child() {
    let body = json!({
        "op": "launch",
        "command": ["/bin/sleep", "10"],
        "cwd": "/",
        "environment": {},
        "timeout_millis": 30000,
    });
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(200));
        flag.store(true, Ordering::SeqCst);
    });
    let started = std::time::Instant::now();
    let answer = answer(request(&body.to_string()), stop);
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(answer["timed_out"], false);
    assert_eq!(answer["returncode"], Value::Null);
}

#[cfg(unix)]
#[test]
fn a_parent_liveness_pipe_reaches_the_child_and_closes_with_it() {
    let answer = launch(
        &[
            "/bin/sh",
            "-c",
            "printf %s \"$HOL_GUARD_PARENT_LIVENESS_FD\"",
        ],
        "",
        5000,
        r#"{"parent_liveness":true}"#,
    );
    assert_eq!(answer["returncode"], 0);
    let descriptor: i32 = answer["stdout"].as_str().unwrap().parse().unwrap();
    assert!(descriptor > 2);
}

#[test]
fn a_hold_job_request_names_the_process_to_hold() {
    let parsed = request(r#"{"op":"hold_job","process_id":42,"allow_breakaway":true}"#);
    assert!(matches!(
        parsed,
        Request::HoldJob {
            process_id: 42,
            allow_breakaway: true
        }
    ));
    assert!(serde_json::from_str::<Request>(r#"{"op":"hold_job"}"#).is_err());
}

#[cfg(not(windows))]
#[test]
fn holding_a_job_is_unavailable_off_windows() {
    let reader = std::io::Cursor::new(b"{\"op\":\"hold_job\",\"process_id\":1}\n".to_vec());
    let answer = run_command(reader).expect("answers");
    let parsed: Value = serde_json::from_slice(&answer).unwrap();
    assert_eq!(parsed["error"], "Windows Job Objects are unavailable");
}

#[cfg(unix)]
#[test]
fn a_launch_answer_reports_the_quarantine_as_settled() {
    let answered = launch(&["/bin/echo", "ok"], "", 5000, "");
    assert_eq!(answered["quarantine_settled"], true);
    assert_eq!(answered["survivors"], serde_json::json!([]));
    assert_eq!(answered["containment_failed"], false);
}

#[test]
fn the_hook_environment_op_keeps_only_allowlisted_names() {
    let answered = answer(
        request(
            r#"{"op":"hook_environment","source":{"HOME":"/u","LC_ALL":"C","AWS_SECRET":"x"}}"#,
        ),
        Arc::new(AtomicBool::new(false)),
    );
    assert_eq!(answered["environment"]["HOME"], "/u");
    assert_eq!(answered["environment"]["LC_ALL"], "C");
    assert!(answered["environment"].get("AWS_SECRET").is_none());
}

#[cfg(unix)]
#[test]
fn a_failing_child_reports_its_exit_code_and_is_contained() {
    let answered = launch(&["/bin/sh", "-c", "echo bad >&2; exit 7"], "", 5000, "");
    assert_eq!(answered["returncode"], 7);
    assert_eq!(answered["stderr"], "bad\n");
    assert_eq!(answered["containment_failed"], false);
}

#[cfg(unix)]
#[test]
fn a_closed_stdin_stops_the_child_tree() {
    // The request line is the whole of stdin, so the reader hits EOF at once:
    // the caller that is interrupted or dies leaves no child running.
    let body = json!({
        "op": "launch",
        "command": ["/bin/sh", "-c", "sleep 30 & wait"],
        "cwd": std::env::temp_dir().to_string_lossy(),
        "environment": { "PATH": std::env::var("PATH").unwrap_or_default() },
        "timeout_millis": 20000,
    });
    let started = std::time::Instant::now();
    let answer =
        run_command(std::io::Cursor::new(format!("{body}\n").into_bytes())).expect("answers");
    let parsed: Value = serde_json::from_slice(&answer).unwrap();
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(parsed["timed_out"], false);
    assert_eq!(parsed["containment_failed"], false);
}

#[cfg(unix)]
#[test]
fn raw_output_carries_the_exact_bytes_each_stream_wrote() {
    let command = ["/bin/sh", "-c", "printf 'a\\377b'; printf 'e\\200' >&2"];
    let raw = launch(&command, "", 5000, r#"{"raw_output": true}"#);
    assert_eq!(raw["stdout_hex"], "61ff62");
    assert_eq!(raw["stderr_hex"], "6580");
    // The decoded text is the lossy form of the same bytes.
    assert_eq!(raw["stdout"], "a\u{fffd}b");
    let plain = launch(&command, "", 5000, "");
    assert_eq!(plain["stdout_hex"], Value::Null);
    assert_eq!(plain["stderr_hex"], Value::Null);
}

use super::*;
use base64::Engine as _;

fn request(argv: &[&str], timeout_seconds: f64, output_limit_bytes: usize) -> Value {
    json!({
        "schema": SCHEMA,
        "argv": argv,
        "cwd": std::env::temp_dir().to_string_lossy(),
        "env": {},
        "timeout_seconds": timeout_seconds,
        "output_limit_bytes": output_limit_bytes,
    })
}

fn answer(request: &Value) -> Result<Value, String> {
    run_command(request.to_string().as_bytes())
        .map(|bytes| serde_json::from_slice(&bytes).expect("answer is JSON"))
}

fn decoded(answer: &Value, stream: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(answer[stream].as_str().expect("stream is text"))
        .expect("stream is base64")
}

#[test]
fn invalid_budgets_and_requests_are_refused_before_spawn() {
    let base = request(&["/bin/true"], 1.0, 4096);
    let mut cases = Vec::new();
    for (field, value) in [
        ("timeout_seconds", json!(0)),
        ("timeout_seconds", json!(-1)),
        ("timeout_seconds", json!(3601)),
        ("timeout_seconds", json!("1")),
        ("output_limit_bytes", json!(0)),
        ("output_limit_bytes", json!(131073)),
        ("output_limit_bytes", json!(1.5)),
        ("schema", json!("bounded-probe.v0")),
        ("argv", json!([])),
        ("cwd", json!("relative")),
        ("unknown", json!(true)),
    ] {
        let mut case = base.clone();
        case[field] = value;
        cases.push(case);
    }
    for case in cases {
        assert_eq!(
            answer(&case).expect_err("request is refused"),
            "bounded_probe_request_invalid",
            "{case}"
        );
    }
}

#[test]
fn a_missing_executable_reports_an_execution_failure() {
    let probe = answer(&request(&["/nonexistent/hol-guard-probe"], 1.0, 4096)).expect("answer");
    assert_eq!(probe, json!({ "error": "execution_failed" }));
}

#[cfg(unix)]
mod unix {
    use super::*;

    fn shell(script: &str, timeout_seconds: f64, output_limit_bytes: usize) -> Value {
        answer(&request(
            &["/bin/sh", "-c", script],
            timeout_seconds,
            output_limit_bytes,
        ))
        .expect("answer")
    }

    #[test]
    fn both_streams_and_the_exit_status_are_returned() {
        let probe = shell("printf out; printf err >&2; exit 3", 5.0, 4096);
        assert_eq!(probe["returncode"], 3);
        assert_eq!(decoded(&probe, "stdout"), b"out");
        assert_eq!(decoded(&probe, "stderr"), b"err");
        assert_eq!(probe["timed_out"], false);
        assert_eq!(probe["output_overflow"], false);
        assert_eq!(probe["capture_incomplete"], false);
    }

    #[test]
    fn the_probe_gets_no_stdin_and_only_the_given_environment() {
        let mut probe_request = request(
            &[
                "/bin/sh",
                "-c",
                "read line; printf '%s|%s' \"$line\" \"$PROBE_VALUE$HOME\"",
            ],
            5.0,
            4096,
        );
        probe_request["env"] = json!({ "PROBE_VALUE": "kept" });
        let probe = answer(&probe_request).expect("answer");
        assert_eq!(decoded(&probe, "stdout"), b"|kept");
    }

    #[test]
    fn the_streams_share_one_budget_and_an_overrun_stops_the_probe() {
        let started = Instant::now();
        let probe = shell(
            "printf 'aaaa'; printf 'bbbb' >&2; sleep 1; head -c 4096 /dev/zero; sleep 30",
            30.0,
            16,
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(probe["output_overflow"], true);
        assert_eq!(probe["timed_out"], false);
        let kept = decoded(&probe, "stdout").len() + decoded(&probe, "stderr").len();
        assert_eq!(kept, 16);
        assert_eq!(decoded(&probe, "stderr"), b"bbbb");
    }

    #[test]
    fn a_probe_past_its_deadline_is_killed() {
        let started = Instant::now();
        let probe = shell("printf started; sleep 30", 0.3, 4096);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(probe["timed_out"], true);
        assert_eq!(probe["returncode"], -9);
        assert_eq!(decoded(&probe, "stdout"), b"started");
    }

    #[test]
    fn a_descendant_holding_the_pipe_times_out_and_dies_with_the_group() {
        let directory = tempfile::tempdir().expect("tempdir");
        let effect = directory.path().join("effect");
        let script = format!(
            "(sleep 2; printf ran > '{}') & printf 'version 1\\n'",
            effect.display()
        );
        let probe = shell(&script, 0.5, 4096);
        assert_eq!(probe["timed_out"], true);
        assert_eq!(probe["returncode"], 0);
        std::thread::sleep(Duration::from_millis(2500));
        assert!(!effect.exists(), "the descendant outlived the probe");
    }

    #[test]
    fn binary_output_round_trips() {
        let probe = shell("printf '\\377\\000\\376'", 5.0, 4096);
        assert_eq!(decoded(&probe, "stdout"), [0xff, 0x00, 0xfe]);
    }
}

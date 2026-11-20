//! The config RPC client against a fake `codex app-server` written in `/bin/sh`.

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::*;

const SCRIPT: &str = r#"#!/bin/sh
mode=MODE
big() { head -c "$1" /dev/zero | tr '\0' "$2"; }
while IFS= read -r line; do
  printf '%s\n' "$line" >> requests.log
  case "$line" in
    *'"id":'*) ;;
    *) continue ;;
  esac
  id=$(printf '%s' "$line" | sed 's/.*"id":\([0-9]*\).*/\1/')
  case "$line" in
    *'"method":"initialize"'*)
      if [ "$mode" = slow ]; then sleep 0.3; fi
      printf '{"id":%s,"result":{"userAgent":"fixture"}}\n' "$id"
      if [ "$mode" = blocked_input ]; then exec sleep 60; fi
      continue ;;
  esac
  case "$mode" in
    exit) echo "private configuration must never be logged" >&2; exit 7 ;;
    timeout) trap '' TERM; exec sleep 60 ;;
    oversized) big 1048577 x; echo ;;
    duplicate) printf '{"id":%s,"result":{},"result":{"private":"never expose"}}\n' "$id" ;;
    wrong_id) printf '{"id":true,"result":{}}\n' ;;
    float_id) printf '{"id":%s.0,"result":{}}\n' "$id" ;;
    nonfinite) printf '{"id":%s,"result":{"version":NaN}}\n' "$id" ;;
    deep) printf '{"id":%s,"result":{"nested":%s0%s}}\n' "$id" "$(big 2000 '[')" "$(big 2000 ']')" ;;
    bad_error_code) printf '{"id":%s,"error":{"data":{"code":{"private":"never expose"}}}}\n' "$id" ;;
    conflict) printf '{"id":%s,"error":{"code":-32000,"data":{"configWriteErrorCode":"configVersionConflict"},"message":"private configuration must not be exposed"}}\n' "$id" ;;
    readonly) printf '{"id":%s,"error":{"data":"configLayerReadonly"}}\n' "$id" ;;
    notifications) i=0; while [ $i -lt 3 ]; do printf '{"method":"note"}\n'; i=$((i+1)); done
      printf '{"id":%s,"result":{"accepted":true}}\n' "$id" ;;
    slow) sleep 0.3; printf '{"id":%s,"result":{"accepted":true}}\n' "$id" ;;
    grandchild) sleep 60 >/dev/null 2>&1 </dev/null & echo $! > grandchild.pid
      trap '' TERM; wait ;;
    flood) i=0; while [ $i -lt 70 ]; do printf '{"method":"note"}\n'; i=$((i+1)); done ;;
    *) printf '{"id":%s,"result":{"accepted":true}}\n' "$id" ;;
  esac
done
"#;

fn environment() -> Vec<(String, String)> {
    vec![("PATH".to_owned(), "/usr/bin:/bin".to_owned())]
}

fn write_host(dir: &Path, mode: &str) -> String {
    let path = dir.join("app-server");
    fs::write(&path, SCRIPT.replace("MODE", mode)).expect("script");
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("mode");
    path.to_string_lossy().into_owned()
}

/// Starts the fake host. A fresh script can briefly be busy for exec while
/// another test thread forks, so a failed start is tried again.
fn open_host(dir: &Path, mode: &str) -> ConfigRpc {
    let executable = write_host(dir, mode);
    for _ in 0..20 {
        let opened = ConfigRpc::open(
            &executable,
            Some(dir),
            &environment(),
            Duration::from_millis(500),
        );
        if let Ok(rpc) = opened {
            return rpc;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("fake host did not start");
}

fn logged_methods(dir: &Path) -> Vec<String> {
    fs::read_to_string(dir.join("requests.log"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|message| message["method"].as_str().map(str::to_owned))
        .collect()
}

fn read(rpc: &mut ConfigRpc) -> Result<Map<String, Value>, Reason> {
    rpc.request("config/read", &json!({"includeLayers": true}))
}

#[test]
fn rpc_only_initializes_and_uses_allowed_configuration_operations() {
    let dir = tempfile::tempdir().expect("dir");
    let mut rpc = open_host(dir.path(), "normal");

    assert_eq!(read(&mut rpc).expect("read"), {
        let mut expected = Map::new();
        expected.insert("accepted".to_owned(), json!(true));
        expected
    });
    assert_eq!(rpc.request("turn/start", &json!({})), Err(UNSUPPORTED));
    assert_eq!(
        rpc.request("config/batchWrite", &json!({"edits": []})),
        Err(VERSION_REQUIRED)
    );
    assert!(rpc
        .request(
            "config/batchWrite",
            &json!({"expectedVersion": "version-1", "edits": []})
        )
        .is_ok());
    rpc.close();

    assert_eq!(
        logged_methods(dir.path()),
        [
            "initialize",
            "initialized",
            "config/read",
            "config/batchWrite"
        ]
    );
    assert!(rpc.exit_code().is_some());
}

#[test]
fn invalid_or_conflicting_responses_fail_without_exposing_payloads() {
    let cases = [
        ("oversized", LIMIT),
        ("duplicate", INVALID),
        ("wrong_id", INVALID),
        ("float_id", INVALID),
        ("nonfinite", INVALID),
        ("deep", INVALID),
        ("bad_error_code", REJECTED),
        ("conflict", CHANGED),
        ("readonly", READONLY),
        ("flood", LIMIT),
    ];
    for (mode, reason) in cases {
        let dir = tempfile::tempdir().expect("dir");
        let mut rpc = open_host(dir.path(), mode);

        let outcome = read(&mut rpc);

        assert_eq!(outcome, Err(reason), "{mode}");
        assert!(!reason.contains("private"), "{mode}");
        rpc.close();
        assert!(rpc.exit_code().is_some(), "{mode}");
    }
}

#[test]
fn notifications_before_the_reply_are_skipped() {
    let dir = tempfile::tempdir().expect("dir");
    let mut rpc = open_host(dir.path(), "notifications");

    assert!(read(&mut rpc).is_ok());
}

#[test]
fn stalled_response_terminates_only_the_task_owned_host() {
    let dir = tempfile::tempdir().expect("dir");
    let mut rpc = open_host(dir.path(), "timeout");
    let started = Instant::now();

    assert_eq!(read(&mut rpc), Err(TIMEOUT));
    rpc.close();

    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(rpc.exit_code().is_some());
}

#[test]
fn process_exit_is_unavailable_and_its_diagnostics_are_never_surfaced() {
    let dir = tempfile::tempdir().expect("dir");
    let mut rpc = open_host(dir.path(), "exit");

    let outcome = read(&mut rpc);

    assert_eq!(outcome, Err(UNAVAILABLE));
    rpc.close();
    assert_eq!(rpc.exit_code(), Some(Some(7)));
}

#[test]
fn stalled_input_pipe_cannot_bypass_timeout_or_prevent_cleanup() {
    let dir = tempfile::tempdir().expect("dir");
    let mut rpc = open_host(dir.path(), "blocked_input");
    let started = Instant::now();

    let outcome = rpc.request(
        "config/batchWrite",
        &json!({"expectedVersion": "1", "fixture": "x".repeat(200_000)}),
    );
    rpc.close();

    assert_eq!(outcome, Err(TIMEOUT));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(rpc.exit_code().is_some());
}

#[test]
fn invalid_version_values_are_rejected_before_any_write() {
    let dir = tempfile::tempdir().expect("dir");
    let mut rpc = open_host(dir.path(), "normal");
    let too_long = json!("x".repeat(257));

    for version in [
        Value::Null,
        json!(true),
        json!(1),
        json!({}),
        json!([]),
        json!(""),
        too_long,
    ] {
        assert_eq!(
            rpc.request(
                "config/batchWrite",
                &json!({"expectedVersion": version, "edits": []})
            ),
            Err(VERSION_REQUIRED),
            "{version}"
        );
    }
    rpc.close();

    assert!(!logged_methods(dir.path()).contains(&"config/batchWrite".to_owned()));
}

#[test]
fn a_host_that_cannot_start_is_unavailable() {
    let dir = tempfile::tempdir().expect("dir");
    let missing = dir.path().join("no-such-codex");

    let outcome = ConfigRpc::open(
        &missing.to_string_lossy(),
        Some(dir.path()),
        &environment(),
        Duration::from_millis(500),
    );

    assert_eq!(outcome.err(), Some(UNAVAILABLE));
}

#[test]
fn depth_limit_ignores_brackets_and_escaped_quotes_inside_strings() {
    let payload =
        json!({"description": format!("{}\\\"{}", "[".repeat(1000), "}".repeat(1000))}).to_string();
    assert!(depth_within_limit(payload.as_bytes()));
    assert!(depth_within_limit(
        format!("{}0{}", "[".repeat(64), "]".repeat(64)).as_bytes()
    ));
    assert!(!depth_within_limit(
        format!("{}0{}", "[".repeat(65), "]".repeat(65)).as_bytes()
    ));
}

#[test]
fn the_message_parser_refuses_repeated_keys_constants_and_trailing_text() {
    assert!(parse(b"{\"id\":1,\"result\":{}}\n").is_some());
    assert!(parse(b"{\"id\":1,\"id\":2}\n").is_none());
    assert!(parse(b"{\"version\":NaN}\n").is_none());
    assert!(parse(b"{\"id\":1} trailing\n").is_none());
}

/// Whether the process still exists (a zombie that init has not reaped yet counts).
fn process_exists(pid: i32) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;
    kill(Pid::from_raw(pid), None).is_ok()
}

#[test]
fn stopping_a_stalled_host_also_stops_what_it_started() {
    let dir = tempfile::tempdir().expect("dir");
    let mut rpc = open_host(dir.path(), "grandchild");

    assert_eq!(read(&mut rpc), Err(TIMEOUT));
    rpc.close();

    let pid: i32 = fs::read_to_string(dir.path().join("grandchild.pid"))
        .expect("the host started a child")
        .trim()
        .parse()
        .expect("pid");
    let deadline = Instant::now() + Duration::from_secs(5);
    while process_exists(pid) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(!process_exists(pid), "the host's child outlived the host");
}

#[test]
fn the_session_ends_itself_and_its_host_before_a_caller_deadline_can_kill_it() {
    let dir = tempfile::tempdir().expect("dir");
    let executable = write_host(dir.path(), "slow");
    let started = Instant::now();
    // Each reply takes 0.3 s and each request may take 5 s, so only the
    // session limit can end this.
    let mut rpc = ConfigRpc::open_within(
        &executable,
        Some(dir.path()),
        &environment(),
        Duration::from_secs(5),
        Duration::from_millis(700),
    )
    .expect("the handshake fits in the limit");

    let outcomes: Vec<_> = (0..6).map(|_| read(&mut rpc)).collect();

    assert!(outcomes.contains(&Err(TIMEOUT)), "{outcomes:?}");
    let first_timeout = outcomes.iter().position(|o| *o == Err(TIMEOUT)).unwrap();
    assert!(outcomes[first_timeout..].iter().all(|o| *o == Err(TIMEOUT)));
    assert!(started.elapsed() < Duration::from_secs(4));
    rpc.close();
    assert!(rpc.exit_code().is_some());
}

#[test]
fn a_session_with_no_time_left_does_not_start_a_host_exchange() {
    let dir = tempfile::tempdir().expect("dir");
    let executable = write_host(dir.path(), "normal");

    let outcome = ConfigRpc::open_within(
        &executable,
        Some(dir.path()),
        &environment(),
        Duration::from_secs(5),
        Duration::ZERO,
    );

    assert_eq!(outcome.err(), Some(UNAVAILABLE));
    assert!(logged_methods(dir.path()).is_empty());
}

#[test]
fn the_session_limit_sits_below_the_callers_deadline() {
    // The Python caller kills the op at 75 s (`runtime/codex_mcp_setup.py`).
    assert!(SESSION_LIMIT + Duration::from_secs(10) <= Duration::from_secs(75));
}

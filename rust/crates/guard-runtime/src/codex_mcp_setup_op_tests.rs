//! The `codex-mcp-setup` command: request checks, and a host process it starts.

use super::*;

#[test]
fn setup_rejects_configuration_key_injection() {
    let too_long = "a".repeat(65);
    let longest = "a".repeat(64);
    for name in [
        "other.config",
        "../../config",
        "",
        too_long.as_str(),
        "Upper",
        "-lead",
        "_lead",
    ] {
        assert!(!valid_name(name), "{name}");
        let request = json!({
            "op": "install",
            "executable": "/nonexistent/codex",
            "cwd": "/",
            "environment": {},
            "name": name,
            "entry_json": "{\"url\":\"https://example.test\"}",
        });

        let answer = run_command(request.to_string().as_bytes()).expect("answer");

        let answer: Value = serde_json::from_slice(&answer).expect("json");
        assert_eq!(answer["error"], json!(INVALID_SELECTION), "{name}");
    }
    for name in ["reviewed", "a", "0x_y-z", longest.as_str()] {
        assert!(valid_name(name), "{name}");
    }
}

#[test]
fn a_rollback_request_with_an_unreadable_receipt_entry_is_refused() {
    let request = json!({
        "op": "rollback",
        "executable": "/nonexistent/codex",
        "cwd": "/",
        "environment": {},
        "receipt": {"name": "reviewed", "file_path": "/x", "version": "1", "entry_json": "{"},
    });

    let answer = run_command(request.to_string().as_bytes()).expect("answer");

    let answer: Value = serde_json::from_slice(&answer).expect("json");
    assert_eq!(answer["error"], json!(INVALID_RECEIPT));
}

#[test]
fn a_malformed_request_is_an_error_not_an_answer() {
    assert!(run_command(&b"{\"op\":\"other\"}"[..]).is_err());
    assert!(run_command(&b"not json"[..]).is_err());
}

#[cfg(unix)]
mod through_a_host_process {
    use std::fs;
    use std::time::Duration;

    use super::*;

    const SCRIPT: &str = r#"#!/bin/sh
[ "$HOL_PROBE" = 1 ] || exit 3
while IFS= read -r line; do
  case "$line" in *'"id":'*) ;; *) continue ;; esac
  id=$(printf '%s' "$line" | sed 's/.*"id":\([0-9]*\).*/\1/')
  case "$line" in
    *'"method":"initialize"'*) printf '{"id":%s,"result":{}}\n' "$id" ;;
    *) printf '{"id":%s,"result":{"layers":[{"name":{"type":"user","file":"/synthetic/config.toml","profile":null},"version":"1","config":{"mcp_servers":{"reviewed":{"url":"https://example.test"}}}}]}}\n' "$id" ;;
  esac
done
"#;

    fn ask(request: &Value) -> Value {
        for _ in 0..20 {
            let answer = run_command(request.to_string().as_bytes()).expect("answer");
            let answer: Value = serde_json::from_slice(&answer).expect("json");
            if answer["error"] != json!("codex_config_rpc_unavailable") {
                return answer;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("host never answered");
    }

    fn host(dir: &std::path::Path) -> String {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("codex");
        fs::write(&path, SCRIPT).expect("script");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("mode");
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn the_op_starts_the_host_with_the_environment_it_was_given() {
        let dir = tempfile::tempdir().expect("dir");
        let executable = host(dir.path());
        let environment = json!({"PATH": "/usr/bin:/bin", "HOL_PROBE": "1"});

        let install = ask(&json!({
            "op": "install",
            "executable": executable,
            "cwd": dir.path(),
            "environment": environment,
            "name": "reviewed",
            "entry_json": "{\"url\":\"https://example.test\"}",
        }));
        let rollback = ask(&json!({
            "op": "rollback",
            "executable": executable,
            "cwd": dir.path(),
            "environment": environment,
            "receipt": {
                "name": "reviewed",
                "file_path": "/synthetic/config.toml",
                "version": "2",
                "entry_json": "{\"url\":\"https://example.test\"}",
                "previous_version": "1",
            },
        }));

        assert_eq!(install["error"], json!(EXISTS));
        assert_eq!(rollback["error"], json!(CHANGED));
    }

    #[test]
    fn a_host_that_cannot_start_is_reported_as_unavailable() {
        let dir = tempfile::tempdir().expect("dir");
        let missing = dir.path().join("no-such-codex");

        let answer = run_command(
            json!({
                "op": "install",
                "executable": missing,
                "cwd": dir.path(),
                "environment": {},
                "name": "reviewed",
                "entry_json": "{}",
            })
            .to_string()
            .as_bytes(),
        )
        .expect("answer");

        let answer: Value = serde_json::from_slice(&answer).expect("json");
        assert_eq!(answer["error"], json!("codex_config_rpc_unavailable"));
    }
}

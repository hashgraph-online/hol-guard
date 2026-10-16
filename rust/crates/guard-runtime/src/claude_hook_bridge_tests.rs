//! The bridge's config, query and URL rules, and its end-to-end flow
//! against a scripted loopback daemon and real fallback processes.

use std::io::Cursor;

use super::*;
use crate::claude_hook_bridge_fixture::{closed_port, home_with_daemon, Exchange, GuardHome};
use crate::claude_hook_bridge_url::{py_unquote, query_values};

const PRE_TOOL_USE: &str =
    r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
const ALLOW: &str =
    r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}"#;
const FALLBACK_ALLOW: &str = r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"fallback"}}"#;

fn shell(script: &str) -> Vec<String> {
    vec!["/bin/sh".to_owned(), "-c".to_owned(), script.to_owned()]
}

fn fallback_printing(body: &str) -> Vec<String> {
    shell(&format!("cat >/dev/null; printf '%s' '{body}'"))
}

fn fallback_exiting(code: u8) -> Vec<String> {
    shell(&format!("cat >/dev/null; exit {code}"))
}

fn config_for(home: &GuardHome, fallback: Vec<String>, recovery: Vec<String>) -> String {
    serde_json::json!({
        "state_path": home.state_path.to_str().unwrap(),
        "fallback_daemon_url": format!("http://127.0.0.1:{}", closed_port()),
        "query": format!("guard-home={}", home.home_text().replace('/', "%2F")),
        "fallback_command": fallback,
        "recovery_command": recovery,
    })
    .to_string()
}

fn respond(config: &str, input: &str) -> String {
    hook_response(config, &mut Cursor::new(input.as_bytes().to_vec())).expect("hook response")
}

fn degraded_reason(output: &str) -> String {
    let payload: serde_json::Value = serde_json::from_str(output).expect("hook JSON");
    let reason = payload["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .expect("deny reason");
    assert_eq!(
        payload["hookSpecificOutput"]["permissionDecision"], "deny",
        "{output}"
    );
    reason.to_owned()
}

#[test]
fn daemon_answer_is_forwarded_with_its_proof() {
    let (home, daemon) = home_with_daemon("allow", vec![Exchange::Hook(200, ALLOW.to_owned())]);
    let config = config_for(&home, fallback_exiting(3), Vec::new());
    assert_eq!(respond(&config, PRE_TOOL_USE), ALLOW);
    let hooks = daemon.join().unwrap();
    let [hook] = hooks.as_slice() else {
        panic!("one hook request, got {hooks:?}");
    };
    assert!(
        hook.target.starts_with("/v1/hooks/claude-code?guard-home="),
        "{}",
        hook.target
    );
    assert_eq!(hook.header("X-Guard-Daemon-Proof").map(str::len), Some(64));
    assert_eq!(hook.header("X-Guard-Daemon-Nonce").map(str::len), Some(64));
    let body: serde_json::Value = serde_json::from_slice(&hook.body).unwrap();
    assert_eq!(body["tool_name"], "Bash");
}

#[test]
fn refused_authentication_denies_without_fallback() {
    let (home, daemon) = home_with_daemon(
        "unauthorized",
        vec![Exchange::RefuseChallenge(401, "denied")],
    );
    let config = config_for(&home, fallback_printing(FALLBACK_ALLOW), Vec::new());
    let reason = degraded_reason(&respond(&config, PRE_TOOL_USE));
    assert_eq!(
        reason,
        "HOL Guard denied the action because daemon authentication failed: \
         daemon returned HTTP 401: denied"
    );
    daemon.join().unwrap();
}

#[test]
fn unavailable_daemon_is_denied_without_the_local_hook() {
    let (home, daemon) = home_with_daemon(
        "fallback",
        vec![Exchange::Hook(503, "unavailable".to_owned())],
    );
    let config = config_for(&home, fallback_printing(FALLBACK_ALLOW), Vec::new());
    assert_eq!(
        degraded_reason(&respond(&config, PRE_TOOL_USE)),
        "HOL Guard could not complete native review \
         (daemon returned HTTP 503: unavailable) and denied this action."
    );
    daemon.join().unwrap();
}

#[test]
fn overloaded_daemon_is_denied_without_the_local_hook() {
    let (home, daemon) = home_with_daemon("overload", vec![Exchange::Hook(429, "busy".to_owned())]);
    let config = config_for(&home, fallback_printing(FALLBACK_ALLOW), shell("exit 0"));
    let reason = degraded_reason(&respond(&config, PRE_TOOL_USE));
    assert!(reason.contains("HTTP 429"), "{reason}");
    assert_eq!(daemon.join().unwrap().len(), 1);
}

#[test]
fn missing_state_is_denied_without_the_local_hook() {
    let home = GuardHome::new("missing");
    std::fs::remove_file(home.home.join("daemon-discovery-key")).unwrap();
    let config = config_for(&home, fallback_exiting(3), Vec::new());
    assert_eq!(
        degraded_reason(&respond(&config, PRE_TOOL_USE)),
        "HOL Guard could not complete native review \
         (daemon state is unavailable) and denied this action."
    );
}

#[test]
fn non_http_fallback_url_is_a_control_plane_failure() {
    let home = GuardHome::new("https");
    let mut config: serde_json::Value = serde_json::from_str(&config_for(
        &home,
        fallback_printing(FALLBACK_ALLOW),
        Vec::new(),
    ))
    .unwrap();
    config["fallback_daemon_url"] = "https://127.0.0.1:1".into();
    let reason = degraded_reason(&respond(&config.to_string(), PRE_TOOL_USE));
    assert_eq!(
        reason,
        "HOL Guard denied the action because daemon authentication failed: \
         daemon URL must use http, not 'https'"
    );
}

#[test]
fn query_for_another_home_is_refused_without_the_fallback() {
    let home = GuardHome::new("mismatch");
    let mut config: serde_json::Value =
        serde_json::from_str(&config_for(&home, fallback_exiting(3), Vec::new())).unwrap();
    config["query"] = "guard-home=%2Felsewhere".into();
    assert_eq!(
        degraded_reason(&respond(&config.to_string(), PRE_TOOL_USE)),
        "HOL Guard could not complete native review (daemon state path does not \
         match the hook Guard home) and denied this action."
    );
}

#[test]
fn oversized_input_is_denied() {
    let home = GuardHome::new("oversized");
    let config = config_for(&home, fallback_printing(FALLBACK_ALLOW), Vec::new());
    let input = " ".repeat(MAX_HOOK_INPUT_BYTES + 1);
    assert_eq!(
        degraded_reason(&respond(&config, &input)),
        "HOL Guard blocked this action because hook input exceeded the safe size limit."
    );
}

#[test]
fn invalid_config_is_denied() {
    assert_eq!(
        degraded_reason(&respond("{}", PRE_TOOL_USE)),
        format!(
            "HOL Guard could not complete native review ({INVALID_CONFIG}) and denied this action."
        )
    );
}

#[test]
fn failed_recovery_retry_is_reported() {
    let home = GuardHome::new("retry");
    home.write_state(&home.state(closed_port()));
    let config = config_for(&home, fallback_exiting(3), shell("exit 0"));
    let reason = degraded_reason(&respond(&config, PRE_TOOL_USE));
    assert!(
        reason.contains("; daemon recovery retry failed: "),
        "{reason}"
    );
    assert!(reason.ends_with(") and denied this action."), "{reason}");
    assert!(!reason.contains("fallback"), "{reason}");
}

#[test]
fn a_daemon_the_recovery_starts_later_answers_the_hook_once() {
    let (home, daemon) = home_with_daemon(
        "started-later",
        vec![
            Exchange::ProveIdentity,
            Exchange::Hook(200, ALLOW.to_owned()),
        ],
    );
    // The recovery command only schedules the start: the daemon's state
    // appears a little after the command has already exited.
    let pending = home.scratch("pending-state.json");
    std::fs::rename(&home.state_path, &pending).unwrap();
    let marker = home.scratch("recovery-ran");
    let config = config_for(
        &home,
        fallback_exiting(3),
        shell(&format!(": > '{}'", marker.display())),
    );
    let state_path = home.state_path.clone();
    let publisher = std::thread::spawn(move || {
        while !marker.exists() {
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(300));
        std::fs::rename(pending, state_path).unwrap();
    });
    assert_eq!(respond(&config, PRE_TOOL_USE), ALLOW);
    publisher.join().unwrap();
    assert_eq!(daemon.join().unwrap().len(), 1);
}

#[test]
fn recovered_daemon_answers_the_retry() {
    let (home, daemon) = home_with_daemon(
        "recovered",
        vec![
            Exchange::RefuseChallenge(503, "down"),
            Exchange::ProveIdentity,
            Exchange::Hook(200, ALLOW.to_owned()),
        ],
    );
    let marker = home.scratch("failure-kind");
    let recovery = shell(&format!(
        "printf '%s' \"$HOL_GUARD_HOOK_FAILURE_KIND\" > '{}'",
        marker.display()
    ));
    let config = config_for(&home, fallback_exiting(3), recovery);
    assert_eq!(respond(&config, PRE_TOOL_USE), ALLOW);
    assert_eq!(
        std::fs::read_to_string(marker).unwrap(),
        "transport-failure"
    );
    assert_eq!(daemon.join().unwrap().len(), 1);
}

#[test]
fn config_requires_string_fields_and_a_fallback() {
    let valid = r#"{"state_path":"/h/daemon-state.json","fallback_daemon_url":"http://127.0.0.1:1","query":"guard-home=%2Fh","fallback_command":["guard"]}"#;
    let config = parse_config(valid).unwrap();
    assert!(config.recovery_command.is_empty());
    for invalid in [
        "[]",
        r#"{"state_path":"/h/daemon-state.json","fallback_daemon_url":"x","query":"q","fallback_command":[]}"#,
        r#"{"state_path":1,"fallback_daemon_url":"x","query":"q","fallback_command":["g"]}"#,
        r#"{"state_path":"s","fallback_daemon_url":"x","query":"q","fallback_command":["g"],"recovery_command":[1]}"#,
    ] {
        assert_eq!(parse_config(invalid), None, "{invalid}");
    }
}

#[test]
fn unquote_and_query_values_follow_urllib() {
    assert_eq!(py_unquote("%2Fa%zz%4"), "/a%zz%4");
    assert_eq!(py_unquote("%E2%82%AC"), "\u{20ac}");
    assert_eq!(py_unquote("%FF"), "\u{fffd}");
    assert_eq!(py_unquote("caf\u{e9}%21"), "caf\u{e9}!");
    assert_eq!(
        query_values(
            "guard-home=%2Fx+y&guard-home=&flag&guard%2Dhome=%2Fz",
            "guard-home"
        ),
        ["/x y", "/z"]
    );
}

#[test]
fn state_path_is_bound_to_one_guard_home() {
    let cases = [
        (
            "",
            "guard-home=%2Fh",
            "daemon state path must be a non-empty filesystem path",
        ),
        (
            "relative/daemon-state.json",
            "guard-home=%2Fh",
            "daemon state path must be an absolute daemon-state.json path",
        ),
        (
            "/h/other.json",
            "guard-home=%2Fh",
            "daemon state path must be an absolute daemon-state.json path",
        ),
        (
            "/h/daemon-state.json",
            "guard-home=%2Fh&guard-home=%2Fh",
            "daemon hook query must bind one Guard home",
        ),
        (
            "/h/daemon-state.json",
            "other=1",
            "daemon hook query must bind one Guard home",
        ),
        (
            "/h/daemon-state.json",
            "guard-home=%2Fh%00",
            "daemon hook query contains an invalid Guard home",
        ),
        (
            "/h/daemon-state.json",
            "guard-home=h",
            "daemon state path does not match the hook Guard home",
        ),
        (
            "/h/daemon-state.json",
            "guard-home=%2Fg",
            "daemon state path does not match the hook Guard home",
        ),
    ];
    for (raw, query, message) in cases {
        assert_eq!(
            state_path_for_query(raw, query),
            Err(message.to_owned()),
            "{raw} {query}"
        );
    }
    assert_eq!(
        state_path_for_query("/h/daemon-state.json", "guard-home=%2Fh"),
        Ok(PathBuf::from("/h/daemon-state.json"))
    );
}

#[test]
fn fallback_daemon_url_must_be_loopback_http() {
    for accepted in [
        "http://127.0.0.1:8080/",
        "http://[::1]:8080/",
        "  http://localhost:1/",
        "HTTP://LOCALHOST:65535",
    ] {
        assert_eq!(assert_loopback_http_url(accepted), Ok(()), "{accepted}");
    }
    let refused = [
        (
            "https://127.0.0.1:1/",
            "daemon URL must use http, not 'https'",
        ),
        ("127.0.0.1:1/", "daemon URL must use http, not ''"),
        (
            "http://example.com:1/",
            "daemon URL must target loopback, not 'example.com'",
        ),
        (
            "http://[evil]:1/",
            "daemon URL must target loopback, not 'evil'",
        ),
        ("http://[::1/", "Invalid IPv6 URL"),
        ("http://x[::1]:1/", "Invalid IPv6 URL"),
        (
            "http://127.0.0.1/",
            "daemon URL must include an explicit port",
        ),
        (
            "http://127.0.0.1:8x/",
            "Port could not be cast to integer value as '8x'",
        ),
        ("http://127.0.0.1:70000/", "Port out of range 0-65535"),
    ];
    for (url, message) in refused {
        assert_eq!(
            assert_loopback_http_url(url),
            Err(message.to_owned()),
            "{url}"
        );
    }
}

#[test]
fn endpoint_query_drops_controls_and_fragment() {
    assert_eq!(endpoint_query("a=1\t&b=2\n#frag"), "a=1&b=2");
    assert_eq!(endpoint_query("guard-home=%2Fh"), "guard-home=%2Fh");
}

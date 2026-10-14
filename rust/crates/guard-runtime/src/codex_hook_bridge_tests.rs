//! The native Codex bridge: Python parity for its inputs, routing of daemon
//! answers, and one authenticated exchange against a scripted daemon.

use std::net::TcpListener;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::*;
use crate::claude_hook_bridge_fixture::{spawn_daemon, write_private, Exchange, GuardHome};

const VECTORS: &str = include_str!("../testdata/codex_hook_bridge/vectors.json");
/// Windows config arguments from `encode_hook_config_argument(windows=True)`
/// and the text `decode_bridge_config_argument` returns for each (`null`
/// where Python refuses the argument).
const BASE64URL_CONFIGS: &str =
    include_str!("../testdata/codex_hook_bridge/base64url_configs.json");
const TOKEN: &str = "codex-token-fixture";

fn vectors(section: &str) -> Vec<Value> {
    let all: Value = serde_json::from_str(VECTORS).unwrap();
    all[section].as_array().unwrap().clone()
}

fn timeouts(pairs: &[(&str, i64)]) -> Vec<(String, i64)> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), *value))
        .collect()
}

#[test]
fn config_arguments_are_accepted_as_python_accepts_them() {
    for case in vectors("configs") {
        let argument = case["argument"].as_str().unwrap();
        let expected = case["expected"].as_object().map(|config| BridgeConfig {
            state_path: config["state_path"].as_str().unwrap().to_owned(),
            query: config["query"].as_str().unwrap().to_owned(),
            hook_timeouts: config["hook_timeouts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|pair| {
                    (
                        pair[0].as_str().unwrap().to_owned(),
                        pair[1].as_i64().unwrap(),
                    )
                })
                .collect(),
        });
        assert_eq!(parse_config(argument), expected, "{argument}");
    }
}

#[test]
fn base64url_config_arguments_decode_as_python_decodes_them() {
    let all: Value = serde_json::from_str(BASE64URL_CONFIGS).unwrap();
    let mut accepted = 0;
    for case in all["cases"].as_array().unwrap() {
        let argument = case["argument"].as_str().unwrap();
        let decoded = case["decoded"].as_str();
        assert_eq!(
            decode_config_argument(argument).as_deref(),
            decoded,
            "{argument:?}"
        );
        let expected = decoded.and_then(parse_config);
        accepted += usize::from(expected.is_some());
        assert_eq!(parse_config(argument), expected, "{argument:?}");
    }
    assert!(
        accepted >= 2,
        "the vectors must include accepted Windows configs"
    );
}

#[test]
fn incomplete_and_oversized_configs_are_left_to_python() {
    assert_eq!(parse_config("eyJzdGF0ZV9wYXRoIjoiIn0"), None);
    let huge = r#"{"state_path":"/h/daemon-state.json","manifest_path":"m","query":"","fallback_command":["x"],"start_command":["y"],"hook_timeouts":{"A":99999999999999999999}}"#;
    assert_eq!(parse_config(huge), None);
}

#[test]
fn request_timeouts_match_python() {
    for case in vectors("request_timeouts") {
        let pairs: Vec<(String, i64)> = case["hook_timeouts"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| (key.clone(), value.as_i64().unwrap()))
            .collect();
        let event = case["event"].as_str().unwrap();
        assert_eq!(
            request_timeout_seconds(event, &pairs),
            case["expected"].as_i64().unwrap(),
            "{case}"
        );
    }
}

#[test]
fn hook_input_is_bounded_and_normalized() {
    assert_eq!(
        bounded_hook_input(b"\xef\xbb\xbf{\"a\":1}").as_deref(),
        Some("{\"a\":1}")
    );
    assert_eq!(bounded_hook_input(b" \n\t").as_deref(), Some("{}"));
    assert_eq!(bounded_hook_input(b" {} ").as_deref(), Some(" {} "));
    assert_eq!(
        bounded_hook_input(&vec![b' '; MAX_HOOK_INPUT_BYTES]).as_deref(),
        Some("{}")
    );
    assert_eq!(
        bounded_hook_input(&vec![b' '; MAX_HOOK_INPUT_BYTES + 1]),
        None
    );
}

#[test]
fn only_sendable_queries_stay_native() {
    assert!(query_is_sendable("home=%2Fh&harness=codex"));
    assert!(query_is_sendable(""));
    for query in ["a b", "a\tb", "caf\u{e9}", "a\u{7f}"] {
        assert!(!query_is_sendable(query), "{query:?}");
    }
}

#[test]
fn clean_answers_are_rendered_natively() {
    let allow = r#"{"hookSpecificOutput":{"permissionDecision":"allow"},"policy_action":"allow","receipt":"r"}"#;
    assert_eq!(
        route_response(allow, PRE_TOOL_USE),
        Route::Respond(r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse"}}"#.to_owned())
    );
    let prompt = r#"{"continue":true,"systemMessage":"caf\u00e9"}"#;
    assert_eq!(
        route_response(prompt, "UserPromptSubmit"),
        Route::Respond(r#"{"continue":true,"systemMessage":"caf\u00e9"}"#.to_owned())
    );
    // A non-PreToolUse deny needs no Python post-processing.
    let post =
        r#"{"decision":"block","reason":"r","hookSpecificOutput":{"permissionDecision":"deny"}}"#;
    assert!(matches!(
        route_response(post, "PostToolUse"),
        Route::Respond(_)
    ));
    let lone = r#"{"systemMessage":"\ud800"}"#;
    assert_eq!(
        route_response(lone, "Stop"),
        Route::Respond(lone.to_owned())
    );
}

#[test]
fn answers_needing_python_are_handed_off() {
    for (text, event) in [
        (
            r#"{"hookSpecificOutput":{"permissionDecision":"deny"}}"#,
            PRE_TOOL_USE,
        ),
        (
            r#"{"hookSpecificOutput":{"permissionDecision":"allow"},"policy_action":"sandbox-required"}"#,
            PRE_TOOL_USE,
        ),
        (
            r#"{"continue":true,"guard_transition_observation":{}}"#,
            "Stop",
        ),
        (r#"{"guard_transition_observation":{"a":1}}"#, PRE_TOOL_USE),
    ] {
        assert_eq!(
            route_response(text, event),
            Route::Handoff(text.to_owned()),
            "{text}"
        );
    }
    // Python compares the decision exactly; other spellings stay native.
    let spaced = r#"{"hookSpecificOutput":{"permissionDecision":"Deny"}}"#;
    assert!(matches!(
        route_response(spaced, PRE_TOOL_USE),
        Route::Respond(_)
    ));
    let listed = r#"{"guard_transition_observation":[1]}"#;
    assert!(matches!(route_response(listed, "Stop"), Route::Respond(_)));
}

#[test]
fn failures_and_odd_answers_are_delegated() {
    for text in [
        "",
        "[]",
        "{",
        r#"{"reason_code":"daemon_hook_process_failed"}"#,
        "{\"systemMessage\":\"\\ud800\u{f0000}\"}",
    ] {
        assert_eq!(
            route_response(text, PRE_TOOL_USE),
            Route::Delegate,
            "{text:?}"
        );
    }
    let other = r#"{"reason_code":"policy_denied","continue":true}"#;
    assert!(matches!(route_response(other, "Stop"), Route::Respond(_)));
}

#[test]
fn pre_tool_input_carries_the_bridge_process() {
    let pairs = timeouts(&[("PreToolUse", 30)]);
    let prepared = prepare(
        r#"{"hook_event_name":"PreToolUse","tool_name":"Bash"}"#,
        &pairs,
    )
    .expect("prepared");
    assert_eq!(prepared.event_name, PRE_TOOL_USE);
    assert_eq!(prepared.timeout, Duration::from_secs(28));
    let data: Value = serde_json::from_str(&prepared.data).unwrap();
    assert_eq!(
        data[BROWSER_WAIT_PROCESS_KEY]["pid"],
        json!(std::process::id())
    );
    assert!(
        data[BROWSER_WAIT_PROCESS_KEY]["startToken"].is_string(),
        "{data}"
    );
    assert_eq!(data[BROWSER_WAIT_TIMEOUT_KEY], json!(27));
    assert_eq!(data["tool_name"], json!("Bash"));
}

#[test]
fn other_events_forward_their_own_input() {
    let pairs = timeouts(&[("Stop", 5), ("PreToolUse", 30)]);
    let raw = r#"{"hook_event_name":"Stop","guard_codex_browser_wait_process":{"pid":1}}"#;
    let prepared = prepare(raw, &pairs).expect("prepared");
    assert_eq!(prepared.event_name, "Stop");
    assert_eq!(prepared.timeout, Duration::from_secs(3));
    let data: Value = serde_json::from_str(&prepared.data).unwrap();
    assert_eq!(data[BROWSER_WAIT_PROCESS_KEY], json!({"pid": 1}));
}

#[test]
fn unclean_input_is_delegated() {
    let pairs = timeouts(&[("PreToolUse", 30)]);
    for raw in [
        "[]",
        "{",
        "{\"hook_event_name\":\"\\udc00\"}",
        "{\"a\":\"\\ud800\u{f0001}\"}",
    ] {
        assert!(prepare(raw, &pairs).is_none(), "{raw:?}");
    }
}

#[test]
fn handoff_envelope_carries_the_exchange() {
    let prepared = Prepared {
        event_name: PRE_TOOL_USE.to_owned(),
        data: "{\"a\":\"\u{e9}\"}".to_owned(),
        timeout: Duration::from_secs(28),
    };
    let envelope = handoff_envelope(&prepared, "{\"b\":1}", Duration::from_millis(42));
    assert!(envelope.is_ascii());
    let parsed: Value = serde_json::from_str(&envelope).unwrap();
    assert_eq!(
        parsed,
        json!({
            "schema": HANDOFF_SCHEMA,
            "hook_input": "{\"a\":\"\u{e9}\"}",
            "event_name": "PreToolUse",
            "daemon_response": "{\"b\":1}",
            "elapsed_ms": 42,
        })
    );
}

#[test]
fn python_runs_with_the_input_and_reports_its_exit_code() {
    let script = |body: &str| vec!["/bin/sh".to_owned(), "-c".to_owned(), body.to_owned()];
    let check = format!(
        "[ -n \"${ELAPSED_ENV}\" ] || exit 9; read -r line; [ \"$line\" = hello ] && exit 7; exit 8"
    );
    assert_eq!(
        run_python(&script(&check), b"hello\n", Duration::ZERO),
        Some(7)
    );
    assert_eq!(
        run_python(&script("exit 0"), &vec![b'x'; 1 << 20], Duration::ZERO),
        Some(0)
    );
    assert_eq!(
        run_python(&script("kill -9 $$"), b"", Duration::ZERO),
        Some(137)
    );
    assert_eq!(
        run_python(&["/nonexistent/python".to_owned()], b"", Duration::ZERO),
        None
    );
}

fn codex_home(
    label: &str,
    script: Vec<Exchange>,
) -> (
    GuardHome,
    std::thread::JoinHandle<Vec<crate::claude_hook_bridge_fixture::Request>>,
) {
    let home = GuardHome::new(label);
    write_private(&home.home.join("daemon-auth-token"), TOKEN);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut state = home.state(listener.local_addr().unwrap().port());
    state.insert(
        "auth_token_id".to_owned(),
        Value::String(hex::encode(Sha256::digest(TOKEN.as_bytes()))),
    );
    home.write_state(&state);
    let daemon = spawn_daemon(listener, state, script);
    (home, daemon)
}

fn config(home: &GuardHome) -> BridgeConfig {
    BridgeConfig {
        state_path: home.state_path.to_str().unwrap().to_owned(),
        query: "harness=codex&home=%2Fh".to_owned(),
        hook_timeouts: timeouts(&[("PreToolUse", 30), ("Stop", 10)]),
    }
}

#[test]
fn an_authenticated_answer_is_rendered() {
    let answer = r#"{"continue":true,"systemMessage":"ok","receipt":"r"}"#;
    let (home, daemon) = codex_home("codex-allow", vec![Exchange::Hook(200, answer.to_owned())]);
    write_private(&home.home.join(START_FAILED_MARKER), "{}");
    let (route, prepared) = route_hook(
        &config(&home),
        r#"{"hook_event_name":"Stop"}"#,
        Instant::now(),
    );
    assert_eq!(
        route,
        Route::Respond(r#"{"continue":true,"systemMessage":"ok"}"#.to_owned())
    );
    assert_eq!(prepared.unwrap().event_name, "Stop");
    assert!(!home.home.join(START_FAILED_MARKER).exists());
    let hooks = daemon.join().unwrap();
    assert_eq!(hooks.len(), 1);
    assert_eq!(hooks[0].target, "/v1/hooks/codex?harness=codex&home=%2Fh");
    assert_eq!(hooks[0].header("X-Guard-Token"), Some(TOKEN));
    assert!(hooks[0].header("X-Guard-Daemon-Proof").is_some());
    let body: Value = serde_json::from_slice(&hooks[0].body).unwrap();
    assert_eq!(body["hook_event_name"], json!("Stop"));
}

#[test]
fn a_daemon_failure_is_delegated() {
    let (home, daemon) = codex_home("codex-503", vec![Exchange::Hook(503, "down".to_owned())]);
    write_private(&home.home.join(START_FAILED_MARKER), "{}");
    let (route, _) = route_hook(
        &config(&home),
        r#"{"hook_event_name":"Stop"}"#,
        Instant::now(),
    );
    assert_eq!(route, Route::Delegate);
    assert!(home.home.join(START_FAILED_MARKER).exists());
    assert_eq!(daemon.join().unwrap().len(), 1);
}

#[test]
fn a_mismatched_token_is_delegated_before_the_hook_is_sent() {
    let (home, daemon) = codex_home("codex-token", vec![Exchange::Hook(200, "{}".to_owned())]);
    write_private(&home.home.join("daemon-auth-token"), "other-token");
    let (route, _) = route_hook(
        &config(&home),
        r#"{"hook_event_name":"Stop"}"#,
        Instant::now(),
    );
    assert_eq!(route, Route::Delegate);
    assert!(daemon.join().unwrap().is_empty());
}

#[test]
fn a_binding_capture_is_left_to_python() {
    let home = GuardHome::new("codex-capture");
    let diagnostics = home.home.join(CAPTURE_MARKER[0]);
    std::fs::create_dir_all(&diagnostics).unwrap();
    std::os::unix::fs::symlink("/nonexistent", diagnostics.join(CAPTURE_MARKER[1])).unwrap();
    let (route, prepared) = route_hook(
        &config(&home),
        r#"{"hook_event_name":"Stop"}"#,
        Instant::now(),
    );
    assert_eq!(route, Route::Delegate);
    assert!(prepared.is_none());
}

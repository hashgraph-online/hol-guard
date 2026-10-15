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
pub(super) const TOKEN: &str = "codex-token-fixture";

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
            // Every accepted vector names the same start and fallback
            // commands.
            start_command: vec!["y".to_owned()],
            fallback_command: vec!["x".to_owned()],
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
    assert!(client::query_is_sendable("home=%2Fh&harness=codex"));
    assert!(client::query_is_sendable(""));
    for query in ["a b", "a\tb", "caf\u{e9}", "a\u{7f}"] {
        assert!(!client::query_is_sendable(query), "{query:?}");
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
    assert!(matches!(
        route_response(
            r#"{"hookSpecificOutput":{"permissionDecision":"allow"},"policy_action":"sandbox-required"}"#,
            PRE_TOOL_USE
        ),
        Route::Contain(..)
    ));
    // An observation wraps the route the answer settles on.
    for (text, event) in [
        (
            r#"{"continue":true,"guard_transition_observation":{}}"#,
            "Stop",
        ),
        (r#"{"guard_transition_observation":{"a":1}}"#, PRE_TOOL_USE),
    ] {
        assert!(
            matches!(
                route_response(text, event),
                Route::Observed(PyVal::Dict(_), ref route) if matches!(**route, Route::Respond(_))
            ),
            "{text}"
        );
    }
    // Only an object is an observation.
    assert!(matches!(
        route_response(r#"{"guard_transition_observation":[]}"#, PRE_TOOL_USE),
        Route::Respond(_)
    ));
    // A pending approval waits natively.
    let pending = r#"{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"http://h/requests/abcdefgh"}}"#;
    assert!(matches!(
        route_response(pending, PRE_TOOL_USE),
        Route::AwaitApproval(..)
    ));
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
fn odd_answers_fail_closed_and_process_failures_restart_the_daemon() {
    for event_name in [PRE_TOOL_USE, "PermissionRequest", "Stop"] {
        for text in ["", "[]", "{", "{\"systemMessage\":\"\\ud800\u{f0000}\"}"] {
            assert_eq!(
                route_response(text, event_name),
                Route::Respond(fail_closed(event_name)),
                "{event_name} {text:?}"
            );
        }
    }
    assert_eq!(
        route_response(
            r#"{"reason_code":"daemon_hook_process_failed"}"#,
            PRE_TOOL_USE
        ),
        Route::Restart
    );
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
fn input_that_is_not_an_object_is_refused() {
    let pairs = timeouts(&[("PreToolUse", 30)]);
    for raw in ["[]", "{", "\"PostToolUse\"", ""] {
        assert_eq!(
            prepare(raw, &pairs).unwrap_err(),
            Unprepared::Refused(PRE_TOOL_USE.to_owned()),
            "{raw:?}"
        );
    }
}

#[test]
fn lone_surrogates_are_forwarded_as_python_escapes_them() {
    let pairs = timeouts(&[("Stop", 30), ("PreToolUse", 30)]);
    for (raw, forwarded) in [
        (
            "{\"hook_event_name\":\"Stop\",\"a\":\"\\uD800x\\udfff\"}",
            "{\"hook_event_name\":\"Stop\",\"a\":\"\\ud800x\\udfff\",",
        ),
        (
            "{\"hook_event_name\":\"PreToolUse\",\"a\":\"\\ud800\"}",
            "{\"hook_event_name\":\"PreToolUse\",\"a\":\"\\ud800\",",
        ),
    ] {
        let data = prepare(raw, &pairs).expect("prepared").data;
        assert!(data.starts_with(forwarded), "{data}");
    }
    for (raw, event) in [
        ("{\"hook_event_name\":\"\\udc00\"}", "\u{f0400}"),
        ("{\"a\":\"\\ud800\u{f0001}\"}", PRE_TOOL_USE),
    ] {
        let refused = Unprepared::Refused(event.to_owned());
        assert_eq!(prepare(raw, &pairs).unwrap_err(), refused, "{raw:?}");
    }
}

pub(super) fn codex_home(
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
        start_command: Vec::new(),
        fallback_command: Vec::new(),
    }
}

fn shell(script: &str) -> Vec<String> {
    vec!["/bin/sh".to_owned(), "-c".to_owned(), script.to_owned()]
}

const STOP: &str = r#"{"hook_event_name":"Stop"}"#;

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
fn a_daemon_failure_without_a_start_command_fails_closed() {
    let (home, daemon) = codex_home("codex-503", vec![Exchange::Hook(503, "down".to_owned())]);
    write_private(&home.home.join(START_FAILED_MARKER), "{}");
    let (route, _) = route_hook(
        &config(&home),
        r#"{"hook_event_name":"Stop"}"#,
        Instant::now(),
    );
    assert_eq!(route, Route::Respond(fail_closed("Stop")));
    assert!(home.home.join(START_FAILED_MARKER).exists());
    assert_eq!(daemon.join().unwrap().len(), 1);
}

#[test]
fn a_mismatched_token_fails_closed_before_the_hook_is_sent() {
    let (home, daemon) = codex_home("codex-token", vec![Exchange::Hook(200, "{}".to_owned())]);
    write_private(&home.home.join("daemon-auth-token"), "other-token");
    let (route, _) = route_hook(
        &config(&home),
        r#"{"hook_event_name":"Stop"}"#,
        Instant::now(),
    );
    assert_eq!(route, Route::Respond(fail_closed("Stop")));
    assert!(daemon.join().unwrap().is_empty());
}

#[test]
fn a_started_daemon_answers_the_hook() {
    let answer = r#"{"continue":true,"systemMessage":"ok"}"#;
    let (home, daemon) = codex_home("codex-start", vec![Exchange::Hook(200, answer.to_owned())]);
    // The daemon is listening, but its state appears only once started.
    let staged = home.scratch("started-state.json");
    std::fs::rename(&home.state_path, &staged).unwrap();
    let mut bridge = config(&home);
    bridge.start_command = shell(&format!(
        "mv '{}' '{}'",
        staged.display(),
        home.state_path.display()
    ));
    let (route, _) = route_hook(&bridge, STOP, Instant::now());
    assert_eq!(route, Route::Respond(answer.to_owned()));
    assert_eq!(daemon.join().unwrap().len(), 1);
}

#[test]
fn a_process_failure_restarts_the_daemon_and_asks_once_more() {
    let failed = r#"{"reason_code":"daemon_hook_process_failed"}"#;
    let answer = r#"{"continue":true,"systemMessage":"ok"}"#;
    let script = vec![
        Exchange::Hook(200, failed.to_owned()),
        Exchange::Hook(200, failed.to_owned()),
    ];
    let (home, daemon) = codex_home("codex-process", script);
    let mut bridge = config(&home);
    bridge.start_command = shell("exit 0");
    let (route, _) = route_hook(&bridge, STOP, Instant::now());
    // A second process failure is not restarted again.
    assert_eq!(route, Route::Respond(fail_closed("Stop")));
    assert_eq!(daemon.join().unwrap().len(), 2);
    let (home, daemon) = codex_home(
        "codex-process-ok",
        vec![
            Exchange::Hook(200, failed.to_owned()),
            Exchange::Hook(200, answer.to_owned()),
        ],
    );
    let mut bridge = config(&home);
    bridge.start_command = shell("exit 0");
    let (route, _) = route_hook(&bridge, STOP, Instant::now());
    assert_eq!(route, Route::Respond(answer.to_owned()));
    assert_eq!(daemon.join().unwrap().len(), 2);
}

#[test]
fn a_failed_start_fails_closed() {
    let home = GuardHome::new("codex-start-failed");
    let mut bridge = config(&home);
    bridge.start_command = shell("exit 1");
    let (route, _) = route_hook(&bridge, STOP, Instant::now());
    assert_eq!(route, Route::Respond(fail_closed("Stop")));
}

#[test]
fn a_hook_without_time_for_a_start_fails_closed_without_starting() {
    let home = GuardHome::new("codex-start-late");
    let marker = home.scratch("started");
    let mut bridge = config(&home);
    bridge.start_command = shell(&format!(": > '{}'", marker.display()));
    // Three seconds less the grace leaves one, too little for a start.
    bridge.hook_timeouts = timeouts(&[("Stop", 3)]);
    let (route, _) = route_hook(&bridge, STOP, Instant::now());
    assert_eq!(route, Route::Respond(fail_closed("Stop")));
    assert!(!marker.exists());
}

#[path = "codex_hook_bridge_client_tests.rs"]
mod client_tests;

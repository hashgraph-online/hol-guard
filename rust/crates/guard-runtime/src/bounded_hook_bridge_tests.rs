//! The native bounded hook bridge: Python parity for rendering, event names
//! and fail-closed output, the install-time config, and routing against a
//! scripted daemon.

use std::io::BufReader;
use std::net::TcpListener;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use std::path::PathBuf;

use super::config::{daemon_start_command, MANAGED_MARKER};
use super::*;
use crate::bounded_hook_bridge_render::Rendered;
use crate::bounded_hook_bridge_render::NATIVE_HARNESSES;
use crate::claude_hook_bridge_fixture::{
    read_request, write_private, write_response, GuardHome, Request,
};

const VECTORS: &str = include_str!("../testdata/bounded_hook_bridge/vectors.json");
const TOKEN: &str = "bounded-token-fixture";

fn vectors(section: &str) -> Vec<Value> {
    let all: Value = serde_json::from_str(VECTORS).unwrap();
    all[section].as_array().unwrap().clone()
}

fn text(case: &Value, key: &str) -> String {
    case[key].as_str().unwrap().to_owned()
}

fn parsed(source: &str) -> PyVal {
    let Ok(value) = pyjson::parse(source) else {
        panic!("vector JSON does not parse: {source}");
    };
    value
}

fn failed(event_name: &str) -> Route {
    Route::Fail {
        event_name: event_name.to_owned(),
        unmap: false,
    }
}

#[test]
fn daemon_answers_render_as_python_renders_them() {
    for case in vectors("render") {
        let response = parsed(&text(&case, "response"));
        let rendered = daemon_response_to_native(
            response.as_dict().unwrap(),
            &text(&case, "harness"),
            &text(&case, "event"),
            false,
        );
        let expected = Rendered {
            stdout: text(&case, "stdout"),
            stderr: text(&case, "stderr"),
            exit_code: i32::try_from(case["exit_code"].as_i64().unwrap()).unwrap(),
        };
        assert_eq!(rendered, Some(expected), "{case}");
    }
}

#[test]
fn event_names_match_python() {
    for case in vectors("event_names") {
        let input = text(&case, "text");
        assert_eq!(
            event_name(&input, &parsed(&input)),
            text(&case, "event"),
            "{input}"
        );
    }
}

#[test]
fn failure_output_matches_python() {
    for case in vectors("failures") {
        let (stdout, code) = failure_output(&text(&case, "harness"), &text(&case, "event"), false);
        assert_eq!(stdout, text(&case, "stdout"), "{case}");
        assert_eq!(
            i64::from(code),
            case["exit_code"].as_i64().unwrap(),
            "{case}"
        );
    }
}

pub(super) fn argv(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

#[test]
fn only_the_installed_argv_shapes_carry_a_config() {
    assert_eq!(
        config_argument(&argv(&["py", "-I", "-c", "code", "{}"])),
        Some("{}")
    );
    assert_eq!(
        config_argument(&argv(&[
            "py",
            "-I",
            "-c",
            "code",
            "{}",
            "#",
            MANAGED_MARKER
        ])),
        Some("{}")
    );
    let refused: [&[&str]; 5] = [
        &["py", "-c", "code", "{}"],
        &["py", "-I", "-x", "code", "{}"],
        &["py", "-I", "-c", "code", "{}", "extra"],
        &["py", "-I", "-c", "code", "{}", "#", "OTHER"],
        &["py", "-I", "-c", "code", "{}", "x", MANAGED_MARKER],
    ];
    for items in refused {
        assert_eq!(config_argument(&argv(items)), None, "{items:?}");
    }
}

/// The config of an interpreter launch, as `run` parses it.
fn parse_config(argument: &str) -> Option<BridgeConfig> {
    parse_launch_config(argument, false)
}

pub(super) fn config_text(changes: &[(&str, Option<Value>)]) -> String {
    let mut config = json!({
        "python_executable": "/usr/bin/python3",
        "package_root": "/opt/guard",
        "guard_home": "/var/guard",
        "cli_args": ["guard", "hook", "--harness", "copilot"],
        "harness": "copilot",
        "timeout_seconds": 20,
        "frozen_launcher": false,
    });
    let fields = config.as_object_mut().unwrap();
    for (key, value) in changes {
        match value {
            Some(value) => fields.insert((*key).to_owned(), value.clone()),
            None => fields.remove(*key),
        };
    }
    config.to_string()
}

#[test]
fn configs_are_accepted_only_for_the_native_harnesses() {
    let accepted = parse_config(&config_text(&[]));
    assert_eq!(
        accepted,
        Some(BridgeConfig {
            harness: "copilot".to_owned(),
            guard_home: PathBuf::from("/var/guard"),
            timeout: Duration::from_secs(20),
            start_command: daemon_start_command(
                "/usr/bin/python3",
                "/opt/guard",
                "/var/guard",
                &["guard", "hook", "--harness", "copilot"],
            ),
        })
    );
    let started = parse_config(&config_text(&[(
        "start_command",
        Some(json!(["py", "-I"])),
    )]));
    assert_eq!(
        started.map(|config| config.start_command),
        Some(argv(&["py", "-I"]))
    );
    for harness in NATIVE_HARNESSES {
        let config = parse_config(&config_text(&[("harness", Some(json!(harness)))]));
        assert_eq!(
            config.map(|config| config.harness),
            Some(harness.to_owned())
        );
    }
    let fractional = parse_config(&config_text(&[("timeout_seconds", Some(json!(0.5)))]));
    assert_eq!(
        fractional.map(|config| config.timeout),
        Some(Duration::from_millis(500))
    );
    assert!(parse_config(&config_text(&[("frozen_launcher", None)])).is_some());
}

#[test]
fn a_config_without_a_start_command_gets_the_one_install_writes() {
    // Recorded from `daemon_start_command` in `bounded_cli_hook_native.py`.
    let expected = r#"import os,sys;sys.path.insert(0, "/nonexistent-guard/pkg'q");from pathlib import Path;from codex_plugin_scanner.guard.daemon import schedule_guard_daemon_recovery;failure_kind=os.environ.get('HOL_GUARD_HOOK_FAILURE_KIND','transport-failure');failure_kind=failure_kind if failure_kind in {'overload','transport-failure','authenticated-control-plane-failure'} else 'transport-failure';schedule_guard_daemon_recovery(Path('/nonexistent-guard/home'),home_dir=Path('/nonexistent-guard/user'),failure_kind=failure_kind)"#;
    let command = daemon_start_command(
        "/usr/bin/python3",
        "/nonexistent-guard/pkg'q",
        "/nonexistent-guard/home",
        &[
            "guard",
            "hook",
            "--home",
            "/nonexistent-guard/user",
            "--harness",
            "copilot",
        ],
    );
    assert_eq!(command, argv(&["/usr/bin/python3", "-I", "-c", expected]));
}

#[test]
fn configs_python_refuses_or_handles_elsewhere_are_not_native() {
    let refused: [(&str, Option<Value>); 15] = [
        ("harness", Some(json!("Hermes"))),
        ("harness", Some(json!("grok"))),
        ("timeout_seconds", Some(json!(0))),
        ("timeout_seconds", Some(json!(-1))),
        ("timeout_seconds", Some(json!(true))),
        ("timeout_seconds", Some(json!("20"))),
        ("frozen_launcher", Some(json!(true))),
        ("frozen_launcher", Some(json!("no"))),
        ("cli_args", Some(json!(["guard", 1]))),
        ("cli_args", Some(json!("guard hook"))),
        ("guard_home", Some(json!("relative/guard"))),
        ("python_executable", None),
        ("package_root", Some(json!(null))),
        ("start_command", Some(json!("guard daemon"))),
        ("start_command", Some(json!(["guard", 1]))),
    ];
    for (key, value) in refused {
        let config = config_text(&[(key, value)]);
        assert_eq!(parse_config(&config), None, "{config}");
    }
    for config in ["[]", "{", "\"text\"", ""] {
        assert_eq!(parse_config(config), None, "{config}");
    }
}

#[test]
fn prepared_hooks_keep_python_decoding() {
    let prepared = prepare(b"\xef\xbb\xbf{\"hook_event_name\":\"user_prompt_submit\"}").unwrap();
    assert_eq!(prepared.event_name, "UserPromptSubmit");
    assert!(parsed(&prepared.data).as_dict().is_some());
    let refused = |event_name: &str, reason| {
        Err(Route::Refuse {
            event_name: event_name.to_owned(),
            reason,
            unmap: false,
        })
    };
    assert_eq!(
        prepare(b"{\"hook_event_name\":\"PostToolUse\",\"x\":\"\xff\"}"),
        refused("PreToolUse", FAILURE_REASON)
    );
    assert_eq!(prepare(b"[]"), refused("PreToolUse", FAILURE_REASON));
    assert_eq!(
        prepare(br#"[{"hook_event_name":"PostToolUse"}]"#),
        refused("PostToolUse", FAILURE_REASON)
    );
    assert_eq!(prepare(b"not json"), refused("PreToolUse", FAILURE_REASON));
    let mut oversized = br#"{"hook_event_name":"PostToolUse","a":""#.to_vec();
    oversized.resize(MAX_HOOK_INPUT_BYTES + 1, b'x');
    assert_eq!(prepare(&oversized), refused("PostToolUse", OVERSIZE_REASON));
    let surrogate = prepare(br#"{"hook_event_name":"PreToolUse","x":"\uD800"}"#).unwrap();
    assert!(surrogate.mapped && !surrogate.collision);
    assert!(surrogate
        .data
        .starts_with(r#"{"hook_event_name":"PreToolUse","x":"\ud800","#));
}

fn bridge_config(home: &GuardHome, harness: &str) -> BridgeConfig {
    BridgeConfig {
        harness: harness.to_owned(),
        guard_home: home.home.clone(),
        timeout: Duration::from_secs(20),
        start_command: Vec::new(),
    }
}

/// A bridge whose daemon-start command is the shell `script`.
fn starting_bridge(home: &GuardHome, script: &str) -> BridgeConfig {
    BridgeConfig {
        start_command: argv(&["/bin/sh", "-c", script]),
        ..bridge_config(home, "copilot")
    }
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(20)
}

/// Answer one hook POST with `status` and `body`, returning the request.
fn serve_once(listener: TcpListener, status: u16, body: String) -> JoinHandle<Option<Request>> {
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().ok()?;
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut writer = stream.try_clone().unwrap();
        let request = read_request(&mut BufReader::new(stream))?;
        write_response(&mut writer, status, &body, true);
        Some(request)
    })
}

fn home_with_endpoint(label: &str, host: &str, port: u16, token: bool) -> GuardHome {
    let home = GuardHome::new(label);
    write_private(
        &home.state_path,
        &json!({"host": host, "port": port}).to_string(),
    );
    if token {
        write_private(&home.home.join(TOKEN_FILE), TOKEN);
    }
    home
}

const PRE_TOOL: &[u8] = br#"{"hook_event_name":"PreToolUse","tool_name":"Bash"}"#;

#[test]
fn configs_without_a_start_command_fail_closed_when_no_daemon_answers() {
    let fail = failed("PreToolUse");
    let home = GuardHome::new("bounded-no-state");
    assert_eq!(
        route_hook(&bridge_config(&home, "copilot"), PRE_TOOL, soon()),
        fail
    );
    let tokenless = home_with_endpoint("bounded-no-token", "127.0.0.1", 9, false);
    assert_eq!(
        route_hook(&bridge_config(&tokenless, "copilot"), PRE_TOOL, soon()),
        fail
    );
    let remote = home_with_endpoint("bounded-remote", "192.0.2.1", 9, true);
    assert_eq!(
        route_hook(&bridge_config(&remote, "copilot"), PRE_TOOL, soon()),
        fail
    );
}

#[test]
fn a_started_daemon_answers_the_hook() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let answer = r#"{"policy_action":"block","reason":"blocked by policy"}"#;
    let daemon = serve_once(listener, 200, answer.to_owned());
    let home = home_with_endpoint("bounded-started", "127.0.0.1", port, true);
    let staged = home.scratch("started-state.json");
    std::fs::rename(&home.state_path, &staged).unwrap();
    let script = format!("mv '{}' '{}'", staged.display(), home.state_path.display());

    let route = route_hook(&starting_bridge(&home, &script), PRE_TOOL, soon());

    assert!(
        // Copilot reports a deny on stdout and exits 0, as the client does.
        matches!(
            &route,
            Route::Respond { stdout, exit_code: 0, .. }
                if stdout.contains(r#""permissionDecision":"deny""#)
                    && stdout.contains("blocked by policy")
        ),
        "{route:?}"
    );
    assert!(daemon.join().unwrap().is_some());
}

#[test]
fn a_failed_start_fails_closed() {
    let home = GuardHome::new("bounded-start-failed");
    assert_eq!(
        route_hook(&starting_bridge(&home, "exit 1"), PRE_TOOL, soon()),
        failed("PreToolUse")
    );
}

#[test]
fn a_hook_without_time_for_a_start_fails_closed_without_starting() {
    let home = GuardHome::new("bounded-no-time");
    let marker = home.scratch("started");
    let script = format!(": > '{}'", marker.display());
    let deadline = Instant::now() + Duration::from_secs(1);

    let route = route_hook(&starting_bridge(&home, &script), PRE_TOOL, deadline);

    assert_eq!(route, failed("PreToolUse"));
    assert!(!marker.exists());
}

#[test]
fn unreadable_hooks_fail_closed_without_asking_even_past_the_deadline() {
    let home = GuardHome::new("bounded-unreadable");
    assert_eq!(
        route_hook(&bridge_config(&home, "kimi"), b"[]", Instant::now()),
        Route::Refuse {
            event_name: "PreToolUse".to_owned(),
            reason: FAILURE_REASON,
            unmap: false,
        }
    );
}

#[test]
fn a_spent_deadline_fails_closed_for_the_hook_event() {
    let home = GuardHome::new("bounded-spent");
    let prompt = br#"{"hook_event_name":"UserPromptSubmit","prompt":"hi"}"#;
    assert_eq!(
        route_hook(&bridge_config(&home, "zcode"), prompt, Instant::now()),
        failed("UserPromptSubmit")
    );
}

#[test]
fn the_daemon_answer_is_rendered_natively() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let answer = r#"{"policy_action":"block","reason":"blocked by policy"}"#;
    let daemon = serve_once(listener, 200, answer.to_owned());
    let home = home_with_endpoint("bounded-answer", "127.0.0.1", port, true);

    let route = route_hook(&bridge_config(&home, "kimi"), PRE_TOOL, soon());

    let expected = daemon_response_to_native(
        parsed(answer).as_dict().unwrap(),
        "kimi",
        "PreToolUse",
        false,
    )
    .unwrap();
    assert_eq!(
        route,
        Route::Respond {
            stdout: expected.stdout,
            stderr: "blocked by policy".to_owned(),
            exit_code: 2,
        }
    );
    let request = daemon.join().unwrap().unwrap();
    assert_eq!(request.target, "/v1/hooks/kimi");
    assert_eq!(request.header("X-Guard-Token"), Some(TOKEN));
    let sent = parsed(std::str::from_utf8(&request.body).unwrap());
    assert_eq!(sent.get("tool_name"), Some(&PyVal::Str("Bash".to_owned())));
}

#[test]
fn a_hermes_answer_is_the_flat_decision_hermes_reads() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let answer = r#"{"policy_action":"review","reason":" held for review "}"#;
    let daemon = serve_once(listener, 200, answer.to_owned());
    let home = home_with_endpoint("bounded-hermes", "127.0.0.1", port, true);
    let pre_tool_call = br#"{"hook_event_name":"pre_tool_call","tool_name":"terminal"}"#;

    let route = route_hook(&bridge_config(&home, "hermes"), pre_tool_call, soon());

    assert_eq!(
        route,
        Route::Respond {
            stdout: r#"{"decision":"block","reason":"held for review"}"#.to_owned(),
            stderr: String::new(),
            exit_code: 2,
        }
    );
    let request = daemon.join().unwrap().unwrap();
    assert_eq!(request.target, "/v1/hooks/hermes");
}

#[test]
fn a_daemon_that_failed_without_a_start_command_is_not_asked_again() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let daemon = serve_once(listener, 500, "{}".to_owned());
    let home = home_with_endpoint("bounded-refused", "127.0.0.1", port, true);

    let route = route_hook(&bridge_config(&home, "devin"), PRE_TOOL, soon());

    assert_eq!(route, failed("PreToolUse"));
    assert!(daemon.join().unwrap().is_some());
}

#[test]
fn an_answer_the_bridge_cannot_render_fails_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let answer = r#"{"policy_action":"block","reason":["listed"]}"#;
    let daemon = serve_once(listener, 200, answer.to_owned());
    let home = home_with_endpoint("bounded-unrendered", "127.0.0.1", port, true);

    let route = route_hook(&bridge_config(&home, "devin"), PRE_TOOL, soon());

    assert_eq!(route, failed("PreToolUse"));
    assert!(daemon.join().unwrap().is_some());
}

#[path = "bounded_hook_bridge_surrogate_tests.rs"]
mod surrogates;

//! The native answers for Grok's client: the client constants, the
//! invocation the hook command names, and routing against a scripted daemon.

use std::io::{BufRead, BufReader, Read};
use std::net::{TcpListener, TcpStream};
use std::thread::JoinHandle;

use serde_json::{json, Value};

use super::*;
use crate::bounded_hook_bridge_grok_script::{
    invocation, normalize, python_home, python_path, read_client_constants, Invocation,
    ScriptConstants,
};
use crate::bounded_hook_bridge_render::FAILURE_REASON;
use crate::claude_hook_bridge_fixture::{write_private, write_response, GuardHome, Request};

const TOKEN: &str = "grok-token-fixture";
const PRE_TOOL: &[u8] = br#"{"hook_event_name":"PreToolUse","tool_name":"Bash"}"#;
const PROMPT: &[u8] = br#"{"hook_event_name":"UserPromptSubmit","prompt":"hi"}"#;

fn client_text(guard_home: &str, harness: &str, timeout: &str) -> String {
    format!(
        "import os\nGUARD_HOME = {}\nHARNESS = \"{harness}\"\nTIMEOUT_SECONDS = {timeout}\nmain()",
        json!(guard_home)
    )
}

#[test]
fn rendered_constants_are_read_back_from_the_client() {
    let (template, constants) = normalize(&client_text("/g h", "grok", "8")).unwrap();
    assert_eq!(
        template,
        "import os\nGUARD_HOME = __GUARD_HOME__\nHARNESS = __HARNESS__\n\
         TIMEOUT_SECONDS = __TIMEOUT_SECONDS__\nmain()"
    );
    assert_eq!(
        constants,
        ScriptConstants {
            guard_home: "/g h".to_owned(),
            timeout_seconds: 8.0,
        }
    );
    let (_, constants) = normalize(&client_text("/g", "grok", "2.5")).unwrap();
    assert_eq!(constants.timeout_seconds, 2.5);
}

#[test]
fn clients_the_renderer_did_not_write_are_not_read() {
    for text in [
        client_text("/g", "codex", "8"),
        client_text("/g", "grok", "0"),
        client_text("/g", "grok", "-1"),
        client_text("/g", "grok", "nan"),
        client_text("/g", "grok", "soon"),
        format!("{}\nHARNESS = \"grok\"", client_text("/g", "grok", "8")),
        format!("{}\nGUARD_HOME = \"/h\"", client_text("/g", "grok", "8")),
        format!("{}\nTIMEOUT_SECONDS = 9", client_text("/g", "grok", "8")),
        "GUARD_HOME = \"/g\"\nTIMEOUT_SECONDS = 8".to_owned(),
        "GUARD_HOME = 7\nHARNESS = \"grok\"\nTIMEOUT_SECONDS = 8".to_owned(),
        "GUARD_HOME = \"\\ud800\"\nHARNESS = \"grok\"\nTIMEOUT_SECONDS = 8".to_owned(),
    ] {
        assert_eq!(normalize(&text), None, "{text}");
    }
}

#[test]
fn a_client_an_older_guard_rendered_is_answered_natively() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("grok.py");
    // Rendered from another template than the one the bridge was ported from.
    std::fs::write(&script, client_text("/g", "grok", "8")).unwrap();
    let constants = read_client_constants(&script).unwrap();
    assert_eq!(constants.guard_home, "/g");
    std::fs::write(&script, client_text("/g", "codex", "8")).unwrap();
    assert_eq!(read_client_constants(&script), None);
}

#[test]
fn paths_read_as_python_reads_them() {
    assert_eq!(python_path("/").as_deref(), Some("/"));
    assert_eq!(python_path("/a//b/./c/").as_deref(), Some("/a/b/c"));
    assert_eq!(python_path("/a/../b").as_deref(), Some("/a/../b"));
    assert_eq!(python_path("//a"), None);
    assert_eq!(python_path("a/b"), None);
    assert_eq!(python_path(""), None);
}

fn config(guard_home: &str, options: &[&str]) -> String {
    let mut cli_args = vec!["guard", "hook"];
    cli_args.extend_from_slice(options);
    cli_args.push("--json");
    json!({"harness": "grok", "guard_home": guard_home, "cli_args": cli_args}).to_string()
}

#[test]
fn the_hook_command_names_the_home_and_workspace() {
    let home = GuardHome::new("grok-invocation");
    let guard = home.home_text();
    let argument = config(
        guard,
        &[
            "--guard-home",
            guard,
            "--harness",
            "grok",
            "--home",
            "/users/me",
            "--workspace",
            "/work",
        ],
    );
    assert_eq!(
        invocation(&argument, guard),
        Some(Invocation {
            home: "/users/me".to_owned(),
            workspace: Some("/work".to_owned()),
        })
    );
    let argument = config(guard, &["--harness", "grok", "--guard-home", guard]);
    let found = invocation(&argument, guard).unwrap();
    assert_eq!(found.workspace, None);
    assert_eq!(Some(found.home), python_home());
}

#[test]
fn hook_commands_the_client_refuses_are_not_answered() {
    let home = GuardHome::new("grok-invocation-refused");
    let guard = home.home_text();
    let other = GuardHome::new("grok-invocation-other");
    let refused = [
        config(guard, &["--guard-home", guard, "--harness", "codex"]),
        config(guard, &["--guard-home", guard]),
        config(guard, &["--guard-home", guard, "--harness"]),
        config(
            guard,
            &[
                "--guard-home",
                guard,
                "--harness",
                "grok",
                "--harness",
                "grok",
            ],
        ),
        config(
            guard,
            &["--guard-home", guard, "--harness", "grok", "--home", "rel"],
        ),
        config(
            guard,
            &["--guard-home", guard, "--harness", "grok", "--debug", "/x"],
        ),
        config(guard, &["--guard-home", "", "--harness", "grok"]),
        config(
            guard,
            &["--guard-home", other.home_text(), "--harness", "grok"],
        ),
        config(
            other.home_text(),
            &["--guard-home", guard, "--harness", "grok"],
        ),
        json!({"harness": "grok", "guard_home": guard,
               "cli_args": ["guard", "hook", "--guard-home", guard, "--harness", "grok"]})
        .to_string(),
        json!({"harness": "codex", "guard_home": guard,
               "cli_args": ["guard", "hook", "--guard-home", guard, "--harness", "grok", "--json"]})
        .to_string(),
        json!({"harness": "grok", "guard_home": guard,
               "cli_args": ["guard", "hook", "--guard-home", guard, "--harness", 7, "--json"]})
        .to_string(),
        "[]".to_owned(),
    ];
    for argument in refused {
        assert_eq!(invocation(&argument, guard), None, "{argument}");
    }
}

/// One request; a GET carries no `Content-Length`.
fn read(stream: TcpStream) -> Option<Request> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut request = Request {
        target: line.split(' ').nth(1)?.to_owned(),
        headers: Vec::new(),
        body: Vec::new(),
    };
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let (key, value) = line.split_once(':')?;
        request
            .headers
            .push((key.trim().to_owned(), value.trim().to_owned()));
    }
    let length = request
        .header("Content-Length")
        .map_or(Ok(0), str::parse::<usize>);
    request.body = vec![0; length.ok()?];
    reader.read_exact(&mut request.body).ok()?;
    Some(request)
}

/// Answer one request per scripted reply, in order, and return them.
fn serve(listener: TcpListener, replies: Vec<(u16, Value)>) -> JoinHandle<Vec<Request>> {
    std::thread::spawn(move || {
        let mut requests = Vec::new();
        for (status, body) in replies {
            let Ok((stream, _)) = listener.accept() else {
                break;
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut writer = stream.try_clone().unwrap();
            let Some(request) = read(stream) else {
                break;
            };
            write_response(&mut writer, status, &body.to_string(), true);
            requests.push(request);
        }
        requests
    })
}

struct Fixture {
    home: GuardHome,
    daemon: JoinHandle<Vec<Request>>,
}

impl Fixture {
    fn new(label: &str, replies: Vec<(u16, Value)>) -> Self {
        let home = GuardHome::new(label);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        write_private(
            &home.state_path,
            &json!({"host": "127.0.0.1", "port": port}).to_string(),
        );
        write_private(&home.home.join(TOKEN_FILE), TOKEN);
        Self {
            home,
            daemon: serve(listener, replies),
        }
    }

    fn client(&self) -> Client {
        Client {
            guard_home: self.home.home.clone(),
            timeout_seconds: 8.0,
            invocation: Invocation {
                home: "/users/me".to_owned(),
                workspace: Some("/work".to_owned()),
            },
            deadline: Instant::now() + Duration::from_secs(8),
        }
    }

    fn requests(self) -> Vec<Request> {
        self.daemon.join().unwrap()
    }
}

fn body(request: &Request) -> Value {
    serde_json::from_slice(&request.body).unwrap()
}

fn answer(route: &Route) -> (Value, i32) {
    let Route::Respond { stdout, exit_code } = route;
    assert!(stdout.ends_with('\n'), "{stdout:?}");
    (serde_json::from_str(stdout).unwrap(), *exit_code)
}

#[test]
fn a_tool_call_is_answered_from_the_daemon() {
    let fixture = Fixture::new(
        "grok-pretool",
        vec![(200, json!({"policy_action": "allow"}))],
    );
    let route = fixture.client().route(PRE_TOOL);
    assert_eq!(
        answer(&route),
        (
            json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                },
                "decision": "allow",
                "policy_action": "allow",
            }),
            0
        )
    );
    let requests = fixture.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].target, "/v1/hooks/grok?home=%2Fusers%2Fme");
    assert_eq!(requests[0].header("x-guard-token"), Some(TOKEN));
    let sent = body(&requests[0]);
    assert_eq!(sent["cwd"], "/work");
    assert_eq!(sent["tool_name"], "Bash");
}

#[test]
fn a_blocked_tool_call_exits_two() {
    let reply = json!({"policy_action": "block", "reason": "no"});
    let fixture = Fixture::new("grok-pretool-block", vec![(200, reply)]);
    let (stdout, exit_code) = answer(&fixture.client().route(PRE_TOOL));
    assert_eq!(stdout["decision"], "deny");
    assert_eq!(stdout["reason"], "no");
    assert_eq!(exit_code, 2);
}

#[test]
fn a_hook_the_bridge_cannot_read_fails_closed_without_asking() {
    let conflict = br#"{"hook_event_name":"PreToolUse","event":"SessionStart"}"#;
    for (hook, reason) in [
        (&b"not json"[..], FAILURE_REASON),
        (b"[]", FAILURE_REASON),
        (b"\xff", FAILURE_REASON),
        (conflict, CONFLICT_REASON),
        (
            "{\"hook_event_name\":\"Pr\u{e9}ToolUse\"}".as_bytes(),
            FAILURE_REASON,
        ),
    ] {
        let fixture = Fixture::new("grok-unreadable", vec![]);
        let (stdout, exit_code) = answer(&fixture.client().route(hook));
        assert_eq!(stdout["decision"], "deny", "{hook:?}");
        assert_eq!(stdout["reason"], reason, "{hook:?}");
        assert_eq!(exit_code, 0);
        assert!(fixture.requests().is_empty());
    }
}

#[test]
fn an_oversized_hook_fails_closed_without_asking() {
    let mut hook = PRE_TOOL.to_vec();
    hook.resize(MAX_HOOK_INPUT_BYTES + 1, b' ');
    let fixture = Fixture::new("grok-oversize", vec![]);
    let (stdout, exit_code) = answer(&fixture.client().route(&hook));
    assert_eq!(stdout["decision"], "deny");
    assert_eq!(stdout["reason"], OVERSIZE_REASON);
    assert_eq!(exit_code, 0);
    assert!(fixture.requests().is_empty());
}

#[test]
fn a_home_without_a_daemon_fails_closed() {
    let home = GuardHome::new("grok-no-daemon");
    let client = Client {
        guard_home: home.home.clone(),
        timeout_seconds: 8.0,
        invocation: Invocation {
            home: "/users/me".to_owned(),
            workspace: None,
        },
        deadline: Instant::now() + Duration::from_secs(8),
    };
    assert_eq!(
        client.route(PRE_TOOL),
        Route::Respond {
            stdout: failure_stdout(std::str::from_utf8(PRE_TOOL).unwrap()),
            exit_code: 0,
        }
    );
}

#[test]
fn a_daemon_failure_after_contact_fails_closed() {
    let fixture = Fixture::new("grok-daemon-error", vec![(500, json!({}))]);
    let route = fixture.client().route(PRE_TOOL);
    assert_eq!(
        route,
        Route::Respond {
            stdout: failure_stdout(std::str::from_utf8(PRE_TOOL).unwrap()),
            exit_code: 0,
        }
    );
    assert_eq!(answer(&route).0["decision"], "deny");
    assert_eq!(fixture.requests().len(), 1);
}

#[test]
fn a_spent_budget_fails_closed_without_asking() {
    let fixture = Fixture::new("grok-spent", vec![]);
    let mut client = fixture.client();
    client.deadline = Instant::now();
    let (stdout, exit_code) = answer(&client.route(PRE_TOOL));
    assert_eq!(stdout["decision"], "deny");
    assert_eq!(exit_code, 0);
    assert!(fixture.requests().is_empty());
}

#[test]
fn a_prompt_waits_for_the_workspace_then_asks() {
    let ready = json!({"ready": true, "workspace_acknowledged": true, "worker_ready": true});
    let fixture = Fixture::new(
        "grok-prompt",
        vec![(200, ready), (200, json!({"policy_action": "allow"}))],
    );
    let hook = br#"{"hook_event_name":"UserPromptSubmit","guard_remaining_seconds":99}"#;
    assert_eq!(answer(&fixture.client().route(hook)), (json!({}), 0));
    let requests = fixture.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].target,
        "/v1/hooks/grok/readiness?home=%2Fusers%2Fme"
    );
    assert_eq!(body(&requests[0]), json!({"cwd": "/work"}));
    let sent = body(&requests[1]);
    assert!(sent.get("guard_remaining_seconds").is_none());
    let left = sent["guard_remaining_ms"].as_u64().unwrap();
    assert!((1..=4000).contains(&left), "{left}");
}

#[test]
fn a_prompt_for_an_unready_workspace_is_blocked() {
    for ready in [
        json!({"ready": false}),
        json!({"ready": true}),
        json!({"ready": true, "workspace_acknowledged": true, "worker_ready": "yes"}),
        json!({"ready": 1, "native_required": false}),
    ] {
        let fixture = Fixture::new("grok-prompt-unready", vec![(200, ready.clone())]);
        let (stdout, exit_code) = answer(&fixture.client().route(PROMPT));
        assert_eq!(stdout["decision"], "block", "{ready}");
        assert_eq!(exit_code, 0);
        assert_eq!(fixture.requests().len(), 1, "{ready}");
    }
    let ready = json!({"ready": true, "native_required": false});
    let fixture = Fixture::new(
        "grok-prompt-not-native",
        vec![(200, ready), (200, json!({"policy_action": "allow"}))],
    );
    assert_eq!(answer(&fixture.client().route(PROMPT)), (json!({}), 0));
}

fn review(id: &str) -> Value {
    json!({"policy_action": "review", "reason": "look", "approval_request_id": id})
}

#[test]
fn a_review_waits_for_its_approval() {
    let fixture = Fixture::new(
        "grok-wait-allow",
        vec![
            (200, review("r 1")),
            (200, json!({"resolution_action": " Allow "})),
        ],
    );
    let (stdout, exit_code) = answer(&fixture.client().route(PRE_TOOL));
    assert_eq!(stdout["decision"], "allow");
    assert_eq!(stdout["policy_action"], "allow");
    assert_eq!(stdout["hookSpecificOutput"]["permissionDecision"], "allow");
    assert!(stdout.get("reason").is_none());
    assert_eq!(exit_code, 0);
    let requests = fixture.requests();
    assert_eq!(requests[1].target, "/v1/requests/r%201?home=%2Fusers%2Fme");
}

#[test]
fn a_denied_review_stays_blocked() {
    let fixture = Fixture::new(
        "grok-wait-deny",
        vec![
            (200, review("r1")),
            (200, json!({})),
            (200, json!({"resolution_action": "deny"})),
        ],
    );
    let (stdout, exit_code) = answer(&fixture.client().route(PRE_TOOL));
    assert_eq!(stdout["decision"], "deny");
    assert_eq!(stdout["policy_action"], "block");
    assert_eq!(stdout["reason"], "look");
    assert_eq!(exit_code, 2);
    assert_eq!(fixture.requests().len(), 3);
}

#[test]
fn a_review_without_a_wait_is_answered_as_is() {
    let fixture = Fixture::new("grok-wait-off", vec![(200, review("r1"))]);
    write_private(
        &fixture.home.home.join(SETTINGS_FILE),
        "approval_wait_timeout_seconds = 0\n",
    );
    let (stdout, exit_code) = answer(&fixture.client().route(PRE_TOOL));
    assert_eq!(stdout["decision"], "deny");
    assert_eq!(stdout["policy_action"], "review");
    assert_eq!(stdout["approval_request_id"], "r1");
    assert_eq!(exit_code, 2);
    assert_eq!(fixture.requests().len(), 1);
}

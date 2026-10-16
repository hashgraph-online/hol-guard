use super::{
    answered_response, bounded_direct_request, bounded_event, direct_event, direct_request,
    grok_direct_answer, grok_direct_request, harness_event, parse_hook_query, HookQuery,
    CLAUDE_CODE, CODEX, CURSOR,
};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn query(guard_home: Option<&str>, home: Option<&str>, workspace: Option<&str>) -> HookQuery {
    HookQuery {
        guard_home: guard_home.map(str::to_owned),
        home: home.map(str::to_owned),
        workspace: workspace.map(str::to_owned),
        runtime_harness: None,
    }
}

#[test]
fn the_query_parses_like_parse_qs() {
    assert_eq!(
        parse_hook_query("guard-home=%2Fh%2F.hol-guard&home=/h&workspace=/w+x%2By"),
        Some(query(Some("/h/.hol-guard"), Some("/h"), Some("/w x+y")))
    );
    // Blank values and fields without `=` are skipped; the last value wins.
    assert_eq!(
        parse_hook_query("home=/a&home=&home&workspace=/1&workspace=/2&&other=x"),
        Some(query(None, Some("/a"), Some("/2")))
    );
    // An escape that is not one stays as written.
    assert_eq!(
        parse_hook_query("home=/a%2&workspace=%zz%"),
        Some(query(None, Some("/a%2"), Some("%zz%")))
    );
    assert_eq!(parse_hook_query(""), Some(HookQuery::default()));
    assert_eq!(
        parse_hook_query("runtime-harness=cursor&runtime-harness=+")
            .map(|query| query.runtime_harness),
        Some(Some(" ".to_owned()))
    );
}

#[test]
fn a_value_that_is_not_utf8_leaves_the_query_to_the_daemon() {
    assert_eq!(parse_hook_query("home=%ff"), None);
}

struct Homes {
    root: PathBuf,
    guard_home: PathBuf,
    home: PathBuf,
}

impl Drop for Homes {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn homes(name: &str) -> Homes {
    let root = std::env::temp_dir().join(format!(
        "hol-guard-codex-direct-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("user");
    let guard_home = home.join(".hol-guard");
    std::fs::create_dir_all(&guard_home).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    Homes {
        guard_home: root.join("user/.hol-guard"),
        home: root.join("user"),
        root,
    }
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// `quote(text, safe="")`, so any temporary path survives the query.
fn encoded_text(text: &str) -> String {
    text.bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

fn encoded(path: &Path) -> String {
    encoded_text(text(path))
}

const PAYLOAD: &str = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash"}"#;

fn built(homes: &Homes, query: &str, data: &str) -> Option<Value> {
    direct_request(
        CODEX,
        &homes.guard_home,
        query,
        data,
        Duration::from_millis(400),
    )
    .map(|bytes| serde_json::from_slice(&bytes).unwrap())
}

#[test]
fn a_hook_with_the_daemon_context_becomes_a_hook_direct_request() {
    let homes = homes("request");
    let query = format!(
        "guard-home={}&home={}&workspace=/work",
        encoded(&homes.guard_home),
        encoded(&homes.home),
    );
    let request = built(&homes, &query, PAYLOAD).unwrap();
    assert_eq!(
        request,
        json!({
            "operation": "hook_direct",
            "deadline_budget_ms": 400,
            "request": {
                "harness": "codex",
                "guard_home": text(&homes.guard_home),
                "home_dir": text(&homes.home),
                "workspace": "/work",
                "deadline_budget_ms": 400,
                "payload": {"hook_event_name": "PreToolUse", "tool_name": "Bash"},
            },
        })
    );
}

#[test]
fn a_request_resolves_the_homes_the_daemon_would_keep() {
    let homes = homes("resolve");
    let query = format!(
        "guard-home=%20{}%20&home={}",
        encoded_text(&format!("{}/../.hol-guard/", text(&homes.guard_home))),
        encoded_text(&format!("{}/.hol-guard/..", text(&homes.home))),
    );
    let request = built(&homes, &query, PAYLOAD).unwrap();
    assert_eq!(request["request"]["guard_home"], text(&homes.guard_home));
    assert_eq!(request["request"]["home_dir"], text(&homes.home));
    assert!(request["request"].get("workspace").is_none());
}

#[test]
fn a_context_the_daemon_would_replace_takes_the_daemon_path() {
    let homes = homes("replace");
    let other = homes.root.join("other");
    std::fs::create_dir_all(&other).unwrap();
    let guard_home = encoded(&homes.guard_home);
    let home = encoded(&homes.home);
    for query in [
        format!("home={home}"),
        format!("guard-home={}&home={home}", encoded(&other)),
        format!("guard-home=~%2F.hol-guard&home={home}"),
        format!("guard-home={guard_home}&home=user"),
        format!("guard-home={guard_home}&home={}", encoded(&homes.root)),
        format!("guard-home={guard_home}&home={home}%2Fmissing"),
        format!("guard-home={guard_home}&home={home}&runtime-harness=cursor"),
    ] {
        assert_eq!(built(&homes, &query, PAYLOAD), None, "{query}");
    }
}

#[test]
fn a_bounded_hook_asks_under_the_daemons_own_homes() {
    let homes = homes("bounded");
    let built = |harness: &str, guard_home: &Path| {
        bounded_direct_request(harness, guard_home, PAYLOAD, Duration::from_millis(300))
            .map(|bytes| serde_json::from_slice::<Value>(&bytes).unwrap())
    };
    for harness in [
        "copilot", "kimi", "devin", "zcode", "openclaw", "hermes", "cline", "opencode",
    ] {
        assert_eq!(
            built(harness, &homes.guard_home).unwrap(),
            json!({
                "operation": "hook_direct",
                "deadline_budget_ms": 300,
                "request": {
                    "harness": harness,
                    "guard_home": text(&homes.guard_home),
                    "deadline_budget_ms": 300,
                    "payload": {"hook_event_name": "PreToolUse", "tool_name": "Bash"},
                },
            }),
            "{harness}"
        );
    }
    // Grok runs its own client, which asks with `grok_direct_request`.
    for harness in ["grok", "codex", "cursor", "unknown"] {
        assert_eq!(built(harness, &homes.guard_home), None, "{harness}");
    }
    // The daemon would name a guard home spelled another way as written.
    let linked = homes.root.join("linked");
    std::os::unix::fs::symlink(&homes.home, &linked).unwrap();
    for guard_home in [
        linked.join(".hol-guard"),
        homes.home.join("../user/.hol-guard"),
        homes.root.join("missing"),
    ] {
        assert_eq!(built("kimi", &guard_home), None, "{}", guard_home.display());
    }
    assert_eq!(
        bounded_direct_request("kimi", &homes.guard_home, "[]", Duration::from_millis(1)),
        None
    );
}

#[test]
fn a_grok_hook_asks_with_the_home_the_daemon_keeps() {
    let homes = homes("grok");
    let built = |guard_home: &Path, home: &str| {
        grok_direct_request(guard_home, home, PAYLOAD, Duration::from_millis(300))
            .map(|bytes| serde_json::from_slice::<Value>(&bytes).unwrap())
    };
    let mut expected = json!({
        "operation": "hook_direct",
        "deadline_budget_ms": 300,
        "request": {
            "harness": "grok",
            "guard_home": text(&homes.guard_home),
            "deadline_budget_ms": 300,
            "payload": {"hook_event_name": "PreToolUse", "tool_name": "Bash"},
        },
    });
    // The daemon drops a blank `home` and uses its own.
    assert_eq!(built(&homes.guard_home, "").unwrap(), expected);
    expected["request"]["home_dir"] = json!(text(&homes.home));
    assert_eq!(
        built(&homes.guard_home, &format!(" {}/ ", text(&homes.home))).unwrap(),
        expected
    );
    let linked = homes.root.join("linked");
    std::os::unix::fs::symlink(&homes.home, &linked).unwrap();
    for (guard_home, home) in [
        (homes.guard_home.clone(), text(&homes.root).to_owned()),
        (homes.guard_home.clone(), "user".to_owned()),
        (homes.guard_home.clone(), " ".to_owned()),
        (
            homes.guard_home.clone(),
            format!("{}/missing", text(&homes.home)),
        ),
        (linked.join(".hol-guard"), text(&homes.home).to_owned()),
    ] {
        assert_eq!(built(&guard_home, &home), None, "{home}");
    }
    // Permission and notification hooks are the daemon's own.
    let deadline = Instant::now() + Duration::from_secs(1);
    for event in ["PermissionRequest", "Notification"] {
        assert_eq!(
            grok_direct_answer(&homes.guard_home, "", event, PAYLOAD, deadline),
            None,
            "{event}"
        );
    }
}

#[test]
fn a_payload_that_is_not_an_object_takes_the_daemon_path() {
    let homes = homes("payload");
    let query = format!(
        "guard-home={}&home={}",
        encoded(&homes.guard_home),
        encoded(&homes.home),
    );
    assert!(built(&homes, &query, PAYLOAD).is_some());
    for data in ["[]", "\"text\"", "not json"] {
        assert_eq!(built(&homes, &query, data), None, "{data}");
    }
}

#[test]
fn only_an_answer_returns_its_harness_response() {
    let response = json!({"continue": true, "policy_action": "allow"});
    let answer = json!({
        "schema": "guard-hook-direct-result.v1",
        "outcome": "answer",
        "edge": {"harness_response": response},
    });
    let text = answered_response(&serde_json::to_vec(&answer).unwrap()).unwrap();
    assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), response);

    for output in [
        json!({"schema": "guard-hook-direct-result.v1", "outcome": "defer", "reason": "x"}),
        json!({"schema": "other", "outcome": "answer", "edge": {"harness_response": {}}}),
        json!({"schema": "guard-hook-direct-result.v1", "outcome": "answer", "edge": {}}),
        json!({
            "schema": "guard-hook-direct-result.v1",
            "outcome": "answer",
            "edge": {"harness_response": "allow"},
        }),
    ] {
        assert_eq!(
            answered_response(&serde_json::to_vec(&output).unwrap()),
            None,
            "{output}"
        );
    }
    assert_eq!(answered_response(b"not json"), None);
}

#[test]
fn a_blank_runtime_harness_keeps_the_codex_review() {
    let homes = homes("runtime-harness");
    let query = format!(
        "guard-home={}&home={}&runtime-harness=+",
        encoded(&homes.guard_home),
        encoded(&homes.home),
    );
    assert!(built(&homes, &query, PAYLOAD).is_some());
}

#[test]
fn a_hook_without_a_home_leaves_the_resident_the_daemon_home() {
    let homes = homes("no-home");
    let query = format!("guard-home={}&workspace=/work", encoded(&homes.guard_home));
    let request: Value = serde_json::from_slice(
        &direct_request(
            CLAUDE_CODE,
            &homes.guard_home,
            &query,
            PAYLOAD,
            Duration::from_millis(400),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        request,
        json!({
            "operation": "hook_direct",
            "deadline_budget_ms": 400,
            "request": {
                "harness": "claude-code",
                "guard_home": text(&homes.guard_home),
                "workspace": "/work",
                "deadline_budget_ms": 400,
                "payload": {"hook_event_name": "PreToolUse", "tool_name": "Bash"},
            },
        })
    );
    assert_eq!(
        built(&homes, &query, PAYLOAD).unwrap()["request"]["harness"],
        "codex"
    );
}

#[test]
fn lifecycle_hooks_reach_the_resident_and_permission_hooks_do_not() {
    for event in [
        "PreToolUse",
        "PostToolUse",
        "UserPromptSubmit",
        "Stop",
        "SessionStart",
        "TaskComplete",
    ] {
        assert!(direct_event(event), "{event}");
    }
    for event in [
        "",
        "PermissionRequest",
        "permission_request_v2",
        "copilotPermissionRequest",
        "Notification",
        "beforeSubmitPrompt",
    ] {
        assert!(!direct_event(event), "{event}");
    }
}

#[test]
fn claude_code_and_codex_ask_the_resident_about_their_permission_dialogs() {
    assert!(harness_event(&CLAUDE_CODE, "PermissionRequest"));
    assert!(harness_event(&CLAUDE_CODE, "Notification"));
    assert!(harness_event(&CLAUDE_CODE, "Stop"));
    assert!(harness_event(&CODEX, "PermissionRequest"));
    assert!(!harness_event(&CODEX, "Notification"));
    assert!(!harness_event(&CURSOR, "PermissionRequest"));
    for event in [
        "permission_request_v2",
        "notification",
        "copilotPermissionRequest",
    ] {
        assert!(!harness_event(&CLAUDE_CODE, event), "{event}");
        assert!(!harness_event(&CODEX, event), "{event}");
    }
}

#[test]
fn copilot_devin_and_zcode_ask_the_resident_about_their_permission_requests() {
    for harness in ["copilot", "devin", "zcode"] {
        for event in [
            "PermissionRequest",
            "permissionRequest",
            "permissionRequestV2",
        ] {
            assert!(bounded_event(harness, event), "{harness} {event}");
        }
        assert!(bounded_event(harness, "PreToolUse"), "{harness}");
        assert!(!bounded_event(harness, "Notification"), "{harness}");
        assert!(
            !bounded_event(harness, "copilotPermissionRequest"),
            "{harness}"
        );
    }
    for harness in ["kimi", "cline", "opencode", "grok"] {
        assert!(!bounded_event(harness, "PermissionRequest"), "{harness}");
    }
}

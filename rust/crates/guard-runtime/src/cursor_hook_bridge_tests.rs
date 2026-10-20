//! The Cursor bridge's reproduction of its client's request, and the
//! client constants it reads.

use std::time::{Duration, Instant};

use guard_command::hook_adapter_value::parse_python_json;
use serde_json::{json, Value};

use super::*;
use crate::cursor_hook_bridge_response::{FIXED_NOW, UNAVAILABLE_STDOUT};
use crate::cursor_hook_bridge_script::{normalize, read_client_constants, ScriptConstants};

pub(super) fn client_text(guard_home: &str, hook_argv: &str, timeout: &str) -> String {
    format!(
        "import os\nGUARD_HOME = {}\nGUARD_CLI = [\"/bin/hol-guard\"]\n\
         GUARD_RECOVERY_COMMAND = [\"/bin/hol-guard\", \"guard\", \"daemon\"]\n\
         GUARD_HOOK_ARGV = {hook_argv}\nGUARD_INHERIT_ENV_KEYS = [\"PATH\"]\n\
         GUARD_HOOK_TIMEOUT_SECONDS = {timeout}\nmain()",
        json!(guard_home)
    )
}

pub(super) const HOOK_ARGV: &str =
    r#"["guard", "hook", "--harness", "cursor", "--home", "/home/u"]"#;

#[test]
fn rendered_constants_are_read_back_from_the_client() {
    let (template, constants) = normalize(&client_text("/g h", HOOK_ARGV, "57")).unwrap();
    assert_eq!(
        template,
        "import os\nGUARD_HOME = __GUARD_HOME__\nGUARD_CLI = __GUARD_CLI__\n\
         GUARD_RECOVERY_COMMAND = __GUARD_RECOVERY_COMMAND__\n\
         GUARD_HOOK_ARGV = __GUARD_HOOK_ARGV__\n\
         GUARD_INHERIT_ENV_KEYS = __GUARD_INHERIT_ENV_KEYS__\n\
         GUARD_HOOK_TIMEOUT_SECONDS = __GUARD_HOOK_TIMEOUT_SECONDS__\nmain()"
    );
    assert_eq!(
        constants,
        ScriptConstants {
            guard_home: "/g h".to_owned(),
            home: Some("/home/u".to_owned()),
            recovery_command: vec![
                "/bin/hol-guard".to_owned(),
                "guard".to_owned(),
                "daemon".to_owned(),
            ],
            timeout_seconds: 57,
        }
    );
    for (argv, home) in [
        (r#"["guard", "hook"]"#, None),
        (r#"["--home"]"#, None),
        (r#"["--home", "  "]"#, None),
        (r#"["--home", " /h ", "--home", "/i"]"#, Some(" /h ")),
    ] {
        let (_, constants) = normalize(&client_text("/g", argv, "1")).unwrap();
        assert_eq!(constants.home.as_deref(), home, "{argv}");
    }
}

#[test]
fn clients_the_renderer_did_not_write_are_not_read() {
    for text in [
        client_text("/g", HOOK_ARGV, "0"),
        client_text("/g", HOOK_ARGV, "07"),
        client_text("/g", HOOK_ARGV, "-1"),
        client_text("/g", HOOK_ARGV, "1.5"),
        client_text("/g", r#"["--home", 7]"#, "1"),
        client_text("/g", r#""--home""#, "1"),
        format!("{}\nGUARD_HOME = \"/h\"", client_text("/g", HOOK_ARGV, "1")),
        format!("{}\nGUARD_CLI = []", client_text("/g", HOOK_ARGV, "1")),
        client_text("/g", HOOK_ARGV, "1").replace("GUARD_INHERIT_ENV_KEYS = [\"PATH\"]\n", ""),
        client_text("/g", HOOK_ARGV, "1").replace("[\"PATH\"]", "{}"),
        client_text("\u{1}", HOOK_ARGV, "1").replace("\\u0001", "\\ud800"),
    ] {
        assert_eq!(normalize(&text), None, "{text}");
    }
}

#[test]
fn a_client_an_older_guard_rendered_is_answered_natively() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("cursor_hook.py");
    // Rendered from another template than the one the bridge was ported from.
    std::fs::write(&script, client_text("/g", HOOK_ARGV, "3")).unwrap();
    let constants = read_client_constants(&script).unwrap();
    assert_eq!(
        (constants.guard_home.as_str(), constants.timeout_seconds),
        ("/g", 3)
    );
    std::fs::write(&script, client_text("/g", HOOK_ARGV, "0")).unwrap();
    assert_eq!(read_client_constants(&script), None);
    assert_eq!(read_client_constants(&dir.path().join("missing.py")), None);
}

#[test]
fn the_query_is_urlencoded_as_the_client_encodes_it() {
    assert_eq!(
        hook_query("/g h/.hol-guard", Some("/w~a_b.c-d"), Some("/h&x=y")),
        "guard-home=%2Fg+h%2F.hol-guard&workspace=%2Fw~a_b.c-d&home=%2Fh%26x%3Dy"
    );
    assert_eq!(hook_query("/g", None, None), "guard-home=%2Fg");
    assert_eq!(hook_query("/é", None, None), "guard-home=%2F%C3%A9");
    let parsed =
        crate::codex_hook_bridge_direct::parse_hook_query(&hook_query(" /g+h%", Some("/w"), None))
            .unwrap();
    assert_eq!(parsed.guard_home.as_deref(), Some(" /g+h%"));
    assert_eq!(parsed.workspace.as_deref(), Some("/w"));
    assert_eq!(parsed.home, None);
}

fn scratch(label: &str) -> std::path::PathBuf {
    let root =
        std::env::temp_dir().join(format!("cursor-hook-bridge-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("project")).unwrap();
    std::fs::create_dir_all(root.join("root")).unwrap();
    std::fs::create_dir_all(root.join("cwd")).unwrap();
    std::fs::canonicalize(root).unwrap()
}

/// A guard home with the daemon auth token file the client may sign a
/// loopback review link with, or without it.
fn guard_home(label: &str, tokened: bool) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let root = scratch(label);
    if tokened {
        // The client loads the token only from a private file in a private
        // directory.
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let token = root.join("daemon-auth-token");
        std::fs::write(&token, "3f".repeat(32)).unwrap();
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    root
}

fn map(value: Value) -> OMap {
    let OValue::Map(map) = parse_python_json(&value.to_string()).unwrap() else {
        panic!("not a map");
    };
    map
}

#[test]
fn the_workspace_is_the_first_directory_the_client_would_pick() {
    let root = scratch("workspace");
    let dir = |name: &str| root.join(name).to_str().unwrap().to_owned();
    let missing = dir("missing");
    let payload = map(json!({
        "workspace_roots": [7, " ", missing, format!(" {} ", dir("root"))],
        "cwd": dir("cwd"),
    }));
    assert_eq!(
        workspace(
            &payload,
            Some(format!("\t{}\n", dir("project")).into()),
            false
        ),
        Ok(Some(dir("project")))
    );
    assert_eq!(
        workspace(&payload, Some(missing.clone().into()), false),
        Ok(Some(dir("root")))
    );
    assert_eq!(workspace(&payload, None, false), Ok(Some(dir("root"))));
    let camel = map(json!({"workspace_roots": [], "workspaceRoots": [dir("root")]}));
    assert_eq!(workspace(&camel, None, false), Ok(Some(dir("root"))));
    let not_list = map(json!({"workspace_roots": dir("root"), "cwd": dir("cwd")}));
    assert_eq!(workspace(&not_list, None, false), Ok(Some(dir("cwd"))));
    let nothing = map(json!({"workspace_roots": [missing], "cwd": 7}));
    assert_eq!(workspace(&nothing, None, false), Ok(None));
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let undecodable = std::ffi::OsString::from_vec(b"/\xff".to_vec());
        assert_eq!(workspace(&nothing, Some(undecodable), false), Err(()));
    }
    std::fs::remove_dir_all(root).unwrap();
}

fn test_client() -> Client {
    Client {
        guard_home: "/g".to_owned(),
        home: Some("/h".to_owned()),
        recovery_command: Vec::new(),
        event: "preToolUse".to_owned(),
        deadline: Instant::now() + Duration::from_secs(5),
    }
}

#[test]
fn only_tool_hooks_and_observers_are_sent() {
    let client = test_client();
    let shell = br#"{"hook_event_name":"beforeShellExecution","command":"ls","cwd":"/nonexistent-cursor-cwd"}"#;
    let Request {
        data,
        query,
        event,
        kind,
    } = prepared_request(&client, shell).unwrap();
    assert_eq!(query, "guard-home=%2Fg&home=%2Fh");
    assert_eq!(event, "beforeShellExecution");
    assert_eq!(kind, Kind::PreToolUse);
    let sent: Value = serde_json::from_str(&data).unwrap();
    assert_eq!(sent["hook_event_name"], "PreToolUse");
    assert_eq!(sent["cursor_source_hook_event"], "beforeShellExecution");
    let mut with_bom = b"\xef\xbb\xbf \n".to_vec();
    with_bom.extend_from_slice(shell);
    assert!(prepared_request(&client, &with_bom).is_some());
    for raw in [
        &br#"{"hook_event_name":"beforeSubmitPrompt","prompt":"hi"}"#[..],
        br#"{"hook_event_name":"afterFileEdit","file_path":"/tmp/a"}"#,
        br#"{"hook_event_name":"after_shell_execution","command":"ls"}"#,
        br#"{"hook_event_name":"stop"}"#,
        br#"[]"#,
        b"",
        b" \n",
        b"\xc2\xa0{}",
        b"{\"command\": \"ls\"}\xc2\xa0",
        br#"{"command": NaN}"#,
        b"\xff",
    ] {
        assert_eq!(
            prepared_request(&client, raw),
            None,
            "{}",
            String::from_utf8_lossy(raw)
        );
    }
    let mut oversized = shell.to_vec();
    oversized.resize(MAX_HOOK_INPUT_BYTES + 1, b' ');
    assert_eq!(prepared_request(&client, &oversized), None);
    let inferred = br#"{"file_path":"/tmp/a.txt"}"#;
    let request = prepared_request(&client, inferred).unwrap();
    assert_eq!(request.event, "beforeReadFile");
}

#[test]
fn the_answer_is_named_for_the_event_the_client_infers() {
    let client = test_client();
    let event = |raw: &[u8]| prepared_request(&client, raw).map(|request| request.event);
    // A name under another key keeps the client's default.
    assert_eq!(
        event(br#"{"event":"beforeReadFile","file_path":"/tmp/a"}"#).as_deref(),
        Some("preToolUse")
    );
    assert_eq!(
        event(br#"{"hookEventName":" BeforeReadFile ","file_path":"/tmp/a"}"#).as_deref(),
        Some(" BeforeReadFile ")
    );
    assert_eq!(
        event(br#"{"hook_event_name":"","hookEventName":"beforeReadFile","file_path":"/a"}"#)
            .as_deref(),
        Some("beforeReadFile")
    );
    // A name that is not text is inferred over when nothing else names the
    // hook, and otherwise left to the client.
    assert_eq!(
        event(br#"{"hook_event_name":7,"file_path":"/tmp/a"}"#).as_deref(),
        Some("beforeReadFile")
    );
    assert_eq!(
        event(br#"{"hook_event_name":7,"event":"beforeShellExecution","command":"ls"}"#),
        None
    );
}

const ANSWER_VECTORS: &str =
    include_str!("../../../../tests/fixtures/cursor_native_answers/vectors.json");

#[test]
fn answers_match_the_client_for_every_vector() {
    let fixture: Value = serde_json::from_str(ANSWER_VECTORS).unwrap();
    let vectors = fixture["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 20);
    // A loopback review link the client may sign stays with the client.
    let home = guard_home("answers", true);
    for vector in vectors {
        let event = vector["event"].as_str().unwrap();
        let response = vector["response"].as_str().unwrap();
        let Some(stdout) = vector["stdout"].as_str() else {
            // The client signs review links and keeps lone surrogates, which
            // the review and surrogate vectors check; anything else the
            // bridge does not answer fails closed.
            if !(response.to_ascii_lowercase().contains("approval") || response.contains("\\ud800"))
            {
                assert_eq!(
                    answer(Kind::PreToolUse, event, response, &home),
                    None,
                    "{event:?} {response}"
                );
            }
            continue;
        };
        let code = vector["exit_code"].as_i64().unwrap();
        let expected = Some((stdout.to_owned(), i32::try_from(code).unwrap()));
        assert_eq!(
            answer(Kind::PreToolUse, event, response, &home),
            expected,
            "{event:?} {response}"
        );
    }
    std::fs::remove_dir_all(home).unwrap();
}

const REVIEW_VECTORS: &str =
    include_str!("../testdata/cursor_hook_bridge/cursor_review_vectors.json");

#[test]
fn reviews_and_prompts_match_the_client_in_either_guard_home() {
    let fixture: Value = serde_json::from_str(REVIEW_VECTORS).unwrap();
    assert_eq!(
        fixture["schema"],
        "hol-guard-cursor-native-review-answers.v1"
    );
    let vectors = fixture["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 200);
    FIXED_NOW.with(|now| now.set(fixture["now_micros"].as_i64()));
    let signed = vectors
        .iter()
        .filter(|vector| {
            vector["stdout"]
                .as_str()
                .unwrap()
                .contains("#guard-token=gld1.")
        })
        .count();
    assert!(signed >= 30);
    let untokened = guard_home("review-untokened", false);
    let tokened = guard_home("review-tokened", true);
    for vector in vectors {
        let home = match vector["home"].as_str().unwrap() {
            "untokened" => &untokened,
            "tokened" => &tokened,
            other => panic!("unknown home {other}"),
        };
        let event = vector["event"].as_str().unwrap();
        let response = vector["response"].as_str().unwrap();
        let kind = if prompt_event(event) {
            Kind::Prompt
        } else {
            Kind::PreToolUse
        };
        let code = vector["exit_code"].as_i64().unwrap();
        let expected = Some((
            vector["stdout"].as_str().unwrap().to_owned(),
            i32::try_from(code).unwrap(),
        ));
        assert_eq!(
            answer(kind, event, response, home),
            expected,
            "{} {} {event:?} {response}",
            vector["home"],
            vector["case"]
        );
    }
    // A link the client leaves unsigned is shown as it is.
    let odd = r#"{"policy_action":"review","reason":"r","approval_url":"https://guard.example/approvals/a?b=c"}"#;
    let (stdout, code) = answer(Kind::PreToolUse, "beforeShellExecution", odd, &tokened).unwrap();
    assert_eq!(code, 0);
    assert!(stdout.contains("a?b=c.") && !stdout.contains("guard-token"));
    FIXED_NOW.with(|now| now.set(None));
    std::fs::remove_dir_all(untokened).unwrap();
    std::fs::remove_dir_all(tokened).unwrap();
}

#[test]
fn a_prompt_is_sent_only_when_nothing_else_names_the_hook() {
    let client = test_client();
    for name in [
        "UserPromptSubmit",
        " user_prompt_submit ",
        "prompt",
        "userPromptSubmitted",
    ] {
        let raw = json!({"hook_event_name": name, "prompt": "hi"}).to_string();
        let request = prepared_request(&client, raw.as_bytes()).unwrap_or_else(|| panic!("{name}"));
        assert_eq!(request.kind, Kind::Prompt, "{name}");
        assert_eq!(request.event, name);
    }
    for raw in [
        &br#"{"hook_event_name":"UserPromptSubmit","event":"x","prompt":"hi"}"#[..],
        br#"{"hook_event_name":"UserPromptSubmit","eventName":"x","prompt":"hi"}"#,
        br#"{"hook_event_name":"beforeSubmitPrompt","prompt":"hi"}"#,
    ] {
        assert_eq!(
            prepared_request(&client, raw),
            None,
            "{}",
            String::from_utf8_lossy(raw)
        );
    }
}

const AFTER_VECTORS: &str =
    include_str!("../../../../tests/fixtures/cursor_native_answers/after_vectors.json");

/// The stamped payload as `json.loads` reads it, without the environment
/// the stamp adds.
fn sent_payload(data: &str) -> Value {
    let mut sent: Value = serde_json::from_str(data).unwrap();
    sent.as_object_mut()
        .unwrap()
        .remove("guard_execution_environment");
    sent
}

#[test]
fn observers_are_sent_and_answered_as_the_client_does() {
    let fixture: Value = serde_json::from_str(AFTER_VECTORS).unwrap();
    assert_eq!(
        fixture["schema"],
        "hol-guard-cursor-native-after-answers.v1"
    );
    let vectors = fixture["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 8);
    let client = test_client();
    for vector in vectors {
        let input = vector["input"].as_str().unwrap();
        let request = prepared_request(&client, input.as_bytes());
        if vector["observer"] != true {
            assert!(
                request.is_none_or(|request| request.kind != Kind::After),
                "{input}"
            );
            continue;
        }
        let request = request.unwrap_or_else(|| panic!("{input}"));
        assert_eq!(request.kind, Kind::After, "{input}");
        assert_eq!(sent_payload(&request.data), vector["sent"], "{input}");
        for expected in vector["answers"].as_array().unwrap() {
            let body = expected["daemon_body"].as_str().unwrap();
            let stdout = expected["stdout"].as_str().unwrap().to_owned();
            let code = i32::try_from(expected["exit_code"].as_i64().unwrap()).unwrap();
            assert_eq!(
                answer(Kind::After, &request.event, body, Path::new("/g")),
                Some((stdout, code)),
                "{input} {body}"
            );
        }
    }
    // A body `_daemon_hook_result` rejects sends the hook to the client.
    for body in ["", " ", "[]", "null", "\"{}\"", "{", "{} {}"] {
        assert_eq!(
            answer(Kind::After, "afterShellExecution", body, Path::new("/g")),
            None,
            "{body:?}"
        );
    }
}

#[test]
fn only_the_installed_command_shape_is_answered() {
    let root = scratch("client");
    let script = root.join("hook.py");
    std::fs::write(&script, client_text("/g", HOOK_ARGV, "1")).unwrap();
    let script = script.to_str().unwrap().to_owned();
    let argv = |parts: &[&str]| {
        parts
            .iter()
            .map(|part| (*part).to_owned())
            .collect::<Vec<_>>()
    };
    let started = Instant::now();
    let installed = argv(&["python3", "-I", &script, EVENT_FLAG, "preToolUse"]);
    assert!(client(&installed, started).is_some());
    for python_argv in [
        argv(&["python3", "-I", &script, EVENT_FLAG]),
        argv(&["python3", "-E", &script, EVENT_FLAG, "preToolUse"]),
        argv(&["python3", "-I", &script, "--event", "preToolUse"]),
        argv(&[
            "python3",
            "-I",
            "/nonexistent/hook.py",
            EVENT_FLAG,
            "preToolUse",
        ]),
    ] {
        assert!(client(&python_argv, started).is_none(), "{python_argv:?}");
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn an_unreadable_hook_past_its_deadline_answers_as_the_client_does() {
    assert_eq!(unavailable_output("afterShellExecution"), ("{}\n", 0));
    assert_eq!(unavailable_output(" after_mcp-execution "), ("{}\n", 0));
    assert_eq!(unavailable_output("preToolUse"), (UNAVAILABLE_STDOUT, 2));
    assert_eq!(unavailable_output(""), (UNAVAILABLE_STDOUT, 2));
    let stdout: Value = serde_json::from_str(UNAVAILABLE_STDOUT).unwrap();
    assert_eq!(
        stdout,
        json!({
            "permission": "deny",
            "user_message": "HOL Guard could not complete the native hook decision safely.",
        })
    );
}

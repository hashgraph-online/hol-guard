//! The Cursor bridge's reproduction of its client's request, and the
//! ported-client check.

use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::*;
use crate::cursor_hook_bridge_script::{normalize, ported_constants, ScriptConstants};

fn client_text(guard_home: &str, hook_argv: &str, timeout: &str) -> String {
    format!(
        "import os\nGUARD_HOME = {}\nGUARD_CLI = [\"/bin/hol-guard\"]\n\
         GUARD_RECOVERY_COMMAND = [\"/bin/hol-guard\", \"guard\", \"daemon\"]\n\
         GUARD_HOOK_ARGV = {hook_argv}\nGUARD_INHERIT_ENV_KEYS = [\"PATH\"]\n\
         GUARD_HOOK_TIMEOUT_SECONDS = {timeout}\nmain()",
        json!(guard_home)
    )
}

const HOOK_ARGV: &str = r#"["guard", "hook", "--harness", "cursor", "--home", "/home/u"]"#;

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
    // A client the renderer wrote from another template.
    assert_eq!(ported_constants(&client_text("/g", HOOK_ARGV, "1")), None);
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
        workspace(&payload, Some(format!("\t{}\n", dir("project")).into())),
        Ok(Some(dir("project")))
    );
    assert_eq!(
        workspace(&payload, Some(missing.clone().into())),
        Ok(Some(dir("root")))
    );
    assert_eq!(workspace(&payload, None), Ok(Some(dir("root"))));
    let camel = map(json!({"workspace_roots": [], "workspaceRoots": [dir("root")]}));
    assert_eq!(workspace(&camel, None), Ok(Some(dir("root"))));
    let not_list = map(json!({"workspace_roots": dir("root"), "cwd": dir("cwd")}));
    assert_eq!(workspace(&not_list, None), Ok(Some(dir("cwd"))));
    let nothing = map(json!({"workspace_roots": [missing], "cwd": 7}));
    assert_eq!(workspace(&nothing, None), Ok(None));
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let undecodable = std::ffi::OsString::from_vec(b"/\xff".to_vec());
        assert_eq!(workspace(&nothing, Some(undecodable)), Err(()));
    }
    std::fs::remove_dir_all(root).unwrap();
}

fn test_client() -> Client {
    Client {
        guard_home: "/g".to_owned(),
        home: Some("/h".to_owned()),
        deadline: Instant::now() + Duration::from_secs(5),
    }
}

#[test]
fn only_hooks_cursor_asks_before_running_a_tool_are_sent() {
    let client = test_client();
    let shell = br#"{"hook_event_name":"beforeShellExecution","command":"ls","cwd":"/nonexistent-cursor-cwd"}"#;
    let (data, query) = prepared_request(&client, shell).unwrap();
    assert_eq!(query, "guard-home=%2Fg&home=%2Fh");
    let sent: Value = serde_json::from_str(&data).unwrap();
    assert_eq!(sent["hook_event_name"], "PreToolUse");
    assert_eq!(sent["cursor_source_hook_event"], "beforeShellExecution");
    let mut with_bom = b"\xef\xbb\xbf \n".to_vec();
    with_bom.extend_from_slice(shell);
    assert!(prepared_request(&client, &with_bom).is_some());
    for raw in [
        &br#"{"hook_event_name":"afterShellExecution","command":"ls"}"#[..],
        br#"{"hook_event_name":"afterMCPExecution","tool_name":"x"}"#,
        br#"{"hook_event_name":"beforeSubmitPrompt","prompt":"hi"}"#,
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
    assert!(prepared_request(&client, inferred).is_some());
}

#[test]
fn only_an_allow_or_warn_is_answered() {
    assert!(allowed(r#"{"policy_action":"allow","continue":true}"#));
    assert!(allowed(r#"{"policy_action":"warn"}"#));
    for response in [
        r#"{"policy_action":"review"}"#,
        r#"{"policy_action":"block"}"#,
        r#"{"policy_action":"sandbox-required"}"#,
        r#"{"policy_action":"require-reapproval"}"#,
        r#"{"policy_action":"Allow"}"#,
        r#"{"policy_action":["allow"]}"#,
        r#"{"continue":true}"#,
        r#"[]"#,
        "",
    ] {
        assert!(!allowed(response), "{response}");
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
    for python_argv in [
        argv(&["python3", "-I", &script, EVENT_FLAG, "preToolUse"]),
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
        // The fixture is not the ported client, so none of these is read.
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

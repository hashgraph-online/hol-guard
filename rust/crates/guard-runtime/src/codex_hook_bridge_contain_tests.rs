//! Codex sandbox-required answers: Python parity for the installed hook
//! home, the Guard home, the update hint and the contained rewrite.

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use super::codex::version_supported;
use super::*;
use crate::pyjson::parse_mapping_lone_surrogates;

const PYTHON: &str = "/usr/bin/python3";
const BOOTSTRAP: &str = "import sys;sys.path.insert(0, '/opt/guard/site-packages');from codex_plugin_scanner.cli import main;raise SystemExit(main(sys.argv[1:]))";
const WORKSPACE_DENY: &str = r#"{"policy_action":"sandbox-required","decision":"deny","reason_code":"native_workspace_containment_required","required_execution_profile":"workspace-contained-v1","hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Run this inside the contained runner."}}"#;

fn parsed(text: &str) -> PyVal {
    parse_mapping_lone_surrogates(text).unwrap().value
}

fn fallback() -> Vec<String> {
    [
        PYTHON,
        "-I",
        "-c",
        BOOTSTRAP,
        "guard",
        "hook",
        "--harness",
        "codex",
    ]
    .map(str::to_owned)
    .to_vec()
}

#[test]
fn only_a_stable_codex_at_or_above_0_131_applies_the_rewrite() {
    for (stdout, supported) in [
        ("codex-cli 0.131.0", true),
        ("codex-cli 0.131.0\n", true),
        ("  codex-cli 1.0.0  ", true),
        ("codex-cli 0.200.12", true),
        ("codex-cli 0.130.9", false),
        ("codex-cli 0.131.0-beta.1", false),
        ("codex-cli 0.131", false),
        ("codex-cli 0.131.0.1", false),
        ("codex-cli 0..131", false),
        ("codex-cli +0.131.0", false),
        ("codex 0.131.0", false),
        ("codex-cli  0.131.0", false),
        ("", false),
    ] {
        assert_eq!(version_supported(stdout), supported, "{stdout:?}");
    }
}

#[test]
fn the_installed_hook_home_is_read_as_parse_qs_reads_it() {
    for (query, home) in [
        ("harness=codex&home=%2Fh", Some("/h")),
        ("home=/Users/a+b", Some("/Users/a b")),
        ("home=%2Fh%2F..%2F.%2Fx%2F", Some("/h/../x")),
        ("h%6fme=/h", Some("/h")),
        ("&&home=/h&", Some("/h")),
        ("home=/h&home=/h", None),
        ("home", None),
        ("home=", None),
        ("home=relative", None),
        ("home=%2Fh%00", None),
        ("harness=codex", None),
        ("", None),
    ] {
        assert_eq!(hook_home(query).as_deref(), home, "{query:?}");
    }
}

#[test]
fn the_guard_home_is_the_state_file_parent() {
    for (state_path, home) in [
        ("/h/daemon-state.json", Some("/h")),
        ("/h//./daemon-state.json", Some("/h")),
        ("//h/daemon-state.json", Some("//h")),
        ("/daemon-state.json", Some("/")),
        ("h/daemon-state.json", None),
        ("/h/state.json", None),
        ("/h/daemon-state.json/", Some("/h")),
    ] {
        assert_eq!(guard_home(state_path).as_deref(), home, "{state_path:?}");
    }
}

#[test]
fn the_update_hint_extends_the_denial_reason() {
    let hinted = |text: &str| {
        let mut out = String::new();
        crate::hook_env_stamp::dumps(&with_update_hint(parsed(text)), true, false, &mut out);
        out
    };
    assert_eq!(
        hinted(r#"{"hookSpecificOutput":{"permissionDecisionReason":"Blocked.","x":1}}"#),
        format!(
            r#"{{"hookSpecificOutput":{{"permissionDecisionReason":"Blocked. {UPDATE_HINT}","x":1}}}}"#
        )
    );
    for empty in [
        r#"{"hookSpecificOutput":{"permissionDecisionReason":""}}"#,
        r#"{"hookSpecificOutput":{"permissionDecisionReason":1}}"#,
    ] {
        assert_eq!(
            hinted(empty),
            format!(r#"{{"hookSpecificOutput":{{"permissionDecisionReason":"{UPDATE_HINT}"}}}}"#),
            "{empty}"
        );
    }
    assert_eq!(
        hinted(r#"{"hookSpecificOutput":{"permissionDecision":"deny"}}"#),
        format!(
            r#"{{"hookSpecificOutput":{{"permissionDecision":"deny","permissionDecisionReason":"{UPDATE_HINT}"}}}}"#
        )
    );
    for untouched in [r#"{"decision":"deny"}"#, r#"{"hookSpecificOutput":[]}"#] {
        assert_eq!(hinted(untouched), untouched, "{untouched}");
    }
}

#[test]
fn the_sink_prefix_is_the_isolated_interpreter_and_bootstrap() {
    let installed = fallback();
    assert_eq!(sink_prefix(&installed), Some(&installed[..4]));
    for broken in [
        &installed[..4],
        &["python3", "-I", "-c", BOOTSTRAP, "guard"].map(str::to_owned)[..],
        &[PYTHON, "-c", "-I", BOOTSTRAP, "guard"].map(str::to_owned)[..],
        &[PYTHON, "-I", "-c", "import os", "guard"].map(str::to_owned)[..],
        &[PYTHON, "-I", "-c", BOOTSTRAP, "hook"].map(str::to_owned)[..],
    ] {
        assert_eq!(sink_prefix(broken), None, "{broken:?}");
    }
}

/// The request file a routed command names, read back and removed.
fn take_request(command: &str) -> (Vec<u8>, u32) {
    let (_, rest) = command.split_once(" --request-file ").unwrap();
    let path = Path::new(rest.split_once(' ').unwrap().0);
    let bytes = std::fs::read(path).unwrap();
    let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    discard(path);
    (bytes, mode)
}

#[test]
fn a_contained_call_is_rewritten_to_run_the_sink() {
    let workspace = tempfile::tempdir().unwrap();
    let resolved = std::fs::canonicalize(workspace.path()).unwrap();
    let resolved = resolved.to_str().unwrap();
    let payload = parsed(&format!(
        r#"{{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{{"command":"make test","timeout":5}},"cwd":"{}","session_id":"s1","tool_use_id":"t1"}}"#,
        workspace.path().display()
    ));
    let installed = fallback();
    let target = Target {
        prefix: &installed,
        guard_home: "/g",
        home: "/h",
    };
    let routed = routed(&parsed(WORKSPACE_DENY), &payload, false, &target).unwrap();
    assert_eq!(text(&routed, "policy_action"), Some("allow"));
    assert_eq!(text(&routed, "reason_code"), Some(ROUTED_REASON));
    let output = routed.get("hookSpecificOutput").unwrap();
    assert_eq!(text(output, "permissionDecision"), Some("allow"));
    let updated = output.get("updatedInput").unwrap();
    assert_eq!(updated.get("timeout"), Some(&PyVal::Int("5".to_owned())));
    let command = text(updated, "command").unwrap().to_owned();
    let (request, mode) = take_request(&command);
    assert_eq!(mode, 0o600);
    let digest = hex::encode(Sha256::digest(&request));
    let snapshot: serde_json::Value = serde_json::from_slice(&request).unwrap();
    assert_eq!(snapshot["schema"], REQUEST_SCHEMA);
    assert_eq!(snapshot["workspace"], resolved);
    assert_eq!(snapshot["payload"]["tool_name"], "bash");
    assert_eq!(snapshot["payload"]["tool_input"]["command"], "make test");
    assert_eq!(snapshot["payload"]["tool_call_id"], "t1");
    assert_eq!(snapshot["payload"]["session_id"], "s1");
    let expected_tail = format!(
        "guard execute-contained-test --harness codex --guard-home /g --workspace {resolved} --request-file "
    );
    assert!(command.contains(&expected_tail), "{command}");
    assert!(
        command.ends_with(&format!("--request-sha256 {digest} --home /h")),
        "{command}"
    );
    assert!(
        command.starts_with(&format!("{PYTHON} -I -c '")),
        "{command}"
    );
}

#[test]
fn calls_the_sink_cannot_run_keep_the_denial() {
    let workspace = tempfile::tempdir().unwrap();
    let cwd = workspace.path().display().to_string();
    let installed = fallback();
    let target = Target {
        prefix: &installed,
        guard_home: "/g",
        home: "/h",
    };
    let deny = parsed(WORKSPACE_DENY);
    for payload in [
        format!(
            r#"{{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{{"command":"x"}},"cwd":"{cwd}"}}"#
        ),
        format!(
            r#"{{"hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{{"command":"x"}},"cwd":"{cwd}"}}"#
        ),
        format!(
            r#"{{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{{"command":1}},"cwd":"{cwd}"}}"#
        ),
        format!(
            r#"{{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":"x","cwd":"{cwd}"}}"#
        ),
        format!(
            r#"{{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{{"command":"x"}},"cwd":"{cwd}/missing"}}"#
        ),
        r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"x"}}"#
            .to_owned(),
    ] {
        assert_eq!(
            routed(&deny, &parsed(&payload), false, &target),
            None,
            "{payload}"
        );
    }
    let payload = parsed(&format!(
        r#"{{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{{"command":"x"}},"cwd":"{cwd}"}}"#
    ));
    for response in [
        r#"{"reason_code":"native_workspace_containment_required","required_execution_profile":"git-readonly-v1"}"#,
        r#"{"reason_code":"native_unknown","required_execution_profile":"workspace-contained-v1"}"#,
        r#"{"reason_code":"native_workspace_containment_required","required_execution_profile":"workspace-contained-v1","observe_mode":true}"#,
    ] {
        assert_eq!(
            routed(&parsed(response), &payload, false, &target),
            None,
            "{response}"
        );
    }
    let bare = Target {
        prefix: &installed[..4],
        guard_home: "/g",
        home: "/h",
    };
    assert_eq!(routed(&deny, &payload, false, &bare), None);
}

fn bridge(query: &str) -> BridgeConfig {
    BridgeConfig {
        state_path: "/g/daemon-state.json".to_owned(),
        query: query.to_owned(),
        hook_timeouts: Vec::new(),
        start_command: Vec::new(),
        fallback_command: fallback(),
    }
}

fn prepared(data: &str) -> Prepared {
    Prepared {
        event_name: PRE_TOOL_USE.to_owned(),
        data: data.to_owned(),
        timeout: Duration::from_secs(30),
    }
}

const RENDERED_DENY: &str = r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Run this inside the contained runner."}}"#;

#[test]
fn a_denial_outside_a_codex_launch_carries_the_update_hint() {
    // No launching Codex applies the rewrite, whatever launched the runner.
    FIXED_CODEX_APPLIES.with(|applies| applies.set(Some(false)));
    let deadline = Instant::now() + Duration::from_secs(5);
    let route = settle(
        &bridge("harness=codex&home=%2Fh"),
        &prepared(r#"{"hook_event_name":"PreToolUse","tool_name":"Bash"}"#),
        parsed(WORKSPACE_DENY),
        false,
        deadline,
    );
    FIXED_CODEX_APPLIES.with(|applies| applies.set(None));
    assert_eq!(
        route,
        Route::Respond(format!(
            r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Run this inside the contained runner. {UPDATE_HINT}"}}}}"#
        ))
    );
}

#[test]
fn a_denial_containment_does_not_apply_to_stands() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let hook = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash"}"#;
    for (query, data) in [
        ("harness=codex", hook),
        ("home=relative", hook),
        ("home=%2Fh", "[]"),
        (
            "home=%2Fh",
            r#"{"hook_event_name":"PreToolUse","guard_containment_receipt_only":true}"#,
        ),
    ] {
        let route = settle(
            &bridge(query),
            &prepared(data),
            parsed(WORKSPACE_DENY),
            false,
            deadline,
        );
        assert_eq!(
            route,
            Route::Respond(RENDERED_DENY.to_owned()),
            "{query} {data}"
        );
    }
    let allowed = WORKSPACE_DENY.replace(r#""decision":"deny""#, r#""decision":"allow""#);
    let route = settle(
        &bridge("home=%2Fh"),
        &prepared(hook),
        parsed(&allowed),
        false,
        deadline,
    );
    assert_eq!(route, Route::Respond(RENDERED_DENY.to_owned()));
}

#[test]
fn a_contained_denial_that_names_an_approval_still_waits() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let response = r#"{"policy_action":"sandbox-required","decision":"deny","hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Approve at http://127.0.0.1:4781/requests/req_12345678"}}"#;
    let route = settle(
        &bridge("harness=codex"),
        &prepared(r#"{"hook_event_name":"PreToolUse"}"#),
        parsed(response),
        false,
        deadline,
    );
    assert!(matches!(route, Route::AwaitApproval(..)), "{route:?}");
}

use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::{
    dispatch, environment_harness, harness_from_executable, parent_harness, runtime_hook_harness,
};

fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

fn from_env(pairs: &[(&str, &str)]) -> Option<&'static str> {
    environment_harness(&env(pairs))
}

#[test]
fn cursor_env_marks_a_claude_hook_as_cursor() {
    let cursor = env(&[
        ("CURSOR_VERSION", "2.0.0"),
        ("CURSOR_PROJECT_DIR", "/tmp/project"),
    ]);
    assert_eq!(runtime_hook_harness("claude-code", &cursor), "cursor");
    assert_eq!(runtime_hook_harness("Claude_Code", &cursor), "cursor");
    assert_eq!(runtime_hook_harness("claude", &cursor), "cursor");
    assert_eq!(runtime_hook_harness("opencode", &cursor), "opencode");
    assert_eq!(
        runtime_hook_harness("claude-code", &env(&[])),
        "claude-code"
    );
}

#[test]
fn a_claude_session_started_from_a_cursor_terminal_stays_claude() {
    for marker in ["CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"] {
        let inherited = env(&[("CURSOR_VERSION", "2.0.0"), (marker, "1")]);
        assert_eq!(
            runtime_hook_harness("claude-code", &inherited),
            "claude-code"
        );
    }
    let blank = env(&[("CURSOR_VERSION", "2.0.0"), ("CLAUDECODE", " ")]);
    assert_eq!(runtime_hook_harness("claude-code", &blank), "cursor");
}

#[test]
fn each_runtime_family_is_matched() {
    for (pairs, harness) in [
        (&[("ZCODE_ENV", "production")][..], "zcode"),
        (&[("ZCODE_APP_VERSION", "3.10.2")], "zcode"),
        (&[("__CFBundleIdentifier", "dev.zcode.app")], "zcode"),
        (&[("CLAUDECODE", "1")], "claude-code"),
        (&[("CLAUDE_CODE_ENTRYPOINT", "cli")], "claude-code"),
        (&[("CURSOR_TRACE_ID", "trace-1")], "cursor"),
        (&[("CODEX_SANDBOX", "1")], "codex"),
        (&[("CODEX_THREAD_ID", "thread-1")], "codex"),
        (&[("GROK_AGENT", "1")], "grok"),
        (&[("GROK_SESSION_ID", "session-1")], "grok"),
        (&[("OPENCODE_CONFIG_CONTENT", "{}")], "opencode"),
        (&[("DEVIN_PROJECT_DIR", "/workspace/project")], "devin"),
        (&[("MUSE_SESSION_ID", "session-1")], "muse"),
        (&[("MUSE_THREAD_ID", "thread-1")], "muse"),
        (&[("HOL_GUARD_ORIGIN_HARNESS", "grok")], "grok"),
        (
            &[("HOL_GUARD_ORIGIN_HARNESS", " Claude_Code ")],
            "claude-code",
        ),
    ] {
        assert_eq!(from_env(pairs), Some(harness), "{pairs:?}");
    }
    for pairs in [
        &[("CODEX_HOME", "/tmp/codex-home")][..],
        &[("GROK_HOME", "/tmp/grok-home")],
        &[("OPENCODE_CONFIG", "/tmp/opencode.json")],
        &[("HOL_GUARD_ORIGIN_HARNESS", "guard-cli")],
    ] {
        assert_eq!(from_env(pairs), None, "{pairs:?}");
    }
}

#[test]
fn blank_and_unrelated_env_names_no_harness() {
    assert_eq!(from_env(&[]), None);
    assert_eq!(
        from_env(&[("PATH", "/usr/bin"), ("TERM", "xterm-256color")]),
        None
    );
    assert_eq!(from_env(&[("ZCODE_ENV", "  ")]), None);
    assert_eq!(
        from_env(&[("__CFBundleIdentifier", "com.apple.Terminal")]),
        None
    );
}

#[test]
fn the_fixed_order_breaks_a_tie() {
    assert_eq!(
        from_env(&[
            ("ZCODE_ENV", "production"),
            ("CLAUDECODE", "1"),
            ("CURSOR_SESSION_ID", "s-1")
        ]),
        Some("zcode")
    );
    assert_eq!(
        from_env(&[("CURSOR_SESSION_ID", "s-1"), ("CODEX_SANDBOX", "1")]),
        Some("cursor")
    );
    // A stamped origin outranks every marker.
    assert_eq!(
        from_env(&[("HOL_GUARD_ORIGIN_HARNESS", "pi"), ("CLAUDECODE", "1")]),
        Some("pi")
    );
}

#[test]
fn executables_map_by_name_or_app_path() {
    for (path, harness) in [
        ("/opt/apps/codex", Some("codex")),
        ("/opt/apps/Codex", Some("codex")),
        ("/opt/apps/claude", Some("claude-code")),
        ("/opt/apps/cursor-agent", Some("cursor")),
        ("/opt/apps/zcode-cli", Some("zcode")),
        ("C:\\tools\\Grok.EXE", None),
        ("/opt/apps/grok.exe", Some("grok")),
        ("/opt/apps/muse-bin/", Some("muse")),
        (
            "/Applications/Cursor.app/Contents/MacOS/Helper",
            Some("cursor"),
        ),
        ("C:\\Apps\\Codex.app\\bin\\helper", Some("codex")),
        ("/opt/codex-helper", None),
        ("/opt/grok-helper", None),
        ("/opt/node", None),
        ("/opt/python", None),
        ("", None),
    ] {
        assert_eq!(harness_from_executable(path), harness, "{path}");
    }
}

#[test]
fn the_nearest_harness_ancestor_is_found_without_reading_arguments() {
    for (executable, harness) in [
        ("codex", "codex"),
        ("Codex", "codex"),
        ("pi", "pi"),
        ("omp", "omp"),
        ("zcode", "zcode"),
        ("zcode-cli", "zcode"),
        ("grok", "grok"),
    ] {
        let table = format!("42 41 /bin/zsh\n41 40 /opt/apps/{executable}\n40 1 /opt/apps/cursor");
        assert_eq!(parent_harness(&table, 42), Some(harness), "{executable}");
    }
}

#[test]
fn unknown_malformed_and_cyclic_ancestry_stays_unknown() {
    for table in [
        "42 1 /bin/zsh",
        "42 42 /bin/zsh",
        "malformed",
        "42 1",
        "42 x /opt/codex",
        "42 1 /opt/codex-helper",
        "42 1 /opt/node",
        "",
    ] {
        assert_eq!(parent_harness(table, 42), None, "{table}");
    }
    // The walk stops at init and at an unlisted parent.
    assert_eq!(parent_harness("42 1 /bin/zsh\n1 0 /opt/codex", 42), None);
    assert_eq!(parent_harness("42 41 /bin/zsh", 42), None);
    assert_eq!(parent_harness("42 1 /opt/codex", 1), None);
}

#[test]
fn a_long_chain_is_cut_off_at_eight_ancestors() {
    let mut table: Vec<String> = (10..20)
        .map(|pid| format!("{pid} {} /bin/sh", pid + 1))
        .collect();
    table.push("20 1 /opt/apps/codex".to_owned());
    // Ten shells before the harness: past the bound.
    assert_eq!(parent_harness(&table.join("\n"), 10), None);
    // Eight rows are read starting at the parent itself, so the harness is
    // reached from the seventh shell and missed from the eighth-from-last.
    assert_eq!(parent_harness(&table.join("\n"), 12), None);
    assert_eq!(parent_harness(&table.join("\n"), 13), Some("codex"));
}

#[test]
fn an_executable_keeps_its_inner_spacing() {
    assert_eq!(
        parent_harness(
            "42 1  /Applications/Cursor.app/Contents/MacOS/Cursor Helper",
            42
        ),
        Some("cursor")
    );
}

fn ask(request: &Value) -> Value {
    dispatch(request).expect("a valid request")
}

#[test]
fn the_kind_answers_each_op() {
    assert_eq!(
        ask(&json!({"op": "environment", "env": {"CODEX_SANDBOX": "1"}})),
        json!({"harness": "codex"})
    );
    assert_eq!(
        ask(&json!({"op": "environment", "env": {}})),
        json!({"harness": null})
    );
    assert_eq!(
        ask(
            &json!({"op": "runtime_hook", "requested": "claude-code", "env": {"CURSOR_VERSION": "2"}})
        ),
        json!({"harness": "cursor"})
    );
    assert_eq!(
        ask(&json!({"op": "runtime_hook", "requested": "Claude_Code", "env": {}})),
        json!({"harness": "Claude_Code"})
    );
    assert_eq!(
        ask(&json!({"op": "origin_env", "harness": "grok"})),
        json!({"env": {"HOL_GUARD_ORIGIN_HARNESS": "grok"}})
    );
    assert_eq!(
        ask(&json!({"op": "origin_env", "harness": " Claude_Code "})),
        json!({"env": {"HOL_GUARD_ORIGIN_HARNESS": "claude-code"}})
    );
    for unknown in ["guard-cli", "unknown", ""] {
        assert_eq!(
            ask(&json!({"op": "origin_env", "harness": unknown})),
            json!({"env": {}})
        );
    }
}

#[test]
fn malformed_requests_are_refused() {
    for request in [
        json!({"op": "environment"}),
        json!({"op": "environment", "env": {"A": 1}}),
        json!({"op": "parent"}),
        json!({"op": "parent", "ppid": "1"}),
        json!({"op": "runtime_hook", "env": {}}),
        json!({"op": "nonsense"}),
        json!({}),
        json!([]),
    ] {
        assert!(dispatch(&request).is_err(), "{request}");
    }
}

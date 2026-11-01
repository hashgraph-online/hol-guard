use std::fs;

use super::*;
use crate::hook_removal_prune::text_is_guard;

const GUARD_COMMAND: &str = "hol-guard hook --harness claude-code --event PreToolUse";
const USER_COMMAND: &str = "/usr/local/bin/my-audit-hook --log";

fn run(request: Value) -> Result<Value, String> {
    let bytes = run_command(request.to_string().as_bytes())?;
    Ok(serde_json::from_slice(&bytes).expect("answer is JSON"))
}

fn sweep_file(path: &Path, dry_run: bool) -> Value {
    let request = json!({ "schema": SCHEMA, "op": "sweep-file", "path": path, "dry_run": dry_run });
    run(request).expect("sweep-file answer")["file"].clone()
}

fn payload(value: &Value) -> PyVal {
    parse(&value.to_string()).expect("payload parses")
}

fn handler(command: &str) -> Value {
    json!({ "type": "command", "command": command })
}

fn claude_settings() -> Value {
    json!({
        "model": "opus",
        "hooks": {
            "PreToolUse": [
                { "matcher": "*", "hooks": [handler(GUARD_COMMAND)] },
                { "matcher": "Bash", "hooks": [handler(USER_COMMAND)] },
            ],
            "Stop": [{ "hooks": [handler(GUARD_COMMAND)] }],
        },
    })
}

fn removed_events(settings: &Value) -> Vec<String> {
    prune_guard_hooks(&payload(settings))
        .map(|(_, removed)| removed)
        .unwrap_or_default()
}

#[test]
fn guard_signatures_match() {
    for command in [
        GUARD_COMMAND,
        "/Users/x/.local/bin/hol-guard hook --harness codex",
        "\"C:\\Users\\x\\bin\\hol-guard.exe\" hook --harness codex",
        "python -m codex_plugin_scanner.cli guard hook --harness codex",
        "python -c \"main(['guard', 'hook'])\" -m codex_plugin_scanner.cli",
        "bash -c '/home/x/.hol-guard/managed/bounded-hooks/run.sh'",
        "HOL_GUARD_MANAGED=1 something",
        "unterminated 'quote hol-guard-codex-hook",
    ] {
        assert!(text_is_guard(command), "{command}");
    }
}

#[test]
fn other_commands_are_not_guard() {
    for command in [
        USER_COMMAND,
        "echo guard",
        "git diff",
        "",
        "   ",
        "hol-guard status",
        "python -m codex_plugin_scanner.cli scan",
    ] {
        assert!(!text_is_guard(command), "{command}");
    }
}

#[test]
fn prune_removes_only_guard_handlers_and_empty_events() {
    let (pruned, removed) = prune_guard_hooks(&payload(&claude_settings())).expect("pruned");

    assert_eq!(removed, vec!["PreToolUse".to_owned(), "Stop".to_owned()]);
    let expected = json!({
        "model": "opus",
        "hooks": { "PreToolUse": [{ "matcher": "Bash", "hooks": [handler(USER_COMMAND)] }] },
    });
    assert_eq!(pruned, payload(&expected));
}

#[test]
fn prune_drops_the_hooks_key_once_nothing_is_left() {
    let settings = json!({ "a": 1, "hooks": [handler(GUARD_COMMAND)] });

    let (pruned, removed) = prune_guard_hooks(&payload(&settings)).expect("pruned");

    assert_eq!(removed, vec![String::new()]);
    assert_eq!(pruned, payload(&json!({ "a": 1 })));
}

#[test]
fn prune_leaves_a_payload_without_guard_hooks_alone() {
    for settings in [
        json!({ "model": "opus" }),
        json!({ "hooks": "not a list" }),
        json!({ "hooks": { "Stop": "x", "PreToolUse": [5, handler(USER_COMMAND)] } }),
    ] {
        assert!(
            prune_guard_hooks(&payload(&settings)).is_none(),
            "{settings}"
        );
    }
}

#[test]
fn prune_matches_claude_exec_form_args() {
    let exec_handler = json!({
        "type": "command",
        "command": "/opt/python/bin/python3",
        "args": ["-m", "codex_plugin_scanner.cli", "guard", "hook", "--harness", "claude-code"],
    });
    let user_handler =
        json!({ "type": "command", "command": "/usr/bin/python3", "args": ["-m", "my_audit"] });
    let settings = json!({ "hooks": { "PreToolUse": [{ "matcher": "*", "hooks": [exec_handler, user_handler] }] } });

    let (pruned, removed) = prune_guard_hooks(&payload(&settings)).expect("pruned");

    assert_eq!(removed, vec!["PreToolUse".to_owned()]);
    let expected =
        json!({ "hooks": { "PreToolUse": [{ "matcher": "*", "hooks": [user_handler] }] } });
    assert_eq!(pruned, payload(&expected));
}

#[test]
fn prune_matches_exec_form_with_spaced_paths_and_markers() {
    for exec_handler in [
        json!({ "type": "command", "command": "/opt/guard bin/hol-guard", "args": ["hook", "--harness", "claude-code"] }),
        json!({ "type": "command", "command": "/bin/sh", "args": ["-c", "HOL_GUARD_HOOK_ARGV=1 exec guard-shim"] }),
        json!({ "type": "command", "command": "/bin/echo", "args": ["hol guard managed"] }),
    ] {
        let settings =
            json!({ "hooks": { "PreToolUse": [{ "matcher": "*", "hooks": [exec_handler] }] } });
        assert_eq!(removed_events(&settings), vec!["PreToolUse".to_owned()]);
    }
}

#[test]
fn prune_keeps_exec_form_handlers_whose_marker_only_spans_arguments() {
    for args in [
        json!(["hol guard", "managed"]),
        json!(["hol", "guard", "managed"]),
    ] {
        let exec_handler = json!({ "type": "command", "command": "/bin/echo", "args": args });
        let settings =
            json!({ "hooks": { "PreToolUse": [{ "matcher": "*", "hooks": [exec_handler] }] } });
        assert!(removed_events(&settings).is_empty(), "{settings}");
    }
}

#[test]
fn json_rewrite_matches_python_indent_two() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("settings.json");
    let mut settings = claude_settings();
    settings["n"] = json!(1.5e20);
    settings["u"] = json!("\u{e9}\u{2028}");
    settings["e"] = json!({});
    settings["l"] = json!([]);
    fs::write(&path, settings.to_string()).expect("write");
    let before = fs::read(&path).expect("read");

    let planned = sweep_file(&path, true);
    assert_eq!(planned["removed"], json!(2));
    assert_eq!(planned["wrote"], json!(false));
    assert_eq!(fs::read(&path).expect("read"), before);

    let swept = sweep_file(&path, false);
    assert_eq!(swept["removed"], json!(2));
    assert_eq!(swept["wrote"], json!(true));
    assert_eq!(swept["event_names"], json!(["PreToolUse", "Stop"]));
    let written = fs::read_to_string(&path).expect("read");
    let mut expected = String::new();
    // serde_json may reorder the input keys; expect the order the file holds.
    let order: Vec<String> = match parse(&String::from_utf8(before).expect("utf-8")) {
        Ok(PyVal::Dict(entries)) => entries.into_iter().map(|(key, _)| key).collect(),
        _ => panic!("input is a mapping"),
    };
    expected.push('{');
    for (index, key) in order.iter().enumerate() {
        expected.push_str(if index == 0 { "\n  " } else { ",\n  " });
        expected.push_str(match key.as_str() {
            "model" => "\"model\": \"opus\"",
            "n" => "\"n\": 1.5e+20",
            "u" => "\"u\": \"\\u00e9\\u2028\"",
            "e" => "\"e\": {}",
            "l" => "\"l\": []",
            "hooks" => "\"hooks\": {\n    \"PreToolUse\": [\n      {\n        \"matcher\": \"Bash\",\n        \"hooks\": [\n          {\n            \"type\": \"command\",\n            \"command\": \"/usr/local/bin/my-audit-hook --log\"\n          }\n        ]\n      }\n    ]\n  }",
            other => panic!("unexpected key {other}"),
        });
    }
    expected.push_str("\n}\n");
    assert_eq!(written, expected);
}

#[test]
fn a_lone_surrogate_escape_is_not_rewritten() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("settings.json");
    let text =
        format!("{{\"note\": \"\\ud800\", \"hooks\": [{{\"command\": \"{GUARD_COMMAND}\"}}]}}");
    fs::write(&path, &text).expect("write");

    let swept = sweep_file(&path, false);

    assert_eq!(swept["error"], json!("rewrite_not_lossless"));
    assert_eq!(swept["removed"], json!(0));
    assert_eq!(swept["wrote"], json!(false));
    assert_eq!(fs::read_to_string(&path).expect("read"), text);
}

#[test]
fn toml_edit_keeps_comments_and_unrelated_tables() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("config.toml");
    fs::write(
        &path,
        "# keep me\nmodel = \"gpt\" # trailing\n\n[projects.\"/work\"]\ntrust_level = \"trusted\"\n\n[[hooks.PreToolUse]]\nmatcher = \"*\"\n\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = \"hol-guard hook --harness codex\"\n",
    )
    .expect("write");

    let swept = sweep_file(&path, false);

    assert_eq!(swept["removed"], json!(1));
    assert_eq!(swept["wrote"], json!(true));
    let written = fs::read_to_string(&path).expect("read");
    assert!(written.contains("# keep me"), "{written}");
    assert!(written.contains("# trailing"), "{written}");
    assert!(!written.contains("hol-guard"), "{written}");
    let reloaded = written.parse::<DocumentMut>().expect("toml");
    let expected = json!({ "model": "gpt", "projects": { "/work": { "trust_level": "trusted" } } });
    assert!(same(&table_value(reloaded.as_table()), &payload(&expected)));
}

#[test]
fn toml_inline_hooks_keep_the_user_handler() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("config.toml");
    fs::write(
        &path,
        format!("hooks = {{ Stop = [{{ command = \"{GUARD_COMMAND}\" }}, {{ command = \"echo hi\" }}] }}\n"),
    )
    .expect("write");

    let swept = sweep_file(&path, false);

    assert_eq!(swept["removed"], json!(1));
    assert_eq!(swept["event_names"], json!(["Stop"]));
    let written = fs::read_to_string(&path).expect("read");
    assert!(!written.contains("hol-guard"), "{written}");
    assert!(written.contains("echo hi"), "{written}");
}

#[test]
fn unreadable_shapes_are_typed_and_never_written() {
    let directory = tempfile::tempdir().expect("tempdir");
    let cases = [
        ("broken.json", "{not json", "unparseable"),
        ("list.json", "[1, 2]", "unexpected_shape"),
        ("broken.toml", "a = [", "unparseable"),
    ];
    for (name, content, error) in cases {
        let path = directory.path().join(name);
        fs::write(&path, content).expect("write");

        let swept = sweep_file(&path, false);

        assert_eq!(swept["error"], json!(error), "{name}");
        assert_eq!(swept["removed"], json!(0), "{name}");
        assert_eq!(fs::read_to_string(&path).expect("read"), content);
    }
    assert_eq!(
        sweep_file(directory.path(), false)["error"],
        json!("not_regular_file")
    );
    assert_eq!(
        sweep_file(&directory.path().join("absent.json"), false)["error"],
        json!("unreadable")
    );
}

#[test]
fn files_keeps_existing_sweepable_files_inside_the_roots_once() {
    let directory = tempfile::tempdir().expect("tempdir");
    let home = directory.path().join("home");
    let outside = directory.path().join("outside");
    fs::create_dir_all(home.join(".claude")).expect("home");
    fs::create_dir_all(&outside).expect("outside");
    let settings = home.join(".claude/settings.json");
    fs::write(&settings, "{}").expect("settings");
    fs::write(home.join("notes.yaml"), "a: 1").expect("yaml");
    fs::write(outside.join("hooks.json"), "{}").expect("outside file");
    let candidates = [
        settings.clone(),
        settings.clone(),
        home.join("notes.yaml"),
        home.join("absent.json"),
        outside.join("hooks.json"),
    ];

    let answer = run(json!({
        "schema": SCHEMA,
        "op": "files",
        "candidates": candidates,
        "roots": [home, directory.path().join("missing-root")],
    }))
    .expect("files answer");

    assert_eq!(answer, json!({ "files": [settings] }));
}

#[cfg(unix)]
#[test]
fn a_symlinked_config_is_reported_and_never_edited() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("tempdir");
    let home = directory.path().join("home");
    fs::create_dir_all(home.join("dotfiles")).expect("dotfiles");
    fs::create_dir_all(home.join(".claude")).expect("claude");
    let target = home.join("dotfiles/claude-settings.json");
    fs::write(&target, claude_settings().to_string()).expect("target");
    let link = home.join(".claude/settings.json");
    symlink(&target, &link).expect("link");
    let before = fs::read(&target).expect("read");

    for (dry_run, removed) in [(true, 2), (false, 0)] {
        let answer = run(json!({
            "schema": SCHEMA,
            "op": "sweep",
            "candidates": [link],
            "roots": [home],
            "dry_run": dry_run,
        }))
        .expect("sweep answer");

        assert_eq!(
            answer,
            json!({ "files": [{
                "path": link,
                "removed": removed,
                "wrote": false,
                "error": "symlink_not_followed",
                "event_names": ["PreToolUse", "Stop"],
            }] })
        );
    }
    assert!(fs::symlink_metadata(&link)
        .expect("link")
        .file_type()
        .is_symlink());
    assert_eq!(fs::read(&target).expect("read"), before);
}

#[cfg(unix)]
#[test]
fn a_rewrite_keeps_the_file_mode() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("settings.json");
    fs::write(&path, claude_settings().to_string()).expect("write");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("chmod");

    assert_eq!(sweep_file(&path, false)["wrote"], json!(true));

    let mode = fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
    assert_eq!(mode, 0o640);
    let leftovers = fs::read_dir(directory.path()).expect("list").count();
    assert_eq!(leftovers, 1);
}

#[test]
fn requests_are_validated() {
    let absolute = std::env::temp_dir().join("settings.json");
    let refused = [
        json!({ "schema": "hook-removal-sweep.v0", "op": "files" }),
        json!({ "schema": SCHEMA, "op": "sweep-file" }),
        json!({ "schema": SCHEMA, "op": "sweep-file", "path": "relative.json" }),
        json!({ "schema": SCHEMA, "op": "sweep-file", "path": absolute, "roots": [absolute] }),
        json!({ "schema": SCHEMA, "op": "files", "candidates": ["relative.json"] }),
        json!({ "schema": SCHEMA, "op": "files", "path": absolute }),
        json!({ "schema": SCHEMA, "op": "sweep", "roots": [absolute, absolute, absolute] }),
        json!({ "schema": SCHEMA, "op": "delete" }),
        json!({ "schema": SCHEMA, "op": "files", "extra": 1 }),
    ];
    for request in refused {
        assert!(run(request.clone()).is_err(), "{request}");
    }
}

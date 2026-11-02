use std::fs;
use std::path::PathBuf;

use serde_json::{json, Value};

use super::*;

const HOME: &str = "/g/guard";
const CURRENT: &str = "/usr/local/guard/bin/python";
const FOREIGN: &str = "/home/u/.local/pipx/venvs/hol-guard/bin/python";
#[cfg(unix)]
const SPACED_FOREIGN: &str = "/opt/Application Support/pipx/venvs/hol-guard/bin/python";
const WINDOWS_PYTHON: &str = r"C:\Users\u\pipx\venvs\hol-guard\Scripts\python.exe";
const OLD_DIGEST: &str = "8888888888888888888888888888888888888888888888888888888888888888";
const NEW_DIGEST: &str = "2222222222222222222222222222222222222222222222222222222222222222";

struct Artifact {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

fn artifact(bytes: impl AsRef<[u8]>) -> Artifact {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("artifact");
    fs::write(&path, bytes).expect("write artifact");
    Artifact { _dir: dir, path }
}

fn foreign(text: &str, current: &str) -> bool {
    names_foreign_interpreter(&artifact(text).path, Some(current), HOME)
}

fn stale(text: &str, digest: &str) -> bool {
    names_stale_runtime(&artifact(text).path, digest, PIN_SCAN_MAX_BYTES)
}

#[cfg(unix)]
fn bootstrap() -> String {
    "import sys;sys.path.insert(0,'/site');\
     from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import main_from_argv;\
     raise SystemExit(main_from_argv(sys.argv[1:]))"
        .to_owned()
}

fn config(value: &Value) -> String {
    serde_json::to_string(value).expect("config")
}

fn pinned(digest: &str) -> String {
    config(
        &json!({"hooks": [{"command": format!("/g/native-runtime/{digest}/hol-guard-runtime bounded-hook-bridge")}]}),
    )
}

#[cfg(unix)]
#[test]
fn a_json_argv_hook_naming_another_interpreter_is_foreign() {
    for interpreter in [FOREIGN, SPACED_FOREIGN] {
        let hook = |python: &str| {
            let argv = json!([python, "-I", "-c", bootstrap(), r#"{"harness":"zcode"}"#]);
            config(&json!({"hooks": {"PreToolUse": [{"command": argv}]}}))
        };
        assert!(foreign(&hook(interpreter), CURRENT));
        assert!(!foreign(&hook(CURRENT), CURRENT));
    }
}

#[cfg(unix)]
#[test]
fn a_shell_command_inside_json_names_its_interpreter() {
    let hook = |python: &str| {
        let command = format!(
            r#"{python} -I -c '{}' '{{"harness": "zcode"}}'"#,
            bootstrap()
        );
        config(&json!({"hooks": {"PreToolUse": [{"command": command}]}}))
    };

    assert!(foreign(&hook(FOREIGN), CURRENT));
    assert!(!foreign(&hook(CURRENT), CURRENT));
}

#[cfg(unix)]
#[test]
fn a_native_bridge_prefix_does_not_hide_the_interpreter() {
    let runtime = format!("/g/native-runtime/{}/hol-guard-runtime", "a".repeat(64));
    let argv = json!([
        runtime,
        "bounded-hook-bridge",
        FOREIGN,
        "-I",
        "-c",
        bootstrap()
    ]);

    assert!(foreign(&config(&json!({"command": argv})), CURRENT));
}

#[cfg(unix)]
#[test]
fn the_source_cli_form_names_its_interpreter() {
    let argv = json!([
        FOREIGN,
        "-I",
        "-s",
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "hook"
    ]);

    assert!(foreign(&config(&json!({"command": argv})), CURRENT));
}

#[cfg(unix)]
#[test]
fn a_user_hook_before_guards_entry_is_not_read_with_it() {
    let user = json!({"type": "command", "command": "/usr/bin/python3 -I -c 'print(1)'"});
    let managed = [
        format!("{CURRENT} -I -c '{}'", bootstrap()),
        format!(
            "{HOME}/native-runtime/{}/hol-guard-runtime bounded-hook-bridge",
            "a".repeat(64)
        ),
    ];
    for command in managed {
        let handler = json!({"type": "command", "command": command});
        let hooks = json!({"hooks": {"events": {"PreToolUse": [{"hooks": [user, handler]}]}}});
        let text = serde_json::to_string_pretty(&hooks).expect("config");

        assert!(!foreign(&text, CURRENT));
    }
}

#[cfg(unix)]
#[test]
fn a_posix_launcher_for_an_interpreter_path_with_an_apostrophe_is_read() {
    let interpreter = "/opt/O'Brien/venv/bin/python";
    let launcher = format!(
        "#!/bin/sh\n# HOL Guard managed hook\nexec '/opt/O'\"'\"'Brien/venv/bin/python' -I -s \
         {HOME}/managed/cline/hook-workers/PreToolUse.py\n"
    );

    assert!(foreign(&launcher, CURRENT));
    assert!(!foreign(&launcher, interpreter));
}

#[test]
fn a_windows_launcher_names_its_interpreter() {
    let launcher = format!(
        "# HOL Guard managed hook\n$Python = '{WINDOWS_PYTHON}'\n\
         $Worker = '{HOME}/managed/cline/hook-workers/PreToolUse.py'\n\
         $Args = @(\"-I\", \"-s\", $Worker)\n$Raw = [Console]::In.ReadToEnd()\nexit 0\n"
    );

    assert!(foreign(&launcher, CURRENT));
    assert!(!foreign(&launcher, WINDOWS_PYTHON));
    // A doubled apostrophe in the PowerShell literal is one in the path.
    let quoted = launcher.replace(r"\u\", r"\O''Brien\");
    assert!(!foreign(
        &quoted,
        &WINDOWS_PYTHON.replace(r"\u\", r"\O'Brien\")
    ));
}

#[test]
fn a_windows_json_escaped_path_is_compared_unescaped() {
    let argv = json!([WINDOWS_PYTHON, "-I", "-s", "-m", "codex_plugin_scanner.cli"]);
    let text = config(&json!({"command": argv}));

    assert!(foreign(&text, CURRENT));
    assert!(!foreign(&text, WINDOWS_PYTHON));
}

#[test]
fn other_invocations_are_not_foreign() {
    let texts = [
        // A stdlib-only client does not depend on which Guard install owns the interpreter.
        config(
            &json!({"command": ["/usr/bin/python3", "-I", format!("{HOME}/managed/bounded-hooks/grok.py")]}),
        ),
        // A user's own hook is not Guard's client.
        config(&json!({"command": ["/usr/bin/python3", "-I", "-c", "print('ok')"]})),
        config(&json!({"command": ["/usr/bin/python3", "-I", "-s", "/home/u/my_hook.py"]})),
        "grep -I -c needle haystack\n".to_owned(),
        // No interpreter path precedes the flag.
        config(&json!({"args": ["-I", "-s", "-m", "codex_plugin_scanner.cli"]})),
        String::new(),
    ];
    for text in texts {
        assert!(!foreign(&text, CURRENT), "{text}");
    }
}

#[test]
fn a_binary_or_missing_file_is_not_foreign() {
    let mut binary = b"\x7fELF\0\0".to_vec();
    binary.extend_from_slice(format!("{FOREIGN} -I -s -m codex_plugin_scanner.cli").as_bytes());
    let binary = artifact(binary);

    assert!(!names_foreign_interpreter(
        &binary.path,
        Some(CURRENT),
        HOME
    ));
    assert!(!names_foreign_interpreter(
        &binary.path.with_file_name("absent"),
        Some(CURRENT),
        HOME
    ));
}

#[test]
fn a_frozen_guard_owns_no_python_launcher() {
    let argv = json!([WINDOWS_PYTHON, "-I", "-s", "-m", "codex_plugin_scanner.cli"]);
    let text = artifact(config(&json!({"command": argv})));

    assert!(names_foreign_interpreter(&text.path, None, HOME));
}

#[test]
fn a_long_unbroken_file_is_scanned_in_linear_time() {
    let text = format!("{} -I -s {}", "x".repeat(1024 * 1024), "y".repeat(4096));

    assert!(!foreign(&text, CURRENT));
}

#[test]
fn a_windows_escaped_pin_is_read() {
    let text =
        format!(r#"{{"command": "C:\\g\\native-runtime\\{OLD_DIGEST}\\hol-guard-runtime.exe"}}"#);

    assert!(stale(&text, NEW_DIGEST));
    assert!(!stale(&text, OLD_DIGEST));
}

#[test]
fn a_pin_past_the_first_megabyte_is_read() {
    let text = format!(
        r#"{{"notes": "{}", "command": "/g/native-runtime/{OLD_DIGEST}/hol-guard-runtime"}}"#,
        "x".repeat(4 * 1024 * 1024 + 7)
    );

    assert!(stale(&text, NEW_DIGEST));
}

#[test]
fn a_preserved_user_field_naming_a_runtime_path_is_not_a_stale_pin() {
    let text = format!(
        r#"{{"notes": "archived under /home/u/.hol-guard/native-runtime/{OLD_DIGEST}/ before the upgrade"}}"#
    );

    assert!(!stale(&text, NEW_DIGEST));
}

#[test]
fn a_note_beside_a_current_hook_command_is_not_a_stale_pin() {
    let text = format!(
        r#"{{"notes": "old copy: /home/u/.hol-guard/native-runtime/{OLD_DIGEST}/", "command": "/home/u/.hol-guard/native-runtime/{NEW_DIGEST}/hol-guard-runtime bounded-hook-bridge"}}"#
    );

    assert!(!stale(&text, NEW_DIGEST));
    assert!(stale(&pinned(OLD_DIGEST), NEW_DIGEST));
    assert!(!stale(&pinned(NEW_DIGEST), NEW_DIGEST));
}

#[test]
fn a_pin_followed_by_more_of_a_name_is_not_a_pin() {
    let text = format!("/g/native-runtime/{OLD_DIGEST}/hol-guard-runtime.exe2 /g/native-runtime/{OLD_DIGEST}/hol-guard-runtime-old");

    assert!(!stale(&text, NEW_DIGEST));
}

#[test]
fn a_file_past_the_scan_budget_is_not_read_to_the_end() {
    let text = format!(
        r#"{{"notes": "{}", "command": "/g/native-runtime/{OLD_DIGEST}/hol-guard-runtime"}}"#,
        "x".repeat(256)
    );
    let file = artifact(text);

    assert!(!names_stale_runtime(&file.path, NEW_DIGEST, 128));
    assert!(names_stale_runtime(
        &file.path,
        NEW_DIGEST,
        PIN_SCAN_MAX_BYTES
    ));
    assert!(!names_stale_runtime(
        &file.path.with_file_name("absent"),
        NEW_DIGEST,
        PIN_SCAN_MAX_BYTES
    ));
}

#[test]
fn the_command_answers_both_scans_over_every_path() {
    let pinned_file = artifact(pinned(OLD_DIGEST));
    let launcher = artifact(config(
        &json!({"command": [WINDOWS_PYTHON, "-I", "-s", "-m", "codex_plugin_scanner.cli"]}),
    ));
    let paths = [&pinned_file.path, &launcher.path].map(|path| path.to_string_lossy().into_owned());
    let request = json!({
        "schema": SCHEMA,
        "paths": paths,
        "runtime_digest": NEW_DIGEST,
        "interpreter": {"current": WINDOWS_PYTHON, "guard_home": HOME},
    });
    let answer = |request: &Value| -> Value {
        let bytes = run_command(config(request).as_bytes()).expect("answer");
        serde_json::from_slice(&bytes).expect("json")
    };

    assert_eq!(
        answer(&request),
        json!({"stale_runtime": true, "foreign_interpreter": false})
    );
    let mut frozen = request.clone();
    frozen["interpreter"]["current"] = Value::Null;
    frozen["runtime_digest"] = Value::from(OLD_DIGEST);
    assert_eq!(
        answer(&frozen),
        json!({"stale_runtime": false, "foreign_interpreter": true})
    );
    let skipped =
        json!({"schema": SCHEMA, "paths": paths, "runtime_digest": null, "interpreter": null});
    assert_eq!(
        answer(&skipped),
        json!({"stale_runtime": false, "foreign_interpreter": false})
    );
}

#[test]
fn requests_are_validated() {
    let too_many = vec!["/missing"; MAX_PATHS + 1];
    let invalid = [
        json!({"schema": "hook-launch-scan.v0", "paths": []}),
        json!({"schema": SCHEMA, "paths": too_many}),
        json!({"schema": SCHEMA, "paths": [], "extra": true}),
        json!({"schema": SCHEMA, "paths": [], "interpreter": {"current": null}}),
    ];
    for request in invalid {
        assert_eq!(
            run_command(config(&request).as_bytes()),
            Err("hook_launch_scan_request_invalid".to_owned()),
            "{request}"
        );
    }
    let oversized = vec![b' '; MAX_REQUEST_BYTES as usize + 1];
    assert_eq!(
        run_command(oversized.as_slice()),
        Err("hook_launch_scan_request_too_large".to_owned())
    );
}

//! The Windows Codex contained rewrite: Python parity for the sink command
//! line, the bootstrap's package root, the launching Codex's name and the
//! snapshot the sink reads.

use std::path::Path;
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

use super::super::codex::is_codex;
use super::super::{routed, text, Target, REQUEST_SCHEMA};
use super::*;
use crate::pyjson::{parse_mapping_lone_surrogates, PyVal};

const PYTHON: &str = r"C:\Python\python.exe";
const BOOTSTRAP: &str = r"import sys;sys.path.insert(0, 'C:\\Guard\\site-packages');from codex_plugin_scanner.cli import main;raise SystemExit(main(sys.argv[1:]))";
const PYTHON_DENY: &str = r#"{"policy_action":"sandbox-required","decision":"deny","reason_code":"native_python_eval_readonly_containment_required","required_execution_profile":"python-eval-readonly-v1","hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"}}"#;

fn owned(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn powershell_join_quotes_each_argument_as_a_literal() {
    assert_eq!(
        powershell_join(&owned(&[
            r"C:\Program Files\py.exe",
            "-c",
            "print('$x'); `a`"
        ]))
        .as_deref(),
        Some(r"& 'C:\Program Files\py.exe' '-c' 'print(''$x''); `a`'")
    );
    assert_eq!(
        powershell_join(&owned(&["a\u{2019}b", "%PATH%&|;()"])).as_deref(),
        Some("& 'a\u{2019}\u{2019}b' '%PATH%&|;()'")
    );
    assert_eq!(
        powershell_join(&owned(&[r"C:\dir\", "no space"])).as_deref(),
        Some(r"& 'C:\dir\' 'no space'")
    );
}

#[test]
fn powershell_join_refuses_arguments_it_cannot_carry() {
    for argv in [
        owned(&[]),
        owned(&["a", ""]),
        owned(&["say \"hi\""]),
        owned(&["line\nbreak"]),
        owned(&["tab\tseparated"]),
        owned(&["bell\u{7f}"]),
        owned(&[r"C:\with space\"]),
    ] {
        assert_eq!(powershell_join(&argv), None, "{argv:?}");
    }
}

#[test]
fn the_sink_line_is_one_both_shells_read_the_same_way() {
    let argv = owned(&[
        PYTHON,
        "-I",
        "-c",
        "import sys;sys.path.insert(0, 'C:/Guard/site-packages');from codex_plugin_scanner.cli import main;raise SystemExit(main(sys.argv[1:]))",
        "guard",
        r"C:\Users\a b\x;$y&`z`",
    ]);
    assert_eq!(
        sink_command_line(&argv).as_deref(),
        Some(concat!(
            "C:/Python/python.exe '-I' '-c' ",
            "'import sys;sys.path.insert(0,sys.argv.pop(1));from codex_plugin_scanner.cli import main;raise SystemExit(main(sys.argv[1:]))' ",
            r"'C:/Guard/site-packages' 'guard' 'C:\Users\a b\x;$y&`z`'",
        ))
    );
    let frozen = owned(&[r"C:\Guard\hol-guard.exe", "execute-contained-test"]);
    assert_eq!(
        sink_command_line(&frozen).as_deref(),
        Some("C:/Guard/hol-guard.exe 'execute-contained-test'")
    );
}

#[test]
fn a_sink_line_only_powershell_reads_is_the_fallback() {
    // A program path no bare word can hold, or an argument with a quote in
    // it, keeps the PowerShell call operator form.
    for (argv, expected) in [
        (
            owned(&[r"C:\Program Files\py.exe", "x"]),
            r"& 'C:\Program Files\py.exe' 'x'",
        ),
        (
            owned(&[r"C:\Guard\hol-guard.exe", "it's"]),
            r"& 'C:\Guard\hol-guard.exe' 'it''s'",
        ),
        (
            owned(&[r"\\server\py.exe", "x"]),
            r"& '\\server\py.exe' 'x'",
        ),
        (
            owned(&[PYTHON, "-I", "-c", BOOTSTRAP, "guard"]),
            &format!(
                "& '{PYTHON}' '-I' '-c' '{}' 'guard'",
                BOOTSTRAP.replace('\'', "''")
            ),
        ),
    ] {
        assert_eq!(
            sink_command_line(&argv).as_deref(),
            Some(expected),
            "{argv:?}"
        );
    }
    assert_eq!(sink_command_line(&owned(&[PYTHON, "say \"hi\""])), None);
}

#[test]
fn the_bootstrap_names_the_package_root_with_forward_slashes() {
    let prefix = owned(&[PYTHON, "-I", "-c", BOOTSTRAP]);
    assert_eq!(
        sink_prefix(&prefix),
        owned(&[
            PYTHON,
            "-I",
            "-c",
            "import sys;sys.path.insert(0, 'C:/Guard/site-packages');from codex_plugin_scanner.cli import main;raise SystemExit(main(sys.argv[1:]))",
        ])
    );
    let frozen = owned(&[r"C:\Guard\hol-guard.exe"]);
    assert_eq!(sink_prefix(&frozen), frozen);
    for unusual in [
        r"import sys;sys.path.insert(0, 'C:\\it\'s');from codex_plugin_scanner.cli import main;raise SystemExit(main(sys.argv[1:]))",
        r#"import sys;sys.path.insert(0, "C:\\it's");from codex_plugin_scanner.cli import main;raise SystemExit(main(sys.argv[1:]))"#,
        r"import sys;sys.path.insert(0, 'C:\x01');from codex_plugin_scanner.cli import main;raise SystemExit(main(sys.argv[1:]))",
    ] {
        let prefix = owned(&[PYTHON, "-I", "-c", unusual]);
        assert_eq!(sink_prefix(&prefix), prefix, "{unusual}");
    }
}

#[test]
fn codex_on_windows_is_matched_without_case_or_exe() {
    for (path, codex) in [
        (
            r"C:\Users\a\AppData\Roaming\npm\node_modules\@openai\codex\vendor\x86_64-pc-windows-msvc\codex\codex.exe",
            true,
        ),
        (r"C:\tools\Codex.EXE", true),
        (r"C:\tools\codex-aarch64-pc-windows-msvc.exe", true),
        (r"C:\tools\codex-x86_64-pc-windows-msvc.exe", true),
        (r"C:\Program Files\nodejs\node.exe", false),
        (r"C:\tools\codex-evil.exe", false),
        (r"C:\tools\codex.exe.bak", false),
        (r"C:\tools\my-codex.exe", false),
    ] {
        assert_eq!(is_codex(Path::new(path)), codex, "{path}");
    }
}

#[test]
fn a_tilde_workspace_expands_only_for_the_current_user() {
    assert_eq!(resolved_workspace("~someone-else"), None);
    let home = crate::claude_hook_bridge::home_directory().unwrap();
    let expected = plain_path(std::fs::canonicalize(&home).unwrap().to_str().unwrap());
    assert_eq!(resolved_workspace("~").as_deref(), Some(expected.as_str()));
    assert_eq!(plain_path(r"\\?\UNC\server\share\x"), r"\\server\share\x");
    assert_eq!(plain_path(r"\\?\C:\x"), r"C:\x");
}

/// The request file a routed sink command names.
fn request_path(command: &str) -> String {
    let (_, rest) = command.split_once("'--request-file' '").unwrap();
    rest.split_once('\'').unwrap().0.to_owned()
}

#[test]
fn a_contained_python_call_is_rewritten_to_a_sink_command_both_shells_run() {
    let workspace = tempfile::tempdir().unwrap();
    let resolved = plain_path(
        std::fs::canonicalize(workspace.path())
            .unwrap()
            .to_str()
            .unwrap(),
    );
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "python scripts/report.py"},
        "cwd": workspace.path().to_str().unwrap(),
        "session_id": "s1",
        "tool_use_id": "t1",
    })
    .to_string();
    let payload = parse_mapping_lone_surrogates(&payload).unwrap().value;
    let installed = owned(&[
        PYTHON,
        "-I",
        "-c",
        BOOTSTRAP,
        "guard",
        "hook",
        "--harness",
        "codex",
    ]);
    let target = Target {
        prefix: &installed,
        guard_home: r"C:\Users\a\.hol-guard",
        home: r"C:\Users\a",
    };
    let deny = parse_mapping_lone_surrogates(PYTHON_DENY).unwrap().value;
    let routed = routed(&deny, &payload, false, &target).unwrap();
    assert_eq!(text(&routed, "policy_action"), Some("allow"));
    let updated = routed
        .get("hookSpecificOutput")
        .and_then(|output| output.get("updatedInput"))
        .unwrap();
    let command = text(updated, "command").unwrap().to_owned();
    let request = request_path(&command);
    let bytes = std::fs::read(&request).unwrap();
    super::super::discard(Path::new(&request));
    let digest = hex::encode(Sha256::digest(&bytes));
    let snapshot: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(snapshot["schema"], REQUEST_SCHEMA);
    assert_eq!(snapshot["workspace"], resolved.as_str());
    assert_eq!(snapshot["payload"]["tool_call_id"], "t1");

    let temp = trusted_local_temp().unwrap();
    let directory = Path::new(&request).parent().unwrap();
    assert_eq!(
        directory.parent().unwrap().to_str().unwrap().to_lowercase(),
        temp.to_str().unwrap().to_lowercase()
    );
    assert!(directory
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(REQUEST_DIRECTORY_PREFIX)));
    assert!(
        command.starts_with(&format!(
            "C:/Python/python.exe '-I' '-c' '{ARGV_BOOTSTRAP}' 'C:/Guard/site-packages' "
        )),
        "{command}"
    );
    assert!(
        command.contains(&format!(
            "'guard' 'execute-contained-test' '--harness' 'codex' '--guard-home' 'C:\\Users\\a\\.hol-guard' '--workspace' '{resolved}' '--request-file' "
        )),
        "{command}"
    );
    assert!(
        command.ends_with(&format!(
            "'--request-sha256' '{digest}' '--home' 'C:\\Users\\a'"
        )),
        "{command}"
    );
}

#[test]
fn a_call_no_shell_can_quote_keeps_the_denial() {
    let workspace = tempfile::tempdir().unwrap();
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "python scripts/report.py"},
        "cwd": workspace.path().to_str().unwrap(),
    })
    .to_string();
    let payload = parse_mapping_lone_surrogates(&payload).unwrap().value;
    let installed = owned(&[
        PYTHON,
        "-I",
        "-c",
        BOOTSTRAP,
        "guard",
        "hook",
        "--harness",
        "codex",
    ]);
    let target = Target {
        prefix: &installed,
        guard_home: r"C:\Users\a\.hol-guard",
        home: "C:\\Users\\a \"quoted\"",
    };
    let deny = parse_mapping_lone_surrogates(PYTHON_DENY).unwrap().value;
    assert_eq!(routed(&deny, &payload, false, &target), None::<PyVal>);
}

#[test]
fn every_ancestor_started_before_its_child() {
    use super::super::codex::windows_start_time;

    let parents = guard_runtime_windows_process::process_parent_ids().unwrap();
    let parent = parents[&std::process::id()];
    let own = windows_start_time(std::process::id()).unwrap();
    assert!(windows_start_time(parent).unwrap() <= own);
    assert_eq!(windows_start_time(u32::MAX - 3), None);
}

/// Set a file's or directory's modification time two days back.
fn age(path: &Path) {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    std::fs::OpenOptions::new()
        .access_mode(FILE_WRITE_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(2 * 86_400))
        .unwrap();
}

#[test]
fn only_day_old_plain_snapshots_are_reclaimed() {
    let temp = tempfile::tempdir().unwrap();
    let make = |name: &str, old: bool| {
        let directory = temp.path().join(name);
        std::fs::create_dir(&directory).unwrap();
        let request = directory.join(REQUEST_FILE_NAME);
        std::fs::write(&request, b"{}").unwrap();
        if old {
            age(&request);
            age(&directory);
        }
        directory
    };
    let stale = make(&format!("{REQUEST_DIRECTORY_PREFIX}stale"), true);
    let fresh = make(&format!("{REQUEST_DIRECTORY_PREFIX}fresh"), false);
    let other = make("unrelated-stale", true);
    cleanup_stale_requests(temp.path());
    assert!(!stale.exists());
    assert!(fresh.join(REQUEST_FILE_NAME).exists());
    assert!(other.join(REQUEST_FILE_NAME).exists());
}

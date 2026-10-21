//! The contained route hands the sink the command the denial was answered
//! for. A virtualenv activation exports settings and runs nothing else, so
//! the pre-tool pass projects `source .venv/bin/activate && pytest -q` to
//! `.venv/bin/pytest -q` and answers for that; the sink models no shell
//! builtin, so the snapshot has to carry the projected text or the sink
//! cannot plan a call Guard already judged.

#![cfg(unix)]

use super::request::REQUEST_FILE_NAME;
use super::{route_on, Host, SinkTarget};
use serde_json::{json, Map, Value};
use std::fs;
use std::path::{Path, PathBuf};

const PYTEST_READONLY: &str = "native_pytest_readonly_containment_required";

fn scratch(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "hook-direct-contained-venv-{label}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("tmp")).unwrap();
    fs::create_dir_all(root.join("project")).unwrap();
    fs::canonicalize(root).unwrap()
}

/// What `uv`, `venv` and `virtualenv` all write: a `deactivate` function, a
/// root, and a `PATH` with the environment's own `bin` in front of it.
fn environment(workspace: &Path, programs: &[&str]) {
    let venv = workspace.join(".venv");
    fs::create_dir_all(venv.join("bin")).unwrap();
    fs::write(
        venv.join("pyvenv.cfg"),
        "home = /usr/bin\nversion = 3.12.0\n",
    )
    .unwrap();
    fs::write(
        venv.join("bin/activate"),
        format!(
            r#"deactivate () {{
    if [ -n "${{_OLD_VIRTUAL_PATH:-}}" ] ; then
        PATH="${{_OLD_VIRTUAL_PATH:-}}"
        export PATH
        unset _OLD_VIRTUAL_PATH
    fi
    if [ ! "${{1:-}}" = "nondestructive" ] ; then
        unset -f deactivate
    fi
}}

deactivate nondestructive

VIRTUAL_ENV='{environment}'
export VIRTUAL_ENV

_OLD_VIRTUAL_PATH="$PATH"
PATH="$VIRTUAL_ENV/bin:$PATH"
export PATH

hash -r 2>/dev/null || true
"#,
            environment = venv.display()
        ),
    )
    .unwrap();
    for program in programs {
        fs::write(venv.join("bin").join(program), "#!/bin/sh\nexit 0\n").unwrap();
    }
}

fn denial() -> Value {
    json!({
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": PYTEST_READONLY,
        "required_execution_profile": "pytest-readonly-v2",
    })
}

fn payload(command: &str, cwd: &str) -> Map<String, Value> {
    serde_json::from_value(json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "cwd": cwd,
    }))
    .unwrap()
}

/// The snapshot and the `updatedInput` the route produced for `command`.
fn routed(root: &Path, command: &str) -> (Value, Value) {
    routed_from(root, command, None)
}

/// The same route, with `payload_cwd` standing in for the spelling the harness
/// sent. The edge answers with the settled workspace whatever the harness
/// wrote, so the route has to read the same directory it did.
fn routed_from(root: &Path, command: &str, payload_cwd: Option<&str>) -> (Value, Value) {
    let workspace = root.join("project");
    let workspace = workspace.to_str().unwrap().to_owned();
    let home = root.to_str().unwrap().to_owned();
    let launcher = vec![std::env::current_exe()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()];
    let target = SinkTarget {
        command: &launcher,
        harness: "omp",
        guard_home: "/g",
        home_dir: &home,
        workspace: &workspace,
    };
    let host = Host {
        platform: |_| true,
        native: |_, _, _| None,
    };
    let temp = root.join("tmp");
    let (response, snapshot) = route_on(
        &denial(),
        &payload(command, payload_cwd.unwrap_or(&workspace)),
        &target,
        host,
        &temp,
    )
    .unwrap()
    .expect("the denial routes to the sink");
    let request = fs::read_dir(&temp)
        .unwrap()
        .flatten()
        .next()
        .unwrap()
        .path()
        .join(REQUEST_FILE_NAME);
    let written: Value = serde_json::from_slice(&fs::read(request).unwrap()).unwrap();
    drop(snapshot);
    (written, response)
}

#[test]
fn an_activation_reaches_the_sink_as_the_program_it_hands_the_verdict_to() {
    let root = scratch("program");
    environment(&root.join("project"), &["pytest"]);
    let (snapshot, response) = routed(&root, "source .venv/bin/activate && pytest -q");
    assert_eq!(
        snapshot["payload"]["tool_input"]["command"],
        ".venv/bin/pytest -q"
    );
    // The harness still runs the sink, not the projected command itself.
    let updated = &response["hookSpecificOutput"]["updatedInput"]["command"];
    assert!(
        updated
            .as_str()
            .unwrap()
            .contains("guard execute-contained-test --harness omp"),
        "{updated}"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn the_route_reads_the_workspace_the_edge_answered_with() {
    let root = scratch("spelling");
    environment(&root.join("project"), &["pytest"]);
    // Oh My Pi can send `~/project`, and Claude Code a path through a symlink.
    // The edge settled both to the workspace before it answered, so a route
    // that resolved the activation script against the harness's own spelling
    // would hand the sink text no denial was given for.
    let (snapshot, _) = routed_from(
        &root,
        "source .venv/bin/activate && pytest -q",
        Some("~/project"),
    );
    assert_eq!(
        snapshot["payload"]["tool_input"]["command"],
        ".venv/bin/pytest -q"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_command_the_activation_scan_cannot_read_keeps_its_own_bytes() {
    let root = scratch("unread");
    // No `pyvenv.cfg` marker: the scan has proven nothing about `.venv`.
    let venv = root.join("project/.venv/bin");
    fs::create_dir_all(&venv).unwrap();
    fs::write(
        venv.join("activate"),
        "VIRTUAL_ENV=/x\nexport VIRTUAL_ENV\n",
    )
    .unwrap();
    for command in [
        "source .venv/bin/activate && pytest -q",
        "pytest -q",
        "source .venv/bin/activate; pytest -q",
    ] {
        let (snapshot, _) = routed(&root, command);
        assert_eq!(snapshot["payload"]["tool_input"]["command"], command);
        fs::remove_dir_all(root.join("tmp")).unwrap();
        fs::create_dir_all(root.join("tmp")).unwrap();
    }
    fs::remove_dir_all(root).unwrap();
}

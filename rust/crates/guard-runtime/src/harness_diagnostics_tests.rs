use serde_json::{json, Value};

use super::*;

const CONFIG: &str = "/home/user/.stubtool/config.json";

fn artifact(artifact_type: &str, command: Option<&str>, args: &[&str]) -> Value {
    json!({
        "artifact_type": artifact_type,
        "command": command,
        "args": [args],
        "harness": "stubtool",
    })
}

fn guard_hook() -> Value {
    artifact("hook", Some("hol-guard"), &["hook", "stubtool"])
}

fn launcher() -> Value {
    artifact(GUARD_LAUNCHER_SHIM, None, &[])
}

fn detection(config_paths: &[&str], command_available: bool, artifacts: &[Value]) -> Value {
    json!({
        "config_paths": [config_paths],
        "command_available": command_available,
        "artifacts": [artifacts],
    })
}

fn warnings_for(detection: Value, proves: bool, timed_out: bool) -> Vec<String> {
    let answer = dispatch(&json!({
        "op": "warnings",
        "harness": "stubtool",
        "executable": "stubcli",
        "command_absence_proves_uninstalled": proves,
        "runtime_probe_timed_out": timed_out,
        "detection": detection,
    }))
    .expect("warnings");
    serde_json::from_value(answer["warnings"].clone()).expect("warning list")
}

fn status_for(detection: Value, warnings: &[&str], proves: bool) -> String {
    let answer = dispatch(&json!({
        "op": "setup_status",
        "command_absence_proves_uninstalled": proves,
        "detection": detection,
        "warnings": [warnings],
    }))
    .expect("setup status");
    answer["setup_status"].as_str().expect("status").to_owned()
}

/// The status `HarnessAdapter.diagnostics` reports: the warnings this kind
/// adds, then the status those warnings leave.
fn diagnosed(detection: Value, own: &[&str], proves: bool) -> (Vec<String>, String) {
    let mut warnings: Vec<String> = own.iter().map(|warning| (*warning).to_owned()).collect();
    warnings.extend(warnings_for(detection.clone(), proves, false));
    let borrowed: Vec<&str> = warnings.iter().map(String::as_str).collect();
    let status = status_for(detection, &borrowed, proves);
    (warnings, status)
}

#[test]
fn an_unmanaged_config_is_told_to_install_guard() {
    assert_eq!(
        warnings_for(detection(&[CONFIG], true, &[]), true, false),
        [
            "stubtool config was found, but Guard is not installed for this harness. \
             Run `hol-guard install stubtool` to enable protection."
        ]
    );
}

#[test]
fn a_missing_command_beside_leftover_guard_config_suggests_uninstall() {
    assert_eq!(
        warnings_for(detection(&[CONFIG], false, &[guard_hook()]), true, false),
        [
            "Guard is configured for stubtool, but the stubcli command is not available on this \
             machine. Install stubcli, or run `hol-guard uninstall stubtool` to remove the \
             leftover Guard configuration."
        ]
    );
}

#[test]
fn a_harness_running_hooks_without_its_command_is_not_told_to_uninstall() {
    assert_eq!(
        warnings_for(detection(&[CONFIG], false, &[guard_hook()]), false, false),
        [
            "Guard is configured for stubtool, but the stubcli command is not available on this \
             machine. Install stubcli to protect stubtool command-line sessions. The \
             configuration is still in use, because stubtool runs Guard's hooks without it."
        ]
    );
}

#[test]
fn an_unmanaged_config_without_its_command_gets_both_warnings() {
    assert_eq!(
        warnings_for(detection(&[CONFIG], false, &[]), true, true),
        [
            "stubtool config was found, but Guard is not installed for this harness. \
             Run `hol-guard install stubtool` to enable protection.",
            "stubtool config was found, but the stubcli command is not available on PATH.",
            "stubcli diagnostics timed out before Guard could confirm runtime state.",
        ]
    );
}

#[test]
fn nothing_found_adds_no_warning() {
    assert!(warnings_for(detection(&[], false, &[]), true, false).is_empty());
    assert!(warnings_for(detection(&[], true, &[guard_hook()]), true, false).is_empty());
}

#[test]
fn guard_config_for_an_uninstalled_tool_is_not_found() {
    let (warnings, status) = diagnosed(detection(&[CONFIG], false, &[guard_hook()]), &[], true);
    assert_eq!(status, "not_found");
    assert!(warnings[0].contains("hol-guard uninstall stubtool"));
}

#[test]
fn guard_config_for_an_installed_tool_is_active() {
    let (warnings, status) = diagnosed(detection(&[CONFIG], true, &[guard_hook()]), &[], true);
    assert_eq!(status, "active");
    assert!(warnings.is_empty());
}

#[test]
fn adapter_faults_never_read_as_an_uninstalled_tool() {
    for own in [
        "Guard native hooks are disabled for stubtool.",
        "Managed Codex hooks are missing from the stubtool config.",
        "The configured stubtool executable was rejected as untrusted.",
        "Stale or duplicate Guard-managed stubtool entries detected.",
    ] {
        for available in [false, true] {
            let found = detection(&[CONFIG], available, &[guard_hook()]);
            let (_, status) = diagnosed(found, &[own], true);
            // An unrecognised fault on an installed tool raises no setup marker.
            let expected = if available && !own.contains("hooks") {
                "active"
            } else {
                "broken"
            };
            assert_eq!(status, expected, "{own} available={available}");
        }
    }
}

#[test]
fn a_guard_launcher_stays_broken_without_its_command() {
    let (_, alone) = diagnosed(detection(&[], false, &[guard_hook()]), &[], true);
    assert_eq!(alone, "broken");
    let (_, beside) = diagnosed(detection(&[CONFIG], false, &[launcher()]), &[], true);
    assert_eq!(beside, "broken");
    let managed_config = "/home/user/.stubtool/hol-guard-hooks.json";
    let found = detection(&[managed_config, CONFIG], false, &[launcher()]);
    assert_eq!(diagnosed(found, &[], true).1, "not_found");
}

#[test]
fn a_harness_running_hooks_without_its_command_stays_broken() {
    let (_, status) = diagnosed(detection(&[CONFIG], false, &[guard_hook()]), &[], false);
    assert_eq!(status, "broken");
}

#[test]
fn unmanaged_findings_are_partial_or_not_found() {
    assert_eq!(
        status_for(detection(&[CONFIG], false, &[]), &[], true),
        "partial"
    );
    assert_eq!(status_for(detection(&[], true, &[]), &[], true), "partial");
    assert_eq!(
        status_for(detection(&[], false, &[]), &[], true),
        "not_found"
    );
}

#[test]
fn a_config_path_is_managed_by_its_pathlib_name() {
    assert!(guard_managed_path("/x/hol-guard-hooks.json"));
    assert!(guard_managed_path("/x/HOL-Guard/"));
    assert!(guard_managed_path("hol-guard/."));
    assert!(guard_managed_path("hol-guard"));
    assert!(!guard_managed_path("/x/hol-guard/config.json"));
    assert!(!guard_managed_path(""));
    assert!(!guard_managed_path("/"));
    assert!(!guard_managed_path("."));
    assert!(!guard_managed_path("/x/my-hol-guard"));
}

#[test]
fn guard_command_names_match_the_harness_in_either_spelling() {
    assert!(is_guard_command_name("guard-stubtool", "stubtool"));
    assert!(is_guard_command_name(
        "/usr/local/bin/GUARD-stubtool",
        "stubtool"
    ));
    assert!(is_guard_command_name(
        "C:\\Users\\me\\bin\\guard-stubtool.CMD",
        "stubtool"
    ));
    assert!(is_guard_command_name("bin/guard-stubtool/", "stubtool"));
    assert!(!is_guard_command_name("guard-stubtool.exe", "stubtool"));
    assert!(!is_guard_command_name("guard-other", "stubtool"));
    // The name is lowered, the harness is not.
    assert!(!is_guard_command_name("guard-StubTool", "StubTool"));
    assert!(!is_guard_command_name("", ""));
}

#[test]
fn artifacts_use_guard_by_type_command_or_any_argument() {
    let uses = |item: Value| {
        dispatch(&json!({ "op": "uses_guard", "artifacts": [[item]] })).expect("uses")["uses_guard"]
            == json!(true)
    };
    assert!(uses(launcher()));
    assert!(uses(artifact("hook", Some("guard-stubtool"), &[])));
    assert!(uses(artifact("hook", Some("/opt/HOL-GUARD/bin/x"), &[])));
    assert!(uses(artifact(
        "mcp",
        Some("python"),
        &["-m", "Codex_Plugin_Scanner.CLI"]
    )));
    assert!(!uses(artifact("mcp", Some("python"), &["-m", "server"])));
    assert!(!uses(artifact("mcp", None, &[])));
}

#[test]
fn chunked_lists_join_back_in_order() {
    let plain = artifact("mcp", Some("node"), &["server.js"]);
    let answer = dispatch(&json!({
        "op": "uses_guard",
        "artifacts": [[plain.clone(), plain], [], [launcher()]],
    }))
    .expect("uses");
    assert_eq!(answer, json!({ "uses_guard": true }));
    let split_args = json!({
        "artifact_type": "hook",
        "command": "node",
        "args": [["--flag"], ["hol-guard"]],
        "harness": "stubtool",
    });
    let answer = dispatch(&json!({ "op": "uses_guard", "artifacts": [[split_args]] }));
    assert_eq!(answer, Ok(json!({ "uses_guard": true })));
    let found = json!({
        "config_paths": [[], ["/a/config.json"], ["/a/hol-guard.json"]],
        "command_available": true,
        "artifacts": [],
    });
    assert_eq!(status_for(found, &[], true), "active");
}

#[test]
fn malformed_requests_are_refused() {
    let found = detection(&[CONFIG], true, &[]);
    let mut numeric_command = artifact("hook", Some("x"), &[]);
    numeric_command["command"] = json!(3);
    for request in [
        json!([]),
        json!({ "op": "unknown" }),
        json!({ "op": "uses_guard" }),
        json!({ "op": "uses_guard", "artifacts": [launcher()] }),
        json!({ "op": "uses_guard", "artifacts": [[launcher()]], "extra": 1 }),
        json!({ "op": "uses_guard", "artifacts": [[{ "artifact_type": "hook" }]] }),
        json!({ "op": "uses_guard", "artifacts": [[numeric_command]] }),
        json!({
            "op": "setup_status",
            "command_absence_proves_uninstalled": true,
            "detection": found.clone(),
            "warnings": ["flat"],
        }),
        json!({
            "op": "warnings",
            "harness": "stubtool",
            "executable": "stubcli",
            "command_absence_proves_uninstalled": "yes",
            "runtime_probe_timed_out": false,
            "detection": found,
        }),
    ] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}

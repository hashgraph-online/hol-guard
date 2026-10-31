//! A leading `cd` to or below a sibling repository's root takes the native
//! sink, which runs the call from that root as Guard's own sink does. A `cwd`
//! argument is decided as that `cd`, which the native sink writes it as.

#![cfg(unix)]

use super::{directory_input, native_shape, WORKSPACE_PROFILE};
use serde_json::json;
use std::fs;

#[test]
fn a_cd_to_or_below_a_sibling_root_takes_the_native_sink() {
    // `/tmp`, not `$TMPDIR`, which macOS keeps below `/private/var`.
    let fixture = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
    let root = fs::canonicalize(fixture.path()).unwrap();
    for directory in [
        "home/app/.git",
        "home/app/sub",
        "home/report/.git",
        "home/report/web",
    ] {
        fs::create_dir_all(root.join(directory)).unwrap();
    }
    let (home, report) = (root.join("home"), root.join("home/report"));
    let workspace = root.join("home/app");
    let denial = json!({
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": "native_workspace_containment_required",
        "required_execution_profile": WORKSPACE_PROFILE,
    });
    let shape = |command: String| {
        let input = json!({ "command": command }).as_object().unwrap().clone();
        native_shape(
            &denial,
            &input,
            workspace.to_str().unwrap(),
            home.to_str().unwrap(),
        )
    };
    assert!(shape(format!("cd {}/web && npm test", report.display())));
    // A `cd` into the workspace still runs whole from its root.
    assert!(shape(format!("cd {}/sub && npm test", workspace.display())));
    // At the sibling's root both sinks peel the `cd` and ask about the
    // rest again from there. A directory in no repository keeps the
    // daemon's sink.
    assert!(shape(format!("cd {} && npm test", report.display())));
    assert!(shape(format!("cd {} && npm test", workspace.display())));
    assert!(shape("cd ../report && npm test".to_owned()));
    assert!(!shape(format!("cd {}/home && npm test", root.display())));
}

#[test]
fn a_cwd_argument_is_decided_as_the_directory_change_the_sink_runs() {
    let fixture = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
    let root = fs::canonicalize(fixture.path()).unwrap();
    for directory in [
        "home/app/.git",
        "home/app/sub",
        "home/report/.git",
        "home/report/web",
    ] {
        fs::create_dir_all(root.join(directory)).unwrap();
    }
    let (home, report) = (root.join("home"), root.join("home/report"));
    let workspace = root.join("home/app");
    let (workspace, home) = (workspace.to_str().unwrap(), home.to_str().unwrap());
    let denial = json!({
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": "native_workspace_containment_required",
        "required_execution_profile": WORKSPACE_PROFILE,
    });
    let decided = |cwd: String| {
        let input = json!({ "command": "npm test", "cwd": cwd })
            .as_object()
            .unwrap()
            .clone();
        // The call as sent names its own directory, which the sink settles.
        assert!(!native_shape(&denial, &input, workspace, home));
        let decided = directory_input(&input, workspace, home)?;
        assert!(!decided.contains_key("cwd"));
        Some(native_shape(&denial, &decided, workspace, home))
    };
    assert_eq!(decided("sub".to_owned()), Some(true));
    assert_eq!(decided(format!("{}/web", report.display())), Some(true));
    // The session directory drops the argument and runs the call as sent.
    assert_eq!(decided(String::new()), Some(true));
    // A sibling's own root is peeled and asked about again there by either
    // sink. An argument the sink refuses keeps the daemon's sink.
    assert_eq!(decided(report.display().to_string()), Some(true));
    assert_eq!(decided("@sub".to_owned()), None);
}

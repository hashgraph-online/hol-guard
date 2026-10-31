//! A leading `cd` below a sibling repository's root takes the native sink,
//! which runs the call from that root as Guard's own sink does.

#![cfg(unix)]

use super::{native_shape, WORKSPACE_PROFILE};
use serde_json::json;
use std::fs;

#[test]
fn a_cd_below_a_sibling_root_takes_the_native_sink() {
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
    // The sibling's root is planned again there, so it keeps the daemon's
    // sink, as does a directory in no repository.
    assert!(!shape(format!("cd {} && npm test", report.display())));
    assert!(!shape(format!("cd {}/home && npm test", root.display())));
}

//! On macOS the per-user temporary directory lives below `/private/var`, which
//! is otherwise system state. Routine work in a workspace created there must
//! stay quiet, while the temporary directory itself and system paths do not.
#![cfg(target_os = "macos")]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

fn decision(home: &std::path::Path, cwd: &std::path::Path, command: &str) -> String {
    evaluate_pre_tool_envelope_with_context(
        "codex",
        "PreToolUse",
        &json!({"tool_name":"Bash", "tool_input":{"command":command}}),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    )
    .minimum_action
}

#[test]
fn routine_work_in_a_private_temporary_workspace_is_quiet() {
    let temporary = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    assert!(
        temporary.starts_with("/private/var/folders"),
        "expected the per-user temporary directory, got {}",
        temporary.display()
    );
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let workspace = temporary.join(format!(
        "guard-temp-workspace-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&workspace).unwrap();
    let _cleanup = Cleanup(workspace.clone());
    std::fs::write(workspace.join("notes.md"), "fixture\n").unwrap();
    let home = std::path::PathBuf::from(std::env::var_os("HOME").unwrap());
    // The workspace may be named through the /var alias, as $TMPDIR spells it.
    let alias = std::path::Path::new("/var").join(workspace.strip_prefix("/private/var").unwrap());
    for cwd in [&workspace, &alias] {
        for command in [
            "mkdir -p build/out",
            "touch build/out/report.txt",
            "cat notes.md",
        ] {
            assert_eq!(
                decision(&home, cwd, command),
                "allow",
                "{command} in {}",
                cwd.display()
            );
        }
    }
    // The shared temporary directory is not a workspace, and system paths stay guarded.
    assert_ne!(decision(&home, &temporary, "mkdir -p build/out"), "allow");
    assert_ne!(
        decision(&home, &workspace, "mkdir -p /private/var/db/guard-fixture"),
        "allow"
    );
}

struct Cleanup(std::path::PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

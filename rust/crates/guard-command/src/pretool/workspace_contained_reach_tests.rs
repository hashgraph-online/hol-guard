//! An inline or heredoc program that reaches past what the workspace sandbox
//! withholds keeps its review: the sandbox neither hides system files nor
//! keeps a child git from discarding the work tree.
use crate::pretool::workspace_contained_tests::{controls, host, workspace, CONTAINED};

/// Removes a test workspace when the test ends, whether it passed or not.
struct Cleanup(std::path::PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_heredoc_program_that_opens_a_system_file_keeps_its_review() {
    let ws = workspace("python-system-file", true);
    let _cleanup = Cleanup(ws.clone());
    std::fs::write(ws.join("data.csv"), "a,b\n").unwrap();
    let home = ws.parent().unwrap().to_str().unwrap().to_owned();
    let outcome = |_: &str, command: &str, cwd: &std::path::Path| {
        let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
            "claude-code",
            "PreToolUse",
            &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
            Some(&controls()),
            None,
            Some(&home),
            cwd.to_str(),
        );
        (result.reason_code, result.minimum_action)
    };
    for body in [
        "with open('/etc/passwd') as f:\n    print(f.read())",
        "print(open('/var/lib/pam/auth').read())",
        "with open('/root/.bashrc', 'a') as f:\n    f.write('alias ls=x')",
    ] {
        let command = format!("python3 - <<'PYEOF'\n{body}\nPYEOF");
        let (reason, action) = outcome("claude-code", &command, &ws);
        assert_ne!(reason, CONTAINED, "{command}");
        assert_ne!(action, "allow", "{command}");
    }
    for command in [
        "python3 -c \"print(open('/etc/passwd').read())\"",
        "python3 - <<< \"print(open('/etc/passwd').read())\"",
    ] {
        let (reason, action) = outcome("claude-code", command, &ws);
        assert_ne!(reason, CONTAINED, "{command}");
        assert_ne!(action, "allow", "{command}");
    }
    let command = "python3 - <<'PYEOF'\nwith open('data.csv') as f:\n    print(f.read())\nPYEOF";
    let (reason, _) = outcome("claude-code", command, &ws);
    assert_eq!(reason == CONTAINED, host(), "{reason}: {command}");
}

#[test]
fn a_lone_inline_program_that_reaches_past_the_sandbox_keeps_its_review() {
    let ws = workspace("inline-program-past-sandbox", true);
    let _cleanup = Cleanup(ws.clone());
    let home = ws.parent().unwrap().to_str().unwrap().to_owned();
    let outcome = |command: &str| {
        let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
            "claude-code",
            "PreToolUse",
            &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
            Some(&controls()),
            None,
            Some(&home),
            ws.to_str(),
        );
        (result.reason_code, result.minimum_action)
    };
    // The read-only evaluation sandbox neither hides system files nor keeps
    // a child git from discarding the work tree, so these are reviewed.
    for command in [
        "python3 -c \"print(open('/etc/passwd').read())\"",
        "python3 -c 'import subprocess as s; s.run([\"git\", \"reset\", \"--hard\", \"HEAD\"])'",
        "python3 -c 'import subprocess; subprocess.run([\"git\", \"clean\", \"-f\", \"-d\", \"-x\"])'",
        "node -e 'require(\"child_process\").execSync(\"git checkout -- .\")'",
    ] {
        let (reason, action) = outcome(command);
        assert_eq!(action, "review", "{command} ({reason})");
    }
    // A program that only reads the work tree still runs contained.
    let command =
        "python3 -c 'import subprocess; subprocess.run([\"git\", \"status\", \"--short\"])'";
    let (reason, action) = outcome(command);
    assert_ne!(action, "allow", "{command} ({reason})");
    // Linux contains it too where bubblewrap can mount; Windows narrows by shell.
    if cfg!(target_os = "macos") {
        assert_eq!(action, "sandbox-required", "{command} ({reason})");
    }
}

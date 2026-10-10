#![cfg(unix)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

struct TempTree(PathBuf);

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn decision(
    harness_tool: &str,
    payload: serde_json::Value,
    home: &Path,
    cwd: &Path,
) -> (String, String) {
    let (tool_name, input_key, input_value) = if harness_tool == "read" {
        ("read", "path", payload["path"].as_str().unwrap().to_owned())
    } else {
        (
            "bash",
            "command",
            payload["command"].as_str().unwrap().to_owned(),
        )
    };
    let result = evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({
            "tool_name": tool_name,
            "tool_input": {input_key: input_value},
        }),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    );
    (result.minimum_action, result.reason_code)
}

fn under_sensitive_temp(path: &Path) -> bool {
    let rendered = path.to_string_lossy().replace('\\', "/");
    let lowered = rendered.to_ascii_lowercase();
    lowered == "/var"
        || lowered.starts_with("/var/")
        || lowered == "/private/var"
        || lowered.starts_with("/private/var/")
}

#[test]
fn ordinary_workspace_under_system_temp_stays_bounded() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "hol-guard-var-workspace-{}-{nonce}",
        std::process::id()
    ));
    let home = root.join("home");
    let project = root.join("project");
    let outside = root.join("outside");
    let sibling = home.join("other-project");
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::create_dir_all(project.join("docs")).unwrap();
    std::fs::create_dir_all(project.join("output")).unwrap();
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::create_dir_all(&sibling).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(project.join("README.md"), "ordinary project\n").unwrap();
    std::fs::write(project.join("src/one.ts"), "export const fixture = 1;\n").unwrap();
    std::fs::write(project.join("src/two.ts"), "export const ordinary = 2;\n").unwrap();
    std::fs::write(
        project.join("src/settings.ts"),
        "export const retryLimit = 3;\n",
    )
    .unwrap();
    std::fs::write(
        project.join("src/path with spaces.ts"),
        "export const fixture = 1;\n",
    )
    .unwrap();
    std::fs::write(project.join("docs/notes.md"), "ordinary notes\n").unwrap();
    std::fs::write(project.join(".env"), "synthetic-canary\n").unwrap();
    std::fs::write(project.join(".git/config"), "[core]\n").unwrap();
    std::fs::write(outside.join("note.ts"), "outside\n").unwrap();
    let _tree = TempTree(root);

    let canonical_project = std::fs::canonicalize(&project).unwrap();
    let project_text = canonical_project.to_str().unwrap();
    let home = std::fs::canonicalize(&home).unwrap();
    let outside_file = std::fs::canonicalize(outside.join("note.ts")).unwrap();
    let src = canonical_project.join("src");
    let docs = canonical_project.join("docs");

    for path in ["README.md", "src/settings.ts", "src/one.ts"] {
        let (action, reason) = decision("read", json!({"path": path}), &home, &canonical_project);
        assert_eq!(action, "allow", "{path} {reason}");
        assert_eq!(reason, "native_exact_safe_file_read", "{path}");
    }
    let (secret_action, secret_reason) =
        decision("read", json!({"path": ".env"}), &home, &canonical_project);
    assert_ne!(secret_action, "allow", "{secret_reason}");

    let allowed = [
        "cat src/one.ts | grep -efixt".to_owned(),
        "cat src/one.ts | rg -efixt".to_owned(),
        "grep -n ordinary src/one.ts src/two.ts".to_owned(),
        "cat src/one.ts | sed -n -e '1,2p' -".to_owned(),
        "cat src/one.ts | sed -e 's/fixture/public/g'".to_owned(),
        "wc -c src/one.ts && od -c src/one.ts | tail -2".to_owned(),
        "cp -- 'src/path with spaces.ts' 'output/copy with spaces.ts'".to_owned(),
        format!("cp src/one.ts {}/other-project/copied.ts", home.display()),
        format!("grep -rn ordinary {} {}", src.display(), docs.display()),
    ];
    for command in &allowed {
        let (action, reason) = decision(
            "bash",
            json!({"command": command}),
            &home,
            &canonical_project,
        );
        assert_eq!(action, "allow", "{command} {reason}");
        assert_eq!(reason, "native_exact_safe_command", "{command}");
    }

    let denied = [
        "cat .env",
        "cp .env output/copied.env",
        "cp -- .env output/copied.env",
        "cp src/one.ts .git/config",
        "cat src/one.ts | sort -o .env",
        "find src -type f -delete",
        "cat /etc/passwd",
    ];
    for command in denied {
        let (action, reason) = decision(
            "bash",
            json!({"command": command}),
            &home,
            &canonical_project,
        );
        assert_ne!(action, "allow", "{command} {reason}");
    }

    if under_sensitive_temp(&canonical_project) {
        let (action, reason) = decision(
            "read",
            json!({"path": outside_file.to_str().unwrap()}),
            &home,
            &canonical_project,
        );
        assert_ne!(
            action, "allow",
            "path outside the verified project must stay denied under {project_text}: {reason}"
        );
        let (action, reason) = decision(
            "bash",
            json!({"command": format!("cat {}", outside_file.display())}),
            &home,
            &canonical_project,
        );
        assert_ne!(action, "allow", "{reason}");
    }
}

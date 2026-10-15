#![cfg(unix)]
//! Oh My Pi content searches over its own `~/.agent/artifacts` reports.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// The root stays below the target directory: `$TMPDIR` on macOS resolves
/// under `/private/var`, which the sensitive-root screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-omp-artifact-search")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let home = root.join("home");
    for file in [
        ".agent/artifacts/report.md",
        ".agent/artifacts/runs/summary.md",
        ".agent/skills/x/SKILL.md",
        ".agent/skills/x/run.py",
        "project/main.py",
    ] {
        write(home.join(file), "Inert synthetic fixture\n");
    }
    std::fs::canonicalize(home).unwrap()
}

fn grep(home: &Path, path: &Path) -> String {
    grep_spelled(home, path.to_str().unwrap())
}

fn grep_spelled(home: &Path, path: &str) -> String {
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name": "grep", "tool_input": {"pattern": "Inert", "path": path}}),
        None,
        None,
        home.to_str(),
        home.join("project").to_str(),
    )
    .minimum_action
}

#[test]
fn grep_over_artifact_documents_proceeds() {
    let home = home();
    let artifacts = home.join(".agent/artifacts");
    assert_eq!(grep(&home, &artifacts), "allow");
    assert_eq!(grep(&home, &artifacts.join("runs")), "allow");
    assert_eq!(grep_spelled(&home, "~/.agent/artifacts"), "allow");
}

#[test]
fn tilde_spelled_grep_over_skills_still_asks() {
    let home = home();
    assert_ne!(grep_spelled(&home, "~/.agent/skills"), "allow");
    assert_ne!(grep_spelled(&home, "~/.agent/skills/x"), "allow");
    assert_ne!(grep_spelled(&home, "~/.agent"), "allow");
}

#[test]
fn grep_that_could_reach_other_agent_state_still_asks() {
    let home = home();
    // The skills tree holds a script, and `~/.agent` holds everything else.
    assert_ne!(grep(&home, &home.join(".agent/skills")), "allow");
    assert_ne!(grep(&home, &home.join(".agent")), "allow");
    for (name, make) in [
        ("data.json", false),
        (".cache/note.md", false),
        ("link.md", true),
    ] {
        let home = self::home();
        let artifacts = home.join(".agent/artifacts");
        if make {
            std::os::unix::fs::symlink(home.join("project/main.py"), artifacts.join(name)).unwrap();
        } else {
            write(artifacts.join(name), "Inert synthetic fixture\n");
        }
        assert_ne!(grep(&home, &artifacts), "allow", "{name}");
    }
}

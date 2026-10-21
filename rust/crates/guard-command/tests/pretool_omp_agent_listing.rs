#![cfg(unix)]
//! Names-only listings of the Oh My Pi agent home (`~/.agent`).
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
        .join("../../target/pretool-omp-agent-listing")
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
        ".agent/skills/x/SKILL.md",
        "project/main.py",
        "elsewhere/.agent/notes.md",
    ] {
        write(home.join(file), "Inert synthetic fixture\n");
    }
    std::fs::canonicalize(home).unwrap()
}

fn shell(home: &Path, command: &str) -> String {
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        home.to_str(),
        home.join("project").to_str(),
    )
    .minimum_action
}

#[test]
fn listing_the_agent_home_proceeds() {
    let home = home();
    let absolute = home.join(".agent");
    let absolute = absolute.to_str().unwrap();
    for command in [
        "ls ~/.agent".to_owned(),
        "ls -la ~/.agent".to_owned(),
        "ls -R ~/.agent".to_owned(),
        "ls -R ~/.agent/".to_owned(),
        format!("ls -la {absolute}"),
        format!("ls -R {absolute}"),
        "find ~/.agent -maxdepth 4 -name SKILL.md".to_owned(),
        format!("find {absolute} -type f"),
    ] {
        assert_eq!(shell(&home, &command), "allow", "{command}");
    }
    // `${HOME}` comes from the shell, and this process's HOME is not the
    // fixture home, so the operand names some other directory.
    assert_ne!(
        shell(
            &home,
            "find ${HOME}/.agent -maxdepth 4 -name SKILL.md 2>/dev/null"
        ),
        "allow"
    );
}

#[test]
fn recursive_listing_still_screens_agent_home_entries() {
    for entry in [".env", "auth/credentials.json", "keys/id_rsa.pem"] {
        let home = home();
        write(home.join(".agent").join(entry), "Inert synthetic fixture\n");
        assert_ne!(shell(&home, "ls -R ~/.agent"), "allow", "{entry}");
        assert_ne!(shell(&home, "find ~/.agent -type f"), "allow", "{entry}");
        // A recursive listing prints every name it reaches, which is why the
        // entry above holds it back. A name pattern prints only the paths it
        // selects, and one that could select a credential is refused before
        // the walk is reached, so the entry cannot appear in the output.
        assert_eq!(
            shell(&home, "find ~/.agent -name SKILL.md"),
            "allow",
            "{entry}"
        );
    }
}

#[test]
fn content_searches_and_other_hidden_roots_still_ask() {
    let home = home();
    for command in [
        "grep -r Inert ~/.agent",
        "grep -rl Inert ~/.agent",
        "cat ~/.agent",
        "ls -R ~/elsewhere/.agent",
        "find ~/.agent -name SKILL.md -exec cat {} +",
        "find ~/.agent -fprint /tmp/names",
        "find -L ~/.agent -name SKILL.md",
        "ls ~/.ssh",
        "ls -R ~/.config",
    ] {
        assert_ne!(shell(&home, command), "allow", "{command}");
    }
}

#[test]
fn linked_agent_home_still_asks() {
    let home = home();
    // A link may not turn other hidden application state into the agent home.
    let real = home.join(".config/agent-copy");
    std::fs::create_dir_all(&real).unwrap();
    std::fs::rename(home.join(".agent"), real.join("state")).unwrap();
    std::os::unix::fs::symlink(real.join("state"), home.join(".agent")).unwrap();
    assert_ne!(shell(&home, "ls ~/.agent"), "allow");
    assert_ne!(shell(&home, "ls -R ~/.agent"), "allow");
    assert_ne!(shell(&home, "find ~/.agent -name SKILL.md"), "allow");
}

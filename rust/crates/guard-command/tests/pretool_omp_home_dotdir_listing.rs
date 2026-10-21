#![cfg(unix)]
//! Oh My Pi's own listing tools reach a dot-directory in the home directory
//! on the same terms `ls ~/.nvm` does.
//!
//! The shell screen has allowed that listing for a while. The host's `glob`,
//! `ls` and `find` tools take the path as tool input instead of as a command,
//! and that route used to answer from the content-read screens alone, so a
//! toolchain inventory asking what is installed under `~/.nvm` raised an
//! approval while the same question in `bash` ran quietly.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// The root stays below the crate's target directory: `$TMPDIR` on macOS
/// resolves under `/private/var`, which the sensitive-root screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-omp-home-dotdir-listing")
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
        ".nvm/versions/node/v22.11.0/bin/node",
        ".agents/skills/release/SKILL.md",
        ".config/ngrok/ngrok.yml",
        ".config/gh/hosts.yml",
        ".ssh/config",
        "project/main.py",
    ] {
        write(home.join(file), "Inert synthetic fixture\n");
    }
    std::fs::canonicalize(home).unwrap()
}

fn tool(home: &Path, name: &str, input: serde_json::Value) -> String {
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name": name, "tool_input": input}),
        None,
        None,
        home.to_str(),
        home.join("project").to_str(),
    )
    .minimum_action
}

fn shell(home: &Path, command: &str) -> String {
    tool(home, "bash", json!({ "command": command }))
}

#[test]
fn the_listing_tools_answer_a_dot_directory_the_shell_already_lists() {
    let home = home();
    for path in ["~/.nvm", "~/.agents/skills", "~/.config/ngrok"] {
        assert_eq!(shell(&home, &format!("ls {path}")), "allow", "ls {path}");
        assert_eq!(
            tool(&home, "glob", json!({ "path": path })),
            "allow",
            "glob {path}"
        );
        assert_eq!(
            tool(&home, "ls", json!({ "path": path })),
            "allow",
            "ls tool {path}"
        );
    }
}

#[test]
fn the_host_list_separator_lists_every_directory_it_names() {
    let home = home();
    assert_eq!(
        tool(
            &home,
            "glob",
            json!({"path": "~/.nvm;~/.agents/skills", "hidden": true, "gitignore": false})
        ),
        "allow"
    );
}

#[test]
fn a_credential_store_keeps_its_review_through_the_tools() {
    let home = home();
    for path in ["~/.ssh", "~/.config/gh", "~/.nvm;~/.ssh"] {
        assert_ne!(
            tool(&home, "glob", json!({ "path": path })),
            "allow",
            "glob {path}"
        );
        assert_ne!(
            tool(&home, "ls", json!({ "path": path })),
            "allow",
            "ls tool {path}"
        );
    }
}

#[test]
fn a_walk_below_the_directory_keeps_its_review() {
    let home = home();
    // `find` and a `pattern` recurse, so the names inside `~/.config/gh`
    // would come back with the rest of `~/.config`.
    assert_ne!(tool(&home, "find", json!({"path": "~/.config"})), "allow");
    assert_ne!(
        tool(
            &home,
            "glob",
            json!({"path": "~/.config", "pattern": "*.yml"})
        ),
        "allow"
    );
}

#[test]
fn private_state_of_the_tool_that_owns_the_directory_keeps_its_review() {
    let home = home();
    write(home.join(".nvm/.cache/index"), "Inert synthetic fixture\n");
    assert_ne!(
        tool(&home, "glob", json!({"path": "~/.nvm/.cache"})),
        "allow"
    );
}

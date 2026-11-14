#![cfg(unix)]
//! Listing a zip archive and reading a file's extended attributes only read.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// A home holding one project with an archive in it. The archive bytes do
/// not matter: the decision reads only the command. The root stays below the
/// target directory: `$TMPDIR` on macOS resolves under `/private/var`, which
/// the sensitive-root screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-archive-listing")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    let project = home.join("project");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    write(project.join("README.md"), "# Fixture\n");
    write(project.join("dist/app.zip"), "PK\u{5}\u{6}");
    write(project.join("dist/tool.whl"), "PK\u{5}\u{6}");
    std::fs::canonicalize(home).unwrap()
}

fn action(home: &Path, command: &str) -> String {
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: "/usr/bin:/bin".to_owned(),
        environment_digest: "0".repeat(64),
        home: Some(home.to_str().unwrap().to_owned()),
        ..Default::default()
    };
    let cwd = home.join("project");
    let result = evaluate_pre_tool_envelope_with_execution_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        PathContext {
            home_dir: home.to_str(),
            cwd: cwd.to_str(),
            python_environment_inert: true,
            ..PathContext::default()
        },
        Some(&environment),
    );
    format!("{} {}", result.minimum_action, result.reason_code)
}

#[test]
fn listing_an_archive_or_reading_attributes_proceeds() {
    let home = home();
    for command in [
        "unzip -l dist/app.zip",
        "unzip -lv dist/app.zip",
        "unzip -l -q dist/app.zip",
        "unzip -v dist/tool.whl",
        "unzip -z dist/app.zip",
        "unzip -l dist/app.zip README.md",
        "unzip -l dist/app.zip | head -20",
        "unzip -l dist/app.zip | grep -i readme",
        "unzip -Z -1 dist/app.zip",
        "zipinfo dist/app.zip",
        "zipinfo -1 dist/tool.whl",
        "xattr README.md",
        "xattr -l README.md",
        "xattr -p com.apple.quarantine README.md",
        "xattr -px com.apple.quarantine README.md",
        "xattr -l dist",
    ] {
        assert_eq!(
            action(&home, command),
            "allow native_exact_safe_command",
            "{command}"
        );
    }
}

#[test]
fn extracting_or_changing_attributes_keeps_its_review() {
    let home = home();
    for command in [
        // Extraction writes into the working tree.
        "unzip dist/app.zip",
        "unzip -o dist/app.zip",
        "unzip -l dist/app.zip -d out",
        "unzip -q dist/app.zip",
        "unzip -p dist/app.zip README.md",
        // A wildcard member could expand to a file named like an option.
        "unzip -l dist/app.zip *",
        // No archive at all.
        "unzip -l",
        "zipinfo -M dist/app.zip",
        // A sensitive archive name is screened like a `cat` of it.
        "unzip -l ~/.ssh/id_rsa",
        // Writing, deleting, clearing and recursing.
        "xattr -w com.example.flag 1 README.md",
        "xattr -d com.apple.quarantine README.md",
        "xattr -c README.md",
        "xattr -r -d com.apple.quarantine dist",
        "xattr -lr dist",
        "xattr -p com.apple.quarantine",
        "tar -tzf dist/app.zip",
    ] {
        assert!(
            !action(&home, command).starts_with("allow"),
            "{command} was allowed"
        );
    }
}

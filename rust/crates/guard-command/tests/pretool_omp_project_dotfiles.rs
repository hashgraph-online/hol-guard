#![cfg(unix)]
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::{json, Value};

struct Fixture {
    home: std::path::PathBuf,
    project: std::path::PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.home.parent().unwrap());
    }
}

fn fixture() -> Fixture {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-omp-project-dotfiles")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    let project = home.join("project");
    for file in [
        ".gitignore",
        ".editorconfig",
        "src/.gitignore",
        ".dockerignore/notes.md",
        ".git/config",
        ".git/hooks/pre-commit",
        ".git/info/exclude",
    ] {
        let path = project.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "synthetic fixture\n").unwrap();
    }
    Fixture { home, project }
}

fn run(f: &Fixture, tool: &str, input: Value) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name": tool, "tool_input": input}),
        None,
        None,
        f.home.to_str(),
        f.project.to_str(),
    )
}

#[test]
fn project_config_dotfiles_are_ordinary_reads_and_writes() {
    let f = fixture();
    for path in [".gitignore", "src/.gitignore", ".editorconfig"] {
        let result = run(&f, "read", json!({"path": path}));
        assert_eq!(result.minimum_action, "allow", "{path}: {result:?}");
    }
    for path in [".gitignore", ".editorconfig", "src/.prettierignore"] {
        let result = run(&f, "write", json!({"path": path, "content": "dist/\n"}));
        assert_eq!(
            (result.minimum_action.as_str(), result.reason_code.as_str()),
            ("allow", "native_exact_safe_file_write"),
            "{path}"
        );
    }
}

#[test]
fn git_internals_and_dotfile_directories_stay_reviewed() {
    let f = fixture();
    for path in [
        ".git/config",
        ".git/hooks/pre-commit",
        ".git/info/exclude",
        ".git-credentials",
        ".dockerignore/notes.md",
    ] {
        let result = run(&f, "write", json!({"path": path, "content": "x\n"}));
        assert_ne!(result.minimum_action, "allow", "{path}: {result:?}");
    }
    let result = run(&f, "read", json!({"path": ".dockerignore/notes.md"}));
    assert_ne!(result.minimum_action, "allow", "{result:?}");
}

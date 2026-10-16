#![cfg(unix)]

//! Oh My Pi `grep` and `glob` over a workspace that tracks sensitive-named
//! fixtures, and over one that holds nested checkouts and named pipes.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use guard_contracts::PreToolResultV1;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    home: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn fixture() -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-omp-tracked-search")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    Fixture { root, home }
}

fn git(directory: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(directory)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

/// A repository that tracks `tracked` files and leaves `loose` untracked.
fn repository(f: &Fixture, name: &str, tracked: &[(&str, &str)], loose: &[(&str, &str)]) {
    let workspace = f.home.join(name);
    std::fs::create_dir_all(&workspace).unwrap();
    git(&workspace, &["init", "-q"]);
    for (file, text) in tracked {
        write(workspace.join(file), text);
    }
    git(&workspace, &["add", "-A", "-f"]);
    for (file, text) in loose {
        write(workspace.join(file), text);
    }
}

fn omp(f: &Fixture, cwd: &str, tool: &str, input: Value) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name": tool, "tool_input": input}),
        None,
        None,
        f.home.to_str(),
        f.home.join(cwd).to_str(),
    )
}

fn allowed(result: &PreToolResultV1) -> bool {
    result.minimum_action == "allow"
}

const PLAIN: &str = "API_URL=http://localhost:8080\nMODE=test\n";

#[test]
fn a_tracked_fixture_without_a_credential_value_is_not_a_secret() {
    let f = fixture();
    repository(
        &f,
        "app",
        &[
            (".env", PLAIN),
            ("tests/fixtures/.env.test", PLAIN),
            ("src/main.ts", "export {};\n"),
        ],
        &[],
    );
    for input in [
        json!({"pattern": "MODE", "path": "."}),
        json!({"pattern": "MODE"}),
    ] {
        let result = omp(&f, "app", "grep", input.clone());
        assert!(allowed(&result), "{input}: {}", result.reason_code);
    }
    let result = omp(&f, "app", "glob", json!({"path": "**/*"}));
    assert!(allowed(&result), "{}", result.reason_code);
}

#[test]
fn credential_shaped_values_untracked_files_and_stores_keep_review() {
    let f = fixture();
    // A tracked file holding a credential-shaped value.
    let key = format!("AWS_ACCESS_KEY_ID={}{}\n", "AKIA", "IOSFODNN7REALKEY");
    repository(&f, "leaky", &[(".env", key.as_str())], &[]);
    // A short password the detector flags only by the file's name.
    repository(&f, "short", &[(".env", "PASSWORD=\"Abcdefghijkl\"\n")], &[]);
    // A tracked fixture beside an untracked `.env`.
    repository(&f, "mixed", &[(".env.example", PLAIN)], &[(".env", PLAIN)]);
    // A tracked file in a credential-store directory.
    repository(&f, "stored", &[(".aws/credentials", PLAIN)], &[]);
    // A tracked fixture beside an ignored one, with the ignore rules off.
    repository(
        &f,
        "ignored",
        &[(".gitignore", ".env.local\n"), (".env", PLAIN)],
        &[(".env.local", PLAIN)],
    );
    for cwd in ["leaky", "short", "mixed", "stored"] {
        let input = json!({"pattern": "MODE", "path": "."});
        assert!(!allowed(&omp(&f, cwd, "grep", input)), "{cwd}");
    }
    let input = json!({"pattern": "MODE", "path": ".", "gitignore": false});
    assert!(!allowed(&omp(&f, "ignored", "grep", input)));
    // The same repository is fine while the ignore rules apply.
    let input = json!({"pattern": "MODE", "path": "."});
    assert!(allowed(&omp(&f, "ignored", "grep", input)));
}

#[test]
fn glob_names_ignore_sensitive_names_and_named_pipes() {
    let f = fixture();
    repository(&f, "app", &[("src/a.sh", "true\n")], &[(".env", PLAIN)]);
    let pipe = f.home.join("app/dev.pipe");
    let made = Command::new("mkfifo").arg(&pipe).status().unwrap();
    assert!(made.success());
    for path in [".", "**/*.sh", "**/*"] {
        let result = omp(&f, "app", "glob", json!({"path": path}));
        assert!(allowed(&result), "{path}: {}", result.reason_code);
    }
}

#[test]
fn nested_checkouts_each_bring_their_own_entry_budget() {
    let f = fixture();
    repository(&f, "app", &[("src/a.ts", "export {};\n")], &[]);
    for nested in ["wt-one", "wt-two"] {
        let checkout = f.home.join("app").join(nested);
        std::fs::create_dir_all(checkout.join(".git")).unwrap();
        for directory in 0..110 {
            let directory = checkout.join(format!("d{directory}"));
            std::fs::create_dir_all(&directory).unwrap();
            for file in 0..100 {
                std::fs::File::create(directory.join(format!("f{file}.ts"))).unwrap();
            }
        }
    }
    // Together the checkouts exceed one content-search budget.
    let input = json!({"pattern": "export", "path": "."});
    let result = omp(&f, "app", "grep", input);
    assert!(allowed(&result), "{}", result.reason_code);
    // A sensitive file inside a nested checkout is still in reach.
    write(f.home.join("app/wt-two/.env"), PLAIN);
    let input = json!({"pattern": "export", "path": "."});
    assert!(!allowed(&omp(&f, "app", "grep", input)));
}

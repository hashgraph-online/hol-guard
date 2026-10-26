#![cfg(unix)]
//! Content reads of installed dependency and toolchain source below hidden
//! home directories proceed. Credential and config files beside the install
//! root, sensitive files inside it, links that leave it and every write keep
//! review.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

use crate::git_helper_fixture::FixtureCleanup;

const PIPX_PACKAGE: &str = ".local/pipx/venvs/tool/lib/python3.12/site-packages/pkg";
const USER_PACKAGE: &str = ".local/lib/python3.12/site-packages/pkg";
const CRATE_SOURCE: &str = ".cargo/registry/src/index/serde-1.0.0/src";
const CORE_SOURCE: &str = ".rustup/toolchains/stable/lib/rustlib/src/rust/library/core/src";
const BUN_MODULES: &str = ".bun/install/global/node_modules";

/// A home with installed package trees, credential and config files beside
/// them, and a project. The root stays below the target directory: `$TMPDIR`
/// on macOS resolves under `/private/var`, which the system-root screen
/// rejects.
fn home(name: &str) -> (FixtureCleanup, PathBuf) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-installed-package-source")
        .join(format!(
            "{name}-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let files: [(String, &str); 19] = [
        (
            "work/project/.git/HEAD".to_owned(),
            "ref: refs/heads/main\n",
        ),
        ("work/project/src/main.py".to_owned(), "print('main')\n"),
        (format!("{PIPX_PACKAGE}/mod.py"), "_COLD_START = 0.5\n"),
        (format!("{PIPX_PACKAGE}/.env"), "TOKEN=synthetic\n"),
        (format!("{PIPX_PACKAGE}/server.pem"), "synthetic\n"),
        (format!("{USER_PACKAGE}/mod.py"), "X = 1\n"),
        (format!("{CRATE_SOURCE}/lib.rs"), "pub fn serde() {}\n"),
        (format!("{CORE_SOURCE}/lib.rs"), "//! core\n"),
        (format!("{BUN_MODULES}/vite/package.json"), "{}\n"),
        (
            ".nvm/versions/node/v25.2.1/lib/node_modules/npm/package.json".to_owned(),
            "{}\n",
        ),
        (".bun/install/cache/vite/package.json".to_owned(), "{}\n"),
        (
            ".aws/node_modules/pkg/index.js".to_owned(),
            "module.exports = 1;\n",
        ),
        (".cargo/credentials.toml".to_owned(), "[registry]\n"),
        (".cargo/config.toml".to_owned(), "[build]\n"),
        (
            ".npmrc".to_owned(),
            "registry=https://registry.example.com/\n",
        ),
        (".config/gh/hosts.yml".to_owned(), "example.com:\n"),
        (
            ".local/share/keyrings/login.keyring".to_owned(),
            "synthetic\n",
        ),
        (".ssh/config".to_owned(), "Host example\n"),
        (".ssh/id_ed25519".to_owned(), "synthetic\n"),
    ];
    for (path, contents) in files {
        let path = home.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
    // A package entry that is a link to a key store, and a package tree
    // reached through a linked directory.
    std::os::unix::fs::symlink(home.join(".ssh"), home.join(BUN_MODULES).join("linked")).unwrap();
    std::os::unix::fs::symlink(home.join(".local/lib"), home.join(".local/linked-lib")).unwrap();
    (cleanup, std::fs::canonicalize(home).unwrap())
}

fn action(home: &Path, harness: &str, command: &str) -> String {
    let cwd = home.join("work/project");
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    )
    .minimum_action
}

#[test]
fn installed_package_source_reads_proceed() {
    let (_cleanup, home) = home("allowed");
    let absolute = format!("cat {}/{PIPX_PACKAGE}/mod.py", home.display());
    let commands = [
        format!("rg -n 'X|_COLD' ~/{PIPX_PACKAGE}/mod.py"),
        format!("sed -n 1,40p ~/{PIPX_PACKAGE}/mod.py"),
        absolute,
        format!("grep -rn X ~/{USER_PACKAGE}/"),
        format!("cat ~/{CRATE_SOURCE}/lib.rs"),
        format!("rg -n fn ~/{CRATE_SOURCE}"),
        format!("head ~/{CORE_SOURCE}/lib.rs"),
        format!("cat ~/{BUN_MODULES}/vite/package.json"),
        "cat ~/.nvm/versions/node/v25.2.1/lib/node_modules/npm/package.json".to_owned(),
    ];
    for harness in ["claude-code", "codex", "omp"] {
        for command in &commands {
            assert_eq!(
                action(&home, harness, command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn sensitive_files_and_files_beside_install_roots_keep_review() {
    let (_cleanup, home) = home("sensitive");
    let commands = [
        format!("cat ~/{PIPX_PACKAGE}/.env"),
        format!("cat ~/{PIPX_PACKAGE}/server.pem"),
        // The walk reaches the package's `.env`.
        format!("grep -rn X ~/{PIPX_PACKAGE}"),
        "cat ~/.cargo/credentials.toml".to_owned(),
        "cat ~/.cargo/config.toml".to_owned(),
        "cat ~/.npmrc".to_owned(),
        "cat ~/.config/gh/hosts.yml".to_owned(),
        "cat ~/.local/share/keyrings/login.keyring".to_owned(),
        "cat ~/.bun/install/cache/vite/package.json".to_owned(),
        // A package tree inside a credential store is not an install root.
        "cat ~/.aws/node_modules/pkg/index.js".to_owned(),
    ];
    for harness in ["claude-code", "codex", "omp"] {
        for command in &commands {
            assert_ne!(
                action(&home, harness, command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn links_leaving_or_entering_install_roots_keep_review() {
    let (_cleanup, home) = home("links");
    for command in [
        format!("cat ~/{BUN_MODULES}/linked/config"),
        format!("cat ~/{BUN_MODULES}/linked/id_ed25519"),
        format!("grep -rn Host ~/{BUN_MODULES}/linked"),
        "cat ~/.local/linked-lib/python3.12/site-packages/pkg/mod.py".to_owned(),
    ] {
        assert_ne!(action(&home, "codex", &command), "allow", "{command}");
    }
}

#[test]
fn writes_into_install_roots_keep_review() {
    let (_cleanup, home) = home("writes");
    for command in [
        format!("cp src/main.py ~/{USER_PACKAGE}/mod.py"),
        format!("echo X = 2 > ~/{USER_PACKAGE}/mod.py"),
        format!("sed -i s/X/Y/ ~/{USER_PACKAGE}/mod.py"),
        format!("touch ~/{BUN_MODULES}/vite/index.js"),
        format!("rm ~/{USER_PACKAGE}/mod.py"),
        format!("mv ~/{USER_PACKAGE}/mod.py src/mod.py"),
        format!("tee ~/{CRATE_SOURCE}/lib.rs"),
    ] {
        for harness in ["claude-code", "codex", "omp"] {
            assert_ne!(
                action(&home, harness, &command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}

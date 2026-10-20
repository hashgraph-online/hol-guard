//! Searching a scratch checkout below the shared temporary directory from
//! another workspace. Test vectors named for credentials are data a test
//! reads, so they do not hold the search; real key files and credential
//! stores still do.
#![cfg(unix)]
use crate::git_helper_fixture as fixture;
use fixture::*;
use serde_json::json;
use std::path::{Path, PathBuf};

struct Bench {
    _cleanup: FixtureCleanup,
    home: PathBuf,
    workspace: PathBuf,
    crates: PathBuf,
}

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

fn bench(tag: &str) -> Bench {
    let root = std::fs::canonicalize("/tmp").unwrap().join(format!(
        "guard-rg-bench-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let home = root.join("home");
    let workspace = home.join("project");
    let checkout = root.join("bench");
    let crates = checkout.join("rust/crates");
    std::fs::create_dir_all(&workspace).unwrap();
    write(
        &checkout.join(".gitignore"),
        "target/\n.env*\n!.env.example\n",
    );
    write(&crates.join("router/src/lib.rs"), "pub enum Route {}\n");
    write(
        &crates.join("runtime/testdata/secrets_cli/secrets_cli_vectors.json"),
        "{\"cases\":[]}\n",
    );
    write(
        &crates.join("runtime/testdata/secret_store_oracle.json"),
        "{}\n",
    );
    write(
        &crates.join("command/tests/fixtures/sfrs/intermediate_tokens.json"),
        "[]\n",
    );
    assert!(std::process::Command::new("git")
        .args(["init", "--quiet"])
        .arg(&checkout)
        .env("HOME", &home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap()
        .success());
    Bench {
        _cleanup: FixtureCleanup(root),
        home,
        workspace,
        crates,
    }
}

fn decide(bench: &Bench, command: &str) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "codex",
        "PreToolUse",
        &json!({"tool_name":"Bash", "tool_input":{"command":command}}),
        None,
        None,
        bench.home.to_str(),
        bench.workspace.to_str(),
    )
}

#[test]
fn rg_over_a_temporary_checkout_with_test_vectors_is_quiet() {
    let bench = bench("vectors");
    let crates = bench.crates.display();
    for command in [
        format!(
            r#"rg -n "enum Route\b|enum BridgeRoute|Delegate\b.*=>|Handoff\b" {crates} --type rust -l | head -30"#
        ),
        format!("rg -n Route {crates}"),
        format!("rg -l secrets_cli {crates}"),
    ] {
        let result = decide(&bench, &command);
        assert_eq!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}

#[test]
fn rg_over_a_temporary_checkout_keeps_real_credentials_reviewed() {
    let bench = bench("stores");
    let crates = bench.crates.display();
    let search = format!("rg -n Route {crates} --type rust -l | head -30");
    for (file, contents) in [
        ("runtime/secrets/prod.json", "{}\n"),
        ("runtime/config/credentials.json", "{}\n"),
        ("runtime/testdata/keys/server.pem", "pem\n"),
        ("runtime/tests/fixtures/deploy.key", "key\n"),
        // The checkout's `.gitignore` re-includes `.env.example`, so `rg`
        // does open this one.
        ("runtime/tests/.env.example", "TOKEN=fixture\n"),
        // A test directory inside a credential directory is still a store.
        ("runtime/secrets/tests/prod.json", "{}\n"),
        ("runtime/credentials/fixtures/aws.json", "{}\n"),
    ] {
        let path = bench.crates.join(file);
        write(&path, contents);
        let result = decide(&bench, &search);
        assert_ne!(
            result.minimum_action, "allow",
            "{file}: {}",
            result.reason_code
        );
        std::fs::remove_file(&path).unwrap();
    }
    // A hidden file no rule re-includes is one `rg` never opens, so it does
    // not hold the search.
    let npmrc = bench.crates.join("runtime/tests/.npmrc");
    write(&npmrc, "registry\n");
    assert_eq!(
        decide(&bench, &search).minimum_action,
        "allow",
        "runtime/tests/.npmrc"
    );
    std::fs::remove_file(&npmrc).unwrap();
    // So is a search rooted in a credential directory.
    write(&bench.crates.join("secrets/tests/prod.json"), "{}\n");
    let rooted = format!("rg -n Route {crates}/secrets");
    let result = decide(&bench, &rooted);
    assert_ne!(
        result.minimum_action, "allow",
        "{rooted}: {}",
        result.reason_code
    );
    std::fs::remove_dir_all(bench.crates.join("secrets")).unwrap();
    for command in [
        format!("rg --pre cat Route {crates}"),
        format!("rg --pre-glob '*.json' --pre cat Route {crates}"),
        format!("RIPGREP_CONFIG_PATH={crates}/rc rg Route {crates}"),
        format!("rg --hidden Route {crates}"),
        format!("rg -L Route {crates}"),
    ] {
        let result = decide(&bench, &command);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}

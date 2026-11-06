//! Cargo's local verbs compile and test inside the workspace sandbox; the
//! verbs that reach a registry keep the admission they have. A host without
//! the sandbox, such as Windows, keeps the admission for local verbs too.
use crate::pretool::workspace_contained_tests::{controls, host, workspace, CONTAINED};

const MANIFEST: &str =
    "[package]\nname = \"app-portal\"\nversion = \"0.1.0\"\nedition = \"2021\"\n";
const LOCKFILE: &str = "version = 3\n\n[[package]]\nname = \"app-portal\"\nversion = \"0.1.0\"\n";

fn outcome(harness: &str, command: &str, cwd: &std::path::Path) -> (String, String) {
    let controls = controls();
    let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
        Some(&controls),
        None,
        Some("/Users/nobody"),
        cwd.to_str(),
    );
    (result.reason_code, result.minimum_action)
}

/// A checkout that is a Cargo package.
fn package(name: &str) -> std::path::PathBuf {
    let ws = workspace(name, true);
    std::fs::write(ws.join("Cargo.toml"), MANIFEST).unwrap();
    std::fs::write(ws.join("Cargo.lock"), LOCKFILE).unwrap();
    ws
}

#[test]
fn cargo_builds_and_tests_the_package_inside_the_sandbox() {
    let ws = package("cargo-local");
    for command in [
        "cargo check",
        "cargo check --locked",
        "cargo check 2>&1 | tail -15",
        "cargo check --locked --offline 2>&1 | tail -15",
        "cargo build --locked",
        "cargo test --locked --offline",
        "cargo clippy --all-targets",
        "cargo fmt --check",
        "cargo +nightly fmt",
        "cargo run --bin app-portal",
        "cargo doc --no-deps",
        "cargo tree --depth 1",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_eq!(reason == CONTAINED, host(), "{reason} {harness}: {command}");
            if !host() {
                assert_eq!(
                    minimum, "review",
                    "{reason}: no sandbox must require review"
                );
            }
        }
    }
}

/// A subcommand cargo resolves to a `cargo-NAME` program drives cargo's own
/// build of this workspace: a coverage run of the suite, a snapshot suite, an
/// expansion, a read of the dependencies the crate declares. Each reaches no
/// further than `cargo test` already does, so each is contained with it.
#[test]
fn the_named_workspace_subcommands_run_inside_the_sandbox_too() {
    let ws = package("cargo-subcommands");
    for command in [
        "cargo llvm-cov --lcov --output-path lcov.info",
        "cargo llvm-cov nextest",
        "cargo tarpaulin --out Xml",
        "cargo insta test",
        "cargo expand --lib",
        "cargo machete",
        "cargo udeps --workspace",
        "cargo mutants",
        "cargo mutants --in-place",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_eq!(reason == CONTAINED, host(), "{reason} {harness}: {command}");
            if !host() {
                assert_eq!(
                    minimum, "review",
                    "{reason}: no sandbox must require review"
                );
            }
        }
    }
}

/// A name cargo has no program for is a program cargo would go and find, so a
/// subcommand this module does not name keeps the review it has.
#[test]
fn an_unnamed_subcommand_keeps_its_review() {
    let ws = package("cargo-unnamed");
    for command in [
        "cargo audit",
        "cargo deny check",
        "cargo fetch-the-world",
        "cargo generate --git https://example.test/template",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
}

#[test]
fn the_registry_verbs_and_a_bare_directory_keep_their_review() {
    let ws = package("cargo-registry");
    for command in [
        "cargo install cargo-nextest",
        "cargo add serde",
        "cargo update",
        "cargo publish --dry-run",
        "cargo fetch",
        "cargo vendor",
        "cargo check && cargo add serde",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
    // Without a manifest cargo searches upward, out of the workspace the
    // sandbox holds.
    let bare = workspace("cargo-bare", true);
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, _) = outcome(harness, "cargo check", &bare);
        assert_ne!(reason, CONTAINED, "{harness}");
    }
}

/// Which package a verb compiles moves with a `cd` ahead of it, and the
/// manifest is found the way cargo finds it: from the directory the command
/// enters, then upward to the workspace root. A member directory holds its
/// own manifest, and one that holds none still compiles against the root's.
#[test]
fn the_package_a_verb_compiles_moves_with_the_command() {
    let ws = package("cargo-nested");
    std::fs::create_dir_all(ws.join("crates/engine")).unwrap();
    std::fs::write(ws.join("crates/engine/Cargo.toml"), MANIFEST).unwrap();
    std::fs::create_dir_all(ws.join("docs")).unwrap();
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, minimum) = outcome(harness, "cd crates/engine && cargo test --offline", &ws);
        assert_eq!(reason == CONTAINED, host(), "{reason} {harness}");
        if !host() {
            assert_eq!(
                minimum, "review",
                "{reason}: no sandbox must require review"
            );
        }
        let (reason, minimum) = outcome(harness, "cd docs && cargo test", &ws);
        assert_eq!(reason == CONTAINED, host(), "{reason} {harness}");
        if !host() {
            assert_eq!(
                minimum, "review",
                "{reason}: no sandbox must require review"
            );
        }
    }
}

/// `--manifest-path` names the package outright, so a workspace whose crate
/// sits in a subdirectory builds from the root. The manifest must be a
/// `Cargo.toml` the workspace holds; anything else keeps its review.
#[test]
fn a_manifest_path_inside_the_workspace_compiles_that_package() {
    let ws = workspace("cargo-manifest", true);
    std::fs::create_dir_all(ws.join("rust")).unwrap();
    std::fs::write(ws.join("rust/Cargo.toml"), MANIFEST).unwrap();
    std::fs::write(ws.join("rust/notes.toml"), MANIFEST).unwrap();
    let absolute = format!(
        "cargo test --manifest-path {} -p app-portal -- --exact",
        ws.join("rust/Cargo.toml").display()
    );
    for command in [
        "cargo test --manifest-path rust/Cargo.toml -p app-portal",
        "cargo check --manifest-path=rust/Cargo.toml",
        absolute.as_str(),
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_eq!(reason == CONTAINED, host(), "{reason} {harness}: {command}");
            if !host() {
                assert_eq!(minimum, "review", "{reason}: {command}");
            }
        }
    }
    for command in [
        "cargo test --manifest-path rust/notes.toml",
        "cargo test --manifest-path rust/missing/Cargo.toml",
        "cargo test --manifest-path rust/../rust/Cargo.toml",
        "cargo test --manifest-path rust/Cargo.toml --manifest-path rust/Cargo.toml",
        "cargo test --manifest-path=",
        "cargo test --manifest-path",
        "cargo install --manifest-path rust/Cargo.toml",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
}

/// Cargo's own options stand in front of the verb, and the ones that only
/// say how it reports, or how strictly it treats the lockfile and the
/// network, leave the verb the verb it was.
#[test]
fn an_option_in_front_of_the_verb_leaves_the_work_it_names() {
    let ws = package("cargo-global-options");
    for command in [
        "cargo --offline test",
        "cargo -q test",
        "cargo --quiet test",
        "cargo -v build",
        "cargo -vv build",
        "cargo --verbose check",
        "cargo --locked --offline test",
        "cargo --frozen build",
        "cargo --color always test",
        "cargo --color=never test",
        "cargo +nightly --offline test",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_eq!(reason == CONTAINED, host(), "{reason} {harness}: {command}");
            if !host() {
                assert_eq!(minimum, "review", "{reason}: {command}");
            }
        }
    }
}

/// An option that chooses a config key, an unstable flag or another
/// directory decides what the run resolves and where, which is what the
/// admission rests on; and reading past an inert one never turns a registry
/// verb into local work.
#[test]
fn an_option_that_decides_what_the_run_reads_keeps_its_review() {
    let ws = package("cargo-global-options-refused");
    for command in [
        "cargo --config build.rustc-wrapper=\"sccache\" test",
        "cargo --config=net.offline=false test",
        "cargo -Z unstable-options test",
        "cargo -Zscript test",
        "cargo -C crates/engine test",
        "cargo --color test",
        "cargo --offline install cargo-nextest",
        "cargo -q add serde",
        "cargo --locked update",
        "cargo --offline publish --dry-run",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
}

/// A subcommand cargo resolves to its own program may carry its own
/// directory option, and that option moves the whole run: `cargo-mutants`
/// builds, tests and rewrites the sources of the crate `-d`/`--dir` names,
/// and `cargo-tarpaulin` builds and tests the one under `-r`/`--root`. A
/// crate the workspace holds stays contained; one outside it, or a line that
/// leaves no one directory to judge, keeps its review.
#[test]
fn a_subcommand_directory_option_is_read_against_the_workspace() {
    let ws = package("cargo-subcommand-directory");
    std::fs::create_dir_all(ws.join("crates/engine")).unwrap();
    std::fs::write(ws.join("crates/engine/Cargo.toml"), MANIFEST).unwrap();
    let outside = std::env::temp_dir().join(format!(
        "guard-outside-{}-cargo-subcommand-directory",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("Cargo.toml"), MANIFEST).unwrap();
    let outside = outside.canonicalize().unwrap();

    for command in [
        "cargo mutants -d crates/engine",
        "cargo mutants --dir crates/engine --in-place",
        "cargo mutants --dir=crates/engine",
        "cargo mutants -dcrates/engine",
        "cargo tarpaulin --root crates/engine --out Xml",
        "cargo tarpaulin --root=crates/engine",
        "cargo tarpaulin -r crates/engine",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_eq!(reason == CONTAINED, host(), "{reason} {harness}: {command}");
            if !host() {
                assert_eq!(minimum, "review", "{reason}: {command}");
            }
        }
    }

    let escapes = [
        format!("cargo mutants -d {} --in-place", outside.display()),
        format!("cargo mutants --dir={}", outside.display()),
        format!("cargo mutants -d{}", outside.display()),
        format!("cargo tarpaulin --root {} --out Xml", outside.display()),
        format!("cargo tarpaulin -r{}", outside.display()),
        "cargo mutants -d ../".to_owned(),
        "cargo mutants -d crates/../crates/engine".to_owned(),
        "cargo mutants -d crates/missing".to_owned(),
        "cargo mutants -d docs".to_owned(),
        "cargo mutants --dir crates/engine --dir crates/engine".to_owned(),
        "cargo mutants --dir=".to_owned(),
        "cargo mutants --dir".to_owned(),
    ];
    std::fs::create_dir_all(ws.join("docs")).unwrap();
    for command in &escapes {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
    let _ = std::fs::remove_dir_all(&outside);
}

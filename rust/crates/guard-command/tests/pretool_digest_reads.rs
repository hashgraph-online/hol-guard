#![cfg(unix)]
//! Digest printers over files an agent has just built or downloaded.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// A home holding one project with built artifacts beside its sources, and the
/// private key a digest has no business reaching. The root stays below the
/// target directory: `$TMPDIR` on macOS resolves under `/private/var`, which
/// the sensitive-root screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-digest-reads")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let home = root.join("home");
    let project = home.join("project");
    write(project.join("README.md"), "# Fixture\n");
    write(project.join("dist/app.whl"), "synthetic wheel\n");
    write(project.join("dist/app.tar.gz"), "synthetic archive\n");
    write(project.join("checksums.txt"), "0  dist/app.whl\n");
    write(home.join(".ssh/id_ed25519"), "SYNTHETIC KEY\n");
    std::fs::canonicalize(home).unwrap()
}

/// The decision both shell harnesses reach, or "mixed" when they differ.
fn shell(home: &Path, command: &str) -> String {
    let project = home.join("project");
    let [omp, zcode] = ["omp", "zcode"].map(|harness| {
        evaluate_pre_tool_envelope_with_execution_context(
            harness,
            "PreToolUse",
            &json!({"tool_name": "bash", "tool_input": {"command": command}}),
            None,
            None,
            PathContext {
                home_dir: home.to_str(),
                cwd: project.to_str(),
                cdpath_unset: false,
                rustup_override_absent: false,
                npm_config_inert: false,
                pip_config_inert: false,
                shell_home_matches: false,
                ripgrep_config_absent: false,
                psql_environment: Default::default(),
            },
            None,
        )
        .minimum_action
    });
    if omp == zcode {
        omp
    } else {
        format!("mixed: omp {omp}, zcode {zcode}")
    }
}

#[test]
fn digests_of_named_files_proceed() {
    let home = home();
    for command in [
        "shasum -a 256 dist/app.whl",
        "shasum -a256 dist/app.whl dist/app.tar.gz",
        "sha256sum dist/app.whl",
        "sha256sum --tag dist/app.whl",
        "sha256sum -- dist/app.whl",
        "md5sum README.md",
        "sha512sum -b dist/app.tar.gz",
        "sha1sum dist/app.whl dist/app.tar.gz",
        "cksum README.md",
        "sha256sum dist/app.whl | tail -1",
    ] {
        assert_eq!(shell(&home, command), "allow", "{command}");
    }
}

#[test]
fn digests_that_reach_further_keep_their_review() {
    let home = home();
    for command in [
        // `-c` opens every file the list names, which no operand screened.
        "sha256sum -c checksums.txt",
        "shasum -a 256 --check checksums.txt",
        "sha256sum --ignore-missing -c checksums.txt",
        // The operand is a string the shell builds, not a path to screen.
        "md5 -s secret",
        "sha256sum $(cat checksums.txt)",
        // Nothing stands in for the operands the proof needs.
        "sha256sum",
        // BSD `md5 -p` copies standard input through, so a screened operand
        // does not cover everything the command prints.
        "md5 -p README.md",
    ] {
        assert_eq!(shell(&home, command), "review", "{command}");
    }
}

/// A private key is not a build artifact to fingerprint. Whether the secret
/// screens hold it at a review or block it outright is their call; the digest
/// proof must not let it through.
#[test]
fn digests_of_a_private_key_do_not_proceed() {
    let home = home();
    for command in [
        "shasum -a 256 ~/.ssh/id_ed25519",
        "sha256sum ~/.ssh/id_ed25519",
    ] {
        assert_ne!(shell(&home, command), "allow", "{command}");
    }
}

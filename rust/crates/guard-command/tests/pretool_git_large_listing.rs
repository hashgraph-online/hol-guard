// Creating this many files is slow on Windows runners; the limits are shared.
#![cfg(not(windows))]
use crate::git_helper_fixture as fixture;
use fixture::*;
use serde_json::json;

const FILES: usize = 16_000;

fn status(harness: &str, home: &std::path::Path, repository: &std::path::Path) -> (String, String) {
    let result = evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":"git status --short"}}),
        Some(&github_controls("enabled")),
        None,
        home.to_str(),
        repository.to_str(),
    );
    (result.decision, result.reason_code)
}

// An exclusive root, so a directory left by an interrupted run is never reused.
fn unique_root() -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    for attempt in 0.. {
        let root = std::env::temp_dir().join(format!(
            "guard large listing {}-{nonce}-{attempt}",
            std::process::id()
        ));
        match std::fs::create_dir(&root) {
            Ok(()) => return root,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("failed to create fixture root: {error}"),
        }
    }
    unreachable!()
}

// Fixture Git commands ignore any repository, index or config overrides
// inherited from the test process.
fn git(home: &std::path::Path, repository: &std::path::Path) -> std::process::Command {
    let mut command = std::process::Command::new("git");
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("GIT_") {
            command.env_remove(name);
        }
    }
    command
        .arg("-C")
        .arg(repository)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1");
    command
}

// A globally installed filter (Git LFS defines one) makes the probe list every
// tracked and untracked path. A large checkout must not exceed the listing
// limits, while a filter attached to any of its paths still needs review.
#[test]
fn large_repository_reads_stay_proven_with_a_global_filter() {
    let root = unique_root();
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let repository = root.join("repository");
    let files = repository.join("generated");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&files).unwrap();
    std::fs::write(
        home.join(".gitconfig"),
        "[filter \"synthetic\"]\n\tclean = false\n\tsmudge = false\n\trequired = true\n",
    )
    .unwrap();
    let padding = "p".repeat(90);
    for index in 0..FILES {
        std::fs::write(files.join(format!("{index:05}-{padding}.txt")), "").unwrap();
    }
    for arguments in [&["init", "--quiet"][..], &["add", "--all"][..]] {
        assert!(git(&home, &repository)
            .args(arguments)
            .status()
            .unwrap()
            .success());
    }
    let staged = git(&home, &repository)
        .args(["ls-files", "--stage", "-z"])
        .output()
        .unwrap();
    assert!(
        staged.stdout.len() > 2 * 1024 * 1024,
        "the fixture must exceed the former listing limits"
    );
    for harness in ["omp", "zcode"] {
        let (decision, reason) = status(harness, &home, &repository);
        assert_eq!(decision, "allow", "{harness}: {reason}");
    }
    std::fs::write(
        repository.join(".gitattributes"),
        format!("generated/15999-{padding}.txt filter=synthetic\n"),
    )
    .unwrap();
    for harness in ["omp", "zcode"] {
        assert_eq!(
            status(harness, &home, &repository),
            ("deny".into(), "native_git_execution_context_review".into()),
            "{harness}"
        );
    }
}

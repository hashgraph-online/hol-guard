use crate::git_helper_fixture as fixture;
use fixture::*;
use serde_json::json;

fn decide(
    harness: &str,
    command: &str,
    home: &std::path::Path,
    repository: &std::path::Path,
) -> String {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&github_controls("enabled")),
        None,
        home.to_str(),
        repository.to_str(),
    )
    .decision
}

#[test]
fn hash_object_reads_are_allowed_and_writes_stay_reviewed() {
    // Keep the fixture outside the system temporary directory: file reads
    // below /private/var are not proven bounded.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/git-hash-object")
        .join(std::process::id().to_string());
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    let repository = root.join("repository");
    let _cleanup = FixtureCleanup(root.clone());
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(repository.join("src")).unwrap();
    assert!(std::process::Command::new("git")
        .args(["init", "--quiet"])
        .arg(&repository)
        .status()
        .unwrap()
        .success());
    std::fs::write(repository.join("src/main.rs"), "fn main() {}\n").unwrap();
    std::fs::write(repository.join("Cargo.toml"), "[package]\n").unwrap();
    std::fs::write(repository.join(".env"), "SYNTHETIC=1\n").unwrap();
    std::fs::write(repository.join("src/filtered.bin"), "synthetic\n").unwrap();
    std::fs::write(home.join("notes.txt"), "synthetic\n").unwrap();
    std::fs::write(
        repository.join(".gitattributes"),
        "*.bin filter=synthetic\n",
    )
    .unwrap();
    let config = repository.join(".git/config");
    for (settings, command, expected) in [
        ("", "git hash-object src/main.rs", "allow"),
        ("", "git hash-object src/main.rs Cargo.toml", "allow"),
        ("", "git hash-object -t blob -- src/main.rs", "allow"),
        ("", "git hash-object --no-filters src/main.rs", "allow"),
        ("", "git -C . hash-object src/main.rs", "allow"),
        ("", "git hash-object -w src/main.rs", "review"),
        ("", "git hash-object --stdin < src/main.rs", "review"),
        ("", "git hash-object --stdin-paths", "review"),
        ("", "git hash-object --literally src/main.rs", "review"),
        (
            "",
            "git hash-object --path=src/main.rs Cargo.toml",
            "review",
        ),
        ("", "git hash-object -t bogus src/main.rs", "review"),
        ("", "git hash-object", "review"),
        ("", "git hash-object .env", "review"),
        ("", "git hash-object ../outside", "review"),
        ("", "git hash-object src", "review"),
        ("", "git hash-object ~/.ssh/id_ed25519", "review"),
        ("", "git hash-object :src/main.rs", "review"),
        ("", "git hash-object ~/notes.txt", "review"),
        // A configured clean filter is a program. It runs only for a named
        // file whose attributes select it, unless --no-filters disables it.
        (
            "[filter \"synthetic\"]\nclean = ./synthetic-never-execute\n",
            "git hash-object src/main.rs",
            "allow",
        ),
        (
            "[filter \"synthetic\"]\nclean = ./synthetic-never-execute\n",
            "git hash-object Cargo.toml src/main.rs",
            "allow",
        ),
        (
            "[filter \"synthetic\"]\nclean = ./synthetic-never-execute\n",
            "git hash-object src/filtered.bin",
            "deny",
        ),
        (
            "[filter \"synthetic\"]\nclean = ./synthetic-never-execute\n",
            "git hash-object src/main.rs src/filtered.bin",
            "deny",
        ),
        (
            "[filter \"synthetic\"]\nclean = ./synthetic-never-execute\n",
            "git hash-object --no-filters src/filtered.bin",
            "allow",
        ),
        (
            "",
            "git -c filter.synthetic.clean=./synthetic-never-execute hash-object src/filtered.bin",
            "review",
        ),
    ] {
        std::fs::write(&config, settings).unwrap();
        for harness in ["omp", "zcode"] {
            let decision = decide(harness, command, &home, &repository);
            if expected == "review" {
                assert_ne!(decision, "allow", "{harness}: {command}: {settings}");
            } else {
                assert_eq!(decision, expected, "{harness}: {command}: {settings}");
            }
        }
    }
}

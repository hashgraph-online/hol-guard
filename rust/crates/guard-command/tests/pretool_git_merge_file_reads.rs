//! `git merge-file -p` prints a three-way merge of three files and writes
//! none of them. Agents run it to preview how two edits of one file combine,
//! and it was held for review in every spelling. The printing form is now a
//! read of its three files; the writing form and every spelling that reaches
//! past those files keep their review.

use crate::git_helper_fixture as fixture;
use fixture::*;
use serde_json::json;

const HARNESSES: &[&str] = &["omp", "zcode", "codex", "claude-code"];

fn decide(
    harness: &str,
    command: &str,
    home: &std::path::Path,
    repository: &std::path::Path,
) -> (String, String) {
    let result = evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&github_controls("enabled")),
        None,
        home.to_str(),
        repository.to_str(),
    );
    (result.decision, result.reason_code)
}

/// The root lives under `target/`: on macOS `$TMPDIR` resolves into a
/// location the sensitive-root screen refuses, which would decide the `allow`
/// cases for a reason of its own. The cleanup guard exists before the first
/// write, so a failed setup removes what it made.
fn repository_fixture(name: &str) -> (FixtureCleanup, std::path::PathBuf, std::path::PathBuf) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-git-merge-file-reads")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let cleanup = FixtureCleanup(std::fs::canonicalize(&root).unwrap());
    let home = cleanup.0.join("home");
    let repository = cleanup.0.join("repository");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::create_dir_all(repository.join("src")).unwrap();
    std::fs::create_dir_all(repository.join("vendor/src")).unwrap();
    std::fs::create_dir_all(repository.join("lib/src")).unwrap();
    assert!(std::process::Command::new("git")
        .args(["init", "--quiet"])
        .arg(&repository)
        .status()
        .unwrap()
        .success());
    for side in ["ours", "base", "theirs"] {
        for directory in ["src", "lib/src"] {
            std::fs::write(
                repository.join(format!("{directory}/{side}.ts")),
                format!("export const side = \"{side}\";\n"),
            )
            .unwrap();
        }
    }
    std::fs::write(home.join(".ssh/id_ed25519"), "not a key\n").unwrap();
    // `vendor/src/ours.ts` names the private key. The workspace file of the
    // same relative name is ordinary, so only a screen run in the directory
    // `-C` selects sees the link.
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        home.join(".ssh/id_ed25519"),
        repository.join("vendor/src/ours.ts"),
    )
    .unwrap();
    for side in ["base", "theirs"] {
        std::fs::write(repository.join(format!("vendor/src/{side}.ts")), "x\n").unwrap();
    }
    (cleanup, home, repository)
}

#[test]
fn a_printing_three_way_merge_is_a_read_and_the_writing_merge_stays_reviewed() {
    let (_cleanup, home, repository) = repository_fixture("merge-file");
    let key = home.join(".ssh/id_ed25519");
    let key = key.display();
    for (command, expected) in [
        ("git merge-file -p src/ours.ts src/base.ts src/theirs.ts".to_owned(), "allow"),
        ("git merge-file --stdout src/ours.ts src/base.ts src/theirs.ts | head -40".to_owned(), "allow"),
        (
            "git merge-file -p --diff3 -L ours -L base -L theirs src/ours.ts src/base.ts src/theirs.ts".to_owned(),
            "allow",
        ),
        (
            "git merge-file -q -p --zdiff3 --marker-size=9 src/ours.ts src/base.ts src/theirs.ts; echo $?".to_owned(),
            "allow",
        ),
        // Without `-p` the merge is written over the first file.
        ("git merge-file src/ours.ts src/base.ts src/theirs.ts".to_owned(), "review"),
        ("git merge-file --diff3 src/ours.ts src/base.ts src/theirs.ts".to_owned(), "review"),
        // A private file is not one this read may print.
        (format!("git merge-file -p {key} src/base.ts src/theirs.ts"), "review"),
        // Object ids read the object store, and two files are no merge.
        ("git merge-file -p --object-id HEAD:a HEAD:b HEAD:c".to_owned(), "review"),
        ("git merge-file -p src/ours.ts src/base.ts".to_owned(), "review"),
        ("git merge-file -p src/ours.ts ../base.ts src/theirs.ts".to_owned(), "review"),
        // Git opens the files in the directory `-C` selects, so they are
        // screened there.
        ("git -C lib merge-file -p src/ours.ts src/base.ts src/theirs.ts".to_owned(), "allow"),
        #[cfg(unix)]
        ("git -C vendor merge-file -p src/ours.ts src/base.ts src/theirs.ts".to_owned(), "review"),
        ("git --git-dir=.git merge-file -p src/ours.ts src/base.ts src/theirs.ts".to_owned(), "review"),
    ] {
        for harness in HARNESSES {
            let (decision, reason_code) = decide(harness, &command, &home, &repository);
            if expected == "review" {
                assert_ne!(decision, "allow", "{harness}: {command}: {reason_code}");
            } else {
                assert_eq!(decision, expected, "{harness}: {command}: {reason_code}");
            }
        }
    }
}

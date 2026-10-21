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
fn branch_listing_is_allowed_and_mutation_stays_reviewed() {
    let root = std::env::temp_dir().join(format!("guard-git-branch-{}", std::process::id()));
    let home = root.join("home");
    let repository = root.join("repository");
    let _cleanup = FixtureCleanup(root.clone());
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&repository).unwrap();
    assert!(std::process::Command::new("git")
        .args(["init", "--quiet"])
        .arg(&repository)
        .status()
        .unwrap()
        .success());
    let config = repository.join(".git/config");
    for (settings, command, expected) in [
        ("", "git branch", "allow"),
        ("", "git branch --list", "allow"),
        ("", "git branch -a", "allow"),
        ("", "git branch -r", "allow"),
        ("", "git branch -vv", "allow"),
        ("", "git branch -avv", "allow"),
        ("", "git branch -avv && kubectl get namespaces", "allow"),
        ("", "git branch -ad main", "review"),
        (
            "",
            "git branch -avD main && kubectl get namespaces",
            "review",
        ),
        ("", "git branch --show-current", "allow"),
        ("", "git branch --list 'feat/*'", "allow"),
        ("", "git --no-pager branch --list", "allow"),
        ("", "git branch --list | cat", "allow"),
        ("", "git branch new-feature", "review"),
        ("", "git branch -D main", "review"),
        ("", "git branch -d main", "review"),
        ("", "git branch -m old new", "allow"),
        ("", "git branch -c old new", "review"),
        ("", "git branch -f main HEAD", "review"),
        ("", "git branch --set-upstream-to=origin/main", "review"),
        ("", "git branch -u origin/main", "review"),
        ("", "git branch --edit-description", "review"),
        ("", "git branch --format='%(refname)'", "review"),
        ("", "git branch feat/* --list", "review"),
        // Leading overrides and configured helpers keep the listing reviewed.
        (
            "",
            "git -c core.pager=./synthetic-never-execute branch --list",
            "review",
        ),
        (
            "",
            "git -c pager.branch=./synthetic-never-execute branch",
            "review",
        ),
        (
            "[core]\npager = ./synthetic-never-execute\n",
            "git branch --list",
            "deny",
        ),
        (
            "[pager]\nbranch = ./synthetic-never-execute\n",
            "git branch --list",
            "deny",
        ),
        (
            "[core]\npager = ./synthetic-never-execute\n",
            "git --no-pager branch --list",
            "allow",
        ),
        (
            "[core]\npager = ./synthetic-never-execute\n",
            "git branch --list | cat",
            "allow",
        ),
        ("[column]\nui = always\n", "git branch --list", "allow"),
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

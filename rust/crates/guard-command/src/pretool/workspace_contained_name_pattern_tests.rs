//! A search that leaves Git's metadata out of its walk by name.
//!
//! The tree holds a `.env`, so no read-only proof admits a recursive search
//! of it and the workspace sandbox is the route these commands take. Each one
//! names `.git` only as a pattern to skip.

use super::workspace_contained_tests::{reason, workspace, CONTAINED};

fn searchable(name: &str) -> std::path::PathBuf {
    let ws = workspace(name, true);
    std::fs::create_dir_all(ws.join("src")).unwrap();
    std::fs::write(
        ws.join("src/lib.py"),
        "def match_case(word):\n    return word\n",
    )
    .unwrap();
    std::fs::write(ws.join(".env"), "API_TOKEN=fixture\n").unwrap();
    ws
}

#[test]
fn a_search_that_skips_git_metadata_by_name_runs_in_the_workspace_sandbox() {
    let ws = searchable("git-name-pattern");
    // The same search without the exclusion is the baseline: naming `.git`
    // only to skip it must take the route the plain walk takes. Linux CI's
    // bubblewrap does not contain every harness's plain walk, so the route is
    // asserted outright only on macOS, where Seatbelt always runs.
    let baseline = "grep -rn match_case .";
    for command in [
        "grep -RIn --exclude-dir=.git 'match_case(' .",
        "grep -RInE --exclude-dir=.git '(^|[^[:alnum:]_-])match_case([^[:alnum:]_-]|$)' . || true",
        "grep -rn --exclude-dir=.git --exclude-dir=node_modules match_case .",
        "find . -type f -not -path './.git/*' -print0 | xargs -0 grep -l match_case",
        "find . -path ./.git -prune -o -type f -print0 | xargs -0 grep -l match_case",
        "find . -type f ! -path '*/.git/*' -name '*.py' -print0 | xargs -0 grep -n match_case",
    ] {
        for harness in ["codex", "omp"] {
            let route = reason(harness, baseline, &ws, true);
            if cfg!(target_os = "macos") {
                assert_eq!(route, CONTAINED, "{harness}: {baseline}");
            }
            assert_eq!(
                reason(harness, command, &ws, true),
                route,
                "{harness}: {command}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn a_path_into_git_metadata_still_keeps_the_review() {
    let ws = searchable("git-name-operand");
    for command in [
        // The metadata directory as the walk's root or a file operand.
        "grep -rn match_case .git",
        "find .git -name config",
        "find ./.git/hooks -type f -print0 | xargs -0 grep -l match_case",
        // A separated grep value can be the pattern of an earlier `-e`, which
        // makes the next word a file grep reads.
        "grep -rn --exclude-dir .git/hooks match_case .",
        "grep -n -e --exclude-dir .git/config",
        // `find` tests that open or write their argument.
        "find . -newer .git/HEAD -type f",
        "find . -name '*.py' -fprint .git/hooks/pre-commit",
        // The command `-exec` runs parses its own arguments, so a `-name`
        // there is grep's pattern and the next word a file grep reads.
        "find . -exec grep -e -name .git/HEAD \\;",
        "find . -type f -exec grep -e -name .git/HEAD {} +",
        // Only `grep` reads its name globs; another tool's same option
        // spelling is not a pattern.
        "cp --exclude-dir=.git src/lib.py .git/hooks/pre-commit",
    ] {
        for harness in ["codex", "omp"] {
            assert_ne!(
                reason(harness, command, &ws, true),
                CONTAINED,
                "{harness}: {command}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&ws);
}

//! One `sed` edit fanned out over the files a `find` walk found.
//!
//! `sed -i 's/a/b/g' tests/*.py` runs in the workspace sandbox. Agents apply
//! the same rename across a tree as `find tests -name '*.py' -type f -exec
//! sed -i ... {} +`, and that spelling was held for review: the parser read
//! any `find -exec` outside the read-only fan-out list as running an unknown
//! program. The `sed` form is now modelled exactly and held to the bar the
//! glob form meets. A script that executes commands, a walk that leaves the
//! workspace or is not limited to regular files, or any other program after
//! `-exec`, keeps its review.

use crate::git_helper_fixture as fixture;
use fixture::FixtureCleanup;
use serde_json::json;
use std::path::{Path, PathBuf};

const CONTAINED: (&str, &str) = ("sandbox-required", "native_workspace_containment_required");

fn checkout(label: &str) -> (PathBuf, FixtureCleanup) {
    let root = std::env::temp_dir().join(format!(
        "guard-find-exec-sed-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let project = root.join("project");
    std::fs::create_dir_all(project.join("tests")).unwrap();
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(project.join("tests/test_a.py"), "x._reset()\n").unwrap();
    std::fs::write(project.join("src/a.py"), "X = 1\n").unwrap();
    fixture::git(&root, &project, &["init", "--quiet", "-b", "main"]);
    let root = fixture::canonical_spelling(&root);
    (root.clone(), FixtureCleanup(root))
}

fn outcome(root: &Path, command: &str) -> (String, String) {
    let result = fixture::evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name":"Bash","tool_input":{"command":command}}),
        Some(&fixture::local_admin_controls(Vec::new())),
        None,
        root.to_str(),
        root.join("project").to_str(),
    );
    (result.minimum_action, result.reason_code)
}

#[cfg(unix)]
#[test]
fn a_sed_edit_over_found_files_runs_in_the_workspace_sandbox() {
    let (root, _cleanup) = checkout("edits");
    for command in [
        r#"find tests -name "*.py" -type f -exec sed -i '' 's/\._reset(/._reset_impl(/g' {} \;"#,
        "find tests -name '*.py' -type f -exec sed -i 's/old/new/g' {} +",
        "find src tests -type f -name '*.py' -exec gsed -i -e 's/a/b/' {} +",
        "find . -path ./node_modules -prune -o -type f -name '*.py' -exec sed -i.bak 's/a/b/' {} +",
    ] {
        let (action, reason) = outcome(&root, command);
        assert_eq!((action.as_str(), reason.as_str()), CONTAINED, "{command}");
    }
}

#[test]
fn an_edit_that_would_not_fit_the_sandbox_keeps_its_review() {
    let (root, _cleanup) = checkout("misfits");
    for command in [
        // Extra file operands must not slip past the workspace-wide wipe
        // screen merely because the find walk itself is narrow.
        "find tests -name '*.py' -type f -exec sed -i 'd' ./* {} +",
        "find tests -name '*.py' -type f -exec sed -i 's/a/b/' ../* {} +",
        "find tests -name '*.py' -type f -exec sed -i 's/a/b/' tests/other.py {} +",
        "find tests -name '*.py' -type f -exec sed -i -e 's/a/b/' README.md {} +",
        "find tests -type f -exec sed -i 's/a/b/e' {} +",
        "find tests -type f -exec sed -i -e 'e touch x' {} +",
        "find tests -type f -exec sed -i -f edits.sed {} +",
        "find tests -name '*.py' -exec sed -i 's/a/b/' {} +",
        "find /etc -type f -exec sed -i 's/a/b/' {} +",
        "find . -type f -exec sed -i 's/a/b/' {} +",
        "find tests -type f -exec sed -i 's/a/b/' {} \\; -delete",
        "find tests -type f -exec cp {} /tmp/x \\;",
        "find tests -type f -exec sh -c 'sed -i s/a/b/ \"$1\"' _ {} \\;",
        "find tests -type f -execdir sed -i 's/a/b/' {} +",
        "find tests -type f -exec ./sed -i 's/a/b/' {} +",
    ] {
        let (action, _) = outcome(&root, command);
        assert!(
            action != "allow" && action != "sandbox-required",
            "{command}: {action}"
        );
    }
}

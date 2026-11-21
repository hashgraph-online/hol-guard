//! Git inside the workspace sandbox.
//!
//! Git reads and the writes that stay inside the checkout are the ordinary
//! work the sandbox bounds; the writes that reach the main checkout's own
//! metadata, a hostile configuration, and a conversion of a directory that is
//! not a fresh workspace stay out of it. These read the same route as their
//! neighbours in [`super::workspace_contained_tests`].

use super::workspace_contained_tests::{host, reason, workspace, CONTAINED};

#[test]
fn git_init_converts_only_in_a_fresh_workspace() {
    let fresh = workspace("init", false);
    let existing = workspace("init-existing", true);
    let expected = host();
    assert_eq!(
        reason("omp", "git init", &fresh, true) == CONTAINED,
        expected
    );
    assert_eq!(
        reason("omp", "git init && git add -A", &fresh, true) == CONTAINED,
        expected
    );
    assert_ne!(reason("omp", "git init", &existing, true), CONTAINED);
    assert_ne!(reason("omp", "git init sub", &fresh, true), CONTAINED);
    // Earlier work may precede the init when only `&&` joins them.
    assert_eq!(
        reason(
            "omp",
            "mkdir src && git init -b main && git add -A",
            &fresh,
            true
        ) == CONTAINED,
        expected
    );
    for command in [
        // A prefix runs in its own shell, so shell state cannot carry over.
        "cd src && git init",
        "export NAME=x && git init",
        "true || git init",
        "true; git init",
        "true | git init",
        "git init && mkdir src && git init",
    ] {
        assert_ne!(reason("omp", command, &fresh, true), CONTAINED, "{command}");
    }
}

#[test]
fn hostile_git_configuration_stays_at_review() {
    let ws = workspace("hostile", true);
    std::fs::write(
        ws.join(".git/config"),
        "[core]\n\thooksPath = /outside/hooks\n",
    )
    .unwrap();
    assert_ne!(reason("omp", "./todo.py add x", &ws, true), CONTAINED);
    std::fs::write(
        ws.join(".git/config"),
        "[include]\n\tpath = ../.gitconfig\n",
    )
    .unwrap();
    assert_ne!(reason("omp", "./todo.py add x", &ws, true), CONTAINED);
    std::fs::write(
        ws.join(".git/config"),
        "[core]\n\tfsmonitor = ./tools/mon\n",
    )
    .unwrap();
    let got = reason("omp", "./todo.py add x", &ws, true);
    assert_eq!(got == CONTAINED, host());
}

/// A checkout that turns hooks off with `core.hooksPath = /dev/null` stages
/// and commits inside the sandbox like any other.
#[test]
fn null_hook_directory_keeps_git_writes_contained() {
    let ws = workspace("null-hooks", true);
    std::fs::write(
        ws.join(".git/config"),
        "[core]\n\thooksPath = /dev/null\n[user]\n\tname = dev\n[commit]\n\tgpgsign = false\n",
    )
    .unwrap();
    for command in ["git add src/lib.py", "git add .", "git commit -m x"] {
        assert_eq!(
            reason("omp", command, &ws, true) == CONTAINED,
            host(),
            "{command}"
        );
    }
    std::fs::write(
        ws.join(".git/config"),
        "[core]\n\thooksPath = /dev/null/hooks\n",
    )
    .unwrap();
    assert_ne!(reason("omp", "git add .", &ws, true), CONTAINED);
}

#[test]
fn git_commands_that_write_sandbox_denied_metadata_stay_out_of_the_sandbox() {
    let ws = workspace("git-metadata", true);
    for command in [
        "git worktree add -b report ../report-wt main && ls ../report-wt",
        "mkdir -p .git/worktrees; git worktree add ../wt main",
        "git config user.name Agent && git commit -m x",
        "git remote add origin https://example.com/x.git",
        "git branch -m main trunk",
        "git submodule add ../lib lib",
    ] {
        assert_ne!(reason("omp", command, &ws, true), CONTAINED, "{command}");
    }
}

/// A linked worktree keeps its index, `HEAD`, refs and objects in the main
/// checkout's shared Git directory, which `workspace-contained-v1` grants the
/// run, so ordinary Git there is bounded exactly as it is in a main checkout.
#[test]
fn a_linked_worktree_contains_git_with_its_shared_directory() {
    let root = std::env::temp_dir().join(format!("guard-ws-{}-linked", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (main, tree) = (root.join("main"), root.join("tree"));
    let admin = main.join(".git/worktrees/tree");
    std::fs::create_dir_all(&admin).unwrap();
    std::fs::create_dir_all(&tree).unwrap();
    let (main, tree) = (main.canonicalize().unwrap(), tree.canonicalize().unwrap());
    let admin = admin.canonicalize().unwrap();
    std::fs::write(main.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
    std::fs::write(admin.join("commondir"), "../..\n").unwrap();
    std::fs::write(
        admin.join("gitdir"),
        format!("{}\n", tree.join(".git").display()),
    )
    .unwrap();
    std::fs::write(tree.join(".git"), format!("gitdir: {}\n", admin.display())).unwrap();
    std::fs::write(tree.join("package.json"), "{}").unwrap();
    for command in ["rm notes.txt", "npm run build", "chmod +x scripts/run.sh"] {
        let got = reason("omp", command, &tree, true);
        // A host with a sandbox claims the build with its narrower node
        // build-output profile instead of the general workspace one.
        let narrower =
            command == "npm run build" && got == "native_node_build_output_containment_required";
        assert_eq!(got == CONTAINED || narrower, host(), "{command}");
    }
    // Its index, reflog and objects are the shared Git directory's, which the
    // sandbox grants the run, so these are bounded as in a main checkout.
    for command in [
        "git add -A && git commit -m x",
        "git commit -m init",
        "git stash",
    ] {
        assert_eq!(
            reason("omp", command, &tree, true) == CONTAINED,
            host(),
            "{command}"
        );
    }
    // The shared configuration, hooks and the other worktrees' entries stay
    // write-denied, so Git that has to write one keeps its review.
    for command in [
        "git worktree remove --force ../other",
        "git config user.email agent@example.com",
        "git push origin HEAD",
        // Rebase, sequencer, bisect and squash state are outside the grant.
        "git rebase main",
        "git cherry-pick HEAD~1",
        "git revert --no-edit HEAD",
        "git bisect start",
        "git am -3 fix.patch",
        "git merge --squash main",
    ] {
        assert_ne!(reason("omp", command, &tree, true), CONTAINED, "{command}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

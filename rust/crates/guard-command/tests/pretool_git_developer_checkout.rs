#![cfg(unix)]

//! A developer's checkout carries more than a bare `git init` fixture: an SSH
//! remote, a pruning fetch and a hook manager that points `core.hooksPath` at a
//! directory of the repository. Git's own hook lookup decides what those can
//! run, so an executable shim that stops at once is not a program to review.

use crate::pretool_git_session_ops::{executable_hook, git, session, Session};
use std::os::unix::fs::{symlink, PermissionsExt};

const ADD: &str = "native_exact_safe_worktree_add";
const REFRESH: &str = "native_exact_safe_git_origin_refresh";
const WRITE: &str = "native_exact_safe_git_local_write";
const HOOKS: [&str; 5] = [
    "post-checkout",
    "post-index-change",
    "reference-transaction",
    "pre-auto-gc",
    "post-fetch",
];
const SHIM: &str = "#!/usr/bin/env sh\n. \"$(dirname \"$0\")/h\"\n";
const RUNNER: &str = "#!/usr/bin/env sh\n[ \"$HUSKY\" = \"2\" ] && set -x\nn=$(basename \"$0\")\ns=$(dirname \"$(dirname \"$0\")\")/$n\n\n[ ! -f \"$s\" ] && exit 0\n\nsh -e \"$s\" \"$@\"\n";

/// Husky 9 keeps its shims below `.husky/_` and sets `core.hooksPath` to it.
fn husky(session: &Session, hooks: &[&str]) -> std::path::PathBuf {
    husky_at(session, &session.primary, hooks)
}

/// The same directory in another working tree of the repository.
fn husky_at(session: &Session, root: &std::path::Path, hooks: &[&str]) -> std::path::PathBuf {
    let directory = root.join(".husky/_");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join(".gitignore"), "*\n").unwrap();
    std::fs::write(directory.join("h"), RUNNER).unwrap();
    for hook in hooks {
        let shim = directory.join(hook);
        std::fs::write(&shim, SHIM).unwrap();
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    session.config(&["core.hooksPath", ".husky/_"]);
    directory
}

fn head(session: &Session) -> String {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(&session.primary)
        .env("HOME", &session.home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

#[test]
fn origin_refresh_accepts_what_a_developer_checkout_carries() {
    let session = session("developer");
    let primary = session.primary.display();
    let fetch = format!("git -C {primary} fetch origin main --quiet");
    let chain = format!(
        "git -C {primary} remote -v | head -2; {fetch} && git -C {primary} rev-parse origin/main && git -C {primary} worktree list"
    );
    session.assert_allow(&chain, REFRESH);

    for url in [
        "git@github.com:example-org/app-portal.git",
        "git@github.com:example-org/app-portal",
        "ssh://git@github.com/example-org/app-portal.git",
    ] {
        session.config(&["remote.origin.url", url]);
        session.assert_allow(&fetch, REFRESH);
        session.assert_allow(&chain, REFRESH);
    }
    // The program Git starts for SSH is the user's `ssh`; none of the places
    // that could name another are open.
    session.assert_not_allow(&format!("GIT_SSH_COMMAND=id {fetch}"));
    session.assert_not_allow(&format!(
        "git -C {primary} -c core.sshCommand=id fetch origin main"
    ));
    session.config(&["core.sshCommand", "ssh -o ProxyCommand=id"]);
    session.assert_not_allow(&chain);
    session.config(&["--unset-all", "core.sshCommand"]);
    session.assert_allow(&chain, REFRESH);

    // One GitHub spelling exchanged for the other, in either direction.
    session.config(&[
        "remote.origin.url",
        "https://github.com/example-org/app-portal.git",
    ]);
    session.config(&["url.git@github.com:.insteadOf", "https://github.com/"]);
    session.assert_allow(&chain, REFRESH);
    session.config(&["--unset-all", "url.git@github.com:.insteadOf"]);
    session.config(&["url.git@evil.example:.insteadOf", "https://github.com/"]);
    session.assert_not_allow(&chain);
    session.config(&["--unset-all", "url.git@evil.example:.insteadOf"]);

    // Pruning drops only the remote-tracking refs the plain refspec names;
    // pruning tags would drop the user's own.
    session.config(&["fetch.prune", "true"]);
    session.assert_allow(&chain, REFRESH);
    session.config(&["fetch.pruneTags", "true"]);
    session.assert_not_allow(&chain);
    session.config(&["--unset-all", "fetch.pruneTags"]);
    session.assert_allow(&chain, REFRESH);

    // A hook manager points `core.hooksPath` at a directory of the repository.
    let hooks = session.primary.join(".husky/_");
    std::fs::create_dir_all(&hooks).unwrap();
    session.config(&["core.hooksPath", ".husky/_"]);
    session.assert_allow(&chain, REFRESH);
    // Husky 9's shims stop at once when the project defines no such hook.
    std::fs::write(
        hooks.join("h"),
        "#!/usr/bin/env sh\n[ \"$HUSKY\" = \"2\" ] && set -x\nn=$(basename \"$0\")\ns=$(dirname \"$(dirname \"$0\")\")/$n\n\n[ ! -f \"$s\" ] && exit 0\n\nsh -e \"$s\" \"$@\"\n",
    )
    .unwrap();
    for hook in [
        "pre-auto-gc",
        "reference-transaction",
        "post-fetch",
        "post-index-change",
    ] {
        let shim = hooks.join(hook);
        std::fs::write(&shim, SHIM).unwrap();
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    session.assert_allow(&chain, REFRESH);
    // A project hook of that name is what the shim would run.
    std::fs::write(session.primary.join(".husky/reference-transaction"), "id\n").unwrap();
    session.assert_not_allow(&chain);
    std::fs::remove_file(session.primary.join(".husky/reference-transaction")).unwrap();
    session.assert_allow(&chain, REFRESH);
    // Any other executable under a hook's name runs.
    let shim = hooks.join("post-fetch");
    executable_hook(&shim);
    session.assert_not_allow(&chain);
    std::fs::write(&shim, SHIM).unwrap();
    session.assert_allow(&chain, REFRESH);
    // Status refreshes the index and then runs `post-index-change`: the shim
    // answers for it only while the project defines no hook of that name.
    let status = format!("git -C {primary} status --short");
    assert_eq!(session.evaluate(&status).decision, "allow", "{status}");
    let project_hook = session.primary.join(".husky/post-index-change");
    std::fs::write(&project_hook, "id\n").unwrap();
    session.assert_not_allow(&status);
    std::fs::remove_file(project_hook).unwrap();
    assert_eq!(session.evaluate(&status).decision, "allow", "{status}");

    // A directory outside the repository, or an absolute one, stays reviewed.
    for path in ["/tmp/hooks", "../hooks", "~/hooks"] {
        session.config(&["core.hooksPath", path]);
        session.assert_not_allow(&chain);
    }
}

#[test]
fn worktree_add_in_a_hook_manager_checkout_is_quiet_only_while_no_hook_can_run() {
    let session = session("husky-add");
    let primary = session.primary.display();
    let destination = session.org.join("app-portal-husky");
    let destination = destination.display();
    let sha = head(&session);
    git(
        &session.home,
        &session.primary,
        &["branch", "fix/hooks-existing"],
    );
    let commands = [
        format!("git -C {primary} worktree add {destination} -b fix/hooks-new main"),
        format!("git -C {primary} worktree add {destination} -b fix/hooks-new {sha}"),
        format!("git -C {primary} worktree add {destination} fix/hooks-existing"),
    ];
    let hooks = husky(
        &session,
        &[
            "post-checkout",
            "post-index-change",
            "reference-transaction",
        ],
    );
    for command in &commands {
        session.assert_allow(command, ADD);
    }
    // The shim runs the project's own hook when the project defines one.
    let project = session.primary.join(".husky/post-checkout");
    std::fs::write(&project, "id\n").unwrap();
    for command in &commands {
        session.assert_not_allow(command);
    }
    std::fs::remove_file(&project).unwrap();
    for command in &commands {
        session.assert_allow(command, ADD);
    }
    // Any other executable under a hook's name, or a runner that is not Husky's.
    let shim = hooks.join("reference-transaction");
    executable_hook(&shim);
    session.assert_not_allow(&commands[0]);
    std::fs::write(&shim, SHIM).unwrap();
    session.assert_allow(&commands[0], ADD);
    std::fs::write(hooks.join("h"), "#!/usr/bin/env sh\nid\n").unwrap();
    session.assert_not_allow(&commands[0]);
    std::fs::write(hooks.join("h"), RUNNER).unwrap();
    session.assert_allow(&commands[0], ADD);

    // A fetch earlier in the command can move the start point, so the tree
    // checked out is not the one proven.
    session.assert_not_allow(&format!(
        "git -C {primary} fetch origin main --quiet && git -C {primary} worktree add {destination} -b fix/hooks-new origin/main"
    ));
    // Hooks outside the repository stay reviewed.
    for path in ["/tmp/hooks", "../hooks", "~/hooks", ".husky/../../hooks"] {
        session.config(&["core.hooksPath", path]);
        session.assert_not_allow(&commands[0]);
    }
}

#[test]
fn worktree_add_reads_the_hooks_the_commit_checked_out_tracks() {
    let session = session("tracked-hooks");
    let primary = session.primary.display();
    let destination = session.org.join("app-portal-tracked");
    let command = format!(
        "git -C {primary} worktree add {} -b fix/tracked-hooks main",
        destination.display()
    );
    let hook = session.primary.join("tools/hooks/post-checkout");
    std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
    std::fs::write(&hook, "#!/bin/sh\nexit 0\n").unwrap();
    session.config(&["core.hooksPath", "tools/hooks"]);
    git(
        &session.home,
        &session.primary,
        &["add", "tools/hooks/post-checkout"],
    );
    git(
        &session.home,
        &session.primary,
        &["commit", "--quiet", "-m", "track a hook"],
    );
    // Tracked without the executable bit: Git never runs it.
    session.assert_allow(&command, ADD);
    // The commit that would be checked out tracks a hook Git runs.
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    git(
        &session.home,
        &session.primary,
        &["add", "tools/hooks/post-checkout"],
    );
    git(
        &session.home,
        &session.primary,
        &["commit", "--quiet", "-m", "run it"],
    );
    session.assert_not_allow(&command);
    // An earlier start point tracks the hook without the bit, yet the
    // directory here still holds the executable one: still reviewed.
    session.assert_not_allow(&format!(
        "git -C {primary} worktree add {} -b fix/tracked-hooks main~1",
        destination.display()
    ));
}

#[test]
fn a_hooks_directory_spelled_oddly_or_reached_by_a_link_is_never_a_hook_managers() {
    let session = session("husky-spelling");
    let primary = session.primary.display();
    let destination = session.org.join("app-portal-spelling");
    let add = format!(
        "git -C {primary} worktree add {} -b fix/spelling main",
        destination.display()
    );
    let fetch = format!("git -C {primary} fetch origin main --quiet");
    let status = format!("git -C {primary} status --short");
    let hooks = husky(&session, &HOOKS);
    session.assert_allow(&add, ADD);
    session.assert_allow(&fetch, REFRESH);
    assert_eq!(session.evaluate(&status).decision, "allow", "{status}");
    // A hooks directory in the user's own configuration is read first and
    // overridden by the repository's, which Git then reaches the same way.
    std::fs::create_dir_all(session.home.join(".config/git/hooks")).unwrap();
    std::fs::write(
        session.home.join(".gitconfig"),
        "[core]\n\thooksPath = ~/.config/git/hooks\n",
    )
    .unwrap();
    session.assert_allow(&add, ADD);
    session.assert_allow(&fetch, REFRESH);
    assert_eq!(session.evaluate(&status).decision, "allow", "{status}");

    // Git folds these into the directory above, but nothing here is built
    // from a spelling that is not one plain relative path.
    for path in [".husky/_/", ".husky//_", "./.husky/_", ".husky/./_"] {
        session.config(&["core.hooksPath", path]);
        for command in [&add, &fetch] {
            session.assert_not_allow(command);
        }
    }
    session.config(&["core.hooksPath", ".husky/_"]);
    session.assert_allow(&add, ADD);

    // Husky's runner finds the project hook from the path Git passes it, so a
    // link at the hooks directory sends it to the project's own hook while the
    // resolved path points somewhere that holds none.
    let real = session.primary.join("vendor/_");
    std::fs::create_dir_all(real.parent().unwrap()).unwrap();
    std::fs::rename(&hooks, &real).unwrap();
    symlink("../vendor/_", &hooks).unwrap();
    let project = ["reference-transaction", "post-index-change"]
        .map(|hook| session.primary.join(".husky").join(hook));
    for path in &project {
        std::fs::write(path, "id\n").unwrap();
    }
    for command in [&add, &fetch, &status] {
        session.assert_not_allow(command);
    }
    // The link alone is enough: no project hook is needed to refuse it.
    for path in &project {
        std::fs::remove_file(path).unwrap();
    }
    for command in [&add, &fetch, &status] {
        session.assert_not_allow(command);
    }
    std::fs::remove_file(&hooks).unwrap();
    std::fs::rename(&real, &hooks).unwrap();
    session.assert_allow(&add, ADD);
    session.assert_allow(&fetch, REFRESH);
}

#[test]
fn a_hook_managers_shim_vouches_for_no_write_that_changes_the_tree() {
    let session = session("husky-writes");
    let worktree = session.worktree.display();
    let primary = session.primary.display();
    std::fs::write(session.worktree.join("notes.md"), "notes\n").unwrap();
    let add = format!("cd {worktree} && git add notes.md");
    let commit = format!("cd {worktree} && git add notes.md && git commit -m x");
    let pull = format!("git -C {primary} pull --ff-only");
    let fetch = format!("git -C {primary} fetch origin main --quiet");
    session.config(&["branch.main.remote", "origin"]);
    session.config(&["branch.main.merge", "refs/heads/main"]);
    // The sandbox may take a write into the worktree's shared Git directory
    // instead; either way it raises no review.
    session.assert_quiet(&add, WRITE);
    session.assert_quiet(&commit, WRITE);
    session.assert_allow(&pull, REFRESH);
    session.assert_allow(&fetch, REFRESH);

    // Git finds the shim from either tree. A commit, an index write or a
    // pull changes what the shim would run, so none of them rests on it.
    husky_at(&session, &session.worktree, &HOOKS);
    husky(&session, &HOOKS);
    for command in [&add, &commit, &pull] {
        session.assert_not_allow(command);
    }
    // A fetch writes no file of the tree, so the shim still stops at once.
    session.assert_allow(&fetch, REFRESH);
}

#[test]
fn a_pull_trusts_a_hooks_directory_of_the_user_only_outside_the_checkout() {
    let session = session("user-hooks-pull");
    let primary = session.primary.display();
    let pull = format!("git -C {primary} pull --ff-only");
    let gitconfig = session.home.join(".gitconfig");
    let user_hooks = |value: &str| {
        std::fs::write(&gitconfig, format!("[core]\n\thooksPath = {value}\n")).unwrap();
    };
    session.config(&["branch.main.remote", "origin"]);
    session.config(&["branch.main.merge", "refs/heads/main"]);
    session.assert_allow(&pull, REFRESH);

    // A directory the user keeps outside the checkout holds nothing a pull adds.
    let outside = session.home.join(".config/git/hooks");
    std::fs::create_dir_all(&outside).unwrap();
    let outside_path = outside.display().to_string();
    for value in ["~/.config/git/hooks", outside_path.as_str()] {
        user_hooks(value);
        session.assert_allow(&pull, REFRESH);
    }
    // One that does not exist yet is outside too.
    user_hooks("~/.config/git/later");
    session.assert_allow(&pull, REFRESH);

    // A tracked directory of the checkout can receive a hook from the incoming
    // commit, however the user's configuration spells the path to it.
    let tracked = session.primary.join("tools/hooks");
    std::fs::create_dir_all(&tracked).unwrap();
    let linked = session.home.join(".config/git/linked");
    symlink(&tracked, &linked).unwrap();
    // A link whose target does not exist yet resolves once the commit adds it.
    let dangling = session.home.join(".config/git/dangling");
    symlink(session.primary.join("tools/not-yet"), &dangling).unwrap();
    let dangling_below = format!("{}/hooks", dangling.display());
    let inside = [
        tracked.display().to_string(),
        session.primary.display().to_string(),
        session.primary.join(".git/hooks").display().to_string(),
        linked.display().to_string(),
        dangling.display().to_string(),
        dangling_below,
    ];
    for value in [
        "~/org/app-portal/tools/hooks",
        "~/org/app-portal/tools/not-yet",
        "~/.config/git/../../org/app-portal/tools/hooks",
        "tools/hooks",
    ]
    .into_iter()
    .chain(inside.iter().map(String::as_str))
    {
        user_hooks(value);
        session.assert_not_allow(&pull);
    }
}

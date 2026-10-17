//! Git commands routed to a sibling checkout, a named Git directory or a
//! fresh temporary repository.

use super::{executable_hook, git, session};
use crate::git_helper_fixture::FixtureCleanup;
use std::os::unix::fs::PermissionsExt;

fn allowed(
    session: &super::Session,
    command: &str,
    cwd: &std::path::Path,
) -> Result<String, String> {
    let result = session.evaluate_at(command, cwd);
    (result.minimum_action == "allow")
        .then(|| result.reason_code.clone())
        .ok_or(format!("{command}: {}", result.reason_code))
}

#[test]
fn plain_config_writes_in_a_sibling_checkout_are_quiet() {
    const WRITE: &str = "native_exact_safe_git_config_write";
    let session = session("config-write");
    let primary = session.primary.display();
    let worktree = session.worktree.display();
    for command in [
        format!("git -C {worktree} config rehearsal.probe true"),
        format!(
            "git -C {worktree} config rehearsal.probe true && git -C {worktree} config --unset rehearsal.probe && echo \"git write OK\""
        ),
        format!("git -C {primary} config --local review.lane fix-1"),
        format!("git -C {primary} config unset review.lane"),
    ] {
        session.assert_allow(&command, WRITE);
    }
    for command in [
        format!("git -C {primary} config core.pager id"),
        format!("git -C {primary} config alias.st '!id'"),
        format!("git -C {primary} config url.https://evil.example/.insteadOf https://github.com/"),
        format!("git -C {primary} config credential.helper store"),
        format!("git -C {primary} config include.path /tmp/extra"),
        format!("git -C {primary} config remote.origin.url https://evil.example/app.git"),
        format!("git -C {primary} config rehearsal.editor vim"),
        format!("git -C {primary} config rehearsal.hooksDir hooks"),
        format!("git -C {primary} config rehearsal.probe /tmp/x"),
        format!("git -C {primary} config rehearsal.probe '$(id)'"),
        format!("git -C {primary} config --global rehearsal.probe true"),
        format!("git -C {primary} config --file /tmp/x rehearsal.probe true"),
        format!("git -C {primary} -c core.pager=id config rehearsal.probe true"),
        format!("GIT_CONFIG_GLOBAL=/tmp/x git -C {primary} config rehearsal.probe true"),
        format!("git -C {primary} config rehearsal.probe true && rm -rf build"),
        format!("git -C {primary} config rehearsal.probe true && git -C {primary} push evil main"),
        format!("git -C {primary} config rehearsal.probe true > /tmp/out"),
    ] {
        session.assert_not_allow(&command);
    }
}

#[test]
fn grep_and_named_git_directory_reads_are_quiet_without_helpers() {
    let session = session("grep");
    let primary = session.primary.display();
    let org = session.org.clone();
    for command in [
        format!("git -C {primary} grep -l \"SOME_TOKEN_NAME\" HEAD"),
        format!("git -C {primary} grep -l fixture HEAD -- . | head"),
        format!("git -C {primary} grep -n -i -e fixture -- tracked.txt | head -5"),
        format!("git --git-dir={primary}/.git log --oneline -3"),
        format!("git --git-dir {primary}/.git log --oneline -1"),
        "git --git-dir=app-portal/.git log --oneline -12".to_owned(),
        format!("git --git-dir {primary}/.git config --list 2>&1 | head -20"),
        format!("git -C {primary} config --list 2>&1 | head -20"),
    ] {
        allowed(&session, &command, &org).unwrap();
    }
    for command in [
        format!("git -C {primary} grep -O id fixture"),
        format!("git -C {primary} grep --open-files-in-pager=id fixture"),
        format!("git -C {primary} grep --textconv fixture"),
        format!("git -C {primary} grep -f /etc/passwd"),
        format!("git -C {primary} grep --no-index fixture /etc"),
        format!("git -C {primary} grep fixture HEAD -- .env"),
        format!("git --git-dir={primary}/.git commit -m x"),
        format!("git --git-dir={primary}/.git --work-tree=/ log -1"),
    ] {
        assert!(allowed(&session, &command, &org).is_err(), "{command}");
    }
    session.config(&["core.pager", "id"]);
    let paged = format!("git -C {primary} grep -l fixture");
    assert!(allowed(&session, &paged, &org).is_err(), "{paged}");
}

#[test]
fn new_branch_at_a_start_point_is_quiet_only_when_it_replaces_nothing() {
    const WRITE: &str = "native_exact_safe_git_local_write";
    let session = session("start-point");
    let tree = session.worktree.clone();
    git(&session.home, &tree, &["checkout", "-q", "-b", "side"]);
    std::fs::write(tree.join("generated.txt"), "side\n").unwrap();
    git(&session.home, &tree, &["add", "generated.txt"]);
    git(&session.home, &tree, &["commit", "-q", "-m", "side"]);
    git(&session.home, &tree, &["checkout", "-q", "fix/report-lane"]);
    let log =
        "git checkout -b fix/report-followup origin/main 2>&1 | tail -2 && git log --oneline -1";
    assert_eq!(allowed(&session, log, &tree).as_deref(), Ok(WRITE));
    assert_eq!(
        allowed(&session, "git switch -c feat/side-copy side", &tree).as_deref(),
        Ok(WRITE)
    );
    // An untracked file at a path the start point tracks would be replaced.
    std::fs::write(tree.join("generated.txt"), "local\n").unwrap();
    assert!(allowed(&session, "git switch -c feat/side-copy side", &tree).is_err());
    std::fs::remove_file(tree.join("generated.txt")).unwrap();
    for command in [
        "git checkout -b feat/a side~1",
        "git checkout -b feat/a -- side",
        "git checkout -b feat/a --orphan",
        "git checkout -B feat/a side",
        "git checkout -b feat/a side tracked.txt",
        "git checkout -b feat/a missing-ref",
        "git stash -m note side",
    ] {
        assert!(allowed(&session, command, &tree).is_err(), "{command}");
    }
    session.config(&["includeIf.onbranch:feat/**.path", "extra.conf"]);
    assert!(allowed(&session, "git checkout -b feat/a side && git log -1", &tree).is_err());
    session.config(&["--unset-all", "includeIf.onbranch:feat/**.path"]);
    executable_hook(&session.primary.join(".git/hooks/post-checkout"));
    assert!(allowed(&session, "git switch -c feat/side-copy side", &tree).is_err());
}

#[test]
fn init_of_a_fresh_owned_temporary_directory_is_quiet() {
    const INIT: &str = "native_exact_safe_git_init_target";
    let session = session("init");
    let parent = std::fs::canonicalize("/tmp").unwrap().join(format!(
        "guard-init-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _cleanup = FixtureCleanup(parent.clone());
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let target = parent.display();
    for command in [
        format!("git init -q {target}/scratch"),
        format!("git init {target}/scratch -b main"),
    ] {
        session.assert_allow(&command, INIT);
    }
    // `pretool_git_init_chain` covers what may follow in the new directory.
    session.assert_allow(
        &format!("git init -q {target}/scratch && cd {target}/scratch && git add ."),
        "native_exact_safe_git_init_chain",
    );
    for command in [
        format!("git init -q {target}"),
        format!("git init -q {target}/.scratch"),
        format!("git init -q {target}/one/two"),
        format!("git init --bare {target}/scratch"),
        format!("git init --template={target} {target}/scratch"),
        format!("git init --separate-git-dir {target}/sep {target}/scratch"),
        format!("git init -q {target}/scratch > {target}/init.log"),
        "git init -q /etc/guard-scratch".to_owned(),
    ] {
        session.assert_not_allow(&command);
    }
    git(
        &session.home,
        &session.primary,
        &[
            "config",
            "--global",
            "init.templateDir",
            &format!("{target}/tpl"),
        ],
    );
    session.assert_not_allow(&format!("git init -q {target}/scratch"));
}

#[test]
fn clone_of_a_local_repository_into_a_fresh_directory_is_quiet() {
    const CLONE: &str = "native_exact_safe_git_clone_local";
    let session = session("clone");
    let primary = session.primary.display();
    let home = session.home.display();
    let copy = format!("{home}/app-portal-copy");
    for command in [
        format!("git clone {primary} {copy}"),
        format!("git clone --branch main {primary} {copy}"),
        format!("git clone -q --no-hardlinks {primary} {copy}"),
        format!("git clone --single-branch -b main {primary} {copy}"),
        format!("git clone -n {primary} {copy}"),
    ] {
        session.assert_allow(&command, CLONE);
    }
    for command in [
        // A remote clone fetches a repository nothing here has read.
        format!("git clone https://github.com/example-org/app-portal.git {copy}"),
        format!("git clone file://{primary} {copy}"),
        // The template, the configuration and the submodules of the new
        // repository all decide what later runs in it.
        format!("git clone --template={home}/tpl {primary} {copy}"),
        format!("git clone --recurse-submodules {primary} {copy}"),
        format!("git clone --config core.pager=id {primary} {copy}"),
        format!("git -c core.pager=id clone {primary} {copy}"),
        format!("git clone --separate-git-dir {home}/sep {primary} {copy}"),
        format!("git clone --upload-pack id {primary} {copy}"),
        // The destination must be a directory that does not exist yet,
        // below the home directory or an owned temporary directory.
        format!("git clone {primary} {home}"),
        format!("git clone {primary} /etc/guard-clone"),
        format!("git clone {primary} {copy}/nested/deeper"),
        // A single operand leaves the destination for Git to name.
        format!("git clone {primary}"),
        // The source must be a repository the user already has.
        format!("git clone {home}/org {copy}"),
        format!("git clone {primary} {copy} > {home}/clone.log"),
        format!("git clone {primary} {copy} && rm -rf {primary}"),
        format!("git clone -b missing-branch {primary} {copy}"),
    ] {
        session.assert_not_allow(&command);
    }
    // A hook the new checkout would run, and a template directory whose
    // hooks the copy would keep, each keep their review.
    executable_hook(&session.primary.join(".git/hooks/post-checkout"));
    session.assert_not_allow(&format!("git clone {primary} {copy}"));
    std::fs::remove_file(session.primary.join(".git/hooks/post-checkout")).unwrap();
    session.assert_allow(&format!("git clone {primary} {copy}"), CLONE);
    git(
        &session.home,
        &session.primary,
        &[
            "config",
            "--global",
            "init.templateDir",
            &format!("{home}/tpl"),
        ],
    );
    session.assert_not_allow(&format!("git clone {primary} {copy}"));
}

#[test]
fn init_of_a_fresh_leaf_directly_in_a_temporary_root_is_quiet() {
    const INIT: &str = "native_exact_safe_git_init_target";
    let session = session("init-root");
    let unique = format!(
        "guard-init-root-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let mut roots = vec![std::fs::canonicalize("/tmp").unwrap()];
    let private = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    if cfg!(target_os = "macos") && private.starts_with("/private/var/folders") {
        roots.push(private);
    }
    for root in roots {
        let leaf = root.join(&unique);
        let _cleanup = FixtureCleanup(leaf.clone());
        let target = leaf.display();
        for command in [
            format!("git init -q {target}"),
            format!("git init {target} -b main"),
        ] {
            session.assert_allow(&command, INIT);
        }
        for command in [
            format!("git init -q {}/.{unique}", root.display()),
            format!("git init -q {target}/nested"),
            format!("git init --bare {target}"),
        ] {
            session.assert_not_allow(&command);
        }
        // Another user may create the leaf in the shared root first, so only
        // the user's private macOS root lets later steps use it.
        let chain = format!("git init -q {target} && cd {target} && git add .");
        if root.starts_with("/private/var/folders") {
            session.assert_allow(&chain, "native_exact_safe_git_init_chain");
        } else {
            session.assert_not_allow(&chain);
        }
        // A directory that already exists there, which in the shared root
        // another user may have planted, keeps its review.
        std::fs::create_dir(&leaf).unwrap();
        session.assert_not_allow(&format!("git init -q {target}"));
    }
}

/// `git clone` copies a repository, and a repository can point its object
/// read somewhere else: a `.git` file names another Git directory, a link in
/// its place does the same, and `objects/info/alternates` borrows a store the
/// proof never bounded. Each keeps its review.
#[test]
fn a_clone_whose_repository_data_is_not_its_own_keeps_review() {
    const CLONE: &str = "native_exact_safe_git_clone_local";
    let session = session("clone-data");
    let primary = session.primary.display();
    let home = session.home.display();
    let copy = format!("{home}/app-portal-copy");
    session.assert_allow(&format!("git clone {primary} {copy}"), CLONE);
    // The linked worktree's `.git` is a file naming the primary's Git
    // directory, which is where the clone would read from.
    session.assert_not_allow(&format!("git clone {} {copy}", session.worktree.display()));
    // A link in place of the `.git` directory reads the same way.
    let linked = session.home.join("linked-portal");
    std::fs::create_dir_all(&linked).unwrap();
    std::os::unix::fs::symlink(session.primary.join(".git"), linked.join(".git")).unwrap();
    session.assert_not_allow(&format!("git clone {} {copy}", linked.display()));
    // Alternates send the object read to a store outside the copy.
    let info = session.primary.join(".git/objects/info");
    std::fs::create_dir_all(&info).unwrap();
    for name in ["alternates", "http-alternates"] {
        let file = info.join(name);
        std::fs::write(&file, format!("{home}/objects\n")).unwrap();
        session.assert_not_allow(&format!("git clone {primary} {copy}"));
        std::fs::remove_file(&file).unwrap();
    }
    session.assert_allow(&format!("git clone {primary} {copy}"), CLONE);
}

/// A repository in a temporary directory is the source only while it is the
/// user's own: a directory another user can write to can be rewritten between
/// this proof and the clone, so it keeps its review however it was reached.
#[test]
fn a_clone_from_a_repository_other_users_can_rewrite_keeps_review() {
    const CLONE: &str = "native_exact_safe_git_clone_local";
    let session = session("clone-temp");
    let copy = format!("{}/app-portal-copy", session.home.display());
    let leaf = std::fs::canonicalize("/tmp").unwrap().join(format!(
        "guard-clone-temp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _cleanup = FixtureCleanup(leaf.clone());
    for source in [leaf.clone(), leaf.join("nested")] {
        std::fs::create_dir_all(&source).unwrap();
        git(&session.home, &source, &["init", "--quiet", "-b", "main"]);
        git(
            &session.home,
            &source,
            &["config", "user.name", "Guard Fixture"],
        );
        git(
            &session.home,
            &source,
            &["config", "user.email", "guard-fixture@example.invalid"],
        );
        std::fs::write(source.join("tracked.txt"), "fixture\n").unwrap();
        git(&session.home, &source, &["add", "tracked.txt"]);
        git(
            &session.home,
            &source,
            &["commit", "--quiet", "-m", "fixture"],
        );
        let spelled = source.display().to_string();
        let command = format!("git clone {spelled} {copy}");
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755)).unwrap();
        session.assert_allow(&command, CLONE);
        for mode in [0o777, 0o775] {
            std::fs::set_permissions(&source, std::fs::Permissions::from_mode(mode)).unwrap();
            session.assert_not_allow(&command);
        }
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    // The directory on the way down counts too: a world-writable parent is
    // enough to replace the repository below it.
    let nested = leaf.join("nested");
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o777)).unwrap();
    session.assert_not_allow(&format!("git clone {} {copy}", nested.display()));
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#![cfg(unix)]

use crate::git_helper_fixture as fixture;

#[path = "pretool_git_session_ops/context.rs"]
mod context;

use fixture::{evaluate_pre_tool_envelope_with_context, FixtureCleanup};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub(crate) struct Session {
    pub(crate) home: PathBuf,
    pub(crate) org: PathBuf,
    pub(crate) primary: PathBuf,
    pub(crate) worktree: PathBuf,
    _cleanup: FixtureCleanup,
}

pub(crate) fn default_controls(
) -> guard_command::native_command_controls::CompiledNativeCommandControls {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let mut binding: guard_contracts::NativeCommandControlBindingV1 =
        serde_json::from_value(json!({
            "schema":"guard.native-command-control-binding.v1",
            "program_digest":program.program_digest,
            "catalog_digest":program.catalog_digest,
            "trust_digest":program.trust_digest,
            "health":"protected",
            "revision":1,
            "managed_revision":0,
            "effective_digest":"",
            "layers":[{
                "schema_version":"1.0.0",
                "kind":"local-admin",
                "catalog_digest":program.catalog_digest,
                "global_lockdown":false,
                "controls":[]
            }]
        }))
        .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    guard_command::native_command_controls::CompiledNativeCommandControls::new(&binding).unwrap()
}

pub(crate) fn git(home: &Path, directory: &Path, arguments: &[&str]) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(directory)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .env_remove("GIT_AUTHOR_NAME")
        .env_remove("GIT_AUTHOR_EMAIL")
        .env_remove("GIT_COMMITTER_NAME")
        .env_remove("GIT_COMMITTER_EMAIL")
        .args(arguments)
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

/// `home/org/app-portal` on `main` with a GitHub HTTPS origin, and its linked
/// worktree `home/app-portal-fix` on `fix/report-lane`, beside the cwd.
pub(crate) fn session(label: &str) -> Session {
    let base = if cfg!(target_os = "macos") {
        PathBuf::from("/tmp")
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target")
    };
    let home = std::fs::canonicalize(base).unwrap().join(format!(
        "guard-git-session-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let cleanup = FixtureCleanup(home.clone());
    let org = home.join("org");
    let primary = org.join("app-portal");
    let worktree = home.join("app-portal-fix");
    std::fs::create_dir_all(primary.join("node_modules/pkg")).unwrap();
    git(&home, &primary, &["init", "--quiet", "-b", "main"]);
    git(&home, &primary, &["config", "user.name", "Guard Fixture"]);
    git(
        &home,
        &primary,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    std::fs::write(primary.join(".gitignore"), "node_modules/\n").unwrap();
    std::fs::write(primary.join("tracked.txt"), "fixture\n").unwrap();
    git(&home, &primary, &["add", ".gitignore", "tracked.txt"]);
    git(&home, &primary, &["commit", "--quiet", "-m", "fixture"]);
    git(
        &home,
        &primary,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/example-org/app-portal.git",
        ],
    );
    // A clone records the remote's default branch; `remote add` alone does not.
    git(
        &home,
        &primary,
        &["update-ref", "refs/remotes/origin/main", "HEAD"],
    );
    git(
        &home,
        &primary,
        &[
            "symbolic-ref",
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/main",
        ],
    );
    git(
        &home,
        &primary,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "fix/report-lane",
            worktree.to_str().unwrap(),
        ],
    );
    Session {
        home,
        org,
        primary,
        worktree,
        _cleanup: cleanup,
    }
}

impl Session {
    fn evaluate(&self, command: &str) -> guard_contracts::PreToolResultV1 {
        self.evaluate_at(command, &self.org)
    }

    pub(crate) fn evaluate_at(
        &self,
        command: &str,
        cwd: &Path,
    ) -> guard_contracts::PreToolResultV1 {
        evaluate_pre_tool_envelope_with_context(
            "codex",
            "PreToolUse",
            &json!({"tool_name":"bash", "tool_input":{"command":command}}),
            Some(&default_controls()),
            None,
            self.home.to_str(),
            cwd.to_str(),
        )
    }

    fn assert_allow(&self, command: &str, reason_code: &str) {
        let result = self.evaluate(command);
        assert_eq!(
            (result.minimum_action.as_str(), result.reason_code.as_str()),
            ("allow", reason_code),
            "{command}"
        );
    }

    fn assert_not_allow(&self, command: &str) {
        let result = self.evaluate(command);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }

    pub(crate) fn config(&self, arguments: &[&str]) {
        let mut full = vec!["config"];
        full.extend_from_slice(arguments);
        git(&self.home, &self.primary, &full);
    }
}

pub(crate) fn executable_hook(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn origin_refresh_is_quiet_only_for_a_proven_github_https_origin() {
    let session = session("fetch");
    let primary = session.primary.display();
    let fetch = format!("git -C {primary} fetch origin");
    session.assert_allow(&fetch, "native_exact_safe_git_origin_refresh");
    session.assert_allow(
        &format!("git -C {primary} fetch --quiet --prune origin main"),
        "native_exact_safe_git_origin_refresh",
    );
    // A proven refresh composes with segments that are benign on their own.
    session.assert_allow(
        &format!(
            "git -C {primary} fetch origin main && git -C {primary} log origin/main --oneline -2"
        ),
        "native_exact_safe_git_origin_refresh",
    );
    for command in [
        format!("git -C {primary} fetch origin && rm -rf target"),
        format!("git -C {primary} fetch origin; cat {primary}/.env"),
        format!("git -C {primary} fetch origin && git -C {primary} fetch evil"),
        format!("git -C {primary} fetch evil"),
        format!("git -C {primary} fetch origin --upload-pack=id"),
        format!("git -C {primary} fetch origin '+refs/*:refs/*'"),
        format!("git -C {primary} -c core.sshCommand=id fetch origin"),
        format!("GIT_SSH_COMMAND=id git -C {primary} fetch origin"),
    ] {
        session.assert_not_allow(&command);
    }
    for (key, value) in [
        ("remote.origin.uploadpack", "sh -c id"),
        ("core.sshCommand", "ssh -o ProxyCommand=id"),
        (
            "url.ssh://git@evil.example/.insteadOf",
            "https://github.com/",
        ),
        ("remote.origin.fetch", "+refs/*:refs/*"),
        ("credential.helper", "!sh -c id"),
        ("credential.helper", "/tmp/helper"),
    ] {
        session.config(&[key, value]);
        session.assert_not_allow(&fetch);
        session.config(&["--unset-all", key]);
    }
    for url in [
        "git@github.com:example-org/app-portal.git",
        "https://token@github.com/example-org/app-portal.git",
        "https://github.com.evil.example/example-org/app-portal.git",
        "ext::sh -c id",
    ] {
        session.config(&["remote.origin.url", url]);
        session.assert_not_allow(&fetch);
    }
    session.config(&[
        "remote.origin.url",
        "https://github.com/example-org/app-portal.git",
    ]);
    session.assert_allow(&fetch, "native_exact_safe_git_origin_refresh");
    executable_hook(&session.primary.join(".git/hooks/reference-transaction"));
    session.assert_not_allow(&fetch);
}

#[test]
fn fast_forward_pull_is_quiet_only_without_merge_or_checkout_programs() {
    const REFRESH: &str = "native_exact_safe_git_origin_refresh";
    let session = session("pull");
    let primary = session.primary.display();
    let pull = format!("git -C {primary} pull --ff-only");
    session.config(&["branch.main.remote", "origin"]);
    session.config(&["branch.main.merge", "refs/heads/main"]);
    session.assert_allow(&pull, REFRESH);
    session.assert_allow(&format!("git -C {primary} pull -q --ff-only"), REFRESH);
    // Without `--ff-only` the pull may write a merge commit; this repository
    // has no hook or merge program that commit could start.
    session.assert_allow(&format!("git -C {primary} pull"), REFRESH);
    session.assert_allow(
        &format!("git -C {primary} pull --ff-only origin main"),
        REFRESH,
    );
    for command in [
        format!("git -C {primary} pull --rebase"),
        format!("git -C {primary} pull --ff-only --rebase"),
        format!("git -C {primary} pull --ff-only evil main"),
        format!("git -C {primary} pull --ff-only origin main topic"),
        format!("git -C {primary} pull --ff-only --upload-pack=id origin"),
        format!("git -C {primary} -c core.sshCommand=id pull --ff-only"),
    ] {
        session.assert_not_allow(&command);
    }
    let elsewhere = session.org.display().to_string();
    for (key, value) in [
        ("pull.rebase", "true"),
        ("branch.main.rebase", "merges"),
        ("merge.verifySignatures", "true"),
        ("gpg.program", "/tmp/gpg"),
        ("filter.lfs.smudge", "git-lfs smudge %f"),
        // A repository cannot vouch for its own filter, even the LFS one.
        ("filter.lfs.process", "git-lfs filter-process"),
        // Nor name the programs Git LFS starts beside the user's filter.
        ("lfs.extension.fixture.smudge", "id"),
        ("lfs.customtransfer.fixture.path", "/tmp/transfer"),
        ("lfs.standalonetransferagent", "fixture"),
        ("core.fsmonitor", "/tmp/monitor"),
        ("core.worktree", elsewhere.as_str()),
        ("hook.post-merge.command", "id"),
    ] {
        session.config(&[key, value]);
        session.assert_not_allow(&pull);
        session.config(&["--unset-all", key]);
    }
    // Git pulls from the upstream it reads, so that upstream must be origin.
    session.config(&["branch.main.remote", "evil"]);
    session.assert_not_allow(&pull);
    session.config(&["branch.main.remote", "origin"]);
    session.assert_allow(&pull, REFRESH);
    for hook in ["post-merge", "post-index-change"] {
        let path = session.primary.join(".git/hooks").join(hook);
        executable_hook(&path);
        session.assert_not_allow(&pull);
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn forged_checkout_is_not_a_push_or_removal_target() {
    let session = session("forged");
    let forged = session.home.join("forged");
    std::fs::create_dir_all(&forged).unwrap();
    let admin = session.primary.join(".git/worktrees/app-portal-fix");
    std::fs::write(
        forged.join(".git"),
        format!("gitdir: {}\n", admin.display()),
    )
    .unwrap();
    let forged_text = forged.display();
    session.assert_not_allow(&format!(
        "git -C {forged_text} push -u origin fix/report-lane"
    ));
    session.assert_not_allow(&format!("git -C {forged_text} fetch origin"));
    session.assert_not_allow(&format!(
        "git -C {} worktree remove {forged_text}",
        session.primary.display()
    ));
}

#[test]
fn worktree_maintenance_is_quiet_without_force_or_lock() {
    let session = session("maintenance");
    let primary = session.primary.display();
    let worktree = session.worktree.display();
    let remove = format!("git -C {primary} worktree remove {worktree}");
    session.assert_allow(&remove, "native_exact_safe_worktree_maintenance");
    session.assert_allow(
        &format!("git -C {primary} worktree prune"),
        "native_exact_safe_worktree_maintenance",
    );
    session.assert_allow(
        &format!("git -C {primary} worktree prune --dry-run --verbose"),
        "native_exact_safe_worktree_maintenance",
    );
    for command in [
        format!("git -C {primary} worktree remove --force {worktree}"),
        format!("git -C {primary} worktree remove -f {worktree}"),
        format!("git -C {primary} worktree remove {worktree} --force"),
        format!("git -C {primary} worktree remove {primary}"),
        format!("git -C {primary} worktree remove {}", session.org.display()),
        format!("git -C {primary} worktree prune --expire=now"),
        format!("rm -rf {worktree}"),
    ] {
        session.assert_not_allow(&command);
    }
    git(
        &session.home,
        &session.primary,
        &["worktree", "lock", session.worktree.to_str().unwrap()],
    );
    session.assert_not_allow(&remove);
    git(
        &session.home,
        &session.primary,
        &["worktree", "unlock", session.worktree.to_str().unwrap()],
    );
    session.assert_allow(&remove, "native_exact_safe_worktree_maintenance");
    session.config(&["core.fsmonitor", "/tmp/fsmonitor"]);
    session.assert_not_allow(&remove);
}

#[test]
fn dependency_symlink_is_quiet_only_between_checkouts_of_one_repository() {
    let session = session("symlink");
    let primary = session.primary.display();
    let worktree = session.worktree.display();
    let link = format!("ln -s {primary}/node_modules {worktree}/node_modules");
    session.assert_allow(&link, "native_exact_safe_command");
    let unrelated = session.home.join("unrelated");
    std::fs::create_dir_all(unrelated.join("node_modules")).unwrap();
    std::fs::create_dir_all(session.primary.join(".cache")).unwrap();
    for command in [
        format!("ln -sf {primary}/node_modules {worktree}/node_modules"),
        format!("ln -sn {primary}/node_modules {worktree}/node_modules"),
        format!("ln -s -f {primary}/node_modules {worktree}/node_modules"),
        format!("ln {primary}/node_modules {worktree}/node_modules"),
        format!("ln -s {primary}/node_modules {worktree}/.envrc"),
        format!("ln -s {primary}/node_modules {worktree}/src/node_modules"),
        format!("ln -s {primary}/missing {worktree}/node_modules"),
        format!("ln -s {primary}/tracked.txt {worktree}/tracked-link"),
        format!("ln -s {primary}/.git {worktree}/git-dir"),
        format!("ln -s {primary}/.cache {worktree}/cache"),
        format!("ln -s {primary} {worktree}/primary"),
        format!(
            "ln -s {}/node_modules {worktree}/node_modules",
            unrelated.display()
        ),
        format!("ln -s {primary}/node_modules {worktree}/tracked.txt"),
        format!(
            "ln -s {primary}/node_modules {}/node_modules",
            unrelated.display()
        ),
        format!("ln -s {}/.ssh {worktree}/keys", session.home.display()),
        format!("ln -s {primary}/node_modules {worktree}/node_modules && id"),
    ] {
        session.assert_not_allow(&command);
    }
}

#[test]
fn local_writes_in_a_linked_worktree_are_quiet_only_without_programs() {
    const WRITE: &str = "native_exact_safe_git_local_write";
    let session = session("writes");
    let worktree = session.worktree.display();
    std::fs::write(session.worktree.join("notes.md"), "notes\n").unwrap();
    let at_tree = |command: &str| session.evaluate_at(command, &session.worktree);
    let allowed = |command: &str| {
        let result = at_tree(command);
        (result.minimum_action == "allow" && result.reason_code == WRITE)
            .then_some(())
            .ok_or(format!("{command}: {}", result.reason_code))
    };
    session.assert_allow(&format!("cd {worktree} && git add notes.md"), WRITE);
    session.assert_allow(
        &format!("cd {worktree} && git rm -q tracked.txt && git status --short | head -10"),
        WRITE,
    );
    for command in [
        "git add -A",
        "git add -A && git commit -m 'chore: update'",
        "git commit -am 'fix: handle retry'",
        "git commit -q -m 'fix: handle retry' 2>&1",
        // Output kept in the worktree is a bounded file write.
        "git add notes.md > out.txt",
        "git switch -c feat/retry",
        "git checkout -b feat/retry",
        "git stash",
        "git stash list",
        "git stash apply",
        "git stash pop",
    ] {
        allowed(command).unwrap();
    }
    for command in [
        "git add -f notes.md",
        "git add -p",
        "git rm -f tracked.txt",
        "git commit",
        "git commit -e -m x",
        "git -c core.hooksPath=/tmp/hooks commit -m x",
        "git add notes.md && rm -rf build",
        "git switch main",
        "git stash drop",
    ] {
        assert!(allowed(command).is_err(), "{command}");
    }
    for (key, value) in [
        ("filter.strip.clean", "sed -e s/x//"),
        ("core.fsmonitor", "/tmp/monitor"),
        ("hook.pre-commit.command", "id"),
        ("diff.text.textconv", "cat"),
        ("submodule.recurse", "true"),
    ] {
        session.config(&[key, value]);
        assert!(allowed("git add -A && git commit -m x").is_err(), "{key}");
        session.config(&["--unset-all", key]);
    }
    // Signing by default asks of a commit what `-S` asks, and of nothing else.
    let explicit = allowed("git add -A && git commit -S -m x").is_ok();
    session.config(&["commit.gpgSign", "true"]);
    allowed("git add -A").unwrap();
    allowed("git switch -c feat/signed").unwrap();
    assert_eq!(allowed("git add -A && git commit -m x").is_ok(), explicit);
    session.config(&["gpg.program", "/tmp/gpg"]);
    allowed("git add -A").unwrap();
    assert!(allowed("git add -A && git commit -m x").is_err());
    session.config(&["--unset-all", "gpg.program"]);
    session.config(&["--unset-all", "commit.gpgSign"]);
    // Each form answers only for the hooks it runs.
    let hook = session.primary.join(".git/hooks/pre-commit");
    executable_hook(&hook);
    allowed("git add notes.md").unwrap();
    assert!(allowed("git commit -m x").is_err());
    std::fs::remove_file(hook).unwrap();
    executable_hook(&session.primary.join(".git/hooks/post-index-change"));
    assert!(allowed("git add notes.md").is_err());
}

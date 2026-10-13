#![cfg(unix)]

#[allow(dead_code)]
#[path = "support/git_helper_fixture.rs"]
mod fixture;

use fixture::{evaluate_pre_tool_envelope_with_context, FixtureCleanup};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

struct Session {
    home: PathBuf,
    org: PathBuf,
    primary: PathBuf,
    worktree: PathBuf,
    _cleanup: FixtureCleanup,
}

fn default_controls() -> guard_command::native_command_controls::CompiledNativeCommandControls {
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

fn git(home: &Path, directory: &Path, arguments: &[&str]) {
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
fn session(label: &str) -> Session {
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
        evaluate_pre_tool_envelope_with_context(
            "codex",
            "PreToolUse",
            &json!({"tool_name":"bash", "tool_input":{"command":command}}),
            Some(&default_controls()),
            None,
            self.home.to_str(),
            self.org.to_str(),
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

    fn config(&self, arguments: &[&str]) {
        let mut full = vec!["config"];
        full.extend_from_slice(arguments);
        git(&self.home, &self.primary, &full);
    }
}

fn executable_hook(path: &Path) {
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
    for command in [
        format!("git -C {primary} fetch evil"),
        format!("git -C {primary} fetch origin --upload-pack=id"),
        format!("git -C {primary} fetch origin '+refs/*:refs/*'"),
        format!("git -C {primary} -c core.sshCommand=id fetch origin"),
        format!("GIT_SSH_COMMAND=id git -C {primary} fetch origin"),
        format!("git -C {primary} fetch origin > out.txt"),
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

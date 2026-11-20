#![cfg(unix)]

use crate::git_helper_fixture as fixture;

use fixture::{evaluate_pre_tool_envelope_with_context, FixtureCleanup};
use serde_json::json;
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
        crate::unique_nanos::unique_nanos()
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

const LOCAL_WRITE: &str = "native_exact_safe_git_local_write";

fn write_global(session: &Session, text: &str) {
    std::fs::write(session.home.join(".gitconfig"), text).unwrap();
}

fn assert_reason(session: &Session, command: &str, reason: &str) {
    let result = session.evaluate(command);
    assert_eq!(result.reason_code, reason, "{command}");
}

#[test]
fn escaped_quote_alias_does_not_block_ordinary_git_operations() {
    let session = session("alias");
    let worktree = session.worktree.display();
    // `git add` and `git merge` run no alias (Git never routes the commit a
    // merge writes through `alias.commit`), so the local write proof settles
    // them behind `-C` as it does after `cd`. The aliased `commit` keeps its
    // floor.
    let commands = [
        format!("git -C {worktree} add tracked.txt"),
        format!("git -C {worktree} merge --ff-only HEAD"),
    ];
    let commit = format!("git -C {worktree} commit -m x");
    write_global(
        &session,
        "[alias]\n\tcommit = !bash \\\"/opt/hooks/commit.sh\\\"\n",
    );
    // The workspace sandbox never takes these on any host: `-C` names a
    // linked worktree outside the session directory, and the sandbox cannot
    // reach its shared Git directory.
    for command in &commands {
        assert_reason(&session, command, LOCAL_WRITE);
    }
    assert_reason(&session, &commit, "native_command_review_required");
    // Backticks keep the aliased command at review, with or without escapes.
    write_global(&session, "[alias]\n\tcommit = !bash \\\"`id`\\\"\n");
    for command in &commands {
        assert_reason(&session, command, LOCAL_WRITE);
    }
    assert_reason(&session, &commit, "native_command_review_required");
    // An unknown escape makes the configuration unreadable, so every
    // command stays at review.
    write_global(&session, "[alias]\n\tcommit = !bash \\q\n");
    for command in &commands {
        assert_reason(&session, command, "native_command_review_required");
    }
    assert_reason(&session, &commit, "native_command_review_required");
}

#[test]
fn instead_of_origin_fetch_is_quiet_only_for_a_github_rewrite() {
    let session = session("instead-of");
    let fetch = format!("git -C {} fetch origin", session.primary.display());
    let allowed = "native_exact_safe_git_origin_refresh";
    session.config(&["remote.origin.url", "git@github.com:acme/app.git"]);
    session.assert_allow(&fetch, allowed);
    session.config(&["url.https://github.com/.insteadOf", "git@github.com:"]);
    session.assert_allow(&fetch, allowed);
    session.config(&["url.https://github.com/.pushInsteadOf", "git@github.com:"]);
    session.assert_allow(&fetch, allowed);
    session.config(&["--unset-all", "url.https://github.com/.pushInsteadOf"]);
    session.config(&["--unset-all", "url.https://github.com/.insteadOf"]);
    session.config(&["url.https://git.example/.insteadOf", "git@github.com:"]);
    session.assert_not_allow(&fetch);
    session.config(&["--unset-all", "url.https://git.example/.insteadOf"]);
    session.config(&["url.git@github.com:.insteadOf", "https://github.com/"]);
    session.config(&["remote.origin.url", "https://github.com/acme/app.git"]);
    session.assert_allow(&fetch, allowed);
    session.config(&["--unset-all", "url.git@github.com:.insteadOf"]);
    session.config(&["url.git@git.example:.insteadOf", "https://github.com/"]);
    session.assert_not_allow(&fetch);
}

#[test]
fn bloated_repository_config_keeps_fetch_quiet_but_not_an_outside_hooks_path() {
    let session = session("bloated");
    let fetch = format!("git -C {} fetch origin", session.primary.display());
    let path = session.primary.join(".git/config");
    let mut config = std::fs::read_to_string(&path).unwrap();
    for index in 0..9000 {
        config.push_str(&format!(
            "[branch \"b{index}\"]\n\tremote = origin\n\tmerge = refs/heads/b{index}\n"
        ));
    }
    assert!(config.len() > 400_000);
    std::fs::write(&path, config).unwrap();
    session.assert_allow(&fetch, "native_exact_safe_git_origin_refresh");
    session.config(&["core.hooksPath", "/tmp/tracked-hooks"]);
    session.assert_not_allow(&fetch);
}

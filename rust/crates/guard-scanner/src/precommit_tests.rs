use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

fn temp_root(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "guard-scanner-precommit-{tag}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// `git init` plus a local empty `core.hooksPath`: hosts may export a
/// global hooks path, and the Python module refuses to touch custom
/// hook directories — an empty local value shadows it for the fixture.
fn git_init(dir: &Path) {
    for args in [
        &["init", "-q"][..],
        &["config", "user.email", "t@t"][..],
        &["config", "user.name", "t"][..],
        &["config", "core.hooksPath", ""][..],
    ] {
        run_git(dir, args, GIT_TIMEOUT_SECONDS).unwrap();
    }
}

#[test]
fn install_and_uninstall_round_trip() {
    let dir = temp_root("roundtrip");
    git_init(&dir);
    let result = install_precommit_hook(&dir).unwrap();
    assert_eq!(result.status, "installed");
    assert_eq!(result.hook, "git-hooks/pre-commit");
    assert!(!result.chained_existing);
    let payload = result.to_public_dict();
    assert_eq!(payload["schema"], "guard-secrets-hook.v1");
    assert_eq!(payload["status"], "installed");

    let hook_path = dir.join(".git/hooks/pre-commit");
    let content = fs::read_to_string(&hook_path).unwrap();
    assert!(content.contains(MANAGED_MARKER));
    assert!(content.ends_with("exec hol-guard secrets scan --staged --fail-on-findings\n"));
    assert_eq!(
        fs::metadata(&hook_path).unwrap().permissions().mode() & 0o777,
        0o755
    );

    // Re-install detects the managed marker.
    let again = install_precommit_hook(&dir).unwrap();
    assert_eq!(again.status, "already_installed");
    assert!(!again.chained_existing);

    let removed = uninstall_precommit_hook(&dir).unwrap();
    assert_eq!(removed.status, "uninstalled");
    assert!(!removed.chained_existing);
    assert!(!hook_path.exists());

    let missing = uninstall_precommit_hook(&dir).unwrap();
    assert_eq!(missing.status, "not_installed");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn install_chains_and_uninstall_restores_user_hook() {
    let dir = temp_root("chain");
    git_init(&dir);
    let hooks = dir.join(".git/hooks");
    let user_hook = hooks.join("pre-commit");
    let user_body = "#!/bin/sh\necho user-hook\n";
    fs::write(&user_hook, user_body).unwrap();
    fs::set_permissions(&user_hook, fs::Permissions::from_mode(0o755)).unwrap();

    let result = install_precommit_hook(&dir).unwrap();
    assert_eq!(result.status, "installed");
    assert!(result.chained_existing);
    let backup = hooks.join(BACKUP_NAME);
    assert_eq!(fs::read_to_string(&backup).unwrap(), user_body);
    assert!(fs::read_to_string(hooks.join("pre-commit"))
        .unwrap()
        .contains(MANAGED_MARKER));

    // Already-installed reporting must notice the preserved backup.
    let again = install_precommit_hook(&dir).unwrap();
    assert_eq!(again.status, "already_installed");
    assert!(again.chained_existing);

    let removed = uninstall_precommit_hook(&dir).unwrap();
    assert_eq!(removed.status, "restored");
    assert!(removed.chained_existing);
    assert_eq!(fs::read_to_string(&user_hook).unwrap(), user_body);
    assert!(!backup.exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn symlinked_hook_is_refused_and_left_in_place() {
    let dir = temp_root("symlink");
    git_init(&dir);
    fs::write(dir.join("elsewhere.sh"), "#!/bin/sh\n").unwrap();
    let hook_path = dir.join(".git/hooks/pre-commit");
    std::os::unix::fs::symlink("../../elsewhere.sh", &hook_path).unwrap();

    for outcome in [install_precommit_hook(&dir), uninstall_precommit_hook(&dir)] {
        let error = outcome.unwrap_err();
        assert_eq!(
            error.to_string(),
            "refusing to modify a non-regular Git hook entry"
        );
    }
    assert_eq!(
        fs::read_link(&hook_path).unwrap(),
        PathBuf::from("../../elsewhere.sh")
    );
    assert!(!dir.join(".git/hooks").join(BACKUP_NAME).exists());
    assert_eq!(
        fs::read_to_string(dir.join("elsewhere.sh")).unwrap(),
        "#!/bin/sh\n"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn uninstall_restores_backup_when_hook_is_missing() {
    let dir = temp_root("orphan-backup");
    git_init(&dir);
    let hooks = dir.join(".git/hooks");
    fs::write(hooks.join(BACKUP_NAME), "#!/bin/sh\necho user\n").unwrap();

    let result = uninstall_precommit_hook(&dir).unwrap();

    assert_eq!(result.status, "restored");
    assert!(result.chained_existing);
    assert_eq!(
        fs::read_to_string(hooks.join("pre-commit")).unwrap(),
        "#!/bin/sh\necho user\n"
    );
    assert!(!hooks.join(BACKUP_NAME).exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn custom_hooks_path_is_refused() {
    let dir = temp_root("hookspath");
    git_init(&dir);
    let shared = dir.join("shared-hooks");
    fs::create_dir_all(&shared).unwrap();
    run_git(
        &dir,
        &["config", "core.hooksPath", shared.to_str().unwrap()],
        GIT_TIMEOUT_SECONDS,
    )
    .unwrap();
    let error = install_precommit_hook(&dir).unwrap_err();
    match error {
        PrecommitError::Value(message) => {
            assert!(
                message.contains("custom core.hooksPath is configured"),
                "{message}"
            );
        }
        other => panic!("expected PrecommitError::Value, got {other:?}"),
    }
    // The custom directory must remain untouched.
    assert!(!shared.join("pre-commit").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn non_git_directory_is_refused() {
    let dir = temp_root("nogit");
    let error = install_precommit_hook(&dir).unwrap_err();
    match error {
        // `git config --get core.hooksPath` falls back to the global
        // config outside a worktree, so a host with a global hooks path
        // surfaces that refusal instead; both are Python outcomes.
        PrecommitError::Value(message) => {
            assert!(
                message == "hook target is not a usable Git worktree"
                    || message.contains("custom core.hooksPath is configured"),
                "{message}"
            );
        }
        other => panic!("expected PrecommitError::Value, got {other:?}"),
    }
    let _ = fs::remove_dir_all(&dir);
}

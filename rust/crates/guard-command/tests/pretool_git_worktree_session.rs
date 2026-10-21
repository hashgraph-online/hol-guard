#![cfg(unix)]

//! The worktree proof judges the configuration the agent's own Git reads:
//! sessions that keep the system file or set `XDG_CONFIG_HOME` are proven
//! against those files rather than turned away, and the usual sibling layout
//! `../name` is accepted while the destination stays under home.

// This session test builds its own execution environment. The shared helper
// `evaluate_pre_tool_envelope_with_context` stays for the other Git fixtures.
use crate::git_helper_fixture as fixture;

use fixture::FixtureCleanup;
use serde_json::json;
use std::path::Path;

fn evaluate(
    repository: &Path,
    command: &str,
    xdg_config_home: Option<&Path>,
    no_system: bool,
) -> guard_contracts::PreToolResultV1 {
    evaluate_in(repository, repository, command, xdg_config_home, no_system)
}

fn evaluate_in(
    repository: &Path,
    cwd: &Path,
    command: &str,
    xdg_config_home: Option<&Path>,
    no_system: bool,
) -> guard_contracts::PreToolResultV1 {
    use sha2::{Digest, Sha256};

    let home = repository.parent().unwrap();
    let path = std::env::var("PATH").unwrap();
    let mut environment = std::collections::BTreeMap::from([
        ("PATH", path.clone()),
        ("HOME", home.to_str().unwrap().to_owned()),
    ]);
    if no_system {
        environment.insert("GIT_CONFIG_NOSYSTEM", "1".to_owned());
    }
    if let Some(directory) = xdg_config_home {
        environment.insert("XDG_CONFIG_HOME", directory.to_str().unwrap().to_owned());
    }
    let context = guard_contracts::GuardExecutionEnvironmentV1 {
        path,
        environment_names: environment.keys().map(|key| (*key).to_owned()).collect(),
        environment_digest: hex::encode(Sha256::digest(serde_json::to_vec(&environment).unwrap())),
        home: Some(home.to_str().unwrap().to_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: xdg_config_home.map(|directory| directory.to_str().unwrap().to_owned()),
        git_config_no_system: no_system,
        library_search_paths: Default::default(),
    };
    guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&fixture::github_controls("enabled")),
        None,
        guard_command::pretool::PathContext {
            home_dir: home.to_str(),
            cwd: cwd.to_str(),
            cdpath_unset: false,
            rustup_override_absent: false,
            npm_config_inert: false,
            pip_config_inert: false,
            shell_home_matches: false,
            ripgrep_config_absent: false,
            psql_environment: Default::default(),
        },
        Some(&context),
    )
}

fn git(repository: &Path, arguments: &[&str]) -> bool {
    std::process::Command::new("git")
        .arg("-C")
        .arg(repository)
        .env("HOME", repository.parent().unwrap())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_AUTHOR_NAME")
        .env_remove("GIT_AUTHOR_EMAIL")
        .env_remove("GIT_COMMITTER_NAME")
        .env_remove("GIT_COMMITTER_EMAIL")
        .args(arguments)
        .status()
        .unwrap()
        .success()
}

/// Whether the host's system Git configuration has settings the proof turns
/// away, such as the `filter.lfs` section `git lfs install --system` writes.
fn system_config_is_plain() -> bool {
    let output = std::process::Command::new("git")
        .args(["config", "--system", "--name-only", "--list"])
        .output()
        .unwrap();
    // A filter driver only runs for paths an attributes file assigns to it.
    // The fixture tree has none, so only the system attributes file counts.
    let system_attributes = std::process::Command::new("git")
        .args(["var", "GIT_ATTR_SYSTEM"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned());
    let filters_inert = system_attributes.is_some_and(|path| {
        std::fs::read(path).map_or(true, |bytes| {
            !String::from_utf8_lossy(&bytes)
                .to_ascii_lowercase()
                .contains("filter")
        })
    });
    String::from_utf8_lossy(&output.stdout).lines().all(|key| {
        let key = key.to_ascii_lowercase();
        if key.starts_with("filter.") {
            return filters_inert;
        }
        ![
            "hook.",
            "pager.",
            "include",
            "extensions.",
            "submodule.",
            "core.bare",
            "core.hookspath",
            "core.worktree",
            "core.fsmonitor",
            "core.sshcommand",
            "core.gitproxy",
            "core.askpass",
            "core.pager",
        ]
        .iter()
        .any(|prefix| key.starts_with(prefix))
    })
}

#[test]
fn worktree_proof_follows_the_session_git_configuration() {
    let root_directory = if cfg!(target_os = "macos") {
        std::path::PathBuf::from("/tmp")
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target")
    };
    let root = std::fs::canonicalize(root_directory).unwrap().join(format!(
        "guard-git-worktree-session-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let repository = root.join("repository");
    let _cleanup = FixtureCleanup(root.clone());
    std::fs::create_dir_all(&repository).unwrap();
    assert!(git(&repository, &["init", "--quiet"]));
    assert!(git(&repository, &["config", "user.name", "Guard Fixture"]));
    assert!(git(
        &repository,
        &["config", "user.email", "guard-fixture@example.invalid"]
    ));
    std::fs::write(repository.join("tracked.txt"), "fixture\n").unwrap();
    assert!(git(&repository, &["add", "tracked.txt"]));
    assert!(git(&repository, &["commit", "--quiet", "-m", "fixture"]));

    // Git creates missing parent directories itself. A first worktree under
    // an ordinary scratch directory must not need a separate mkdir approval.
    let nested = "git worktree add .worktrees/review -b nested-review HEAD";
    assert!(!repository.join(".worktrees").exists());
    let admitted = evaluate(&repository, nested, None, true);
    assert_eq!(admitted.minimum_action, "allow", "{}", admitted.reason_code);
    assert_eq!(admitted.reason_code, "native_exact_safe_worktree_add");
    assert!(git(
        &repository,
        &[
            "worktree",
            "add",
            "--quiet",
            ".worktrees/review",
            "-b",
            "nested-review",
            "HEAD"
        ]
    ));
    assert!(repository.join(".worktrees/review/tracked.txt").is_file());
    std::os::unix::fs::symlink("absent", repository.join(".worktrees/dangling")).unwrap();
    std::fs::write(repository.join(".worktrees/file"), "not a directory").unwrap();
    // Existing targets and execution-control destinations remain reviewed.
    for destination in [
        ".worktrees/review",
        ".git/hooks/new/review",
        ".github/workflows/new/review",
        ".worktrees/dangling/new/review",
        ".worktrees/file/new/review",
    ] {
        let result = evaluate(
            &repository,
            &format!("git worktree add {destination} -b protected-review HEAD"),
            None,
            true,
        );
        assert_ne!(result.minimum_action, "allow", "{destination}");
    }

    let sibling = "git worktree add ../weekly-report -b weekly-report";
    let admitted = evaluate(&repository, sibling, None, true);
    assert_eq!(admitted.minimum_action, "allow", "{}", admitted.reason_code);
    assert_eq!(admitted.reason_code, "native_exact_safe_worktree_add");
    assert!(git(
        &repository,
        &[
            "worktree",
            "add",
            "--quiet",
            "../weekly-report",
            "-b",
            "weekly-report"
        ]
    ));
    assert!(root.join("weekly-report/tracked.txt").is_file());

    // Climbing out of home lands beside it. A fresh leaf directly in the
    // shared temporary root, where the macOS fixture home sits, is admitted
    // like any temporary checkout; anywhere else outside home is reviewed.
    let beside_home = format!(
        "git worktree add ../../{}-beside -b beside-home",
        root.file_name().unwrap().to_str().unwrap()
    );
    let beside_home = evaluate(&repository, &beside_home, None, true);
    let home_in_temporary_root = root.parent() == std::fs::canonicalize("/tmp").ok().as_deref();
    assert_eq!(
        beside_home.minimum_action == "allow",
        home_in_temporary_root,
        "{}",
        beside_home.reason_code
    );

    // Leaving home and the temporary directories, or climbing anywhere but
    // the start, keeps review.
    for command in [
        "git worktree add ../../../outside-home -b outside-home",
        "git worktree add sub/../escape -b escape",
        "git worktree add ./here -b here",
        "git worktree add .. -b parent",
        "git worktree add ../.hidden -b hidden",
    ] {
        let result = evaluate(&repository, command, None, true);
        assert_ne!(result.minimum_action, "allow", "{command}");
        // Only the checkout that would leave home is told about the bound.
        assert_eq!(
            result.reason.contains("inside your home directory"),
            command.contains("outside-home"),
            "{command}: {}",
            result.reason
        );
    }

    let xdg = root.join("xdg");
    std::fs::create_dir_all(xdg.join("git")).unwrap();
    std::fs::write(
        xdg.join("git/config"),
        "[user]\n\tname = Guard Fixture\n[credential]\n\thelper = cache\n",
    )
    .unwrap();
    let with_xdg = evaluate(
        &repository,
        "git worktree add ../xdg-report -b xdg-report",
        Some(&xdg),
        true,
    );
    assert_eq!(with_xdg.minimum_action, "allow", "{}", with_xdg.reason_code);

    // The XDG file is read, so a hook directory set there is seen.
    std::fs::write(
        xdg.join("git/config"),
        format!("[core]\n\thooksPath = {}\n", root.join("hooks").display()),
    )
    .unwrap();
    let hooked = evaluate(
        &repository,
        "git worktree add ../hooked-report -b hooked-report",
        Some(&xdg),
        true,
    );
    assert_ne!(hooked.minimum_action, "allow");

    // Without GIT_CONFIG_NOSYSTEM the system file is read too and judged
    // like the others.
    let with_system = evaluate(
        &repository,
        "git worktree add ../system-report -b system-report",
        None,
        false,
    );
    if system_config_is_plain() {
        assert_eq!(
            with_system.minimum_action, "allow",
            "{}",
            with_system.reason_code
        );
    } else {
        assert_ne!(with_system.minimum_action, "allow");
    }
}

fn fixture_repository(label: &str) -> (std::path::PathBuf, FixtureCleanup) {
    let root_directory = if cfg!(target_os = "macos") {
        std::path::PathBuf::from("/tmp")
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target")
    };
    let root = std::fs::canonicalize(root_directory).unwrap().join(format!(
        "guard-git-worktree-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let cleanup = FixtureCleanup(root.clone());
    let repository = root.join("repository");
    std::fs::create_dir_all(&repository).unwrap();
    assert!(git(&repository, &["init", "--quiet"]));
    assert!(git(&repository, &["config", "user.name", "Guard Fixture"]));
    assert!(git(
        &repository,
        &["config", "user.email", "guard-fixture@example.invalid"]
    ));
    std::fs::write(repository.join("tracked.txt"), "fixture\n").unwrap();
    assert!(git(&repository, &["add", "tracked.txt"]));
    assert!(git(&repository, &["commit", "--quiet", "-m", "fixture"]));
    (repository, cleanup)
}

fn allowed(repository: &Path, command: &str) -> bool {
    let result = evaluate(repository, command, None, true);
    result.minimum_action == "allow" && result.reason_code == "native_exact_safe_worktree_add"
}

#[test]
fn worktree_proof_accepts_a_leading_directory_change() {
    let (repository, _cleanup) = fixture_repository("chdir");
    let home = repository.parent().unwrap().to_owned();
    let repo = repository.to_str().unwrap();
    let from_home = |command: &str| {
        let result = evaluate_in(&repository, &home, command, None, true);
        result.minimum_action == "allow" && result.reason_code == "native_exact_safe_worktree_add"
    };
    assert!(from_home(&format!(
        "git -C {repo} worktree add -b fix/one {}/one HEAD",
        home.display()
    )));
    // Relative to the -C directory, `../<home name>` is a fresh leaf in home.
    // From the cwd (home) it would name home itself, which exists, so the
    // acceptance proves the -C directory is used.
    let home_name = home.file_name().unwrap().to_str().unwrap();
    assert!(from_home(&format!(
        "git -C {repo} worktree add -b fix/two ../{home_name}"
    )));
    assert!(from_home(
        "git -C repository worktree add -b fix/three ../three"
    ));
    for command in [
        format!("git -C {repo} -C {repo} worktree add -b a ../a"),
        "git -C '' worktree add -b a ../a".to_owned(),
        format!("git -C {repo}/missing worktree add -b a ../a"),
        format!("git -C {repo}/tracked.txt worktree add -b a ../a"),
        format!("git -C {repo} --git-dir=.git worktree add -b a ../a"),
        format!("git -C {repo} --work-tree=. worktree add -b a ../a"),
        format!("git -C {repo} -c core.hooksPath=/x worktree add -b a ../a"),
        // Above the fixture's parent: neither home nor a temporary directory.
        format!("git -C {repo} worktree add -b a ../../../outside-home-a"),
    ] {
        assert!(!from_home(&command), "{command}");
    }
}

#[test]
fn worktree_proof_allows_inert_global_hooks_path() {
    let (repository, _cleanup) = fixture_repository("hooks");
    let home = repository.parent().unwrap().to_owned();
    let hooks = home.join("hook-manager");
    std::fs::create_dir_all(&hooks).unwrap();
    std::fs::write(hooks.join("commit-msg"), "#!/bin/sh\n").unwrap();
    std::fs::write(hooks.join("helper.sh"), "#!/bin/sh\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};
        std::fs::set_permissions(
            hooks.join("commit-msg"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        symlink(hooks.join("helper.sh"), hooks.join("pre-commit")).unwrap();
    }
    std::fs::write(
        home.join(".gitconfig"),
        format!("[core]\n\thooksPath = {}\n", hooks.display()),
    )
    .unwrap();
    assert!(allowed(&repository, "git worktree add ../h1 -b h1"));
    std::fs::write(
        home.join(".gitconfig"),
        "[core]\n\thooksPath = ~/hook-manager\n",
    )
    .unwrap();
    assert!(allowed(&repository, "git worktree add ../h2 -b h2"));
    std::fs::write(
        home.join(".gitconfig"),
        "[core]\n\thooksPath = hook-manager\n",
    )
    .unwrap();
    assert!(!allowed(&repository, "git worktree add ../h3 -b h3"));

    // A hook Git would run keeps review, including through a symlink name.
    std::fs::write(
        home.join(".gitconfig"),
        "[core]\n\thooksPath = ~/hook-manager\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};
        symlink(hooks.join("helper.sh"), hooks.join("post-index-change")).unwrap();
        assert!(!allowed(&repository, "git worktree add ../h4 -b h4"));
        std::fs::remove_file(hooks.join("post-index-change")).unwrap();
        assert!(allowed(&repository, "git worktree add ../h5 -b h5"));
        std::fs::write(hooks.join("post-checkout"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(
            hooks.join("post-checkout"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(!allowed(&repository, "git worktree add ../h6 -b h6"));
    }

    // Repository-scope hooksPath stays reviewed.
    std::fs::write(home.join(".gitconfig"), "").unwrap();
    assert!(git(
        &repository,
        &["config", "core.hooksPath", hooks.to_str().unwrap()]
    ));
    assert!(!allowed(&repository, "git worktree add ../h7 -b h7"));
}

#[test]
fn worktree_proof_allows_global_filters_only_without_attribute_sources() {
    let (repository, _cleanup) = fixture_repository("filters");
    let home = repository.parent().unwrap().to_owned();
    std::fs::write(
        home.join(".gitconfig"),
        "[filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n\tsmudge = git-lfs smudge -- %f\n\tprocess = git-lfs filter-process\n\trequired = true\n",
    )
    .unwrap();
    assert!(allowed(&repository, "git worktree add ../f1 -b f1"));

    // Global attributes file under the default XDG location.
    let attributes = home.join(".config/git/attributes");
    std::fs::create_dir_all(attributes.parent().unwrap()).unwrap();
    std::fs::write(&attributes, "*.bin filter=lfs\n").unwrap();
    assert!(!allowed(&repository, "git worktree add ../f2 -b f2"));
    std::fs::remove_file(&attributes).unwrap();
    assert!(allowed(&repository, "git worktree add ../f3 -b f3"));

    // info/attributes.
    let info = repository.join(".git/info");
    std::fs::create_dir_all(&info).unwrap();
    std::fs::write(info.join("attributes"), "*.bin filter=lfs\n").unwrap();
    assert!(!allowed(&repository, "git worktree add ../f4 -b f4"));
    std::fs::remove_file(info.join("attributes")).unwrap();

    // A .gitattributes in the checked-out reference, not just the worktree.
    assert!(git(&repository, &["branch", "plain"]));
    std::fs::write(repository.join(".gitattributes"), "*.bin filter=lfs\n").unwrap();
    assert!(git(&repository, &["add", ".gitattributes"]));
    assert!(git(&repository, &["commit", "--quiet", "-m", "attributes"]));
    assert!(!allowed(&repository, "git worktree add ../f5 -b f5"));
    // The reference actually checked out decides.
    assert!(allowed(
        &repository,
        "git worktree add ../f6 -b f6 refs/heads/plain"
    ));
    assert!(!allowed(&repository, "git worktree add ../f7 -b f7 HEAD"));
}

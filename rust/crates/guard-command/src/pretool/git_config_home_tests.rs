use super::super::PathContext;
use super::execution_free;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn environment(home: &Path) -> guard_contracts::GuardExecutionEnvironmentV1 {
    guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: vec![
            "HOME".to_owned(),
            "PATH".to_owned(),
            "GIT_CONFIG_NOSYSTEM".to_owned(),
        ],
        environment_digest: "0".repeat(64),
        home: Some(home.to_string_lossy().into_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        library_search_paths: Default::default(),
    }
}

struct Fixture {
    root: PathBuf,
    declared: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let nonce = crate::unique_nanos::unique_nanos();
        let root =
            std::env::temp_dir().join(format!("hg-git-tilde-{}-{nonce}", std::process::id()));
        let declared = root.join("declared");
        let repo = declared.join("repo");
        fs::create_dir_all(&repo).unwrap();
        fs::create_dir_all(root.join("shell")).unwrap();
        let mut init = Command::new("git");
        for name in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_NAMESPACE",
        ] {
            init.env_remove(name);
        }
        let init = init
            .arg("init")
            .current_dir(&repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", &declared)
            .output()
            .unwrap();
        assert!(
            init.status.success(),
            "{}",
            String::from_utf8_lossy(&init.stderr)
        );
        assert!(repo.join(".git").is_dir(), "git init left the repository");
        Self { root, declared }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn tilde_change_directory_follows_only_the_shell_home() {
    let fixture = Fixture::new();
    let declared = fixture.declared.canonicalize().unwrap();
    let declared_text = declared.to_str().unwrap();
    let arguments = ["-C", "~/repo", "status", "--short"].map(str::to_owned);
    let context = PathContext {
        home_dir: Some(declared_text),
        cwd: Some(declared_text),
        ..PathContext::default()
    };
    let same = environment(&declared);
    assert_eq!(
        execution_free("git", &arguments, context, None, Some(&same), false),
        Some(true),
        "matching homes still prove the expanded repository"
    );

    let shell = fixture.root.join("shell").canonicalize().unwrap();
    let different = environment(&shell);
    assert_eq!(
        execution_free("git", &arguments, context, None, Some(&different), false),
        Some(false),
        "a different shell HOME must not reuse the declared-home proof"
    );
}

#[test]
fn status_outside_any_repository_runs_nothing() {
    let fixture = Fixture::new();
    let declared = fixture.declared.canonicalize().unwrap();
    let declared_text = declared.to_str().unwrap();
    let environment = environment(&declared);
    let outside = PathContext {
        home_dir: Some(declared_text),
        cwd: Some(declared_text),
        ..PathContext::default()
    };
    let status = ["status".to_owned()];
    assert_eq!(
        execution_free("git", &status, outside, None, Some(&environment), false),
        Some(true),
        "Git stops during setup when no repository is found"
    );

    // An unreadable index inside a repository is not proof of anything.
    let repo = declared.join("repo");
    fs::write(repo.join(".git/index"), b"not an index").unwrap();
    let repo_text = repo.to_str().unwrap();
    let inside = PathContext {
        home_dir: Some(declared_text),
        cwd: Some(repo_text),
        ..PathContext::default()
    };
    assert_eq!(
        execution_free("git", &status, inside, None, Some(&environment), false),
        Some(false)
    );
}

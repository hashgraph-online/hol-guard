//! A tracked gitlink, and the two reads it separates.
//!
//! `git status` and `git diff` open each recorded submodule and refresh its
//! index there, under that submodule's own configuration, so a gitlink leaves
//! them unproven. The status listing stays in the superproject, so the same
//! record must not stop it.

use super::super::super::PathContext;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn declared_environment(home: &Path) -> guard_contracts::GuardExecutionEnvironmentV1 {
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
    home: PathBuf,
    repo: PathBuf,
}

impl Fixture {
    /// A superproject whose index carries one gitlink. The mode of that record
    /// is the whole of what the proof reads, so the entry is written straight
    /// into the index; no second repository is cloned into place.
    fn new() -> Self {
        let nonce = crate::unique_nanos::unique_nanos();
        let root =
            std::env::temp_dir().join(format!("hg-git-gitlink-{}-{nonce}", std::process::id()));
        let home = root.join("home");
        let repo = home.join("superproject");
        fs::create_dir_all(&repo).unwrap();
        let git = |arguments: &[&str]| {
            let mut command = Command::new("git");
            // `HOME` redirects only the global file. Command-scope
            // configuration (`GIT_CONFIG_COUNT` and the indexed key/value
            // pairs it counts), an explicit global or system file, and an
            // inherited `XDG_CONFIG_HOME` all still reach this child, and any
            // of them may name a `core.hooksPath` whose pre-commit hook
            // rejects the synthetic commit below. Drop every one of them so
            // the fixture builds the same repository on any developer's
            // machine. With `XDG_CONFIG_HOME` gone, git falls back to the fixture
            // `HOME`, so no second variable has to be invented here.
            for name in [
                "GIT_DIR",
                "GIT_WORK_TREE",
                "GIT_COMMON_DIR",
                "GIT_INDEX_FILE",
                "GIT_OBJECT_DIRECTORY",
                "GIT_NAMESPACE",
                "GIT_CONFIG_COUNT",
                "GIT_CONFIG_GLOBAL",
                "GIT_CONFIG_SYSTEM",
                "XDG_CONFIG_HOME",
            ] {
                command.env_remove(name);
            }
            let output = command
                .args(arguments)
                .current_dir(&repo)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("HOME", &home)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git {arguments:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap()
        };
        git(&["init"]);
        git(&["config", "user.email", "fixture@example.test"]);
        git(&["config", "user.name", "Fixture"]);
        fs::write(repo.join("README"), "synthetic\n").unwrap();
        git(&["add", "README"]);
        git(&["commit", "--no-gpg-sign", "-m", "first"]);
        let recorded = git(&["rev-parse", "HEAD"]).trim().to_owned();
        fs::write(
            repo.join(".gitmodules"),
            "[submodule \"vendor/lib\"]\n\tpath = vendor/lib\n\turl = ./vendor/lib\n",
        )
        .unwrap();
        git(&["add", ".gitmodules"]);
        git(&[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{recorded},vendor/lib"),
        ]);
        Self { root, home, repo }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn a_gitlink_stops_a_descending_read_and_not_the_status_listing() {
    let fixture = Fixture::new();
    let home = fixture.home.canonicalize().unwrap();
    let repo = fixture.repo.canonicalize().unwrap();
    let context = PathContext {
        home_dir: home.to_str(),
        cwd: repo.to_str(),
        shell_home_matches: true,
        ..PathContext::default()
    };
    let environment = declared_environment(&home);
    let free = |arguments: &[&str]| {
        super::super::super::git_config::execution_free(
            "git",
            &arguments
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>(),
            context,
            None,
            Some(&environment),
            false,
        )
    };
    // The listing names each recorded object id from the superproject index
    // and describes it against the submodule's refs. It starts nothing the
    // submodule's own configuration names, so the gitlink leaves it proven.
    assert_eq!(
        free(&["submodule", "status"]),
        Some(true),
        "a recorded submodule is what the listing is for"
    );
    assert_eq!(free(&["submodule"]), Some(true));
    // The descending reads keep the rejection: each opens the submodule and
    // refreshes its index under configuration this probe never read.
    assert_ne!(
        free(&["status", "--short"]),
        Some(true),
        "a descending read keeps its review beside a gitlink"
    );
    assert_ne!(
        free(&["diff", "--stat"]),
        Some(true),
        "a descending read keeps its review beside a gitlink"
    );
}

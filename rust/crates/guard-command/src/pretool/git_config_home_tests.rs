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
        ..Default::default()
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

#[test]
fn a_scripted_index_comparison_keeps_the_file_monitor_screen() {
    let fixture = Fixture::new();
    let declared = fixture.declared.canonicalize().unwrap();
    let declared_text = declared.to_str().unwrap();
    let environment = environment(&declared);
    let repo = declared.join("repo");
    let repo_text = repo.to_str().unwrap();
    let inside = PathContext {
        home_dir: Some(declared_text),
        cwd: Some(repo_text),
        ..PathContext::default()
    };
    let compares = ["diff-index", "--quiet", "HEAD"].map(str::to_owned);
    let cached = ["diff-index", "--cached", "--name-only", "HEAD"].map(str::to_owned);
    assert_eq!(
        execution_free("git", &compares, inside, None, Some(&environment), false),
        Some(true),
        "a repository that configures nothing starts nothing"
    );

    let config = repo.join(".git/config");
    let existing = fs::read_to_string(&config).unwrap();
    fs::write(
        &config,
        format!("{existing}[core]\n\tfsmonitor = /bin/true\n"),
    )
    .unwrap();
    assert_eq!(
        execution_free("git", &compares, inside, None, Some(&environment), false),
        Some(false),
        "comparing the index against the working tree can start the monitor"
    );
    assert_eq!(
        execution_free("git", &cached, inside, None, Some(&environment), false),
        Some(false),
        "--cached still loads the index, so it still reaches the monitor"
    );
}

#[test]
fn an_index_comparison_against_the_working_tree_keeps_the_filter_screen() {
    let fixture = Fixture::new();
    let declared = fixture.declared.canonicalize().unwrap();
    let declared_text = declared.to_str().unwrap();
    let environment = environment(&declared);
    let repo = declared.join("repo");
    let repo_text = repo.to_str().unwrap();
    let inside = PathContext {
        home_dir: Some(declared_text),
        cwd: Some(repo_text),
        ..PathContext::default()
    };
    fs::write(repo.join(".gitattributes"), "* filter=payload\n").unwrap();
    let config = repo.join(".git/config");
    let existing = fs::read_to_string(&config).unwrap();
    fs::write(
        &config,
        format!("{existing}[filter \"payload\"]\n\tclean = /bin/true\n"),
    )
    .unwrap();

    let compares = ["diff-index", "-p", "HEAD"].map(str::to_owned);
    assert_eq!(
        execution_free("git", &compares, inside, None, Some(&environment), false),
        Some(false),
        "re-examining a working-tree file runs its configured clean filter"
    );

    let cached = ["diff-index", "--cached", "-p", "HEAD"].map(str::to_owned);
    assert_eq!(
        execution_free("git", &cached, inside, None, Some(&environment), false),
        Some(true),
        "--cached compares the index against a tree and opens no file"
    );
}

/// `git diff-files` compares the index against the working tree in every
/// spelling it has, so both screens apply to all of them: the index load can
/// start a configured file monitor, and re-examining the files on disk runs a
/// configured clean filter. There is no `--cached` here to opt out of either.
#[test]
fn the_unstaged_index_comparison_keeps_both_screens() {
    let fixture = Fixture::new();
    let declared = fixture.declared.canonicalize().unwrap();
    let declared_text = declared.to_str().unwrap();
    let environment = environment(&declared);
    let repo = declared.join("repo");
    let repo_text = repo.to_str().unwrap();
    let inside = PathContext {
        home_dir: Some(declared_text),
        cwd: Some(repo_text),
        ..PathContext::default()
    };
    let compares = ["diff-files", "--name-only"].map(str::to_owned);
    assert_eq!(
        execution_free("git", &compares, inside, None, Some(&environment), false),
        Some(true),
        "a repository that configures nothing starts nothing"
    );

    let config = repo.join(".git/config");
    let existing = fs::read_to_string(&config).unwrap();
    fs::write(
        &config,
        format!("{existing}[core]\n\tfsmonitor = /bin/true\n"),
    )
    .unwrap();
    assert_eq!(
        execution_free("git", &compares, inside, None, Some(&environment), false),
        Some(false),
        "loading the index can start the monitor"
    );

    fs::write(&config, existing).unwrap();
    fs::write(repo.join(".gitattributes"), "* filter=payload\n").unwrap();
    let existing = fs::read_to_string(&config).unwrap();
    fs::write(
        &config,
        format!("{existing}[filter \"payload\"]\n\tclean = /bin/true\n"),
    )
    .unwrap();
    assert_eq!(
        execution_free("git", &compares, inside, None, Some(&environment), false),
        Some(false),
        "re-examining a working-tree file runs its configured clean filter"
    );
}

/// `name-rev`, `show-branch`, `check-ref-format` and `symbolic-ref` are
/// plumbing: Git starts no pager for any of them, so an ambient `core.pager`
/// leaves them alone and only the verb's own `pager.<verb>` key can name a
/// program for them to run.
#[test]
fn the_ref_readings_page_only_under_their_own_key() {
    let fixture = Fixture::new();
    let declared = fixture.declared.canonicalize().unwrap();
    let declared_text = declared.to_str().unwrap();
    let environment = environment(&declared);
    let repo = declared.join("repo");
    let repo_text = repo.to_str().unwrap();
    let inside = PathContext {
        home_dir: Some(declared_text),
        cwd: Some(repo_text),
        ..PathContext::default()
    };
    let config = repo.join(".git/config");
    let pristine = fs::read_to_string(&config).unwrap();
    for (verb, words) in [
        ("name-rev", vec!["name-rev", "--name-only", "HEAD"]),
        ("show-branch", vec!["show-branch"]),
        (
            "check-ref-format",
            vec!["check-ref-format", "--branch", "main"],
        ),
        ("symbolic-ref", vec!["symbolic-ref", "--short", "HEAD"]),
    ] {
        let reading: Vec<String> = words.iter().map(|word| (*word).to_owned()).collect();
        fs::write(&config, &pristine).unwrap();
        assert_eq!(
            execution_free("git", &reading, inside, None, Some(&environment), false),
            Some(true),
            "{verb} in a repository that configures nothing starts nothing"
        );

        fs::write(&config, format!("{pristine}[core]\n\tpager = /bin/true\n")).unwrap();
        assert_eq!(
            execution_free("git", &reading, inside, None, Some(&environment), false),
            Some(true),
            "{verb} never starts the ambient pager"
        );

        fs::write(
            &config,
            format!("{pristine}[pager]\n\t{verb} = /bin/true\n"),
        )
        .unwrap();
        assert_eq!(
            execution_free("git", &reading, inside, None, Some(&environment), false),
            Some(false),
            "{verb} runs the program its own pager key names"
        );
    }
}

/// `var` and the stdin filters are plumbing too: Git starts no pager for any
/// of them, so an ambient `core.pager` leaves them alone and only the verb's
/// own `pager.<verb>` key can name a program for them to run.
#[test]
fn the_stdin_filters_page_only_under_their_own_key() {
    let fixture = Fixture::new();
    let declared = fixture.declared.canonicalize().unwrap();
    let declared_text = declared.to_str().unwrap();
    let environment = environment(&declared);
    let repo = declared.join("repo");
    let repo_text = repo.to_str().unwrap();
    let inside = PathContext {
        home_dir: Some(declared_text),
        cwd: Some(repo_text),
        ..PathContext::default()
    };
    let config = repo.join(".git/config");
    let pristine = fs::read_to_string(&config).unwrap();
    for (verb, words) in [
        ("var", vec!["var", "-l"]),
        ("patch-id", vec!["patch-id", "--stable"]),
        ("stripspace", vec!["stripspace", "--strip-comments"]),
        ("check-mailmap", vec!["check-mailmap", "--stdin"]),
        ("interpret-trailers", vec!["interpret-trailers", "--parse"]),
    ] {
        let reading: Vec<String> = words.iter().map(|word| (*word).to_owned()).collect();
        fs::write(&config, &pristine).unwrap();
        assert_eq!(
            execution_free("git", &reading, inside, None, Some(&environment), false),
            Some(true),
            "{verb} in a repository that configures nothing starts nothing"
        );

        fs::write(&config, format!("{pristine}[core]\n\tpager = /bin/true\n")).unwrap();
        assert_eq!(
            execution_free("git", &reading, inside, None, Some(&environment), false),
            Some(true),
            "{verb} never starts the ambient pager"
        );

        fs::write(
            &config,
            format!("{pristine}[pager]\n\t{verb} = /bin/true\n"),
        )
        .unwrap();
        assert_eq!(
            execution_free("git", &reading, inside, None, Some(&environment), false),
            Some(false),
            "{verb} runs the program its own pager key names"
        );
    }
}

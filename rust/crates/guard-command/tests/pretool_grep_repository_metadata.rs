#![cfg(unix)]
//! Recursive `grep` over a repository reads its `.git` entry.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn git(directory: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

/// A home with the working project and a committed sibling repository. The
/// root stays below the target directory: `$TMPDIR` on macOS resolves under
/// `/private/var`, which the sensitive-root screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-grep-repository-metadata")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    write(home.join("project/main.py"), "print('retry')\n");
    write(home.join("other-project/notes.md"), "retry once\n");
    let sibling = home.join("other-project");
    git(&sibling, &["init", "--quiet"]);
    git(&sibling, &["config", "user.name", "Fixture"]);
    git(
        &sibling,
        &["config", "user.email", "fixture@example.invalid"],
    );
    git(&sibling, &["add", "notes.md"]);
    git(&sibling, &["commit", "--quiet", "-m", "Synthetic baseline"]);
    std::fs::canonicalize(home).unwrap()
}

fn shell(home: &Path, command: &str) -> String {
    let result = evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        home.to_str(),
        home.join("project").to_str(),
    );
    if result.minimum_action != "allow" {
        eprintln!("{}: {}", result.reason_code, result.reason);
    }
    result.minimum_action
}

#[test]
fn recursive_grep_over_a_sibling_repository_proceeds() {
    let home = home();
    for command in [
        "grep -rln retry ~/other-project",
        "grep -rn retry ~/other-project",
        "grep -c retry ~/other-project/notes.md",
    ] {
        assert_eq!(shell(&home, command), "allow", "{command}");
    }
}

#[test]
fn credential_bearing_repository_config_still_asks() {
    for line in [
        "[http \"https://github.com/\"]\n\textraheader = AUTHORIZATION: basic synthetic\n",
        "[remote \"origin\"]\n\turl = https://user:synthetic@example.com/repo.git\n",
        "[remote \"origin\"]\n\turl = https://synthetic@example.com/repo.git\n",
        "[credential]\n\thelper = store\n",
        "[include]\n\tpath = ../shared.config\n",
    ] {
        let home = home();
        let config = home.join("other-project/.git/config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str(line);
        std::fs::write(&config, text).unwrap();
        assert_ne!(
            shell(&home, "grep -rln retry ~/other-project"),
            "allow",
            "{line}"
        );
    }
}

#[test]
fn repository_key_stores_and_links_still_ask() {
    let home = home();
    write(
        home.join("other-project/.git/git-crypt/keys/default"),
        "synthetic\n",
    );
    assert_ne!(shell(&home, "grep -rln retry ~/other-project"), "allow");

    let home = self::home();
    std::os::unix::fs::symlink(
        home.join("project/main.py"),
        home.join("other-project/.git/linked"),
    )
    .unwrap();
    assert_ne!(shell(&home, "grep -rln retry ~/other-project"), "allow");

    let home = self::home();
    write(home.join("other-project/.git/.env"), "synthetic\n");
    assert_ne!(shell(&home, "grep -rln retry ~/other-project"), "allow");
}

#[test]
fn listings_and_other_hidden_entries_are_unchanged() {
    let home = home();
    write(home.join("other-project/.env"), "retry synthetic\n");
    assert_ne!(shell(&home, "grep -rln retry ~/other-project"), "allow");
    assert_ne!(shell(&home, "grep -rn retry ~/.ssh"), "allow");
}

#[test]
fn legacy_remote_definitions_are_screened() {
    for (directory, text) in [
        (
            "remotes",
            "URL: https://user:synthetic@example.com/repo.git\n",
        ),
        ("branches", "https://synthetic@example.com/repo.git#main\n"),
        // Case-insensitive volumes resolve this like `remotes`.
        (
            "Remotes",
            "URL: https://user:synthetic@example.com/repo.git\n",
        ),
    ] {
        let home = home();
        write(
            home.join(format!("other-project/.git/{directory}/origin")),
            text,
        );
        assert_ne!(
            shell(&home, "grep -rln retry ~/other-project"),
            "allow",
            "{directory}"
        );
    }
    let home = home();
    write(
        home.join("other-project/.git/remotes/origin"),
        "URL: https://github.com/example/repo.git\nPull: refs/heads/main:refs/heads/origin\n",
    );
    assert_eq!(shell(&home, "grep -rln retry ~/other-project"), "allow");
}

#[test]
fn a_git_file_must_be_a_gitdir_pointer() {
    let pointer = |text: &str| {
        let home = home();
        let worktree = home.join("worktree-project");
        write(worktree.join("notes.md"), "retry twice\n");
        write(worktree.join(".git"), text);
        shell(&home, "grep -rln retry ~/worktree-project")
    };
    assert_eq!(pointer("gitdir: /nonexistent/.git/worktrees/x\n"), "allow");
    for text in [
        "synthetic-token-value\n",
        "gitdir: /nonexistent\nsynthetic-token-value\n",
        "",
    ] {
        assert_ne!(pointer(text), "allow", "{text:?}");
    }
}

/// A committed catalog entry whose name carries a credential word is a
/// project document in any repository a recursive search reaches. Every file
/// below holds the pattern, so only the proof of the file itself can admit it:
/// an untracked copy, a `Secret` manifest and a file holding a key keep the
/// review.
#[test]
fn committed_credential_named_documents_in_a_sibling_repository_are_searched() {
    let commit = |home: &Path, name: &str, text: &str| {
        let sibling = home.join("other-project");
        write(sibling.join(name), text);
        git(&sibling, &["add", name]);
        git(&sibling, &["commit", "--quiet", "-m", "Synthetic catalog"]);
    };
    let home = home();
    commit(
        &home,
        "contributions/extensions/command.kubernetes-secrets.json",
        "{\n  \"id\": \"command.kubernetes-secrets\",\n  \"title\": \"retry policy\"\n}\n",
    );
    assert_eq!(shell(&home, "grep -rln retry ~/other-project"), "allow");
    write(
        home.join("other-project/drafts/kubernetes-secrets.json"),
        "{\"title\": \"retry policy\"}\n",
    );
    assert_ne!(shell(&home, "grep -rln retry ~/other-project"), "allow");

    let header = concat!("-----BEGIN RSA PRIVATE", " KEY-----");
    for (name, text) in [
        (
            "deploy/app-secrets.yaml",
            "# retry\napiVersion: v1\nkind: Secret\nmetadata:\n  name: app\n".to_owned(),
        ),
        (
            "config/service-secrets.yaml",
            format!("retry: 1\nsigning: |\n  {header}\n  MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo\n"),
        ),
    ] {
        let home = self::home();
        commit(&home, name, &text);
        assert_ne!(
            shell(&home, "grep -rln retry ~/other-project"),
            "allow",
            "{name}"
        );
    }
}

//! Windows git stays one-time: git reads repository config, attributes,
//! hooks and `PATH` helpers that no digest binds there, so no approval of a
//! git launch is reused, whatever the repository looks like.

use std::path::PathBuf;

use super::launch::{git_repository, put};
use super::{cmd, exact_action_token, json, query, shell, Tree};

const READS: [&str; 10] = [
    "git status",
    "git status --short",
    "git --no-pager log -1",
    "git diff",
    "git show",
    "git ls-files",
    "git rev-parse HEAD",
    "git branch --list",
    "git.exe status",
    "'C:/Program Files/Git/cmd/git.exe' status",
];

fn assert_one_time(tree: &Tree, context: &str) {
    for command in READS {
        let reason = shell(tree, command);
        assert_eq!(reason, Err("git_helper_config"), "{context}: {command}");
    }
    let compound = shell(tree, "cd src && git status");
    assert!(compound.is_err(), "{context}: {compound:?}");
}

/// `git status` run from `relative` under the tree.
fn status_in(tree: &Tree, relative: &str) -> Result<String, &'static str> {
    let cwd = tree.path(relative);
    exact_action_token(&query(tree, "Bash", Some("git status"), json!(null), &cwd))
}

#[test]
fn git_reads_on_windows_stay_one_time() {
    let tree = Tree::new();
    git_repository(&tree);
    let commit = "git -c user.name=t -c user.email=t@t commit -q --allow-empty -m t";
    cmd(&tree.ws(), commit);
    assert_one_time(&tree, "plain repository");
    // The programs Git for Windows ships that run git on the repository.
    for program in ["gitk", "git-gui", "scalar"] {
        let path = format!(r"C:\Program Files\Git\cmd\{program}.exe");
        if PathBuf::from(&path).is_file() {
            let command = format!("'{}' --version", path.replace('\\', "/"));
            assert_eq!(
                shell(&tree, &command),
                Err("git_helper_config"),
                "{program}"
            );
        }
    }
}

#[test]
fn repository_shapes_that_escaped_the_git_digest_stay_one_time() {
    let tree = Tree::new();
    git_repository(&tree);
    let commit = "git -c user.name=t -c user.email=t@t commit -q --allow-empty -m t";
    cmd(&tree.ws(), commit);
    cmd(&tree.ws(), "git worktree add -q wt");
    // A `HEAD` git rejects sends it to the parent repository.
    put(&tree, "ws\\src\\.git\\HEAD", "not a ref\n");
    std::fs::create_dir_all(tree.path("ws\\src\\.git\\objects")).unwrap();
    std::fs::create_dir_all(tree.path("ws\\src\\.git\\refs")).unwrap();
    assert_eq!(status_in(&tree, "ws\\src"), Err("git_helper_config"));
    // Git reads `gitdir: ` exactly, so a padded value names another folder.
    let target = std::fs::read_to_string(tree.path("ws\\wt\\.git")).unwrap();
    let padded = target.replacen("gitdir: ", "gitdir:  ", 1);
    tree.write("ws\\wt\\.git", &padded);
    assert_eq!(status_in(&tree, "ws\\wt"), Err("git_helper_config"));
    // Submodules found through commit trees, and a worktree elsewhere.
    for config in [
        "[diff]\n\tsubmodule = diff\n",
        "[status]\n\tsubmoduleSummary = true\n",
        "[core]\n\tworktree = ../outside\n",
    ] {
        tree.write("ws\\.git\\config", config);
        assert_one_time(&tree, config);
    }
}

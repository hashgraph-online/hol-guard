//! Windows git reuse: Git for Windows finds `astextplain`, the converters it
//! calls and `git-lfs` on `PATH`, `~/bin` first, so a reused read-only git
//! must never reach one, whatever spelling, folder or index layout hides it.

use super::launch::{git_repository, launch, put};
use super::{cmd, shell, Tree};

const LFS_CONFIG: &str = "[filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n\tsmudge = git-lfs smudge -- %f\n\tprocess = git-lfs filter-process\n\trequired = true\n";

#[test]
fn git_path_helpers_never_run_on_reuse() {
    // Git for Windows finds `astextplain` and `git-lfs` on `PATH`, `~/bin`
    // first, so a reused git must not reach either.
    let tree = Tree::new();
    git_repository(&tree);
    tree.write(
        "ws\\.git\\config",
        "[diff \"astextplain\"]\n\ttextconv = astextplain\n",
    );
    for command in [
        "git diff",
        "git show",
        "git log -p",
        "git log --stat",
        "git status -v",
    ] {
        assert_eq!(shell(&tree, command), Err("git_helper_config"), "{command}");
    }
    for command in [
        "git diff --no-textconv",
        "git status",
        "git log -1 --oneline",
    ] {
        assert!(shell(&tree, command).is_ok(), "{command}");
    }
    tree.write("ws\\.git\\config", LFS_CONFIG);
    assert!(shell(&tree, "git status").is_ok());
    // NTFS opens a nested `.GitAttributes` for git's `.gitattributes`.
    put(&tree, "ws\\src\\.GitAttributes", "*.bin filter=lfs\n");
    assert_eq!(shell(&tree, "git status"), Err("git_helper_config"));
    std::fs::remove_file(tree.path("ws\\src\\.GitAttributes")).unwrap();
    tree.write("ws\\.gitattributes", "*.bin filter=lfs -text\n");
    assert_eq!(shell(&tree, "git status"), Err("git_helper_config"));
    assert!(shell(&tree, "git log -1").is_ok());
    // An indexed `.gitattributes` missing from the worktree is read from
    // the index, which no digest binds.
    cmd(&tree.ws(), "git add .gitattributes");
    std::fs::remove_file(tree.path("ws\\.gitattributes")).unwrap();
    assert_eq!(shell(&tree, "git status"), Err("git_helper_config"));
    assert!(shell(&tree, "git log -1").is_ok());
    for name in [
        "GIT_DIR",
        "git_work_tree",
        "GIT_EXEC_PATH",
        "GIT_COMMON_DIR",
        "git_index_file",
    ] {
        let reason = launch(&tree, "git log -1", &|_, _, env| {
            env.insert(name.to_owned(), tree.ws());
        });
        assert_eq!(reason, Err("git_helper_config"), "{name}");
    }
}

#[test]
fn git_option_spellings_cannot_turn_textconv_on() {
    let tree = Tree::new();
    git_repository(&tree);
    tree.write(
        "ws\\.git\\config",
        "[diff \"astextplain\"]\n\ttextconv = astextplain\n",
    );
    // Status takes unique abbreviations, and `--no-textconv` past `--` is a
    // path, not an option.
    for command in [
        "git status --verb",
        "git status --v",
        "git status -sv",
        "git show HEAD -- --no-textconv",
        "git diff -- --no-textconv",
    ] {
        assert_eq!(shell(&tree, command), Err("git_helper_config"), "{command}");
    }
    for command in [
        "git status --short --branch",
        "git status -sb",
        "git show --no-textconv HEAD",
    ] {
        assert!(shell(&tree, command).is_ok(), "{command}");
    }
}

#[test]
fn attributes_the_walk_skips_or_the_index_hides_stay_one_time() {
    let tree = Tree::new();
    git_repository(&tree);
    tree.write("ws\\.git\\config", LFS_CONFIG);
    put(&tree, "ws\\src\\tracked.txt", "tracked\n");
    put(
        &tree,
        "ws\\target\\CACHEDIR.TAG",
        "Signature: 8a477f597d28d172789f06886806bc55\n",
    );
    put(&tree, "ws\\target\\.gitattributes", "* filter=lfs\n");
    cmd(&tree.ws(), "git add src/tracked.txt");
    cmd(&tree.ws(), "git write-tree");
    // An index with only optional extensions and a skipped folder with no
    // tracked path stay reusable.
    assert!(shell(&tree, "git status").is_ok());
    // A build-cache or package folder the walk skips still feeds git the
    // attributes of the tracked paths inside it.
    for marker in ["CACHEDIR.TAG", "pyvenv.cfg"] {
        put(&tree, &format!("ws\\src\\{marker}"), "home = C:\\\n");
        put(&tree, "ws\\src\\.gitattributes", "* filter=lfs\n");
        assert_eq!(
            shell(&tree, "git status"),
            Err("git_helper_config"),
            "{marker}"
        );
        std::fs::remove_file(tree.path(&format!("ws\\src\\{marker}"))).unwrap();
        std::fs::remove_file(tree.path("ws\\src\\.gitattributes")).unwrap();
    }
    // Attributes read from a tree object are bound by no digest.
    tree.write("ws\\.git\\config", "[attr]\n\ttree = HEAD\n");
    assert_eq!(shell(&tree, "git log -1"), Err("git_helper_config"));
}

#[test]
fn split_indexes_fail_closed() {
    let tree = Tree::new();
    git_repository(&tree);
    tree.write("ws\\.git\\config", LFS_CONFIG);
    put(&tree, "ws\\src\\tracked.txt", "tracked\n");
    cmd(&tree.ws(), "git add src/tracked.txt");
    // A split index keeps entries in `sharedindex.<sha>`, out of the parser's
    // sight, so it fails closed.
    assert!(shell(&tree, "git status").is_ok());
    cmd(&tree.ws(), "git update-index --split-index");
    assert!(std::fs::read_dir(tree.path("ws\\.git"))
        .unwrap()
        .flatten()
        .any(|entry| entry
            .file_name()
            .to_string_lossy()
            .starts_with("sharedindex.")));
    assert_eq!(shell(&tree, "git status"), Err("unproven_launch"));
    assert!(shell(&tree, "git log -1").is_ok());
}

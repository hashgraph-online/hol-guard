use super::{assignments, configured_hooks_write, decode};
use std::fs;
use std::path::{Path, PathBuf};

/// A fresh, canonical directory under the build tree.
fn fixture(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/hooks-path-writes")
        .join(name);
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    fs::canonicalize(root).unwrap()
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

/// A repository at `name/repo` whose `.git/config` is `config`, and an empty
/// home beside it.
fn repository(name: &str, config: &str) -> (PathBuf, PathBuf) {
    let base = fixture(name);
    let (repo, home) = (base.join("repo"), base.join("home"));
    write(&repo.join(".git").join("config"), config);
    fs::create_dir_all(&home).unwrap();
    (repo, home)
}

fn hit(target: &Path, home: &Path) -> bool {
    configured_hooks_write(target, home.to_str(), None)
}

#[test]
fn a_relative_hooks_directory_covers_its_files_and_the_directories_that_hold_it() {
    let (repo, home) = repository("relative", "[core]\n\thooksPath = hooks\n");
    assert!(hit(&repo.join("hooks/pre-commit"), &home));
    assert!(hit(&repo.join("hooks"), &home));
    assert!(hit(&repo.join("HOOKS/post-checkout"), &home));
    assert!(!hit(&repo.join("src/app.ts"), &home));
    assert!(!hit(&repo.join("docs/hooks/pre-commit"), &home));
}

#[test]
fn a_header_line_assignment_with_a_comment_names_a_nested_directory() {
    let config = "[core] hooksPath = scripts/githooks # team hooks\n";
    let (repo, home) = repository("header-line", config);
    assert!(hit(&repo.join("scripts/githooks/pre-push"), &home));
    assert!(hit(&repo.join("scripts"), &home));
    assert!(!hit(&repo.join("scripts/build.sh"), &home));
}

// The fixture writes a canonical Windows path (`\\?\D:\...`) unquoted into a git
// config, where backslash starts an escape sequence and `\?` is invalid, so
// the config is unreadable and Guard fails closed. The case needs POSIX paths.
#[cfg(unix)]
#[test]
fn a_hooks_directory_outside_the_work_tree_is_screened_from_that_repository() {
    let base = fixture("outside");
    let (repo, home, shared) = (
        base.join("repo"),
        base.join("home"),
        base.join("shared-hooks"),
    );
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&shared).unwrap();
    write(
        &repo.join(".git").join("config"),
        &format!("[core]\n\thooksPath = {}\n", shared.display()),
    );
    let target = shared.join("pre-commit");
    assert!(!configured_hooks_write(&target, home.to_str(), None));
    assert!(configured_hooks_write(
        &target,
        home.to_str(),
        Some(repo.to_str().unwrap()),
    ));
    assert!(!configured_hooks_write(
        &base.join("notes.txt"),
        home.to_str(),
        Some(repo.to_str().unwrap()),
    ));
}

#[test]
fn a_repository_without_the_setting_keeps_an_ordinary_hooks_directory_writable() {
    let (repo, home) = repository("unset", "[core]\n\tbare = false\n");
    assert!(!hit(&repo.join("hooks/pre-commit"), &home));
    let base = fixture("no-repository");
    assert!(!hit(&base.join("hooks/pre-commit"), &base));
}

#[test]
fn a_linked_worktree_reads_the_shared_configuration() {
    let base = fixture("linked");
    let home = base.join("home");
    fs::create_dir_all(&home).unwrap();
    let common = base.join("main/.git");
    write(&common.join("config"), "[core]\n\thooksPath = hooks\n");
    write(&common.join("worktrees/feature/commondir"), "../..\n");
    let tree = base.join("feature");
    write(
        &tree.join(".git"),
        &format!("gitdir: {}\n", common.join("worktrees/feature").display()),
    );
    assert!(hit(&tree.join("hooks/pre-commit"), &home));
    assert!(!hit(&tree.join("src/lib.rs"), &home));
}

#[test]
fn an_included_file_sets_the_directory_and_is_itself_protected() {
    let (repo, home) = repository("include", "[include]\n\tpath = ../team.gitconfig\n");
    write(
        &repo.join("team.gitconfig"),
        "[core]\n\thooksPath = tools/hooks\n",
    );
    assert!(hit(&repo.join("tools/hooks/commit-msg"), &home));
    assert!(hit(&repo.join("team.gitconfig"), &home));
    assert!(!hit(&repo.join("tools/lint.sh"), &home));
}

#[test]
fn a_hooks_directory_at_the_work_tree_root_covers_only_hook_names() {
    let (repo, home) = repository("root", "[core]\n\thooksPath = .\n");
    assert!(hit(&repo.join("pre-commit"), &home));
    assert!(hit(&repo.join("post-merge.sample"), &home));
    assert!(!hit(&repo.join("README.md"), &home));
    assert!(!hit(&repo.join("src/pre-commit"), &home));
}

#[test]
fn a_continued_value_does_not_hide_the_next_assignment() {
    let config = "[core]\n\teditor = vim \\\n[x]\n\thooksPath = hooks\n";
    let (repo, home) = repository("continued", config);
    assert!(hit(&repo.join("hooks/pre-commit"), &home));
}

#[test]
fn configuration_the_reader_cannot_decode_keeps_the_write_at_review() {
    let (repo, home) = repository("undecodable", "[core]\n\thooksPath = \"hooks\n");
    assert!(hit(&repo.join("src/app.ts"), &home));
    let (repo, home) = repository("unresolved", "[core]\n\thooksPath = ~builder/hooks\n");
    assert!(hit(&repo.join("src/app.ts"), &home));
}

#[test]
fn a_path_that_is_not_utf8_keeps_the_write_at_review() {
    let (repo, home) = repository("non-utf8-hooks", "");
    let config = repo.join(".git").join("config");
    fs::write(&config, b"[core]\n\thooksPath = hooks\xff\n").unwrap();
    assert!(hit(&repo.join("src/app.ts"), &home));
    fs::write(&config, b"[include]\n\tpath = ../team-\xff.gitconfig\n").unwrap();
    assert!(hit(&repo.join("src/app.ts"), &home));
    let base = fixture("non-utf8-gitdir");
    let tree = base.join("feature");
    fs::create_dir_all(&tree).unwrap();
    fs::write(tree.join(".git"), b"gitdir: ../main/.git/worktrees/f\xff\n").unwrap();
    assert!(hit(&tree.join("src/lib.rs"), &base));
}

#[test]
fn bytes_that_are_not_utf8_outside_a_path_leave_the_write_allowed() {
    let (repo, home) = repository("non-utf8-name", "");
    let config = b"[user]\n\tname = Jos\xe9\n[core]\n\thooksPath = hooks # caf\xe9\n";
    fs::write(repo.join(".git").join("config"), config).unwrap();
    assert!(!hit(&repo.join("src/app.ts"), &home));
    assert!(hit(&repo.join("hooks/pre-commit"), &home));
}

#[test]
fn the_global_configuration_applies_outside_any_repository() {
    let base = fixture("global");
    let home = base.join("home");
    write(
        &home.join(".gitconfig"),
        "[core]\n\thooksPath = ~/git-hooks\n",
    );
    assert!(hit(&home.join("git-hooks/pre-commit"), &home));
    assert!(!hit(&home.join("notes/todo.txt"), &home));
    let (repo, _) = repository("global-relative", "");
    write(
        &home.join(".config/git/config"),
        "[core]\n\thooksPath = hooks\n",
    );
    assert!(hit(&repo.join("hooks/pre-commit"), &home));
    assert!(!hit(&repo.join("src/app.ts"), &home));
}

#[test]
fn values_decode_the_way_git_reads_them() {
    assert_eq!(decode(" hooks  ").as_deref(), Some("hooks"));
    assert_eq!(decode(" \"my hooks \" # c").as_deref(), Some("my hooks "));
    assert_eq!(decode(" a\\\\b ; c").as_deref(), Some("a\\b"));
    assert_eq!(decode(" \"x#y\"").as_deref(), Some("x#y"));
    assert_eq!(decode(" a\\q"), None);
    assert_eq!(decode(" a\\"), None);
    assert_eq!(decode(" \"open"), None);
}

#[test]
fn assignments_track_sections_and_skip_comments() {
    let text = "# c = d\n[Core]\n\tHooksPath = a\n[includeIf \"gitdir:/x/\"]\n\tpath = b\n[broken";
    assert_eq!(assignments(text), None);
    let parsed = assignments(&text.replace("[broken", "")).unwrap();
    let keys: Vec<_> = parsed
        .iter()
        .map(|(section, key, _)| (section.as_str(), key.as_str()))
        .collect();
    assert_eq!(keys, [("core", "hookspath"), ("includeif", "path")]);
}

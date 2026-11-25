use super::{holding, searched_names};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn git(root: &Path, home: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .args(["-c", "commit.gpgsign=false"])
        .args(arguments)
        .current_dir(root)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.test")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.test")
        .output()
        .unwrap();
    assert!(output.status.success(), "git {arguments:?}: {output:?}");
}

fn write(root: &Path, relative: &str, text: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn names(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn later() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

/// Tracked files holding a code name as a word are found; a name in many
/// files, a short or dotted name, and an untracked file place nothing.
#[test]
fn names_written_as_code_find_the_tracked_files_holding_them() {
    let (root, home) = (TempDir::new().unwrap(), TempDir::new().unwrap());
    let (root, home) = (root.path(), home.path());
    git(root, home, &["init", "-q", "-b", "main"]);
    write(root, "src/deep/limits.py", "MERGE_LIMIT = 3\n");
    write(root, "src/other.py", "MERGE_LIMITS = 4\n");
    write(root, "README.md", "Set MERGE_LIMIT first.\n");
    write(root, "src/short.py", "abc = 1\nx.y = 2\n");
    for i in 0..9 {
        write(root, &format!("src/f{i}.py"), "comment_id = 1\n");
    }
    git(root, home, &["add", "-A"]);
    git(root, home, &["commit", "-q", "-m", "first"]);
    write(root, "scratch.py", "MERGE_LIMIT = 5\n");
    let asked = searched_names(&names(&["comment_id", "abc", "x.y", "MERGE_LIMIT"]));
    assert_eq!(asked, names(&["comment_id", "MERGE_LIMIT"]));
    let mut found = holding(home, root, &asked, later());
    found.sort();
    assert_eq!(found, names(&["README.md", "src/deep/limits.py"]));
    assert!(holding(home, root, &asked, Instant::now()).is_empty());
}

/// Outside a repository Git searches nothing, even where configuration
/// would let it search the folder.
#[test]
fn a_folder_that_is_no_repository_finds_nothing() {
    let (root, home) = (TempDir::new().unwrap(), TempDir::new().unwrap());
    write(
        home.path(),
        ".gitconfig",
        "[grep]\n\tfallbackToNoIndex = true\n",
    );
    write(root.path(), "limits.py", "MERGE_LIMIT = 3\n");
    let asked = names(&["MERGE_LIMIT"]);
    assert!(holding(home.path(), root.path(), &asked, later()).is_empty());
}

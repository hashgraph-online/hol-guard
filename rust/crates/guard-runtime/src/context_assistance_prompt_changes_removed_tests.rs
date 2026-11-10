use super::*;
use std::fs;
use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;

const BEFORE: &str = "import os


def convert(value):
    \"\"\"Double the value.\"\"\"
    doubled = value * 2
    return doubled


def other():
    return 1
";

const STUBBED: &str = "import os


def convert(value):
    \"\"\"Double the value.\"\"\"
    raise NotImplementedError


def other():
    return 1
";

/// A repository and a home folder outside it.
struct Repo {
    root: TempDir,
    home: TempDir,
}

impl Repo {
    fn new() -> Self {
        let repo = Self {
            root: tempfile::tempdir().unwrap(),
            home: tempfile::tempdir().unwrap(),
        };
        repo.git(&["init", "-q", "-b", "main"]);
        repo
    }

    fn git(&self, arguments: &[&str]) {
        let output = Command::new("git")
            .args(["-c", "commit.gpgsign=false"])
            .args(arguments)
            .current_dir(self.root.path())
            .env("HOME", self.home.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@example.test")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@example.test")
            .output()
            .unwrap();
        assert!(output.status.success(), "git {arguments:?}: {output:?}");
    }

    fn commit(&self, path: &str, text: &str, subject: &str) {
        self.write(path, text);
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "-m", subject]);
    }

    fn write(&self, path: &str, text: &str) {
        let path = self.root.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    /// The note for the stub in `convert`, as the map shows it whole.
    fn note(&self, path: &str) -> Option<String> {
        let text = fs::read_to_string(self.root.path().join(path)).unwrap();
        let start = text
            .lines()
            .position(|line| line.starts_with("def convert"));
        let start = start.unwrap() + 1;
        let shown = [Span::new(path, start as u64, start as u64 + 3, "")];
        let stub = first_stub(&shown, &[(path.to_owned(), text)])?;
        let git = Git::find(self.root.path(), self.home.path()).expect("a trusted git");
        removed(&git, &stub, Instant::now() + Duration::from_secs(10))
    }
}

/// Asked to write a body again after a refactor, an agent searched the
/// history for the old one. The note shows what the stub's commit took out.
#[test]
fn a_stub_shows_what_its_commit_took_out() {
    let repo = Repo::new();
    repo.commit("src/core.py", BEFORE, "first");
    repo.commit(
        "src/core.py",
        STUBBED,
        "Drop old convert implementation for rewrite",
    );
    let note = repo.note("src/core.py").expect("a note");
    assert!(
        note.contains(
            "(\"Drop old convert implementation for rewrite\") wrote the stub at src/core.py:6"
        ),
        "{note}"
    );
    assert!(
        note.contains("\n-    doubled = value * 2\n-    return doubled\n"),
        "{note}"
    );
    assert!(note.contains("+    raise NotImplementedError"), "{note}");
    assert!(!note.contains("def other"), "{note}");
}

/// A stub written where nothing was gives nothing, and so does one not
/// committed yet.
#[test]
fn a_new_or_uncommitted_stub_gives_nothing() {
    let repo = Repo::new();
    repo.commit("src/core.py", STUBBED, "first");
    assert_eq!(repo.note("src/core.py"), None);
    repo.commit("src/core.py", BEFORE, "body");
    repo.write("src/core.py", STUBBED);
    assert_eq!(repo.note("src/core.py"), None);
}

/// A change too long to show is named with the command that shows it.
#[test]
fn a_long_change_is_named() {
    let repo = Repo::new();
    let long: String = (0..120)
        .map(|n| format!("    step_{n} = value + {n}\n"))
        .collect();
    let before = BEFORE.replace("    doubled = value * 2\n", &long);
    repo.commit("src/core.py", &before, "first");
    repo.commit("src/core.py", STUBBED, "Drop old convert");
    let note = repo.note("src/core.py").expect("a note");
    assert!(note.contains("took 121 lines out"), "{note}");
    assert!(note.contains("`git show "), "{note}");
    assert!(!note.contains("step_1 "), "{note}");
}

/// The removed lines are no file's any more, so a secret in them is not
/// shown.
#[test]
fn a_secret_in_the_removed_lines_is_not_shown() {
    let repo = Repo::new();
    let key = format!(
        "{d}BEGIN PRIVATE KEY{d}\nprivate test material\n{d}END PRIVATE KEY{d}",
        d = "-".repeat(5)
    );
    let before = BEFORE.replace(
        "    doubled = value * 2\n",
        &format!("    doubled = value * 2\n{key}\n"),
    );
    repo.commit("src/core.py", &before, "first");
    repo.commit("src/core.py", STUBBED, "Drop old convert");
    assert_eq!(repo.note("src/core.py"), None);
}

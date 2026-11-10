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
        before(&git, &stub, Instant::now() + Duration::from_secs(10))
    }
}

/// Asked to write a body again after a refactor, an agent searched the
/// history for the old one. The note shows the definition before the stub.
#[test]
fn a_stub_shows_its_definition_before() {
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
        note.ends_with(
            "the definition read:\ndef convert(value):\n    \"\"\"Double the value.\"\"\"\n    \
doubled = value * 2\n    return doubled"
        ),
        "{note}"
    );
}

/// Code the same commit took out elsewhere is not the definition's.
#[test]
fn another_definition_removed_with_it_is_not_shown() {
    let repo = Repo::new();
    let gone = "def gone():\n    return 0\n\n\ndef convert(value):";
    let before = BEFORE.replace("def convert(value):", gone);
    repo.commit("src/core.py", &before, "first");
    repo.commit("src/core.py", STUBBED, "Drop old convert");
    let note = repo.note("src/core.py").expect("a note");
    assert!(note.contains("doubled = value * 2"), "{note}");
    assert!(!note.contains("gone"), "{note}");
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

/// A definition too long to show is named with a command that shows it,
/// its path quoted.
#[test]
fn a_long_definition_is_named() {
    let repo = Repo::new();
    let long: String = (0..120)
        .map(|n| format!("    step_{n} = value + {n}\n"))
        .collect();
    let before = BEFORE.replace("    doubled = value * 2\n", &long);
    repo.commit("src dir/core.py", &before, "first");
    repo.commit("src dir/core.py", STUBBED, "Drop old convert");
    let note = repo.note("src dir/core.py").expect("a note");
    assert!(note.contains("The definition ran 123 lines"), "{note}");
    assert!(note.contains(":src dir/core.py'` shows"), "{note}");
    assert!(!note.contains("step_1 "), "{note}");
}

/// The old definition is no file's any more, so a secret in it is not shown.
#[test]
fn a_secret_in_the_old_definition_is_not_shown() {
    let repo = Repo::new();
    let key = format!(
        "{d}BEGIN PRIVATE KEY{d}\nprivate test material\n{d}END PRIVATE KEY{d}",
        d = "-".repeat(5)
    );
    let key = key.replace('\n', "\n    ");
    let before = BEFORE.replace(
        "    doubled = value * 2\n",
        &format!("    doubled = value * 2\n    {key}\n"),
    );
    repo.commit("src/core.py", &before, "first");
    repo.commit("src/core.py", STUBBED, "Drop old convert");
    assert_eq!(repo.note("src/core.py"), None);
}

/// The subject is scanned whole: a password whose host falls past the
/// shortened subject still keeps the note back.
#[test]
fn a_secret_in_the_whole_subject_is_not_shown() {
    let repo = Repo::new();
    let password = ["Kq7Xr2", "mWp9Lq4z"].concat();
    let subject = format!(
        "Drop old convert{} https://alice:{password}@git.lan/alice/notes.git",
        " now".repeat(15)
    );
    repo.commit("src/core.py", BEFORE, "first");
    repo.commit("src/core.py", STUBBED, &subject);
    assert_eq!(repo.note("src/core.py"), None);
}

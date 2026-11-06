use super::*;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::process::Command;
#[cfg(unix)]
use tempfile::TempDir;

const CORE: &str = "import os


def convert(value):
    return value


def other():
    return 1
";

#[cfg(unix)]
fn later() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

/// A repository with one commit, and a home folder outside it.
#[cfg(unix)]
struct Repo {
    root: TempDir,
    home: TempDir,
}

#[cfg(unix)]
impl Repo {
    fn new() -> Self {
        let repo = Self {
            root: tempfile::tempdir().unwrap(),
            home: tempfile::tempdir().unwrap(),
        };
        repo.git(&["init", "-q", "-b", "main"]);
        repo.write("src/core.py", CORE);
        repo.commit("first");
        repo
    }

    fn path(&self) -> &Path {
        self.root.path()
    }

    fn git(&self, arguments: &[&str]) -> String {
        let output = Command::new("git")
            .args(["-c", "commit.gpgsign=false"])
            .args(arguments)
            .current_dir(self.path())
            .env("HOME", self.home.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@example.test")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@example.test")
            .output()
            .unwrap();
        assert!(output.status.success(), "git {arguments:?}: {output:?}");
        String::from_utf8(output.stdout).unwrap()
    }

    fn write(&self, relative: &str, text: &str) {
        let path = self.path().join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    fn commit(&self, subject: &str) {
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "-m", subject]);
    }

    fn found(&self) -> Git {
        Git::find(self.path(), self.home.path()).expect("a trusted git")
    }

    fn session(&self, id: &str) -> Session {
        Session {
            root: self.path().to_path_buf(),
            app: "codex".into(),
            id: id.into(),
        }
    }

    /// Every changed file passes the screen, with its text on disk now.
    fn changes(&self, base: Option<&str>) -> Option<String> {
        changes(&self.found(), base, later(), |paths| {
            paths
                .iter()
                .filter_map(|path| {
                    let text = fs::read_to_string(self.path().join(path)).ok()?;
                    Some((path.clone(), text))
                })
                .collect()
        })
    }
}

#[test]
fn prompts_about_changes_are_recognised() {
    for prompt in [
        "A teammate pushed a fix, check it",
        "review the diff before I merge",
        "What changed in convert?",
        "this regression is new",
        "what did we do in this session",
    ] {
        assert!(about_changes(prompt), "{prompt}");
    }
    for prompt in [
        "add a --verbose flag",
        "rename convert to parse",
        "session cookies leak",
    ] {
        assert!(!about_changes(prompt), "{prompt}");
    }
}

#[test]
fn line_counts_keep_a_removed_header_like_line_in_its_part() {
    let diff = "diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -3,3 +3,3 @@ def run():
 x = 1
---- a/old
+y = 2
 z = 3
diff --git a/gone.py b/gone.py
--- a/gone.py
+++ /dev/null
@@ -1 +0,0 @@
-x
diff --git a/b.py b/b.py
--- a/b.py
+++ b/b.py
@@ -1 +1 @@
-a
+b
\\ No newline at end of file
";
    let found = hunks(diff);
    assert_eq!(found.len(), 2, "{found:?}");
    assert_eq!(found[0].path, "a.py");
    assert_eq!(found[0].start, 3);
    assert_eq!(found[0].body, " x = 1\n---- a/old\n+y = 2\n z = 3\n");
    assert_eq!(found[1].path, "b.py");
    assert!(found[1].body.ends_with("\\ No newline at end of file\n"));
}

#[test]
fn parts_are_labeled_with_their_definition_and_bounded() {
    let hunk = |path: &str, start, body: &str| Hunk {
        path: path.into(),
        start,
        body: body.into(),
    };
    let big = format!(" a\n+{}\n", "x".repeat(BUDGET));
    let parts = vec![(
        "Uncommitted".to_owned(),
        vec![
            hunk(
                "src/core.py",
                4,
                " def convert(value):\n-    return value\n+    return value.strip()\n",
            ),
            hunk("src/core.py", 8, &big),
            hunk("private/notes.txt", 1, "+hidden line\n"),
        ],
    )];
    let texts = vec![("src/core.py".to_owned(), CORE.to_owned())];
    let text = render(&parts, &texts).unwrap();
    assert!(text.starts_with(TITLE));
    assert!(
        text.contains(
            "Uncommitted:\nsrc/core.py:4 in def convert(value): (lines 4-5)\n def convert"
        ),
        "{text}"
    );
    assert!(
        text.contains("src/core.py:8 in def other(): (lines 8-9) (diff not shown)"),
        "{text}"
    );
    assert!(
        !text.contains("hidden line"),
        "a file the screen refused is left out"
    );
    assert!(text.len() < TITLE.len() + BUDGET + 200);
    assert_eq!(render(&parts, &[]), None, "nothing screened, nothing sent");
}

#[cfg(unix)]
#[test]
fn a_session_gets_its_uncommitted_edits_and_commits_since_its_first_prompt() {
    let repo = Repo::new();
    let session = repo.session("changes-since-start");
    let base = started(&session, &repo.found(), later()).unwrap();
    assert!(commit_id(&base));
    repo.write("src/core.py", &CORE.replace("return 1", "return 2"));
    repo.commit("teammate: other returns 2");
    assert_eq!(
        started(&session, &repo.found(), later()).as_deref(),
        Some(base.as_str()),
        "the first prompt's commit stays the base"
    );
    repo.write(
        "src/core.py",
        &CORE
            .replace("return 1", "return 2")
            .replace("return value", "return value.strip()"),
    );
    let text = repo.changes(Some(&base)).unwrap();
    let uncommitted = text.find("Uncommitted:\nsrc/core.py:").unwrap();
    let commit = text.find("Commit ").unwrap();
    assert!(uncommitted < commit, "{text}");
    assert!(text.contains("teammate: other returns 2"), "{text}");
    assert!(
        text.contains("in def convert(value): (lines 4-5)")
            && text.contains("+    return value.strip()"),
        "{text}"
    );
    assert!(
        text.contains("in def other(): (lines 8-9)") && text.contains("+    return 2"),
        "{text}"
    );
    assert_eq!(
        repo.changes(Some("--output=/tmp/x"))
            .map(|text| text.contains("Commit ")),
        Some(false)
    );
}

#[cfg(unix)]
#[test]
fn repository_configuration_cannot_start_programs() {
    let repo = Repo::new();
    let base = repo.git(&["rev-parse", "HEAD"]).trim().to_owned();
    let marker = repo.home.path().join("ran");
    let script = repo.home.path().join("run.sh");
    fs::write(
        &script,
        format!("#!/bin/sh\ntouch '{}'\ncat\n", marker.display()),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let script = script.display().to_string();
    repo.write(".gitattributes", "*.py diff=probe\n");
    repo.write("src/core.py", &CORE.replace("return 1", "return 3"));
    repo.commit("signed-looking change");
    for (key, value) in [
        ("core.fsmonitor", script.as_str()),
        ("diff.external", script.as_str()),
        ("diff.probe.command", script.as_str()),
        ("diff.probe.textconv", script.as_str()),
        ("log.showSignature", "true"),
        ("gpg.program", script.as_str()),
        ("core.pager", script.as_str()),
        ("color.ui", "always"),
        ("diff.noprefix", "true"),
    ] {
        repo.git(&["config", key, value]);
    }
    repo.write("src/core.py", &CORE.replace("return 1", "return 4"));
    let text = repo.changes(Some(&base)).unwrap();
    assert!(!marker.exists(), "a configured program ran");
    assert!(
        text.contains("+    return 4") && text.contains("+    return 3"),
        "{text}"
    );
    assert!(!text.contains('\u{1b}'), "no color codes");
}

#[cfg(unix)]
#[test]
fn a_configured_filter_leaves_out_the_working_tree_and_a_partial_clone_everything() {
    let repo = Repo::new();
    let base = repo.git(&["rev-parse", "HEAD"]).trim().to_owned();
    repo.write("src/core.py", &CORE.replace("return 1", "return 5"));
    repo.commit("committed");
    repo.write("src/core.py", &CORE.replace("return 1", "return 6"));
    repo.git(&["config", "filter.probe.clean", "cat"]);
    let text = repo.changes(Some(&base)).unwrap();
    assert!(!text.contains("Uncommitted:"), "{text}");
    assert!(text.contains("+    return 5"), "{text}");
    repo.git(&["config", "remote.origin.promisor", "true"]);
    assert_eq!(repo.changes(Some(&base)), None);
}

#[cfg(unix)]
#[test]
fn a_secret_in_the_diff_is_left_out_though_the_file_no_longer_has_it() {
    let repo = Repo::new();
    let base = repo.git(&["rev-parse", "HEAD"]).trim().to_owned();
    let key = format!(
        "{d}BEGIN PRIVATE KEY{d}\nprivate test material\n{d}END PRIVATE KEY{d}",
        d = "-".repeat(5)
    );
    repo.write("src/core.py", &format!("{CORE}\n{key}\n"));
    repo.commit("add key");
    // The edit is a part of its own; the removed key's part is left out.
    repo.write(
        "src/core.py",
        &CORE.replace("return value", "return value.strip()"),
    );
    repo.commit("drop key");
    let text = repo.changes(Some(&base)).unwrap();
    assert!(text.contains("+    return value.strip()"), "{text}");
    assert!(!text.contains(&"-".repeat(5)), "{text}");
}

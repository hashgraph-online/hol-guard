//! What a session's prompts get through `since_start`, which decides from the
//! session's first prompt where its changes start.
use super::*;

const ON: &str = "[context_assistance]\nenabled=true\nruntime_id='selected'\n\
[context_assistance.features]\nagent_context=true\n\
[context_assistance.sources]\nworkspace_documents=true\nsource_set_id='selected-workspaces'\n";

/// A prompt about a teammate's push gets the newest commit and its diff,
/// first in its session or not, with any uncommitted edits. Other prompts
/// about changes get what changed since the session started.
#[test]
fn a_prompt_about_a_push_gets_the_newest_commit() {
    let repo = Repo::new();
    let first = repo.git(&["rev-parse", "HEAD"]).trim().to_owned();
    repo.write("src/core.py", &CORE.replace("return 1", "return 2"));
    repo.commit("teammate: other returns 2");
    let guard_home = tempfile::tempdir().unwrap();
    fs::write(guard_home.path().join("config.toml"), ON).unwrap();
    let root = fs::canonicalize(repo.path()).unwrap();
    let ask = |session: &Session, prompt: &str| {
        let home = repo.home.path();
        since_start(
            guard_home.path(),
            home,
            &root,
            "codex",
            Some(session),
            prompt,
            later(),
        )
    };
    let pushed = "A teammate pushed a fix and tests fail";
    let review = repo.session("first-prompt-is-a-review");
    assert_eq!(ask(&review, "review the diff"), None);
    assert!(ask(&review, pushed).is_some_and(|text| text.contains("teammate: other returns 2")));
    let session = repo.session("first-prompt-after-push");
    let text = ask(&session, pushed).unwrap();
    let title = "HOL Guard CIGAR: the newest commit in this project and any uncommitted changes";
    assert!(
        text.starts_with(&format!(
            "{title} (the end of this note has what `git diff {}` prints now)",
            &first[..7]
        )) && text.contains("\nsrc/core.py: other 8-9")
            && text.contains(" teammate: other returns 2 (src/core.py)\n")
            && !text.contains("Not committed yet")
            && text.contains("\n+    return 2\n"),
        "{text}"
    );
    repo.write("src/core.py", &CORE.replace("return 1", "return 3"));
    let text = ask(&session, pushed).unwrap();
    assert!(
        text.starts_with(title)
            && text.contains(
                " teammate: other returns 2 (src/core.py)\n\nNot committed yet: src/core.py\n"
            )
            && text.contains("\n+    return 3\n"),
        "{text}"
    );
    let text = ask(&session, "review the diff").unwrap();
    assert!(
        text.contains("since this session started at commit")
            && text.contains("\nsrc/core.py: other 8-9")
            && !text.contains("teammate: other returns 2"),
        "{text}"
    );
    let lone = Repo::new();
    assert_eq!(newest(&lone.found(), pushed, later()), None);
}

/// A file a commit changes and the working tree changes back has no net
/// change since the session started. The commit line and the line on what
/// is not committed still name it, and the note says it is back as it was:
/// shown only the commit, an agent reviewing the session took the undoing
/// edit for a leftover and put the commit's change back.
#[test]
fn a_file_changed_back_is_still_named() {
    let repo = Repo::new();
    repo.write("src/more.py", "def more():\n    return 1\n");
    repo.commit("add more");
    let guard_home = tempfile::tempdir().unwrap();
    fs::write(guard_home.path().join("config.toml"), ON).unwrap();
    let root = fs::canonicalize(repo.path()).unwrap();
    let session = repo.session("changed-back");
    let ask = |prompt: &str| {
        let home = repo.home.path();
        let session = Some(&session);
        since_start(
            guard_home.path(),
            home,
            &root,
            "codex",
            session,
            prompt,
            later(),
        )
    };
    assert_eq!(ask("review the diff"), None);
    let start = repo.git(&["rev-parse", "HEAD"]).trim().to_owned();
    repo.write("src/more.py", "def more():\n    return 2\n");
    repo.commit("more returns 2");
    repo.write("src/core.py", &CORE.replace("return 1", "return 3"));
    repo.commit("other returns 3");
    repo.write("src/core.py", CORE);
    let text = ask("review the diff").unwrap();
    assert!(
        text.contains("\nsrc/more.py: more 1-2")
            && text.contains(" other returns 3 (src/core.py)\n")
            && text.contains(" more returns 2 (src/more.py)\n")
            && text.contains(&format!(
                "\n\nNot committed yet: src/core.py\n\nChanged and then changed back, so as at \
commit {}: src/core.py",
                &start[..7]
            )),
        "{text}"
    );
}

/// Reviewing a session's changes, an agent ran `git status` and
/// `git diff --check` before anything else, though the note held the diff.
/// The note says what they would: the untracked files and the whitespace
/// errors, by name only in files Guard's read accepts.
#[test]
fn a_review_note_says_what_git_status_and_diff_check_would() {
    let repo = Repo::new();
    repo.write("private/notes.txt", "kept\n");
    repo.commit("add notes");
    let base = repo.git(&["rev-parse", "HEAD"]).trim().to_owned();
    let short = &base[..7];
    repo.write("src/core.py", &CORE.replace("return 1", "return 2"));
    repo.commit("other returns 2");
    let note = || {
        let screen = |paths: &[String]| -> Vec<(String, String)> {
            (paths.iter())
                .filter(|path| !path.starts_with("private/"))
                .filter_map(|path| {
                    let text = fs::read_to_string(repo.path().join(path)).ok()?;
                    Some((path.clone(), text))
                })
                .collect()
        };
        changes(&repo.found(), Since::Start(&base), false, later(), screen).unwrap()
    };
    let text = note();
    assert!(
        text.ends_with(&format!(
            "\n\nUntracked files: none.\n\n`git diff --check {short}` finds no whitespace errors."
        )),
        "{text}"
    );
    repo.write(
        "src/core.py",
        &CORE
            .replace("return 1", "return 2")
            .replace("return value", "return value  "),
    );
    repo.write("private/notes.txt", "kept \n");
    repo.write("src/core_test.py", "def test_convert():\n    pass\n");
    repo.write("private/key.txt", "hidden\n");
    let text = note();
    assert!(
        text.ends_with(&format!(
            "\n\nUntracked files, in no diff here: src/core_test.py and 1 more file.\
\n\n`git diff --check {short}` finds:\nsrc/core.py:5: trailing whitespace.\
\n(1 more error left out)"
        )),
        "{text}"
    );
    assert!(
        !text.contains("key.txt") && !text.contains("private/notes.txt:1"),
        "{text}"
    );
}

/// The whole diff has Git's usual three lines of context, as an agent prints
/// it, and one when three make it too big to show.
#[test]
fn a_whole_diff_has_three_lines_of_context_when_it_fits() {
    let repo = Repo::new();
    let lines: Vec<String> = (0..240)
        .map(|n| format!("value_{n:03} = 'some text here'\n"))
        .collect();
    repo.write("src/values.py", &lines.concat());
    repo.commit("add values");
    let base = repo.git(&["rev-parse", "HEAD"]).trim().to_owned();
    let short = &base[..7];
    repo.write("src/core.py", &CORE.replace("return 1", "return 2"));
    let text = repo.changes(Some(&base)).unwrap();
    assert!(
        text.contains(&format!("\n\n`git diff {short}` prints:\n```diff\n"))
            && text.contains("\n \n \n def other():\n-    return 1\n+    return 2\n"),
        "{text}"
    );
    // A change every eighth line: three lines of context pass the limit.
    let changed: Vec<String> = (lines.iter().enumerate())
        .map(|(n, line)| match n % 8 {
            4 => line.replace("some", "other"),
            _ => line.clone(),
        })
        .collect();
    repo.write("src/values.py", &changed.concat());
    let text = repo.changes(Some(&base)).unwrap();
    assert!(
        text.contains(&format!("\n\n`git diff -U1 {short}` prints:\n```diff\n"))
            && text.contains("\n def other():\n-    return 1\n")
            && !text.contains("\n \n def other():")
            && text.matches("\n+value_").count() == 30,
        "{text}"
    );
}

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
        .map(|changed| changed.text)
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
            "{title} (the end of this note has what `git diff -U1 {}` prints now)",
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
        .map(|changed| changed.text)
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

/// A prompt about a push that names no code also gets the tests that use
/// the definitions the push changed, the close ones shown whole: fixing what
/// the push broke, an agent searched the tests for them and read them next.
#[test]
fn a_prompt_about_a_push_gets_the_tests_of_what_it_changed() {
    let repo = Repo::new();
    repo.write(
        "tests/test_core.py",
        "from src.core import convert, other\n\n\ndef test_other():\n    assert other() == 1\n\n\n\
def test_convert():\n    assert convert(2) == 2\n",
    );
    repo.commit("tests");
    repo.write("src/core.py", &CORE.replace("return 1", "return 2"));
    repo.commit("teammate: other returns 2");
    let guard_home = tempfile::tempdir().unwrap();
    fs::write(guard_home.path().join("config.toml"), ON).unwrap();
    let root = fs::canonicalize(repo.path()).unwrap();
    let session = repo.session("push-and-its-tests");
    let pushed = "A teammate pushed a fix and tests fail";
    let home = repo.home.path();
    let changed = since_start(
        guard_home.path(),
        home,
        &root,
        "codex",
        Some(&session),
        pushed,
        later(),
    );
    assert_eq!(changed.as_ref().unwrap().names, ["other"]);
    let mut response = serde_json::json!({ "hookSpecificOutput": {} });
    let at = (guard_home.path(), root.as_path(), "codex", Some(&session));
    let wait = Duration::from_secs(5);
    used::add_tests(&mut response, at, changed.clone(), &[], wait, || true);
    let text = response["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap_or_default();
    assert!(
        text.contains(
            "\n\nTests that use the changed definitions:\ntests/test_core.py: 1 related tests"
        ) && text.contains(
            "\ntests/test_core.py:4-5\n```\ndef test_other():\n    assert other() == 1\n```"
        ) && !text.contains("def test_convert"),
        "{text}"
    );
    // Project context turned off meanwhile sends nothing.
    let mut off = serde_json::json!({ "hookSpecificOutput": {} });
    used::add_tests(&mut off, at, changed, &[], wait, || false);
    assert_eq!(off, serde_json::json!({ "hookSpecificOutput": {} }));
}

/// A prompt saying the newest commit broke something gets a lead after the
/// note's first line: fix from the code shown without running the tests
/// first, then run the tests the prompt names once. Shown the change and
/// the definitions it touched, an agent still ran the tests to see the
/// failure and read each file whole before its edit.
#[test]
fn a_prompt_about_a_failure_leads_with_fixing_from_the_code_shown() {
    let repo = Repo::new();
    repo.write(
        "tests/test_core.py",
        "from src.core import other\n\n\ndef test_other():\n    assert other() == 1\n",
    );
    repo.commit("tests");
    repo.write("src/core.py", &CORE.replace("return 1", "return 2"));
    repo.commit("teammate: other returns 2");
    let guard_home = tempfile::tempdir().unwrap();
    fs::write(guard_home.path().join("config.toml"), ON).unwrap();
    let root = fs::canonicalize(repo.path()).unwrap();
    let session = repo.session("a-failure");
    let ask = |prompt: &str| {
        let home = repo.home.path();
        let changed = since_start(
            guard_home.path(),
            home,
            &root,
            "codex",
            Some(&session),
            prompt,
            later(),
        );
        changed.unwrap().text
    };
    let lead = "This note shows the newest change. Where it caused the failure, fix it from the \
code shown here without running the tests first: open just the range you change (a file must be \
read before it is edited), edit it, then run ";
    let named = ask("`tests/test_core.py::test_other` started failing after the last commit.");
    let (head, rest) = named.split_once("\n\n").unwrap();
    let command = format!(
        "`cd '{}' && python -m pytest -q tests/test_core.py`",
        root.display()
    );
    assert!(
        head.starts_with("HOL Guard CIGAR: the newest commit in this project")
            && rest.starts_with(&format!("{lead}{command} once to check.\n\n"))
            && rest.contains("\nChanged definitions as they read now:"),
        "{named}"
    );
    // Named no test file, or one that is not there, the lead names no command.
    let others = [
        "A teammate just pushed a commit and now some tests fail.",
        "Something in `other` broke recently. tests/test_gone.py::test_other fails.",
        "../tests/test_core.py::test_other fails since the last commit",
    ];
    for prompt in others {
        let text = ask(prompt);
        let check = format!("{lead}the tests that use it once to check.\n\n");
        assert!(text.contains(&check) && !text.contains("pytest"), "{text}");
    }
    // A push no prompt says broke anything leads with nothing.
    let pushed = ask("Review what the teammate pushed.");
    assert!(
        pushed.contains("Changed definitions") && !pushed.contains("This note shows"),
        "{pushed}"
    );
}

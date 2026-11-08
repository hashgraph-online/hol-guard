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

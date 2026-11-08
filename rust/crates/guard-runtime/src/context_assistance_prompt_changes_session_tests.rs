//! What a session's prompts get through `since_start`, which decides from the
//! session's first prompt where its changes start.
use super::*;

const ON: &str = "[context_assistance]\nenabled=true\nruntime_id='selected'\n\
[context_assistance.features]\nagent_context=true\n\
[context_assistance.sources]\nworkspace_documents=true\nsource_set_id='selected-workspaces'\n";

/// A session whose first prompt is about a teammate's push gets the newest
/// commit with its diff. Its later prompts keep the commit the session
/// started at, and a session whose first prompt is about something else never
/// gets the newest commit.
#[test]
fn a_first_prompt_about_a_push_gets_the_newest_commit() {
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
    assert_eq!(ask(&review, pushed), None);
    let session = repo.session("first-prompt-after-push");
    let text = ask(&session, pushed).unwrap();
    let title = "HOL Guard CIGAR: the newest commit in this project and any uncommitted changes";
    assert!(
        text.starts_with(&format!("{title} (`git diff {}` shows", &first[..7]))
            && text.contains("\nsrc/core.py: other 8-9")
            && text.contains("teammate: other returns 2:\n```diff\n")
            && text.contains("\n+    return 2\n"),
        "{text}"
    );
    repo.write("src/core.py", &CORE.replace("return 1", "return 3"));
    let text = ask(&session, pushed).unwrap();
    assert!(
        text.contains("since this session started at commit")
            && text.contains("\nsrc/core.py: other 8-9")
            && !text.contains("teammate: other returns 2"),
        "{text}"
    );
    let lone = Repo::new();
    assert_eq!(newest(&lone.found(), true, pushed, later()), None);
}

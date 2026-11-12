use super::*;

#[test]
fn prompts_about_changes_are_recognised() {
    for prompt in [
        "A teammate pushed a fix, check it",
        "review the diff before I merge",
        "What changed in convert?",
        "this regression is new",
        "test_parse started failing after the last commit",
        "convert started returning None recently",
        "what did we do in this session",
    ] {
        assert!(about_changes(prompt), "{prompt}");
    }
    for prompt in [
        "add a --verbose flag",
        "Implement parse again so its tests pass",
        "rename convert to parse",
        "session cookies leak",
        "Question, no code changes: which function does this?",
    ] {
        assert!(!about_changes(prompt), "{prompt}");
    }
    assert!(about_others("A teammate pushed a fix, check it"));
    assert!(about_others(
        "the parser test is failing since this session"
    ));
    assert!(!about_others("review the diff before I merge"));
    assert!(!about_others("what did we do in this session"));
}

#[test]
fn a_red_build_since_the_last_push_asks_for_the_pushed_commit() {
    let prompt =
        "tests are red on main since the last push, can you sort it out? don't touch the tests";
    assert!(about_changes(prompt), "{prompt}");
    assert!(about_others(prompt), "{prompt}");
    assert!(about_others("the cache broke with the latest push"));
    for prompt in [
        "push this when it passes",
        "add a push method to the queue",
        "make the last pusher win",
        "Not the last push; explain cache eviction",
        "Not since the last push; explain cache eviction",
        "not from after the latest push; explain the cache",
    ] {
        assert!(!about_changes(prompt), "{prompt}");
        assert!(!about_others(prompt), "{prompt}");
    }
}

use super::*;
use serde_json::json;
use std::path::PathBuf;

fn session(app: &str, id: &str) -> Session {
    Session {
        root: PathBuf::from("/ending-tests"),
        app: app.into(),
        id: id.into(),
    }
}

/// A note Guard added ends with how to spend fewer turns on it, worded for
/// the harness: Claude Code is asked to batch its calls, Codex to work from
/// the code shown and to edit and test in one call. Other harnesses, and a
/// prompt Guard added nothing to, get no ending.
#[test]
fn only_a_note_guard_added_ends_with_the_harness_hint() {
    for (harness, ending) in [
        ("claude-code", Some(BATCHING)),
        ("codex", Some(ACT_ON_IT)),
        ("omp", None),
    ] {
        let mut notice = json!({"hookSpecificOutput": {"additionalContext": "notice"}});
        let before = context_len(&notice);
        end_note(&mut notice, harness, before, None);
        assert_eq!(notice["hookSpecificOutput"]["additionalContext"], "notice");
        add_context(&mut notice, "map");
        end_note(&mut notice, harness, before, None);
        let expected = ending.map_or("notice\n\nmap".to_owned(), |ending| {
            format!("notice\n\nmap\n\n{ending}")
        });
        assert_eq!(
            notice["hookSpecificOutput"]["additionalContext"], expected,
            "{harness}"
        );
    }
}

/// The conversation keeps the first note's hint, so a later note of the same
/// session leaves it off; another session, or a prompt Guard added nothing
/// to, does not use it up.
#[test]
fn a_session_gets_the_hint_once() {
    let note = |harness: &str, session: &Session, added: bool| {
        let mut response = json!({"hookSpecificOutput": {"additionalContext": "notice"}});
        let before = context_len(&response);
        if added {
            add_context(&mut response, "map");
        }
        end_note(&mut response, harness, before, Some(session));
        response["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    for (harness, ending) in [("codex", ACT_ON_IT), ("claude-code", BATCHING)] {
        let first = session(harness, "hint-once");
        assert_eq!(note(harness, &first, false), "notice", "{harness}");
        assert!(note(harness, &first, true).ends_with(ending), "{harness}");
        assert_eq!(note(harness, &first, true), "notice\n\nmap", "{harness}");
        let other = session(harness, "hint-once-other");
        assert!(note(harness, &other, true).ends_with(ending), "{harness}");
    }
}

/// Guard holds a shell command that writes files and then runs tests: it
/// cannot match that script to the project's controls. The Codex hint so asks
/// for the edit and the test as two tool calls from one exec script, and
/// never for one script that does both.
#[test]
fn the_codex_hint_asks_for_the_edit_and_the_test_as_two_tool_calls() {
    assert!(ACT_ON_IT.contains("call apply_patch and then run the test command, as two tool calls"));
    assert!(ACT_ON_IT.contains("not with a shell or Python script that writes files"));
    assert!(!ACT_ON_IT.contains("apply the patch and run the tests)"));
}

/// Claude Code ran the whole suite and committed after the doctest or test a
/// note named had passed, a turn each. The hint says that check finishes the
/// change.
#[test]
fn the_claude_code_hint_says_the_named_check_finishes_the_change() {
    assert!(BATCHING.contains("Once the check a note names passes, the change is done"));
    assert!(BATCHING.contains("a full test run or a commit nobody asked for"));
}

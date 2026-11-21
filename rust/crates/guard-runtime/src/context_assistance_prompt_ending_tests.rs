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
        ("omp", Some(SKIP_THE_LIST)),
        ("pi", None),
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

/// Oh My Pi spends a turn on a todo list even for a one-line fix. Guard
/// cannot tell whether Oh My Pi showed an earlier note, so every note it adds
/// there ends with the hint, which asks to skip the list on small fixes.
#[test]
fn every_oh_my_pi_note_asks_to_skip_the_todo_list_on_a_small_fix() {
    let session = session("omp", "every-note");
    for _ in 0..2 {
        let mut response = json!({"hookSpecificOutput": {"additionalContext": "notice"}});
        let before = context_len(&response);
        add_context(&mut response, "map");
        end_note(&mut response, "omp", before, Some(&session));
        assert_eq!(
            response["hookSpecificOutput"]["additionalContext"],
            format!("notice\n\nmap\n\n{SKIP_THE_LIST}")
        );
    }
    assert!(SKIP_THE_LIST.contains("skip the todo list"));
}

/// Claude Code shows the model only a preview of hook context over 10,000
/// characters, so a longer note is cut to fit, with no code block left open,
/// and still ends with the hint. Other harnesses keep the whole note.
#[test]
fn a_long_claude_code_note_is_cut_to_fit() {
    let block = "src/a.py:1-3\n```\ndef f():\n    return 1\n```\n";
    let long = block.repeat(400);
    for harness in ["claude-code", "codex"] {
        let mut response = json!({"hookSpecificOutput": {"additionalContext": ""}});
        add_context(&mut response, &long);
        fit_note(&mut response, harness, 0, (None, &[]), &mut Vec::new());
        end_note(&mut response, harness, 0, None);
        let text = response["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .unwrap();
        if harness == "codex" {
            assert!(text.len() > long.len());
            continue;
        }
        assert!(text.chars().count() < 10_000, "{}", text.len());
        assert_eq!(text.matches("```").count() % 2, 0);
        assert!(text.contains(CUT) && text.ends_with(BATCHING));
    }
}

/// A block opened with four backticks holds code with three; the cut must
/// not take that line for the block's end and leave the block open.
#[test]
fn a_cut_inside_a_longer_fence_drops_the_whole_block() {
    let code = "x = '```'\n".repeat(2_000);
    let text = format!("intro\nsrc/a.py:1-2000\n````\n{code}````\n");
    assert_eq!(cut(&text, 9_000).unwrap(), format!("intro\n{CUT}"));
}

/// A cut right after a label leaves no label without its code.
#[test]
fn a_cut_before_a_block_drops_its_label() {
    let filler = "y = 0\n".repeat(30);
    let text = format!("{filler}src/b.py:1-2\n```\n{}```\n", "z\n".repeat(200));
    let max = filler.len() + "src/b.py:1-2\n".len() + CUT.len() + 1;
    let kept = cut(&text, max).unwrap();
    assert!(!kept.contains("src/b.py"), "{kept}");
}

/// Code cut from a note was never seen, so when a note is cut the session
/// forgets what this prompt showed, whatever its label, and keeps what
/// earlier prompts showed.
#[test]
fn code_cut_from_a_note_is_forgotten() {
    let session = session("claude-code", "cut-forgets");
    let older = seen::Span::new("src/old.py", 1, 2, "def h():\n    return 3");
    seen::remember(&session, std::slice::from_ref(&older));
    let seen_before = seen::earlier(&session);
    let shown = [
        seen::Span::new("src/a.py", 1, 2, "def f():\n    return 1"),
        seen::Span::new("src/b.py", 1, 1, "import os"),
    ];
    seen::remember(&session, &shown);
    let filler = "y = 0\n".repeat(1_700);
    let note = format!("Imports in src/a.py:\n```\nimport os\n```\n{filler}src/b.py (lines 1-1)\n");
    let mut response = json!({"hookSpecificOutput": {"additionalContext": note}});
    let mut files = vec!["src/a.py".to_owned(), "src/b.py".to_owned()];
    fit_note(
        &mut response,
        "claude-code",
        0,
        (Some(&session), &seen_before),
        &mut files,
    );
    assert_eq!(seen::earlier(&session), [older]);
    assert_eq!(files, ["src/a.py"]);
}

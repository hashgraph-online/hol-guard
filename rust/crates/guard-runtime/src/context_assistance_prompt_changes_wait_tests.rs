use super::*;

const LEFT: Duration = Duration::from_millis(2_100);
const LEAST: Duration = Duration::from_millis(300);

/// A review prompt gets no search after the note on changes, so the note has
/// the wait the search would have had. With a third of it, a busy machine ran
/// out of time before the whole diff and the note left it out.
#[test]
fn a_prompt_the_changes_answer_alone_gives_them_the_wait() {
    for prompt in [
        "Review every change made in this session. Remove leftovers or duplication, \
         match the style of the surrounding code, and make sure the full test suite passes.",
        "What changed since this session started?",
        "Review the diff before I commit",
    ] {
        assert!(answered_alone(prompt), "{prompt}");
        assert_eq!(share(prompt, LEFT, LEAST), LEFT - LEAST, "{prompt}");
    }
}

/// A prompt that names code, a file or a phrase still gets its search, and
/// one not about changes gets no note to wait for.
#[test]
fn a_prompt_with_a_search_after_the_note_keeps_two_thirds_for_it() {
    for prompt in [
        "Review the changes to `parse_header` before I commit",
        "Review the changes in src/core.py",
        "Review the changes to \"the cache is stale\" handling",
        "Fix the off-by-one error in the pager",
        "Don't change anything, explain how the cache works",
    ] {
        assert!(!answered_alone(prompt), "{prompt}");
        assert_eq!(share(prompt, LEFT, LEAST), LEFT / 3, "{prompt}");
    }
}

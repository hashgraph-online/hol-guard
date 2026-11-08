use super::*;

/// A file path names its file, which `named` finds; its folders and name
/// are not words to look for, so `src/app/utils.py` does not map every
/// definition that mentions `src`, `app` or `utils`.
#[test]
fn a_file_path_gives_no_search_words() {
    let prompt = "Tests fail because parse is not implemented (src/app/utils.py).";
    let found = terms(prompt);
    assert_eq!(found, ["test", "parse", "implemented"], "{found:?}");
    assert_eq!(named(prompt), ["src/app/utils.py"]);
    assert!(asks_for_tests(&terms("make tests/test_basic.py pass")));
}

/// Quoted punctuation, such as the `>>>` of a doctest, is not a phrase.
#[test]
fn quoted_punctuation_is_no_phrase() {
    assert_eq!(phrases("add `>>>` lines and a \"Usage\" note"), ["usage"]);
}

/// Plain words that say what to do name no code; the same words written as
/// code still do.
#[test]
fn task_words_name_nothing_unless_written_as_code() {
    let found = terms(
        "A teammate just pushed a commit and now some tests fail. Find the root cause in \
         the library code and fix it after the last commit; don't edit the tests.",
    );
    for word in [
        "teammate", "commit", "root", "cause", "library", "code", "last", "edit", "find",
    ] {
        assert!(!found.contains(&word.to_owned()), "{word}: {found:?}");
    }
    assert!(found.contains(&"test".to_owned()), "{found:?}");
    let found = terms(
        "Add a short usage example to the docstring of `Choice.convert` in src/core.py, \
         written as a doctest (`>>>` lines with their expected output). Make sure the \
         example actually passes.",
    );
    for word in [
        "short",
        "usage",
        "docstring",
        "written",
        "doctest",
        "lines",
        "expected",
        "output",
        "sure",
        "actually",
        "passes",
    ] {
        assert!(!found.contains(&word.to_owned()), "{word}: {found:?}");
    }
    assert!(found.contains(&"convert".to_owned()), "{found:?}");
    let found = terms("Fix `last` and `edit` so `toolz.first` keeps working");
    for word in ["last", "edit", "first"] {
        assert!(found.contains(&word.to_owned()), "{word}: {found:?}");
    }
}

/// A name written as a call is code even outside backticks, as are
/// `URL(...)` and `.normalize()`, but not the plural in `item(s)`. A dotted
/// name is also kept whole as a spelling, since it names a member.
#[test]
fn a_called_or_dotted_name_is_written_as_code() {
    let found = marked_terms(
        "Bug: URL('http://a/b/../c').normalize() gives the wrong path; the item(s) too.",
    );
    for name in ["url", "normalize"] {
        assert!(
            found.contains(&(name.to_owned(), true)),
            "{name}: {found:?}"
        );
    }
    assert!(found.contains(&("item".to_owned(), false)), "{found:?}");
    let found = spellings("Rename `peekable.prepend` to `push_front`");
    assert!(found.contains(&"peekable.prepend".to_owned()), "{found:?}");
}

/// A sentence a docstring or comment wraps is still the one the prompt
/// quotes on one line.
#[test]
fn quoted_text_is_found_where_a_comment_wraps_it() {
    let phrase = phrases("which function does this? \"Execute a call and return the result(s).\"");
    let text =
        "def _multicall():\n    \"\"\"execute a call and return the\n    result(s).\n    \"\"\"\n\
                # execute a call and\n# return the result(s).\n";
    assert_eq!(quoted(text, &phrase), [true]);
    assert_eq!(
        quoted("return the\n\nresult", &["the result".to_owned()]),
        [true]
    );
    // A `*` that starts code, not a comment, stays.
    assert_eq!(quoted("x\n*args", &["x args".to_owned()]), [false]);
}

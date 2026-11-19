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

/// An absolute path, to a file or a folder, names a place on the machine the
/// prompt was written on; its folders are not words to look for either.
#[test]
fn an_absolute_path_gives_no_search_words() {
    let found = terms(
        "Output is in /private/tmp/run-501/tasks/b45t.output and C:\\Users\\tester\\wc-q\\out.txt; \
         fix parse in ~/work/app.",
    );
    for word in [
        "private", "tmp", "task", "b45t", "user", "tester", "work", "app",
    ] {
        assert!(!found.contains(&word.to_owned()), "{word}: {found:?}");
    }
    assert!(found.contains(&"parse".to_owned()), "{found:?}");
    // A path behind `=`, with forward slashes after a drive, or quoted with
    // spaces in it is still a path.
    let found = terms(
        "Set output_file=/private/tmp/run-501/b45t.output, path=/home/alice/work, \
         C:/Users/bob/proj and \"C:\\Program Files\\Vendor\\cache\" or `D:\\My Files\\stash`.",
    );
    for word in [
        "private", "tmp", "home", "alice", "user", "bob", "proj", "program", "vendor", "cache",
        "stash",
    ] {
        assert!(!found.contains(&word.to_owned()), "{word}: {found:?}");
    }
    assert!(found.contains(&"outputfile".to_owned()), "{found:?}");
    // A path inside a tag, as a harness writes a background task's output
    // file, is still a path; the words around the tags stay.
    let found = terms(
        "<task-notification><output-file>/private/tmp/claude-501/-Users-alice-work/tasks/b5k.output\
         </output-file><summary>Watch render CI</summary></task-notification>",
    );
    for word in ["private", "tmp", "claude", "user", "alice", "work", "b5k"] {
        assert!(!found.contains(&word.to_owned()), "{word}: {found:?}");
    }
    assert!(found.contains(&"render".to_owned()), "{found:?}");
}

/// Only the path is left out: a name written right after it stays, a path
/// that holds a `tests` folder asks for no tests, and a web route is not a
/// path on the machine.
#[test]
fn words_beside_a_path_and_web_routes_still_count() {
    let found = terms("Run /tmp/repro.py:parse() then fix (/tmp/out),render in the app.");
    for word in ["parse", "render"] {
        assert!(found.contains(&word.to_owned()), "{word}: {found:?}");
    }
    let found = terms("Fix parse; the log is /private/tmp/tests/task.output");
    assert!(!found.contains(&"test".to_owned()), "{found:?}");
    assert!(found.contains(&"parse".to_owned()), "{found:?}");
    let found = terms("Fix the /api/cart/{id} handler, GET /users/{id}/orders and `/v1/refund`.");
    for word in ["api", "cart", "handler", "user", "order", "refund"] {
        assert!(found.contains(&word.to_owned()), "{word}: {found:?}");
    }
    // A backticked command keeps reading as one with its path left out.
    let found = terms("Run `cat /tmp/out/log.txt` and fix render");
    assert_eq!(found, ["render"]);
    // Nor does a path give names written as code.
    let found = spellings("Fix `parse` in C:\\Users\\alice\\Parser.parse and /tmp/my_run/out.log");
    assert_eq!(found, ["parse"]);
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
        // Terms are singular, so `passes` would be found as `passe`.
        assert!(!found.contains(&term_form(word)), "{word}: {found:?}");
    }
    assert!(found.contains(&"convert".to_owned()), "{found:?}");
    let found = terms("Fix `last` and `edit` so `toolz.first` keeps working");
    for word in ["last", "edit", "first"] {
        assert!(found.contains(&word.to_owned()), "{word}: {found:?}");
    }
    // "out" here found `SortedList._pos`, which has a local named `out`, and
    // the agent read that method before looking at what was pushed.
    let found = terms(
        "tests are red on main since the last push, can you sort it out? don't touch the tests",
    );
    for word in ["red", "main", "since", "out", "touch"] {
        assert!(!found.contains(&word.to_owned()), "{word}: {found:?}");
    }
    let found = terms("make `out` and `main()` stop going green when red");
    for word in ["out", "main"] {
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

/// A quote too long to search whole, such as a docstring sentence, is
/// searched by its first words, which the wrapped docstring still holds.
#[test]
fn a_long_quote_is_searched_by_its_first_words() {
    let sentence =
        "Yield all arguments passed to the function in the same order in which they were passed.";
    let found = phrases(&format!(
        "which function does this? \"{sentence}\" Reply with its path."
    ));
    assert_eq!(
        found,
        ["yield all arguments passed to the function in the same order in which they were"]
    );
    let docstring = "def value_chain(*args):\n    \"\"\"Yield all arguments passed to the function in the same\n    order in which they were passed. If an argument itself is iterable then\n";
    assert_eq!(quoted(&docstring.to_lowercase(), &found), [true]);
    let longest = format!("\"{}\"", "word ".repeat(30).trim_end());
    assert_eq!(phrases(&longest), ["word ".repeat(16).trim_end()]);
    let unbroken = format!("`{}`", "x".repeat(100));
    assert_eq!(phrases(&unbroken), ["x".repeat(80)]);
    // Pasted with other line breaks than the source's, still found.
    let pasted = phrases(
        "which function does this? \"Yield all arguments passed to the\n    function in the same order in which they were passed.\"",
    );
    assert_eq!(pasted, found);
    assert_eq!(quoted(&docstring.to_lowercase(), &pasted), [true]);
}

/// A question that says not to change anything asks where code is, so its
/// note lists tests instead of showing them; a fix that keeps the tests
/// unchanged is not one.
#[test]
fn a_prompt_that_asks_for_no_change_is_told_apart() {
    for prompt in [
        "Question, no code changes: which function does this?",
        "quick question, don\u{2019}t change anything: where is the parser?",
        "Explain how retries work without changing anything.",
        "Do not edit files, just tell me where the cache is cleared.",
        "Don't change anything at all. Where is the cache cleared?",
    ] {
        assert!(asks_no_change(prompt), "{prompt}");
    }
    for prompt in [
        "Find every root cause and fix them all without changing the tests.",
        "Rename `a` to `b` everywhere. Behavior must not change.",
        "Implement it again so the existing tests pass.",
        // A prohibition on part of the project limits a fix.
        "Fix the bug in the library code; don't edit the tests.",
        "Fix the parser but don't change anything else.",
        "Make no changes to the public API, just fix the off-by-one.",
        "Don't edit files in tests/, fix the parser.",
        "Change anything needed to fix this.",
        "Tune the piano changes in score.py.",
        "Fix `parse` so it returns \"no changes\" for empty input.",
    ] {
        assert!(!asks_no_change(prompt), "{prompt}");
    }
}

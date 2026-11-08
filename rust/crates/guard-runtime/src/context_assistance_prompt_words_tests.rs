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
    let found = terms("Fix `last` and `edit` so `toolz.first` keeps working");
    for word in ["last", "edit", "first"] {
        assert!(found.contains(&word.to_owned()), "{word}: {found:?}");
    }
}

use super::*;

/// A file path names its file, which `named` finds; its folders are not
/// words to look for, so `src/app/utils.py` does not map every `src` or
/// `app` definition in the project.
#[test]
fn a_file_path_gives_only_its_file_name() {
    let prompt = "Tests fail because parse is not implemented (src/app/utils.py).";
    let found = terms(prompt);
    assert!(found.contains(&"util".to_owned()), "{found:?}");
    assert!(
        !found.iter().any(|term| term == "src" || term == "app"),
        "{found:?}"
    );
    assert_eq!(named(prompt), ["src/app/utils.py"]);
    let test_path = terms("make tests/test_basic.py pass");
    assert!(asks_for_tests(&test_path), "{test_path:?}");
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

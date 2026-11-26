//! Tests shown whole from more than one test file.
use super::tests::{files, later, looking_for, CORE};
use super::{map, Asked};

/// A change whose tests sit in two files gets the close tests of both: the
/// room the best file leaves goes to the next file when its tests match
/// nearly as well. Tests that only share a common word stay as a count.
#[test]
fn close_tests_in_a_second_file_are_shown_too() {
    let core = "def test_sensitive_core():\n    Choice(['a'], case_sensitive=False)\n";
    let types = "def test_sensitive_types():\n    Choice(['b'], case_sensitive=True)\n";
    let common = "def test_plain():\n    Choice(['a'])\n";
    let list = files(&[
        ("src/core.py", CORE),
        ("tests/test_core.py", core),
        ("tests/test_types.py", types),
        ("tests/test_plain.py", common),
    ]);
    let terms = looking_for(&[("choice", true, 3), ("casesensitive", true, 2)]);
    let first = map(&list, &terms, &Asked::default(), later()).unwrap();
    for shown in [
        "tests/test_core.py:1-2\n```\ndef test_sensitive_core():",
        "tests/test_types.py:1-2\n```\ndef test_sensitive_types():",
    ] {
        assert!(first.text.contains(shown), "{}", first.text);
    }
    assert!(!first.text.contains("def test_plain():"), "{}", first.text);
    assert_eq!(first.shown.len(), 2);
}

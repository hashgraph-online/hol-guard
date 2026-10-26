use serde_json::json;

use super::*;

#[test]
fn strip_matches_python_whitespace() {
    assert_eq!(py_strip("\u{1c}\u{a0} x\u{2003}\n"), "x");
    assert_eq!(py_strip("\u{200b}x"), "\u{200b}x");
}

#[test]
fn equality_follows_python() {
    assert!(py_eq(&json!(1), &json!(1.0)));
    assert!(py_eq(&json!(true), &json!(1)));
    assert!(!py_eq(&json!("1"), &json!(1)));
    assert!(py_eq(&json!({"a": [1, 2.0]}), &json!({"a": [1.0, 2]})));
    assert!(!py_eq(&json!(1.5), &json!(1)));
}

#[test]
fn integers_compare_without_overflow() {
    let huge = "123456789012345678901234567890";
    assert_eq!(int_cmp(huge, "9"), Ordering::Greater);
    assert_eq!(int_cmp("-5", "3"), Ordering::Less);
    assert_eq!(int_cmp("-5", "-3"), Ordering::Less);
    assert_eq!(int_cmp("0", "-0"), Ordering::Equal);
}

#[test]
fn version_tuples_split_on_non_digits() {
    let left = version_tuple("3.16.3-rc1").unwrap();
    assert_eq!(left, ["3", "16", "3", "1"]);
    assert_eq!(
        version_cmp(&left, &version_tuple("3.16.3").unwrap()),
        Ordering::Greater
    );
    assert!(version_tuple("abc").is_none());
    assert_eq!(version_tuple("007.0").unwrap(), ["7", ""]);
}

#[test]
fn uuid_requires_canonical_form() {
    let ok = json!("123e4567-e89b-12d3-a456-426614174000");
    assert!(canonical_uuid(Some(&ok), 128));
    assert!(!canonical_uuid(
        Some(&json!("123E4567-E89B-12D3-A456-426614174000")),
        128
    ));
    assert!(!canonical_uuid(
        Some(&json!("{123e4567-e89b-12d3-a456-426614174000}")),
        128
    ));
}

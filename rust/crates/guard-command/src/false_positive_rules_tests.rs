//! Cases carried over from the Python `TestFakeCredentialClassifier` suite
//! that this module replaced.

use super::*;

#[test]
fn placeholder_credentials_are_classified_as_fake() {
    for text in [
        "your-api-key-here",
        "example-token-123",
        "fake_secret_value",
        "<YOUR_API_KEY>",
        "xxxxxxxxxxxxxxxx",
        "test-token",
        "dummy_secret",
        "replace_me",
        "changeme",
        "password123",
        "abc123",
        "my_api_key",
        "sample-credential",
        "TODO: add token here",
        "FIXME: use real key",
    ] {
        assert!(classify_fake_credential_pattern(text), "{text}");
    }
}

#[test]
fn real_looking_credentials_are_not_classified_as_fake() {
    for text in [
        "ghp_RealRealRealRealRealRealRealReal00",
        "AKIARealAwsKeyWithNoNumericRunHere",
        "sk-proj-RealProjectTokenWithoutFakeWords",
    ] {
        assert!(!classify_fake_credential_pattern(text), "{text}");
    }
}

#[test]
fn python_whitespace_helpers_match_str_semantics() {
    assert_eq!(py_strip("\u{1c}rg foo\u{85} "), "rg foo");
    assert_eq!(
        py_split("a\u{1f}b\u{a0}c").collect::<Vec<_>>(),
        ["a", "b", "c"]
    );
    assert_eq!(py_splitlines("a\r\nb\u{2028}c\n"), ["a", "b", "c"]);
    assert_eq!(py_splitlines(""), Vec::<&str>::new());
}

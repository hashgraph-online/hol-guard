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

#[test]
fn regex_whitespace_matches_python_separators() {
    assert_eq!(
        py_whitespace_pattern(r"a\sb\S"),
        r"a[\s\x1c-\x1f]b[^\s\x1c-\x1f]"
    );
    assert_eq!(py_whitespace_pattern(r"[\s;&|]\\s"), r"[\s\x1c-\x1f;&|]\\s");
    assert_eq!(py_whitespace_pattern(r"\[\s\]"), r"\[[\s\x1c-\x1f]\]");
    // Python `re` treats U+001C..U+001F as `\s`; so must every ported pattern.
    for separator in ['\u{1c}', '\u{1d}', '\u{1e}', '\u{1f}'] {
        // A mutating option after a Python-only separator must still be seen,
        // or the fetch would be classified read-only where Python never did.
        for command in [
            format!("curl https://x.com{separator}--data{separator}x"),
            format!("curl https://x.com{separator}-X{separator}POST"),
            format!("curl https://x.com{separator}-o{separator}out"),
        ] {
            assert_eq!(classify_read_only_http_fetch(&command), None, "{command:?}");
        }
        assert_eq!(
            classify_read_only_http_fetch(&format!("x{separator}curl https://x.com")),
            Some("curl")
        );
    }
}

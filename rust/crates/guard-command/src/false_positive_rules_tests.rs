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

/// One recorded `ntpath.expanduser` case: the path, then `USERPROFILE`,
/// `HOMEDRIVE`, `HOMEPATH` and `USERNAME`, then the expansion ntpath returns.
type NtExpanduserVector = (
    &'static str,
    Option<&'static str>,
    Option<&'static str>,
    Option<&'static str>,
    Option<&'static str>,
    &'static str,
);

/// Recorded from `ntpath.expanduser`; runs on every host because the Windows
/// expansion is plain text logic over four environment variables.
#[test]
fn expanduser_nt_matches_recorded_ntpath_vectors() {
    const PROFILE: Option<&str> = Some(r"C:\Users\Me");
    const ME: Option<&str> = Some("Me");
    let vectors: &[NtExpanduserVector] = &[
        (
            r"~\.claude\skills\demo\SKILL.md",
            PROFILE,
            None,
            None,
            ME,
            r"C:\Users\Me\.claude\skills\demo\SKILL.md",
        ),
        (
            "~/.claude/skills/demo/SKILL.md",
            PROFILE,
            None,
            None,
            ME,
            r"C:\Users\Me/.claude/skills/demo/SKILL.md",
        ),
        ("~", PROFILE, None, None, ME, r"C:\Users\Me"),
        (r"~Me\x", PROFILE, None, None, ME, r"C:\Users\Me\x"),
        (r"~Other\x", PROFILE, None, None, ME, r"C:\Users\Other\x"),
        (r"~Other", PROFILE, None, None, ME, r"C:\Users\Other"),
        // The current account's name no longer matches its own home: ntpath
        // has nothing to rename and leaves the text alone.
        (r"~Other\x", PROFILE, None, None, Some("Nope"), r"~Other\x"),
        (r"~Other\x", PROFILE, None, None, None, r"~Other\x"),
        (r"plain\x", PROFILE, None, None, ME, r"plain\x"),
        (
            r"~\x",
            None,
            Some("C:"),
            Some(r"\Users\Me"),
            ME,
            r"C:\Users\Me\x",
        ),
        // No home in the environment at all.
        (r"~\x", None, None, None, ME, r"~\x"),
    ];
    for (path, profile, drive, home, user, expected) in vectors {
        assert_eq!(
            expanduser_nt(path, *profile, *drive, *home, *user),
            *expected,
            "{path:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn expanduser_text_follows_posix_expanduser_not_the_home_prefix_helper() {
    // `~\` is a home prefix to `home_path_text::expand_home` but an unknown
    // account name to posixpath, which hands the text back untouched. Reading
    // it as a home prefix would file any `~\…` target under the real home.
    assert_eq!(
        expanduser_text(r"~\.claude/skills/demo/SKILL.md"),
        r"~\.claude/skills/demo/SKILL.md"
    );
    assert_eq!(
        expanduser_text("~nosuchaccount7f3a/x"),
        "~nosuchaccount7f3a/x"
    );
    assert_eq!(expanduser_text("plain/x"), "plain/x");

    // A named account that does resolve expands to its home, which is how the
    // grammar keeps recognizing `~user/.claude/skills/…` skill docs.
    let user = nix::unistd::User::from_uid(nix::unistd::getuid())
        .expect("passwd lookup")
        .expect("current account");
    let home = user.dir.to_string_lossy().into_owned();
    let home = home.trim_end_matches('/');
    assert_eq!(
        expanduser_text(&format!("~{}/.claude/skills/demo/SKILL.md", user.name)),
        format!("{home}/.claude/skills/demo/SKILL.md")
    );
}

#[cfg(unix)]
#[test]
fn a_named_home_reads_as_the_same_skill_doc_target_as_its_expansion() {
    let user = nix::unistd::User::from_uid(nix::unistd::getuid())
        .expect("passwd lookup")
        .expect("current account");
    let home = user.dir.clone();
    let named = format!("~{}/.claude/skills/demo/SKILL.md", user.name);
    let expanded = home.join(".claude/skills/demo/SKILL.md");
    assert_eq!(
        target_is_known_skill_doc_path(&named, Some(&home)),
        target_is_known_skill_doc_path(&expanded.to_string_lossy(), Some(&home)),
        "{named:?}"
    );
}

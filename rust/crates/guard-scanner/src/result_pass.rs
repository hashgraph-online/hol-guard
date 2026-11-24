//! `pass` as a test result, not a password.
//!
//! The credential assignment rule reads `pass` after `_` or `-` as a password
//! (`DB_PASS`, `smtp-pass`). Test runners, CI scripts and benchmark reports
//! name their results the same way: `"tests_pass": ok`, `both-pass: {...}`,
//! `all_pass = True`, `first_pass: 12`. Blocking that output stopped agents
//! from reading their own test summaries. A `pass` name is a result when the
//! word right before `pass` counts or names tests. A name that also carries
//! another credential word stays a credential.

/// Words that make `<word>_pass` a test outcome or an algorithm pass.
const RESULT_WORDS: [&str; 24] = [
    "test", "tests", "check", "checks", "case", "cases", "suite", "suites", "both", "all", "any",
    "none", "each", "every", "first", "second", "third", "final", "last", "next", "single", "one",
    "two", "multi",
];

/// Credential words that keep a `pass` name a credential whatever precedes it.
const CREDENTIAL_WORDS: [&str; 8] = [
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "key",
    "credential",
    "auth",
];

/// Whether a credential assignment match names a test result: its key ends in
/// `_pass` or `-pass` after a result word and holds no other credential word.
pub(crate) fn is_result_pass(matched: &str) -> bool {
    let Some(index) = matched.find([':', '=']) else {
        return false;
    };
    let name = matched[..index]
        .trim()
        .trim_matches(['"', '\''])
        .to_ascii_lowercase();
    let Some(stem) = name
        .strip_suffix("pass")
        .and_then(|stem| stem.strip_suffix(['_', '-']))
    else {
        return false;
    };
    if CREDENTIAL_WORDS.iter().any(|word| name.contains(word)) {
        return false;
    }
    let word = stem.rsplit(['_', '-']).next().unwrap_or_default();
    RESULT_WORDS.contains(&word)
}

#[cfg(test)]
mod tests {
    use super::is_result_pass;
    use crate::scan_text;
    use guard_rules::MAX_SCAN_BYTES;

    fn credential_assignment(text: &str) -> bool {
        scan_text(text, true, true, MAX_SCAN_BYTES, None)
            .matches
            .iter()
            .any(|matched| matched.classifier == "credential-assignment")
    }

    #[test]
    fn test_result_names_are_not_passwords() {
        for text in [
            "{\"tests_pass\": ok is True, \"total\": 3}\n",
            "both-pass: {'cost': 1.25, 'requests': 14}\n",
            "all_pass = True\n",
            "first_pass: 12\n",
            "CHECKS_PASS=0\n",
            "summary single-pass: done\n",
        ] {
            assert!(!credential_assignment(text), "{text}");
        }
    }

    #[test]
    fn credential_pass_names_stay_flagged() {
        for text in [
            "DB_PASS=Kq7xY2mN9pL4vR8t\n",
            "smtp-pass: Zx81mQ0vB2nW5eR7\n",
            "admin_pass = \"Hq3vN8xL2pW6tY9z\"\n",
            "tests_secret_pass=Kq7xY2mN9pL4vR8t\n",
            "all_token_pass=Kq7xY2mN9pL4vR8t\n",
        ] {
            assert!(credential_assignment(text), "{text}");
        }
    }

    #[test]
    fn reads_the_name_before_the_separator() {
        assert!(is_result_pass("\"tests_pass\": ok"));
        assert!(is_result_pass("both-pass: {"));
        assert!(!is_result_pass("db_pass=x"));
        assert!(!is_result_pass("bypass=x"));
        assert!(!is_result_pass("tests_passphrase=x"));
    }
}

//! `pass` as a test result, not a password.
//!
//! The credential assignment rule reads `pass` after `_` or `-` as a password
//! (`DB_PASS`, `smtp-pass`). Test runners, CI scripts and benchmark reports
//! name their results the same way: `"tests_pass": ok`, `both-pass: {...}`,
//! `all_pass = True`, `first_pass: 12`. Blocking that output stopped agents
//! from reading their own test summaries. A `pass` name is a result when the
//! word right before `pass` counts or names tests and its value reads as a
//! result: a boolean, a count, a status word or the start of a structure.
//! `TEST_PASS` also names a test account's password, so any other value stays
//! a credential, as does a name that carries another credential word.

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

/// Status words a test result is reported with.
const RESULT_VALUES: [&str; 18] = [
    "true", "false", "yes", "no", "ok", "pass", "passed", "fail", "failed", "error", "done",
    "skip", "skipped", "pending", "none", "null", "nil", "n/a",
];

/// Longest number read as a count, score or ratio (`97.5%`, `120/128`).
const MAX_NUMBER_CHARS: usize = 12;
/// Longest bare digit run read as a count; longer, it may be a PIN or
/// numeric password.
const MAX_COUNT_DIGITS: usize = 6;

/// Whether a credential assignment match names a test result: its key ends in
/// `_pass` or `-pass` after a result word, holds no other credential word, and
/// its value reads as a result.
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
    RESULT_WORDS.contains(&word) && result_value(&matched[index + 1..])
}

/// Whether an assigned value reads as a test result rather than a password.
/// An opening `{` or `[` counts only with nothing or a result after it, so
/// `[Kq7x...]` stays a password.
fn result_value(value: &str) -> bool {
    let value = value
        .trim()
        .trim_matches(['"', '\''])
        .trim_end_matches([',', ';', ')', ']', '}'])
        .to_ascii_lowercase();
    if let Some(inner) = value.strip_prefix(['{', '[']) {
        return inner.is_empty() || result_value(inner);
    }
    let digits = value.chars().filter(char::is_ascii_digit).count();
    let number = value.chars().count() <= MAX_NUMBER_CHARS
        && digits > 0
        && (digits < value.len() || digits <= MAX_COUNT_DIGITS)
        && value
            .chars()
            .all(|character| character.is_ascii_digit() || matches!(character, '.' | '%' | '/'));
    number || RESULT_VALUES.contains(&value.as_str())
}

#[cfg(test)]
mod tests {
    use super::is_result_pass;
    use crate::scan_text;
    use guard_rules::MAX_SCAN_BYTES;

    // Built at runtime so secret scanners do not read the test source as a leak.
    const SAMPLE: &str = concat!("Kq7xY2mN", "9pL4vR8tW3sZ");

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
            format!("DB_PASS={SAMPLE}\n"),
            format!("smtp-pass: {SAMPLE}\n"),
            format!("admin_pass = \"{SAMPLE}\"\n"),
            format!("tests_secret_pass={SAMPLE}\n"),
            format!("all_token_pass={SAMPLE}\n"),
            format!("DB_TEST_PASS={SAMPLE}\n"),
            format!("TEST_PASS=\"{SAMPLE}\"\n"),
            format!("admin_test_pass: {SAMPLE}\n"),
            String::from("LAST_PASS=hunter22\n"),
            String::from("ONE_PASS: 'letmein'\n"),
            String::from("TEST_PASS=12345678901234567\n"),
        ] {
            assert!(credential_assignment(&text), "{text}");
        }
    }

    #[test]
    fn reads_the_name_before_the_separator() {
        assert!(is_result_pass("\"tests_pass\": ok"));
        assert!(is_result_pass("both-pass: {"));
        assert!(!is_result_pass("db_pass=x"));
        assert!(!is_result_pass("bypass=x"));
        assert!(!is_result_pass("tests_passphrase=x"));
        assert!(!is_result_pass("test_pass=x"));
        assert!(is_result_pass("test_pass=97.5%"));
        assert!(is_result_pass("CHECKS_PASS=3/4"));
        assert!(is_result_pass("all_pass=[true"));
        assert!(is_result_pass("test_pass=128"));
        assert!(!is_result_pass("ALL_PASS=123456789012"));
        assert!(!is_result_pass(&format!("test_pass=[{SAMPLE}]")));
    }
}

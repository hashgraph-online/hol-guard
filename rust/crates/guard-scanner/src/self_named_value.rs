//! Assignment values that only spell their own field name.
//!
//! Test fixtures and seed data fill credential fields with stand-ins such as
//! `refresh_token="refresh-token-1"` or `password: "password"`. The value is
//! made of the words already in the field name plus at most a short counter,
//! so it carries nothing an attacker could not read from the name itself.
//! Usage examples in doc comments do the same with another credential word,
//! as in `withQuery(url, { token: "secret" })`. Treating those reads as secret
//! output stopped agents opening ordinary test setup files, and kept whole
//! source files out of the context an agent was given.

/// Words that make an assignment name a credential field.
const CREDENTIAL_WORDS: &[&str] = &[
    "apikey",
    "credential",
    "credentials",
    "key",
    "passwd",
    "password",
    "secret",
    "token",
];

/// Ordinary English qualifiers a fixture puts in front of the field name, as
/// in `new_password="correct-password"` or `token="old-token"`. They describe
/// which stand-in a test means, so they add no secret of their own. Words that
/// could name a real account or environment (`admin`, `root`, `prod`) are
/// deliberately absent, a qualifier only leads, and no qualifier may sit
/// beside a counter: `MyPassword1` is a chosen password, not a field name.
const QUALIFIER_WORDS: &[&str] = &[
    "a", "actual", "an", "another", "bad", "changed", "correct", "current", "expected", "first",
    "good", "initial", "invalid", "my", "new", "old", "original", "other", "previous", "second",
    "that", "the", "their", "this", "updated", "valid", "wrong", "your",
];

/// Most qualifier words one value may carry. Two cover `the-old-password`;
/// more words than that stop looking like a field name with a qualifier.
const MAX_QUALIFIER_WORDS: usize = 2;

/// Longest value considered, so a long literal never qualifies by luck.
const MAX_VALUE_CHARS: usize = 64;

/// Whether a credential assignment match assigns a value whose words are all
/// words of the field name, including a credential word, with at most one
/// short numeric counter and two ordinary qualifiers besides. `tail` is the
/// text after the match: a match the value runs on past (`TOKEN=token"$more"`)
/// is not the whole value.
pub(crate) fn is_self_named(matched: &str, tail: &str) -> bool {
    let Some(index) = matched.find([':', '=']) else {
        return false;
    };
    let mut value = matched[index + 1..].trim();
    let quoted = value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')));
    if quoted {
        value = &value[1..value.len() - 1];
    }
    if !ends_value(tail, quoted) {
        return false;
    }
    if value.is_empty() || value.chars().count() > MAX_VALUE_CHARS {
        return false;
    }
    let name_words = words(&matched[..index]);
    let mut credential_word = false;
    let mut counters = 0_usize;
    let mut qualifiers = 0_usize;
    let mut named = false;
    for word in words(value) {
        if word.chars().all(|character| character.is_ascii_digit()) {
            counters += 1;
            // A counter beside a qualifier is how a chosen password reads
            // (`MyPassword1`), not how a field name does.
            if word.len() > 4 || counters > 1 || qualifiers > 0 {
                return false;
            }
            continue;
        }
        // A bare credential word is a stand-in even when the field names
        // another one: `{ token: "secret" }` in a usage example says no more
        // than `{ token: "token" }` does.
        if !name_words.contains(&word) && !CREDENTIAL_WORDS.contains(&word.as_str()) {
            // Qualifiers lead: `correct-password` describes which stand-in a
            // test means, while `password-old` carries a word of its own.
            if named || !QUALIFIER_WORDS.contains(&word.as_str()) {
                return false;
            }
            qualifiers += 1;
            if qualifiers > MAX_QUALIFIER_WORDS || counters > 0 {
                return false;
            }
            continue;
        }
        named = true;
        credential_word |= CREDENTIAL_WORDS.contains(&word.as_str());
    }
    credential_word
}

/// Whether `tail` begins where the assigned value ends. A closing quote ends
/// the value before `,` `}` `)` `]` or `;`. An unquoted value stops at those
/// characters only as delimiters: `PASSWORD=password,q7Lm` in an env file
/// assigns everything up to the space, so a delimiter followed directly by
/// more value text does not end it. An unquoted value also ends at the quote
/// closing the string it sits in, as in `"/foo?page=a&token=secret"`, when
/// that quote ends the line or comes before a delimiter. A quote followed by
/// anything else may open more value (`TOKEN=token"$more"`).
fn ends_value(tail: &str, quoted: bool) -> bool {
    let delimiter = |character: char| matches!(character, ',' | '}' | ')' | ']' | ';');
    let mut rest = tail.chars();
    match rest.next() {
        None => true,
        Some(next) if next.is_whitespace() => true,
        Some(next) if delimiter(next) => {
            quoted
                || rest
                    .next()
                    .is_none_or(|after| after.is_whitespace() || delimiter(after))
        }
        Some('"' | '\'') if !quoted => rest
            .next()
            .is_none_or(|after| matches!(after, '\r' | '\n') || delimiter(after)),
        Some(_) => false,
    }
}

/// Lower-case words split at separators, case changes and digit runs. Any
/// character other than an ASCII letter, digit or `-`, `_`, `.` or space makes
/// the text unusable, which keeps encoded or symbol-bearing values out.
fn words(text: &str) -> Vec<String> {
    let text = text.trim().trim_matches(['"', '\'']);
    let mut words = Vec::new();
    let mut current = String::new();
    let mut previous: Option<char> = None;
    for character in text.chars() {
        if matches!(character, '-' | '_' | '.' | ' ') {
            flush(&mut current, &mut words);
            previous = None;
            continue;
        }
        if !character.is_ascii_alphanumeric() {
            return vec![String::from("\0")];
        }
        let boundary = previous.is_some_and(|before| {
            (before.is_ascii_lowercase() && character.is_ascii_uppercase())
                || (before.is_ascii_digit() != character.is_ascii_digit())
        });
        if boundary {
            flush(&mut current, &mut words);
        }
        current.push(character.to_ascii_lowercase());
        previous = Some(character);
    }
    flush(&mut current, &mut words);
    words
}

fn flush(current: &mut String, words: &mut Vec<String>) {
    if !current.is_empty() {
        words.push(std::mem::take(current));
    }
}

#[cfg(test)]
mod tests {
    use super::is_self_named;
    use crate::scan_text;
    use guard_rules::MAX_SCAN_BYTES;

    fn credential_assignment(text: &str) -> bool {
        scan_text(text, true, true, MAX_SCAN_BYTES, None)
            .matches
            .iter()
            .any(|matched| matched.classifier == "credential-assignment")
    }

    #[test]
    fn values_that_spell_their_field_name_are_stand_ins() {
        assert!(is_self_named(r#"refresh_token="refresh-token-1""#, ""));
        assert!(is_self_named(r#""password": "password""#, ""));
        assert!(is_self_named("apiKey: 'api-key-12'", ""));
        assert!(is_self_named("SECRET=secret", ""));
        assert!(is_self_named(r#"refreshToken = "refreshToken2""#, ""));
        assert!(is_self_named(r#""password":"password""#, r#","user":"u"}"#));
        assert!(is_self_named("password: password", "}\n"));
        assert!(is_self_named("SECRET=secret", ";"));
    }

    #[test]
    fn a_qualifier_in_front_of_the_field_name_is_still_a_stand_in() {
        assert!(is_self_named(
            r#"'new_password': 'correct-password'"#,
            r#", 'confirm_password': 'x'}"#
        ));
        assert!(is_self_named(r#"password="wrong-password""#, ""));
        assert!(is_self_named(r#"token="the-old-token""#, ""));
    }

    #[test]
    fn a_word_that_could_name_a_real_account_is_not_a_qualifier() {
        assert!(!is_self_named(r#"password="admin-password""#, ""));
        assert!(!is_self_named(r#"password="prod-password""#, ""));
        assert!(!is_self_named(r#"token="the-old-stale-worn-token""#, ""));
        assert!(!is_self_named(r#"username="new-user""#, ""));
    }

    /// Qualifiers describe which stand-in a test means. Past a couple of them
    /// the value stops reading as a field name and starts reading as a phrase
    /// someone chose, so the allowance has a ceiling of its own.
    #[test]
    fn more_than_two_allowed_qualifiers_is_no_longer_a_field_name() {
        assert!(is_self_named(r#"token="the-old-token""#, ""));
        assert!(!is_self_named(r#"token="the-old-correct-token""#, ""));
    }

    /// A chosen password often reads as a word in front of the field name with
    /// a number after it. The counter and the trailing position are what tell
    /// it apart from a stand-in.
    #[test]
    fn a_qualifier_with_a_counter_or_after_the_field_name_is_not() {
        assert!(!is_self_named(r#"DB_PASSWORD=MyPassword1"#, ""));
        assert!(!is_self_named(r#"password="NewPassword2024""#, ""));
        assert!(!is_self_named(r#"token=TheToken12"#, ""));
        assert!(!is_self_named(r#"password="password-old""#, ""));
        assert!(!is_self_named(r#"token="token-the-old""#, ""));
    }

    #[test]
    fn values_with_other_words_or_long_numbers_are_not() {
        assert!(!is_self_named(r#"admin_password="admin""#, ""));
        assert!(!is_self_named(
            r#"refresh_token="refresh-token-918273""#,
            ""
        ));
        assert!(!is_self_named(
            r#"refresh_token="refresh-token-9182-7364""#,
            ""
        ));
        assert!(!is_self_named("password=password1234password5678", ""));
        assert!(!is_self_named("TOKEN=token", "\"$suffix\""));
        let visible = "q7Lm2Xv9Rt4Kp8Wz";
        assert!(!is_self_named("PASSWORD=password", &format!(",{visible}")));
        assert!(!is_self_named("TOKEN=token", &format!("}}{visible}")));
        assert!(!is_self_named(&format!(r#"token="token-{visible}""#), ""));
        assert!(!is_self_named(r#"password="password!""#, ""));
        assert!(!is_self_named(r#"token="1234""#, ""));
        assert!(!is_self_named(r#"api_key="key-value""#, ""));
    }

    #[test]
    fn a_test_fixture_seeding_stand_in_credentials_is_not_secret_output() {
        let fixture = concat!(
            "        store.set_oauth_local_credentials(\n",
            "            issuer=\"https://example.org\",\n",
            "            refresh_token=\"refresh-token-1\",\n",
            "            grant_id=\"grant-1\",\n",
            "        )\n",
        );
        assert!(!credential_assignment(fixture));
    }

    #[test]
    fn a_real_credential_beside_a_stand_in_still_matches() {
        let visible = "q7Lm2Xv9Rt4Kp8Wz";
        assert!(credential_assignment(&format!(
            "refresh_token=\"refresh-token-1\"\naccess_token=\"{visible}\"\n"
        )));
        assert!(credential_assignment(&format!(
            "refresh_token=\"refresh-token-{visible}\"\n"
        )));
        assert!(credential_assignment(&format!(
            "TOKEN=token\"{visible}\"\n"
        )));
        assert!(credential_assignment(&format!(
            "PASSWORD=password,{visible}\n"
        )));
    }

    #[test]
    fn a_bare_credential_word_in_a_usage_example_is_a_stand_in() {
        for text in [
            " * withQuery(\"/foo?page=a\", { token: \"secret\" }); // \"/foo?page=a&token=secret\"\n",
            "api_key = \"secret-token\"\n",
            "auth({ password: 'secret' })\n",
            "PASSWORD=token\n",
        ] {
            assert!(!credential_assignment(text), "{text}");
        }
    }

    #[test]
    fn a_credential_word_with_more_value_stays_flagged() {
        // Built at runtime so secret scanners do not read the test source as a leak.
        let visible = concat!("Kq7xY2mN", "9pL4vR8tW3sZ");
        for text in [
            format!("{{ token: \"secret-{visible}\" }}\n"),
            format!("TOKEN=secret\"{visible}\"\n"),
            format!("url = \"/foo?token=secret\"{visible}\n"),
            String::from("TOKEN=secret\"$MORE\"\n"),
            String::from("password: \"MySecret1\"\n"),
        ] {
            assert!(credential_assignment(&text), "{text}");
        }
    }
}

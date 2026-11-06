//! Assignment values that only spell their own field name.
//!
//! Test fixtures and seed data fill credential fields with stand-ins such as
//! `refresh_token="refresh-token-1"` or `password: "password"`. The value is
//! made of the words already in the field name plus at most a short counter,
//! so it carries nothing an attacker could not read from the name itself.
//! Treating those reads as secret output stopped agents opening ordinary test
//! setup files.

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

/// Longest value considered, so a long literal never qualifies by luck.
const MAX_VALUE_CHARS: usize = 64;

/// Whether a credential assignment match assigns a value whose words are all
/// words of the field name, including a credential word, with at most one
/// short numeric counter besides. `tail` is the text after the match: a match
/// the value runs on past (`TOKEN=token"$more"`) is not the whole value.
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
    for word in words(value) {
        if word.chars().all(|character| character.is_ascii_digit()) {
            counters += 1;
            if word.len() > 4 || counters > 1 {
                return false;
            }
            continue;
        }
        if !name_words.contains(&word) {
            return false;
        }
        credential_word |= CREDENTIAL_WORDS.contains(&word.as_str());
    }
    credential_word
}

/// Whether `tail` begins where the assigned value ends. A closing quote ends
/// the value before `,` `}` `)` `]` or `;`. An unquoted value stops at those
/// characters only as delimiters: `PASSWORD=password,q7Lm` in an env file
/// assigns everything up to the space, so a delimiter followed directly by
/// more value text does not end it.
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
}

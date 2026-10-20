//! Credential fields answered in prose rather than assigned a value.
//!
//! Agents summarize what they read: `- Token: No.`, `Password: not set`,
//! `Mentions an API key: none`. The credential-assignment rule reads the word
//! after the colon as the assigned value, so an honest report that a file holds
//! no secret was returned to the model as a secret match and the output was
//! withheld.
//!
//! Two closed lists do this, because they carry different weight. A word that
//! reports the field is empty says the field has no value at all, so it is an
//! answer wherever it appears: a real secret is not spelled `no`. A word that
//! reports the field's state says the opposite, that something is there, and
//! is a value a person could have chosen, so it reads as an answer only when
//! the field is asking about the credential rather than holding it. Either
//! way the rest of the line is checked: an answer word in front of a value
//! does not turn that value into prose.

/// Words reporting the field has no value. Lower case, and matched whole, so
/// `nonce` is still a value.
const ABSENCE_WORDS: &[&str] = &[
    "absent",
    "empty",
    "false",
    "missing",
    "n",
    "n/a",
    "na",
    "never",
    "nil",
    "no",
    "none",
    "nope",
    "not",
    "nothing",
    "null",
    "omitted",
    "redacted",
    "unknown",
    "unset",
    "unspecified",
];

/// Words reporting the field's state rather than its absence. Each is also a
/// value someone could have chosen, so these read as an answer only when the
/// field asks about the credential. Matched whole, so `yesterday` is still a
/// value.
const STATE_WORDS: &[&str] = &["optional", "present", "required", "tbd", "todo", "y", "yes"];

/// Words that make a field a question or a report about a credential rather
/// than a place one is kept, as in `Has password: yes` or `API key set: yes`.
const REPORT_FIELD_WORDS: &[&str] = &[
    "any",
    "configured",
    "contains",
    "detected",
    "enabled",
    "exists",
    "found",
    "has",
    "have",
    "includes",
    "is",
    "mention",
    "mentioned",
    "mentions",
    "needs",
    "present",
    "provided",
    "references",
    "requires",
    "set",
    "uses",
    "whether",
];

/// Longest answer considered, so a long literal never qualifies by luck.
const MAX_VALUE_CHARS: usize = 16;

/// Shortest run of letters and digits on the rest of the line that is taken
/// for a value rather than a word.
const MIN_VALUE_RUN: usize = 8;

/// Longest run of letters that still reads as a word rather than a chosen
/// value. The longest words that turn up in these reports are around twenty
/// characters, so a letter run past that was not typed as prose.
const MAX_WORD_RUN: usize = 20;

/// How much of the line in front of a match can make its field a question.
const MAX_FIELD_LEAD_CHARS: usize = 48;

/// Whether a credential-assignment match states an answer about the field
/// instead of assigning a value to it.
///
/// Only the unquoted colon form qualifies. A quoted value (`"token": "no"`) is
/// data a program reads, and `=` is an assignment an environment or shell file
/// makes, so both keep their match. `tail` is the text after the match: an
/// answer the value runs on past is not the whole value.
pub(crate) fn is_prose_answer(matched: &str, tail: &str, preceding: &str) -> bool {
    let Some(index) = matched.find([':', '=']) else {
        return false;
    };
    if matched.as_bytes()[index] != b':' {
        return false;
    }
    let value = matched[index + 1..].trim();
    if value.is_empty() || value.chars().count() > MAX_VALUE_CHARS || value.starts_with(['"', '\''])
    {
        return false;
    }
    if !ends_value(tail) {
        return false;
    }
    let answer = value
        .trim_end_matches(['.', ',', ';', '!', '?', ')', ']'])
        .to_ascii_lowercase();
    if answer.is_empty()
        || !answer
            .chars()
            .all(|character| character.is_ascii_alphabetic() || character == '/')
    {
        return false;
    }
    if ABSENCE_WORDS.contains(&answer.as_str()) {
        return true;
    }
    STATE_WORDS.contains(&answer.as_str()) && reports_about_field(preceding, &matched[..index])
}

/// Whether the text in front of the colon asks about a credential instead of
/// holding one. `Has password: yes` and `API key set: yes` report a state;
/// a bare `password: yes` is a field with a value in it. The rule need not
/// have captured the whole field, so the line in front of the match counts
/// too, bounded so an earlier sentence cannot vouch for this one.
fn reports_about_field(preceding: &str, field: &str) -> bool {
    if field.trim_end().ends_with('?') {
        return true;
    }
    // A report word belongs to the field it introduces. `Has token: no; password: yes`
    // answers the first field and assigns the second, so the lead stops at the
    // separator in front of this field rather than borrowing the earlier one.
    let line = preceding
        .rsplit(['\n', '\r', ';'])
        .next()
        .unwrap_or_default();
    let start = line
        .char_indices()
        .rev()
        .take(MAX_FIELD_LEAD_CHARS)
        .last()
        .map_or(line.len(), |(index, _)| index);
    [&line[start..], field].iter().any(|text| {
        text.split(|character: char| !character.is_ascii_alphanumeric())
            .any(|word| REPORT_FIELD_WORDS.contains(&word.to_ascii_lowercase().as_str()))
    })
}

/// Whether `tail` begins where the answer ends. The rule's unquoted arm stops
/// at a space, `"`, `'`, `,` or `}`, so anything else directly after the match
/// is more of the same value and the answer wording proves nothing about it.
///
/// A space is the case worth care. The arm stops there too, so `password: no
/// q7Lm2Xv9Rt4Kp8Wz` matches `no` alone and the value after it is never looked
/// at. The answer only holds when nothing on the rest of that line is shaped
/// like a secret, so `Password: not set` still reads as a report.
fn ends_value(tail: &str) -> bool {
    let Some(next) = tail.chars().next() else {
        return true;
    };
    if matches!(next, ',' | '}' | ')' | ']' | ';') {
        return true;
    }
    next.is_whitespace() && !carries_value(tail)
}

/// Whether the rest of the line holds a token shaped like a credential. `-` and
/// `_` join a run, because a key is written `ab12-cd34-ef56-gh78`, while `/` and
/// `.` end one so a path reads as the words it is made of.
fn carries_value(tail: &str) -> bool {
    tail.split(['\n', '\r'])
        .next()
        .unwrap_or_default()
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || character == '-' || character == '_')
        })
        .any(holds_value)
}

/// Whether one token on that line is a chosen value rather than more prose.
/// It has to be long enough and carry letters, and then either mix digits in or
/// run past any word. Case is not read either way: an operator's `DB_PASSWORD`
/// and an access key id are both upper case.
fn holds_value(token: &str) -> bool {
    let run: String = token
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect();
    if run.len() < MIN_VALUE_RUN || !run.bytes().any(|byte| byte.is_ascii_alphabetic()) {
        return false;
    }
    run.bytes().any(|byte| byte.is_ascii_digit()) || run.len() > MAX_WORD_RUN
}

#[cfg(test)]
mod tests {
    use super::is_prose_answer;
    use crate::scan_text;
    use guard_rules::MAX_SCAN_BYTES;

    fn credential_assignment(text: &str) -> bool {
        scan_text(text, true, true, MAX_SCAN_BYTES, None)
            .matches
            .iter()
            .any(|matched| matched.classifier == "credential-assignment")
    }

    #[test]
    fn answer_words_report_a_field_rather_than_assign_it() {
        assert!(is_prose_answer("Token: No.", "", ""));
        assert!(is_prose_answer("token: no", "\n", ""));
        assert!(is_prose_answer("Secret: none", "", ""));
        assert!(is_prose_answer("password: unset", "", ""));
        assert!(is_prose_answer("api_key: N/A", "", ""));
        assert!(is_prose_answer("Token:No.", "", ""));
        assert!(is_prose_answer("credential: absent", ";", ""));
    }

    #[test]
    fn real_values_and_other_forms_keep_their_match() {
        assert!(!is_prose_answer("password: swordfish", "", ""));
        assert!(!is_prose_answer("token: nonce", "", ""));
        assert!(!is_prose_answer("TOKEN=no", "", ""));
        assert!(!is_prose_answer(r#""token": "no""#, "", ""));
        assert!(!is_prose_answer("token: no", "pe-q7Lm2Xv9", ""));
        assert!(!is_prose_answer("token: no1", "", ""));
        assert!(!is_prose_answer("token:", "", ""));
    }

    #[test]
    fn a_report_that_a_file_holds_no_secret_is_not_secret_output() {
        let report = concat!(
            "Read the README and checked for credentials.\n",
            "- Token: No.\n",
            "- API key: none\n",
            "- Password: not set\n",
        );
        assert!(!credential_assignment(report));
    }

    #[test]
    fn a_real_credential_beside_an_answer_still_matches() {
        let visible = "q7Lm2Xv9Rt4Kp8Wz";
        assert!(credential_assignment(&format!(
            "- Token: No.\npassword: {visible}\n"
        )));
    }

    #[test]
    fn a_state_word_reads_as_an_answer_only_where_the_field_asks() {
        assert!(is_prose_answer("password: yes", "", "Has "));
        assert!(is_prose_answer("API key: present", "", "- Mentions an "));
        assert!(is_prose_answer("key set: yes", "", ""));
        assert!(is_prose_answer("password?: yes", "", ""));
        // A field holding a credential is not asking about one, so a word a
        // person could have chosen as the value keeps its match.
        assert!(!is_prose_answer("password: yes", "", ""));
        assert!(!is_prose_answer("api_key: required", "", "- "));
        assert!(credential_assignment("password: yes\n"));
        assert!(!credential_assignment("Has password: yes\n"));
    }

    #[test]
    fn an_answer_word_in_front_of_a_value_does_not_cover_it() {
        assert!(!is_prose_answer("password: no", " q7Lm2Xv9Rt4Kp8Wz", ""));
        assert!(credential_assignment("password: no q7Lm2Xv9Rt4Kp8Wz\n"));
        // Prose after the answer is still prose.
        assert!(is_prose_answer("Password: not", " set", ""));
        assert!(is_prose_answer("Token: none", " in this file", ""));
        assert!(!credential_assignment("Password: not set in config v2\n"));
    }

    #[test]
    fn a_long_or_separated_value_after_an_answer_is_still_a_value() {
        assert!(!is_prose_answer(
            "password: not",
            " correcthorsebatterystaple",
            ""
        ));
        assert!(!is_prose_answer(
            "token: no",
            " ghp_AbCdEfGhIjKlMnOpQrSt",
            ""
        ));
        assert!(!is_prose_answer("token: no", " ab12-cd34-ef56-gh78", ""));
        assert!(!is_prose_answer("token: no", " AKIAIOSFODNN7EXAMPLE", ""));
        // A path, a setting's name and hyphenated prose are not values.
        assert!(is_prose_answer(
            "Password: unset",
            " - see docs/CONFIGURATION.md",
            ""
        ));
        assert!(is_prose_answer(
            "password: none",
            " - set DB_PASSWORD instead",
            ""
        ));
        assert!(is_prose_answer(
            "Token: none",
            " in this read-only-by-design file",
            ""
        ));
    }

    #[test]
    fn a_report_word_does_not_carry_past_its_own_field() {
        assert!(!is_prose_answer("password: yes", "", "Has token: no; "));
        assert!(credential_assignment("Has token: no; password: yes\n"));
    }
}

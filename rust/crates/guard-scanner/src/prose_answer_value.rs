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

/// Shortest run of digits alone taken for a value. A report writes out epoch
/// seconds, epoch milliseconds, dates, counts and issue numbers beside its
/// answer, and the longest of those is thirteen digits, so a shorter bound read
/// `Token: none as of 1735689600` as a credential. Fourteen is the first length
/// past that, so a numeric secret of any length a report would not write out -
/// a card number, an account number, a numeric key - still reads as a value.
const MIN_DIGIT_RUN: usize = 14;

/// How much of the line in front of a match can make its field a question.
const MAX_FIELD_LEAD_CHARS: usize = 48;

/// Whether a credential-assignment match states an answer about the field
/// instead of assigning a value to it.
///
/// Only the unquoted colon form qualifies. A quoted value (`"token": "no"`) is
/// data a program reads, and `=` is an assignment an environment or shell file
/// makes, so both keep their match. `tail` is the text after the match: an
/// answer the value runs on past is not the whole value. `value_follows` says
/// whether a credential-shaped token comes later on the line, which the caller
/// resolves once per line rather than per match.
pub(crate) fn is_prose_answer(
    matched: &str,
    tail: &str,
    preceding: &str,
    value_follows: bool,
) -> bool {
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
    if !ends_value(tail, value_follows) {
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
/// Where the arm did stop, the value after it is never looked at: `password:
/// no q7Lm2Xv9Rt4Kp8Wz` matches `no` alone, and so does `password: no,
/// q7Lm2Xv9Rt4Kp8Wz`. The answer only holds when nothing on the rest of that
/// line is shaped like a secret, so `Password: not set` still reads as a
/// report. Which character ended the value does not change that: a credential
/// written after a comma is a credential.
fn ends_value(tail: &str, value_follows: bool) -> bool {
    let Some(next) = tail.chars().next() else {
        return true;
    };
    (next.is_whitespace() || matches!(next, ',' | '}' | ')' | ']' | ';')) && !value_follows
}

/// Where the last credential-shaped token on this line starts, as an offset
/// into `tail`, or `None` when the line carries none. `-` and `_` join a run,
/// because a key is written `ab12-cd34-ef56-gh78`, while `/` and `.` end one so
/// a path reads as the words it is made of.
///
/// The caller resolves this once for the line and compares the offset with each
/// match's end. Asking every match whether a value follows it would rescan the
/// rest of the line once per match, which is quadratic on a line of repeated
/// `password: no,` fields.
pub(crate) fn last_value_offset(tail: &str) -> Option<usize> {
    let line = tail.split(['\n', '\r']).next().unwrap_or_default();
    let mut last = None;
    let mut start = None;
    for (index, character) in line.char_indices() {
        if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
            start.get_or_insert(index);
            continue;
        }
        let rest = &line[index + character.len_utf8()..];
        last = start
            .take()
            .filter(|_| !names_field(character, rest))
            .filter(|&begin| holds_value(&line[begin..index]))
            .or(last);
    }
    start.filter(|&begin| holds_value(&line[begin..])).or(last)
}

/// Whether the character that ended a run makes it the name of the next field
/// rather than a value of this one. `Token: none, password_v2: none` answers
/// two fields and assigns neither, so the second field's name must not read as
/// the first field's value.
///
/// What follows the separator decides it, because a field is named `name:
/// value` or `name=value`. A colon no space follows belongs to the token
/// itself, as in a host and port or a basic-auth pair, and base64 padding -
/// `=` before another `=` or at the end of the line - ends a value instead of
/// naming anything, so a key written out in full still reads as one.
fn names_field(ended_by: char, rest: &str) -> bool {
    match (ended_by, rest.chars().next()) {
        (':', Some(next)) => next.is_whitespace(),
        ('=', Some(next)) => next != '=',
        _ => false,
    }
}

/// Whether one token on that line is a chosen value rather than more prose.
/// A token carrying letters has to be long enough and then either mix digits
/// in or run past any word. Case is not read either way: an operator's
/// `DB_PASSWORD` and an access key id are both upper case.
///
/// Digits alone are a value too, at a greater length: an account number, a PIN
/// or a numeric key. The extra length leaves a report free to carry a date, a
/// count or an issue number beside its answer.
fn holds_value(token: &str) -> bool {
    let run: String = token
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect();
    if run.len() < MIN_VALUE_RUN {
        return false;
    }
    if !run.bytes().any(|byte| byte.is_ascii_alphabetic()) {
        return run.len() >= MIN_DIGIT_RUN;
    }
    run.bytes().any(|byte| byte.is_ascii_digit()) || run.len() > MAX_WORD_RUN
}

#[cfg(test)]
mod tests {
    use super::last_value_offset;
    use crate::scan_text;
    use guard_rules::MAX_SCAN_BYTES;

    /// The scanner resolves `value_follows` once per line; a test states the
    /// match and its tail, so it resolves the same answer from that tail.
    fn is_prose_answer(matched: &str, tail: &str, preceding: &str) -> bool {
        super::is_prose_answer(matched, tail, preceding, last_value_offset(tail).is_some())
    }

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

    /// A key written out beside the answer keeps the match whatever ends it:
    /// base64 padding and a port are part of the value, not a field name.
    #[test]
    fn a_padded_or_ported_credential_beside_an_answer_still_matches() {
        assert!(credential_assignment(
            "- Token: none dGhpc2lzYXNlY3JldGtleTEy=\n"
        ));
        assert!(credential_assignment(
            "- Token: none q7Lm2Xv9Rt4Kp8Wz:8080\n"
        ));
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
    fn digits_alone_after_an_answer_are_a_value() {
        assert!(!is_prose_answer("api_key: none", " 4829193755218037", ""));
        assert!(credential_assignment("api_key: none 4829193755218037\n"));
        assert!(!is_prose_answer("pin: not", " set 86753091234567890", ""));
        // A date, a count, an issue number or an epoch stamp beside the answer
        // is still prose: none of them is as long as a numeric secret.
        assert!(is_prose_answer("Token: none", " as of 2026-10-23", ""));
        assert!(is_prose_answer("Password: none", " in 1284 files", ""));
        assert!(is_prose_answer("Token: none", " as of 1735689600", ""));
        assert!(is_prose_answer("Token: none", " as of 1735689600123", ""));
        assert!(!credential_assignment("Token: none as of 2026-10-23\n"));
        assert!(!credential_assignment("Token: none as of 1735689600\n"));
        // One digit past an epoch in milliseconds is where a value starts, so a
        // numeric secret shorter than a card number is still read as one.
        assert!(!is_prose_answer("pin: none", " 48291937552180", ""));
    }

    #[test]
    fn a_field_answered_later_on_the_line_is_not_the_first_field_s_value() {
        assert!(is_prose_answer("Token: none", ", password_v2: none", ""));
        assert!(!is_prose_answer(
            "Token: none",
            " dGhpc2lzYXNlY3JldGtleTEy=",
            ""
        ));
        assert!(!is_prose_answer(
            "Token: none",
            " q7Lm2Xv9Rt4Kp8Wz:8080",
            ""
        ));
        assert!(!credential_assignment("Token: none, password_v2: none\n"));
        assert!(is_prose_answer("Token: none", " (api_key_v2=none)", ""));
        // A value written after the second field still ends both answers. The
        // field is spelled without a credential word so the line carries one
        // value for a scanner to read, not two.
        assert!(!is_prose_answer(
            "Token: none",
            ", rotated_v2: q7Lm2Xv9Rt4Kp8Wz",
            ""
        ));
    }

    #[test]
    fn a_value_after_a_comma_reads_like_one_after_a_space() {
        assert!(!is_prose_answer("password: no", ", q7Lm2Xv9Rt4Kp8Wz", ""));
        assert!(credential_assignment("password: no, q7Lm2Xv9Rt4Kp8Wz\n"));
        assert!(!is_prose_answer(
            "token: none",
            "} ghp_AbCdEfGhIjKlMnOpQrSt",
            ""
        ));
        // A second field answered on the same line is still prose.
        assert!(is_prose_answer("Token: none", ", password: none", ""));
        assert!(is_prose_answer("credential: absent", ";", ""));
        assert!(!credential_assignment("Token: none, password: none\n"));
    }

    #[test]
    fn a_report_word_does_not_carry_past_its_own_field() {
        assert!(!is_prose_answer("password: yes", "", "Has token: no; "));
        assert!(credential_assignment("Has token: no; password: yes\n"));
    }

    #[test]
    fn the_last_value_on_a_line_is_found_in_one_pass() {
        assert_eq!(last_value_offset(", password: no"), None);
        assert_eq!(last_value_offset(", q7Lm2Xv9Rt4Kp8Wz"), Some(2));
        // The answer is the start of the last value-shaped token, not the first.
        assert_eq!(last_value_offset(" a q7Lm2Xv9 b r3Pn6Yw1"), Some(14));
        // A value on a later line belongs to that line.
        assert_eq!(last_value_offset(" no\nlater q7Lm2Xv9Rt4Kp8Wz"), None);
    }

    #[test]
    fn a_line_of_answered_fields_stays_linear() {
        // Reading each match's own tail would rescan the rest of the line once
        // per field, so a line of answered fields alone used to cost its length
        // squared. Every field here is prose and the line is left unflagged.
        let line = format!("{}\n", vec!["password: no"; 400].join(", "));
        assert!(!credential_assignment(&line));
        // The same line ending in a real value flags that value.
        let with_value = line.replace('\n', " q7Lm2Xv9Rt4Kp8Wz\n");
        assert!(credential_assignment(&with_value));
    }
}

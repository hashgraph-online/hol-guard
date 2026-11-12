//! Personal-data shapes read as sensitivity hints.
//!
//! Four deterministic shapes: an email address, a phone number written in an
//! international or North American form, a payment card number that passes the
//! Luhn check, and a national identifier shape (US SSN, UK National Insurance
//! number). They mark content as personal; they are not data-loss prevention
//! and never block on their own.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use guard_contracts::PiiKindV2;
use regex::{Captures, Regex};

static EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|[^a-z0-9._%+-])[a-z0-9][a-z0-9._%+-]{0,63}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,24}(?:$|[^a-z0-9.-])")
        .expect("email pattern")
});
static PHONE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:^|[^0-9A-Za-z+])(?:\+[1-9][0-9]{0,2}[ .-]?(?:\(?[0-9]{1,4}\)?[ .-]?){2,5}[0-9]{2,4}|\(?[2-9][0-9]{2}\)?[ .-][2-9][0-9]{2}[ .-][0-9]{4})(?:$|[^0-9A-Za-z])",
    )
    .expect("phone pattern")
});
static CARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^0-9])([0-9](?:[ -]?[0-9]){12,18})(?:$|[^0-9])").expect("card pattern")
});
static SSN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^0-9-])([0-9]{3})-([0-9]{2})-([0-9]{4})(?:$|[^0-9-])").expect("ssn pattern")
});
static NINO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^A-Za-z0-9])[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?[0-9]{2} ?[0-9]{2} ?[0-9]{2} ?[A-D](?:$|[^A-Za-z0-9])")
        .expect("nino pattern")
});

/// The personal-data kinds present in `text`, sorted.
pub fn pii_kinds(text: &str) -> BTreeSet<PiiKindV2> {
    let mut kinds = BTreeSet::new();
    if text.contains('@') && EMAIL.is_match(text) {
        kinds.insert(PiiKindV2::EmailAddress);
    }
    let digits = text.bytes().filter(u8::is_ascii_digit).count();
    if digits >= 6 && NINO.is_match(text) {
        kinds.insert(PiiKindV2::NationalId);
    }
    if digits < 9 {
        return kinds;
    }
    if PHONE.is_match(text) {
        kinds.insert(PiiKindV2::PhoneNumber);
    }
    if any_capture(&CARD, text, 1, |captures| luhn_card(&captures[1])) {
        kinds.insert(PiiKindV2::PaymentCard);
    }
    if any_capture(&SSN, text, 3, |captures| {
        let area = &captures[1];
        area != "000"
            && area != "666"
            && !area.starts_with('9')
            && &captures[2] != "00"
            && &captures[3] != "0000"
    }) {
        kinds.insert(PiiKindV2::NationalId);
    }
    kinds
}

/// Whether any match satisfies `accept`. Each search resumes where the last
/// match's `last_group` ended, not after the boundary character it consumed,
/// so a rejected candidate never hides one that shares its separator.
fn any_capture(
    pattern: &Regex,
    text: &str,
    last_group: usize,
    mut accept: impl FnMut(&Captures<'_>) -> bool,
) -> bool {
    let mut start = 0;
    while let Some(captures) = pattern.captures_at(text, start) {
        if accept(&captures) {
            return true;
        }
        let Some(end) = captures.get(last_group).map(|group| group.end()) else {
            return false;
        };
        start = end;
    }
    false
}

/// A 13-19 digit number with a valid Luhn check digit and not one repeated digit.
pub fn luhn_card(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) || digits.iter().all(|d| *d == digits[0]) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(index, digit)| {
            if index % 2 == 1 {
                let doubled = digit * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                *digit
            }
        })
        .sum();
    sum % 10 == 0
}

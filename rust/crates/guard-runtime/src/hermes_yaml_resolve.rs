//! PyYAML 1.1 implicit scalar resolution: which plain scalars are booleans,
//! nulls, integers, floats or timestamps.

use saphyr_parser::ScalarStyle;

use super::hermes_yaml::{Foreign, Node, TAG_MERGE, TAG_PREFIX, TAG_STR, TAG_VALUE};

/// The resolved tag, PyYAML's `resolve`.
pub(crate) fn resolved_tag(node: &Node) -> String {
    match node.tag() {
        Some(tag) if tag != "!" => tag.to_owned(),
        explicit => match node {
            Node::Scalar { value, style, .. } => {
                // A plain scalar, or one with the non-specific `!` tag, is resolved
                // by its text; other styles are strings.
                if explicit.is_some() || *style == ScalarStyle::Plain {
                    implicit_scalar_tag(value).to_owned()
                } else {
                    TAG_STR.to_owned()
                }
            }
            Node::Seq { .. } => format!("{TAG_PREFIX}seq"),
            Node::Map { .. } => format!("{TAG_PREFIX}map"),
        },
    }
}

/// The implicit resolvers, in registration order and gated by first character.
pub(crate) fn implicit_scalar_tag(text: &str) -> &'static str {
    let first = text.chars().next();
    if matches!(
        first,
        Some('y' | 'Y' | 'n' | 'N' | 't' | 'T' | 'f' | 'F' | 'o' | 'O')
    ) && is_bool(text)
    {
        return "tag:yaml.org,2002:bool";
    }
    if matches!(first, Some('-' | '+' | '0'..='9' | '.')) && is_float(text) {
        return "tag:yaml.org,2002:float";
    }
    if matches!(first, Some('-' | '+' | '0'..='9')) && is_int(text) {
        return "tag:yaml.org,2002:int";
    }
    if text == "<<" {
        return TAG_MERGE;
    }
    if matches!(first, Some('~' | 'n' | 'N') | None) && is_null(text) {
        return "tag:yaml.org,2002:null";
    }
    if matches!(first, Some('0'..='9')) && timestamp_parts(text, true).is_some() {
        return "tag:yaml.org,2002:timestamp";
    }
    if text == "=" {
        return TAG_VALUE;
    }
    TAG_STR
}

pub(crate) fn is_bool(text: &str) -> bool {
    matches!(
        text,
        "yes"
            | "Yes"
            | "YES"
            | "no"
            | "No"
            | "NO"
            | "true"
            | "True"
            | "TRUE"
            | "false"
            | "False"
            | "FALSE"
            | "on"
            | "On"
            | "ON"
            | "off"
            | "Off"
            | "OFF"
    )
}

pub(crate) fn is_null(text: &str) -> bool {
    matches!(text, "~" | "null" | "Null" | "NULL" | "")
}

pub(crate) fn all(text: &str, accept: impl Fn(char) -> bool) -> bool {
    text.chars().all(accept)
}

pub(crate) fn digit(ch: char) -> bool {
    ch.is_ascii_digit()
}

fn digit_or_underscore(ch: char) -> bool {
    ch.is_ascii_digit() || ch == '_'
}

pub(crate) fn strip_sign(text: &str) -> &str {
    text.strip_prefix(['-', '+']).unwrap_or(text)
}

/// `[0-9][0-9_]*`
fn digits_with_underscores(text: &str) -> bool {
    text.chars().next().is_some_and(digit) && all(text, digit_or_underscore)
}

/// `[0-5]?[0-9]`
fn sexagesimal_part(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    match chars.as_slice() {
        [one] => digit(*one),
        [tens, ones] => ('0'..='5').contains(tens) && digit(*ones),
        _ => false,
    }
}

/// `[0-9][0-9_]*(?::[0-5]?[0-9])+`
fn sexagesimal(text: &str) -> bool {
    let mut pieces = text.split(':');
    let lead = pieces.next().unwrap_or("");
    let rest: Vec<&str> = pieces.collect();
    digits_with_underscores(lead)
        && !rest.is_empty()
        && rest.iter().all(|part| sexagesimal_part(part))
}

/// `(?:[eE][-+][0-9]+)?` at the end of a fraction; returns the fraction part.
fn split_exponent(fraction: &str) -> Option<&str> {
    match fraction.find(['e', 'E']) {
        None => Some(fraction),
        Some(at) => {
            let (head, exponent) = fraction.split_at(at);
            let mut chars = exponent.chars();
            let _ = chars.next();
            let signed = matches!(chars.next(), Some('-' | '+'));
            let rest = chars.as_str();
            (signed && !rest.is_empty() && all(rest, digit)).then_some(head)
        }
    }
}

pub(crate) fn is_float(text: &str) -> bool {
    let body = strip_sign(text);
    let signed = body.len() != text.len();
    if matches!(body, ".inf" | ".Inf" | ".INF") {
        return true;
    }
    if !signed && matches!(body, ".nan" | ".NaN" | ".NAN") {
        return true;
    }
    let Some(dot) = body.find('.') else {
        return false;
    };
    let (whole, fraction) = (&body[..dot], &body[dot + 1..]);
    // [-+]?[0-9][0-9_]*\.[0-9_]*(?:[eE][-+][0-9]+)?
    if digits_with_underscores(whole) {
        if let Some(head) = split_exponent(fraction) {
            if all(head, digit_or_underscore) {
                return true;
            }
        }
    }
    // \.[0-9][0-9_]*(?:[eE][-+][0-9]+)?
    if !signed && whole.is_empty() {
        if let Some(head) = split_exponent(fraction) {
            if digits_with_underscores(head) {
                return true;
            }
        }
    }
    // [-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*
    sexagesimal(whole) && all(fraction, digit_or_underscore)
}

pub(crate) fn is_int(text: &str) -> bool {
    let body = strip_sign(text);
    if let Some(rest) = body.strip_prefix("0b") {
        if !rest.is_empty() && all(rest, |ch| matches!(ch, '0' | '1' | '_')) {
            return true;
        }
    }
    if let Some(rest) = body.strip_prefix("0x") {
        if !rest.is_empty() && all(rest, |ch| ch.is_ascii_hexdigit() || ch == '_') {
            return true;
        }
    }
    if let Some(rest) = body.strip_prefix('0') {
        if !rest.is_empty() && all(rest, |ch| matches!(ch, '0'..='7' | '_')) {
            return true;
        }
    }
    if body == "0" {
        return true;
    }
    let lead_nonzero = body
        .chars()
        .next()
        .is_some_and(|ch| ('1'..='9').contains(&ch));
    lead_nonzero && (all(body, digit_or_underscore) || sexagesimal(body))
}

pub(crate) struct Timestamp {
    year: u32,
    month: u32,
    day: u32,
    time: Option<(u32, u32, u32)>,
    fraction: String,
    offset: Option<i64>,
}

type Chars<'a> = std::iter::Peekable<std::str::Chars<'a>>;

fn take_digits(chars: &mut Chars<'_>, min: usize, max: usize) -> Option<String> {
    let mut out = String::new();
    while out.len() < max {
        match chars.peek() {
            Some(ch) if ch.is_ascii_digit() => {
                out.push(*ch);
                chars.next();
            }
            _ => break,
        }
    }
    (out.len() >= min).then_some(out)
}

fn expect(chars: &mut Chars<'_>, want: char) -> bool {
    if chars.peek() == Some(&want) {
        chars.next();
        true
    } else {
        false
    }
}

fn skip_blanks(chars: &mut Chars<'_>) {
    while matches!(chars.peek(), Some(' ' | '\t')) {
        chars.next();
    }
}

/// The timestamp regular expressions. The resolver admits the date form only
/// with two-digit month and day; the constructor also takes one digit.
pub(crate) fn timestamp_parts(text: &str, resolver: bool) -> Option<Timestamp> {
    let mut chars: Chars<'_> = text.chars().peekable();
    let year = take_digits(&mut chars, 4, 4)?;
    if !expect(&mut chars, '-') {
        return None;
    }
    let month = take_digits(&mut chars, 1, 2)?;
    if !expect(&mut chars, '-') {
        return None;
    }
    let day = take_digits(&mut chars, 1, 2)?;
    let mut stamp = Timestamp {
        year: year.parse().ok()?,
        month: month.parse().ok()?,
        day: day.parse().ok()?,
        time: None,
        fraction: String::new(),
        offset: None,
    };
    if chars.peek().is_none() {
        // Date-only resolution keeps PyYAML's two-digit month and day.
        // A following time uses the long form, which allows one digit.
        if resolver && (month.len() != 2 || day.len() != 2) {
            return None;
        }
        return Some(stamp);
    }
    match chars.peek() {
        Some('T' | 't') => {
            chars.next();
        }
        Some(' ' | '\t') => skip_blanks(&mut chars),
        _ => return None,
    }
    let hour = take_digits(&mut chars, 1, 2)?;
    if !expect(&mut chars, ':') {
        return None;
    }
    let minute = take_digits(&mut chars, 2, 2)?;
    if !expect(&mut chars, ':') {
        return None;
    }
    let second = take_digits(&mut chars, 2, 2)?;
    stamp.time = Some((
        hour.parse().ok()?,
        minute.parse().ok()?,
        second.parse().ok()?,
    ));
    if expect(&mut chars, '.') {
        let mut fraction = String::new();
        while let Some(ch) = chars.peek() {
            if !ch.is_ascii_digit() {
                break;
            }
            fraction.push(*ch);
            chars.next();
        }
        stamp.fraction = fraction;
    }
    skip_blanks(&mut chars);
    match chars.peek().copied() {
        None => return Some(stamp),
        Some('Z') => {
            chars.next();
            stamp.offset = Some(0);
        }
        Some(sign @ ('-' | '+')) => {
            chars.next();
            let hours: i64 = take_digits(&mut chars, 1, 2)?.parse().ok()?;
            let minutes: i64 = if expect(&mut chars, ':') {
                take_digits(&mut chars, 2, 2)?.parse().ok()?
            } else {
                0
            };
            let total = hours * 60 + minutes;
            stamp.offset = Some(if sign == '-' { -total } else { total });
        }
        _ => return None,
    }
    chars.peek().is_none().then_some(stamp)
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                29
            } else {
                28
            }
        }
    }
}

/// `datetime.date(...)`/`datetime.datetime(...)` argument validity.
pub(crate) fn timestamp_value(stamp: &Timestamp) -> Option<Foreign> {
    if stamp.year < 1 || !(1..=12).contains(&stamp.month) {
        return None;
    }
    if stamp.day < 1 || stamp.day > days_in_month(stamp.year, stamp.month) {
        return None;
    }
    let mut canonical = format!("{:04}-{:02}-{:02}", stamp.year, stamp.month, stamp.day);
    if let Some((hour, minute, second)) = stamp.time {
        if hour > 23 || minute > 59 || second > 59 {
            return None;
        }
        let mut fraction: String = stamp.fraction.chars().take(6).collect();
        while fraction.len() < 6 {
            fraction.push('0');
        }
        let offset = stamp
            .offset
            .map_or_else(String::new, |offset| format!("@{offset}"));
        canonical.push_str(&format!(
            "T{hour:02}:{minute:02}:{second:02}.{fraction}{offset}"
        ));
    }
    Some(Foreign::Timestamp(canonical))
}

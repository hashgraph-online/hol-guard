//! Which request a relayed short approval link was signed for.
//!
//! An agent held by a review copies `/requests/<id>/<expires>-<mac>` into its
//! reply by hand, and models sometimes drop, add or change one character of
//! the 32-hex id, the expiry or the MAC on the way. Such a link used to open
//! nothing, which left the user with no way into the review. One slip anywhere
//! in the link is undone here, but only to a link whose MAC verifies for the
//! repaired request and expiry, so a repaired link can only open a request the
//! daemon signed that link for. The MAC is compared without early exits.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::{
    HANDOFF_CLOCK_SKEW_SECONDS, HANDOFF_MAC_BYTES, HANDOFF_MAC_HEX, HANDOFF_TTL_SECONDS,
    HANDOFF_VERSION,
};

pub(super) const HANDOFF_ID_HEX: usize = 32;
const MAX_EXPIRY_DIGITS: usize = 12;
const HEX: &[u8] = b"0123456789abcdef";
const DIGITS: &[u8] = b"0123456789";

pub(super) fn is_lower_hex(text: &str) -> bool {
    text.bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether `length` is the expected length or one character either side.
pub(super) fn within_one_of(length: usize, expected: usize) -> bool {
    length + 1 >= expected && length <= expected + 1
}

/// The request id and signed expiry, in seconds, of a short link with at most
/// one slipped character across `presented_id` and `code`.
pub(super) fn handoff_signed_request(
    presented_id: &str,
    code: &str,
    auth_key: &str,
    now_micros: i64,
) -> Option<(String, i64)> {
    let (digits, presented_mac) = code.split_once('-')?;
    if digits.is_empty()
        || digits.len() > MAX_EXPIRY_DIGITS + 1
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
        || !within_one_of(presented_mac.len(), HANDOFF_MAC_HEX)
        || !is_lower_hex(presented_mac)
        || !within_one_of(presented_id.len(), HANDOFF_ID_HEX)
        || !is_lower_hex(presented_id)
    {
        return None;
    }
    let id_exact = presented_id.len() == HANDOFF_ID_HEX;
    let mac_exact = presented_mac.len() == HANDOFF_MAC_HEX;
    let relayed_expiry = signed_window(digits, now_micros);
    if id_exact {
        if let Some(expires) = relayed_expiry {
            let expected = handoff_mac(auth_key, presented_id, expires)?;
            if within_one_edit(expected.as_bytes(), presented_mac.as_bytes()) {
                return Some((presented_id.to_owned(), expires));
            }
        }
    }
    if !mac_exact {
        return None;
    }
    if id_exact {
        let lengths = digits.len().saturating_sub(1)..=digits.len() + 1;
        for length in lengths.filter(|length| (1..=MAX_EXPIRY_DIGITS).contains(length)) {
            for candidate in one_edit_variants(digits, DIGITS, length) {
                let Some(expires) = signed_window(&candidate, now_micros) else {
                    continue;
                };
                if mac_matches(auth_key, presented_id, expires, presented_mac) {
                    return Some((presented_id.to_owned(), expires));
                }
            }
        }
    }
    let expires = relayed_expiry?;
    one_edit_variants(presented_id, HEX, HANDOFF_ID_HEX)
        .into_iter()
        .find(|candidate| mac_matches(auth_key, candidate, expires, presented_mac))
        .map(|request_id| (request_id, expires))
}

/// The expiry `digits` spell when it is a time a link issued now could carry.
/// Guard never writes a leading zero, so digits with one are not read as a
/// number: parsing would drop the zeros without counting them as slips.
fn signed_window(digits: &str, now_micros: i64) -> Option<i64> {
    if digits.is_empty() || digits.len() > MAX_EXPIRY_DIGITS || digits.starts_with('0') {
        return None;
    }
    let expires: i64 = digits.parse().ok()?;
    let expires_micros = expires.checked_mul(1_000_000)?;
    let latest =
        now_micros.checked_add((HANDOFF_TTL_SECONDS + HANDOFF_CLOCK_SKEW_SECONDS) * 1_000_000)?;
    (expires_micros > now_micros && expires_micros <= latest).then_some(expires)
}

pub(super) fn handoff_mac(auth_key: &str, request_id: &str, expires: i64) -> Option<String> {
    let mut mac = <Hmac<Sha256>>::new_from_slice(auth_key.as_bytes()).ok()?;
    mac.update(format!("{HANDOFF_VERSION}\n{request_id}\n{expires}").as_bytes());
    let digest = mac.finalize().into_bytes();
    Some(hex::encode(digest.get(..HANDOFF_MAC_BYTES)?))
}

fn mac_matches(auth_key: &str, request_id: &str, expires: i64, presented: &str) -> bool {
    handoff_mac(auth_key, request_id, expires).is_some_and(|expected| {
        crate::resident_transport::constant_time_eq(expected.as_bytes(), presented.as_bytes())
    })
}

/// Whether `presented` is `expected` or differs from it by one dropped, added
/// or changed byte. Every position is compared, whatever the outcome.
fn within_one_edit(expected: &[u8], presented: &[u8]) -> bool {
    use std::cmp::Ordering;

    match presented.len().cmp(&expected.len()) {
        Ordering::Equal => {
            let differing: u32 = expected
                .iter()
                .zip(presented)
                .map(|(left, right)| u32::from(left != right))
                .sum();
            differing <= 1
        }
        Ordering::Less if presented.len() + 1 == expected.len() => {
            any_deletion_matches(expected, presented)
        }
        Ordering::Greater if presented.len() == expected.len() + 1 => {
            any_deletion_matches(presented, expected)
        }
        _ => false,
    }
}

/// Whether removing one byte of `longer` leaves `shorter`, checking every byte.
fn any_deletion_matches(longer: &[u8], shorter: &[u8]) -> bool {
    let mut found = false;
    for skipped in 0..longer.len() {
        let mut candidate = Vec::with_capacity(shorter.len());
        candidate.extend_from_slice(&longer[..skipped]);
        candidate.extend_from_slice(&longer[skipped + 1..]);
        found |= crate::resident_transport::constant_time_eq(&candidate, shorter);
    }
    found
}

/// Every spelling of `text` one dropped, added or changed character from it,
/// over `alphabet`, that is `length` long.
fn one_edit_variants(text: &str, alphabet: &[u8], length: usize) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut variants = Vec::new();
    let mut push = |candidate: Vec<u8>| {
        if let Ok(candidate) = String::from_utf8(candidate) {
            variants.push(candidate);
        }
    };
    if bytes.len() == length + 1 {
        for skipped in 0..bytes.len() {
            let mut candidate = bytes.to_vec();
            candidate.remove(skipped);
            push(candidate);
        }
    } else if bytes.len() == length {
        for (position, original) in bytes.iter().enumerate() {
            for &replacement in alphabet.iter().filter(|byte| *byte != original) {
                let mut candidate = bytes.to_vec();
                candidate[position] = replacement;
                push(candidate);
            }
        }
    } else if bytes.len() + 1 == length {
        for position in 0..=bytes.len() {
            for &inserted in alphabet {
                let mut candidate = bytes.to_vec();
                candidate.insert(position, inserted);
                push(candidate);
            }
        }
    }
    variants
}

#[cfg(test)]
#[path = "native_review_link_repair_tests.rs"]
mod tests;

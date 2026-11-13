//! Wallet keys, account numbers and smuggled data in a fetched URL.
//!
//! A fetch whose query carries a private key, a recovery phrase, a wallet
//! address or a bank account number hands that value to the remote host.
//! So does a host name that spells data into its labels, where the DNS lookup
//! alone carries it out. Each value is recognised by its own checksum or
//! shape rather than by the parameter that holds it, so ordinary search terms,
//! identifiers and hashes stay plain.

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;
use sha2::{Digest, Sha256};
use url::Url;

#[path = "web_fetch_mnemonic_words.rs"]
mod mnemonic_words;

const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BECH32: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const MNEMONIC_LENGTHS: [usize; 5] = [24, 21, 18, 15, 12];
/// More labels than any ordinary public host uses; data chunked into a name
/// needs many of them.
const MAX_HOST_LABELS: usize = 6;
/// An opaque run this long in one query value is a payload, not a parameter.
const MAX_OPAQUE_QUERY_RUN: usize = 400;
/// Bounds of a random token sent as a path segment. Shorter mixed-case
/// identifiers, such as video and track ids, are common in ordinary links.
const MIN_TOKEN_SEGMENT: usize = 24;
const MAX_TOKEN_SEGMENT: usize = 64;
/// Bits per character; 24 random letters and digits score about 4.3.
const MIN_TOKEN_ENTROPY: f64 = 4.0;
/// Path words after which a service puts a document identifier.
const DOCUMENT_ROUTES: [&str; 2] = ["d", "folders"];

fn pattern(source: &str) -> Regex {
    Regex::new(source).expect("web fetch payload pattern compiles")
}

static TOKEN: LazyLock<Regex> = LazyLock::new(|| pattern(r"[A-Za-z0-9]+"));
static LEGACY_ADDRESS: LazyLock<Regex> =
    LazyLock::new(|| pattern(r"^[13][1-9A-HJ-NP-Za-km-z]{25,34}$"));
static WIF_KEY: LazyLock<Regex> =
    LazyLock::new(|| pattern(r"^(?:5[HJK][1-9A-HJ-NP-Za-km-z]{49}|[KL][1-9A-HJ-NP-Za-km-z]{51})$"));
static EXTENDED_KEY: LazyLock<Regex> =
    LazyLock::new(|| pattern(r"^(?:xpub6|xprv9|tpubD|tprv8)[1-9A-HJ-NP-Za-km-z]{100,}$"));
static SEGWIT_ADDRESS: LazyLock<Regex> =
    LazyLock::new(|| pattern(r"^(?i:bc|tb)1[A-Za-z0-9]{8,87}$"));
static IBAN: LazyLock<Regex> = LazyLock::new(|| pattern(r"^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$"));
static HEX_KEY: LazyLock<Regex> = LazyLock::new(|| pattern(r"^(?:0x)?[0-9a-fA-F]{64}$"));
static KEY_NAME: LazyLock<Regex> = LazyLock::new(|| {
    pattern(
        r"(?i)^(?:pk|priv|privkey|private|private_?key|mnemonic|seed|seed_?phrase|phrase|wif|xprv)$",
    )
});
static WORD_BREAK: LazyLock<Regex> = LazyLock::new(|| pattern(r"[\s+,]+"));
static OPAQUE_RUN: LazyLock<Regex> =
    LazyLock::new(|| pattern(&format!("[A-Za-z0-9+/_-]{{{MAX_OPAQUE_QUERY_RUN},}}")));
static BASE32_LABEL: LazyLock<Regex> = LazyLock::new(|| pattern(r"^[A-Z2-7]{16,}$"));
static MNEMONIC_INDEX: LazyLock<HashMap<&'static str, u16>> = LazyLock::new(|| {
    mnemonic_words::WORDS
        .iter()
        .zip(0u16..)
        .map(|(word, index)| (*word, index))
        .collect()
});

fn double_sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(bytes)).into()
}

/// Base58 text whose last four bytes are the double-SHA-256 checksum of the
/// rest, as in every Bitcoin address and key encoding.
fn base58_checked(text: &str) -> bool {
    let mut bytes: Vec<u8> = Vec::new();
    for symbol in text.bytes() {
        let Some(mut carry) = BASE58.iter().position(|b| *b == symbol) else {
            return false;
        };
        for byte in bytes.iter_mut().rev() {
            carry += usize::from(*byte) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let zeros = text.bytes().take_while(|b| *b == b'1').count();
    let mut decoded = vec![0u8; zeros];
    decoded.extend(bytes);
    decoded.len() > 4 && {
        let (body, checksum) = decoded.split_at(decoded.len() - 4);
        double_sha256(body)[..4] == *checksum
    }
}

/// A Bitcoin segwit address whose bech32 or bech32m checksum holds.
fn segwit_checked(text: &str) -> bool {
    const GENERATOR: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let lower = text.to_ascii_lowercase();
    let Some((hrp, data)) = lower.rsplit_once('1') else {
        return false;
    };
    let Some(values) = data
        .bytes()
        .map(|b| BECH32.iter().position(|c| *c == b).map(|v| v as u32))
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    let mut checksum: u32 = 1;
    let expanded = hrp
        .bytes()
        .map(|b| u32::from(b >> 5))
        .chain([0])
        .chain(hrp.bytes().map(|b| u32::from(b & 31)))
        .chain(values);
    for value in expanded {
        let top = checksum >> 25;
        checksum = ((checksum & 0x01ff_ffff) << 5) ^ value;
        for (bit, generator) in GENERATOR.iter().enumerate() {
            if (top >> bit) & 1 == 1 {
                checksum ^= generator;
            }
        }
    }
    checksum == 1 || checksum == 0x2bc8_30a3
}

/// An international bank account number whose mod-97 check digits hold.
fn iban_checked(text: &str) -> bool {
    let rotated = text[4..].bytes().chain(text[..4].bytes());
    let mut remainder: u32 = 0;
    for byte in rotated {
        let value = u32::from(match byte {
            b'0'..=b'9' => byte - b'0',
            _ => byte - b'A' + 10,
        });
        let scale = if value >= 10 { 100 } else { 10 };
        remainder = (remainder * scale + value) % 97;
    }
    remainder == 1
}

/// A BIP-39 recovery phrase: every word from the list and the checksum bits
/// matching the SHA-256 of the entropy they encode.
fn mnemonic_checked(words: &[&str]) -> bool {
    let Some(indexes) = words
        .iter()
        .map(|word| MNEMONIC_INDEX.get(word).copied())
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    let bits: Vec<bool> = indexes
        .iter()
        .flat_map(|index| (0..11).rev().map(move |bit| (index >> bit) & 1 == 1))
        .collect();
    let checksum_bits = bits.len() / 33;
    let (entropy_bits, checksum) = bits.split_at(bits.len() - checksum_bits);
    let entropy: Vec<u8> = entropy_bits
        .chunks(8)
        .map(|chunk| {
            chunk
                .iter()
                .fold(0u8, |byte, bit| (byte << 1) | u8::from(*bit))
        })
        .collect();
    let digest = Sha256::digest(&entropy);
    checksum
        .iter()
        .enumerate()
        .all(|(bit, set)| ((digest[0] >> (7 - bit)) & 1 == 1) == *set)
}

fn holds_recovery_phrase(value: &str) -> bool {
    let lowered = value.trim().to_ascii_lowercase();
    let words: Vec<&str> = WORD_BREAK.split(&lowered).collect();
    (0..words.len()).any(|start| {
        MNEMONIC_LENGTHS.iter().any(|length| {
            words
                .get(start..start + length)
                .is_some_and(mnemonic_checked)
        })
    })
}

fn wallet_or_account_token(token: &str) -> bool {
    (LEGACY_ADDRESS.is_match(token) && base58_checked(token))
        || (WIF_KEY.is_match(token) && base58_checked(token))
        || EXTENDED_KEY.is_match(token)
        || (SEGWIT_ADDRESS.is_match(token) && segwit_checked(token))
        || iban_token(token)
}

/// The length of an IBAN from each country that issues them.
const IBAN_LENGTHS: &[(&str, usize)] = &[
    ("AD", 24),
    ("AE", 23),
    ("AL", 28),
    ("AT", 20),
    ("AZ", 28),
    ("BA", 20),
    ("BE", 16),
    ("BG", 22),
    ("BH", 22),
    ("BR", 29),
    ("BY", 28),
    ("CH", 21),
    ("CR", 22),
    ("CY", 28),
    ("CZ", 24),
    ("DE", 22),
    ("DK", 18),
    ("DO", 28),
    ("EE", 20),
    ("EG", 29),
    ("ES", 24),
    ("FI", 18),
    ("FO", 18),
    ("FR", 27),
    ("GB", 22),
    ("GE", 22),
    ("GI", 23),
    ("GL", 18),
    ("GR", 27),
    ("GT", 28),
    ("HR", 21),
    ("HU", 28),
    ("IE", 22),
    ("IL", 23),
    ("IQ", 23),
    ("IS", 26),
    ("IT", 27),
    ("JO", 30),
    ("KW", 30),
    ("KZ", 20),
    ("LB", 28),
    ("LC", 32),
    ("LI", 21),
    ("LT", 20),
    ("LU", 20),
    ("LV", 21),
    ("MC", 27),
    ("MD", 24),
    ("ME", 22),
    ("MK", 19),
    ("MR", 27),
    ("MT", 31),
    ("MU", 30),
    ("NL", 18),
    ("NO", 15),
    ("PK", 24),
    ("PL", 28),
    ("PS", 29),
    ("PT", 25),
    ("QA", 29),
    ("RO", 24),
    ("RS", 22),
    ("SA", 24),
    ("SC", 31),
    ("SE", 24),
    ("SI", 19),
    ("SK", 24),
    ("SM", 27),
    ("ST", 25),
    ("SV", 28),
    ("TL", 23),
    ("TN", 24),
    ("TR", 26),
    ("UA", 29),
    ("VA", 22),
    ("VG", 24),
    ("XK", 20),
];

/// An IBAN with a valid checksum. One written in lower or mixed case must
/// also have its country's length, since a lowercase identifier passes the
/// shape and the checksum by chance far more often than an uppercase one.
fn iban_token(token: &str) -> bool {
    if IBAN.is_match(token) {
        return iban_checked(token);
    }
    let upper = token.to_ascii_uppercase();
    IBAN.is_match(&upper)
        && IBAN_LENGTHS
            .iter()
            .any(|(country, length)| upper.starts_with(country) && upper.len() == *length)
        && iban_checked(&upper)
}

fn query_value_carries_payload(value: &str) -> bool {
    TOKEN
        .find_iter(value)
        .any(|token| wallet_or_account_token(token.as_str()))
        || holds_recovery_phrase(value)
        || OPAQUE_RUN.is_match(value)
}

/// Whether `part`, as written or under up to `MAX_DECODE_DEPTH` layers of
/// percent, hex or base64 encoding, reads as `found`: a recovery phrase sent
/// base64url-encoded is as short as a session token.
fn any_reading(part: &str, depth: usize, found: &dyn Fn(&str) -> bool) -> bool {
    found(part)
        || (depth < super::MAX_DECODE_DEPTH
            && super::decoded_readings(part)
                .iter()
                .any(|reading| any_reading(reading, depth + 1, found)))
}

/// Whether a query name, value or fragment carries a payload in any reading.
fn query_part_carries_payload(part: &str) -> bool {
    any_reading(part, 0, &query_value_carries_payload)
}

/// Whether a query pair sends a hex private key under a key-shaped name,
/// with the name and the value each read through their encodings.
fn names_a_hex_key(key: &str, value: &str) -> bool {
    any_reading(key, 0, &|name| KEY_NAME.is_match(name))
        && any_reading(value, 0, &|value| HEX_KEY.is_match(value))
}

/// Shannon entropy of `value` in bits per character.
fn entropy(value: &str) -> f64 {
    let mut counts = HashMap::new();
    for byte in value.bytes() {
        *counts.entry(byte).or_insert(0usize) += 1;
    }
    let total = value.len() as f64;
    counts
        .values()
        .map(|&count| {
            let share = count as f64 / total;
            -share * share.log2()
        })
        .sum()
}

/// How often adjacent characters change between lowercase, uppercase and
/// digit. A random token switches class at most positions; a run of words, even
/// in CamelCase with a year on the end, switches only at word boundaries.
fn class_switches(segment: &str) -> usize {
    let class = |byte: u8| {
        if byte.is_ascii_digit() {
            0
        } else if byte.is_ascii_uppercase() {
            1
        } else {
            2
        }
    };
    segment
        .as_bytes()
        .windows(2)
        .filter(|pair| class(pair[0]) != class(pair[1]))
        .count()
}

/// Whether a path segment is a random token: 24 to 64 letters and digits in
/// both cases, with no separator, and close to the entropy of random text.
/// That is the shape of an API key or session token, not of a slug, a
/// version, a commit hash (one case) or a UUID (hyphenated). A document
/// identifier routed by its service (`/d/<id>`, `/folders/<id>`) keeps its
/// usual shape and is left alone.
fn token_segment(previous: Option<&str>, segment: &str) -> bool {
    (MIN_TOKEN_SEGMENT..=MAX_TOKEN_SEGMENT).contains(&segment.len())
        && segment.bytes().all(|byte| byte.is_ascii_alphanumeric())
        && segment.bytes().any(|byte| byte.is_ascii_lowercase())
        && segment.bytes().any(|byte| byte.is_ascii_uppercase())
        && segment.bytes().any(|byte| byte.is_ascii_digit())
        && entropy(segment) >= MIN_TOKEN_ENTROPY
        && class_switches(segment) * 3 >= segment.len()
        && !previous.is_some_and(|previous| DOCUMENT_ROUTES.contains(&previous))
}

/// Whether a path segment carries a random token, as a key or session
/// value smuggled into the path of a fetch does.
fn path_carries_token(url: &Url) -> bool {
    let Some(segments) = url.path_segments() else {
        return false;
    };
    let mut previous = None;
    for segment in segments {
        if token_segment(previous, segment) {
            return true;
        }
        previous = Some(segment);
    }
    false
}

/// Whether the path, query or fragment carries a wallet key, recovery
/// phrase, wallet address, bank account number, random token or an opaque
/// payload.
pub(super) fn url_carries_payload(url: &Url) -> bool {
    let decoded = |text: &str| {
        percent_encoding::percent_decode_str(text)
            .decode_utf8_lossy()
            .into_owned()
    };
    // A path segment can carry a recovery phrase as well as a query can; the
    // phrase needs its words split by spaces, `+` or commas, so a hyphenated
    // slug is not read as one.
    let path_phrase = url.path_segments().is_some_and(|mut segments| {
        segments.any(|segment| holds_recovery_phrase(&decoded(segment)))
    });
    let fragment = url.fragment().map(str::to_owned);
    path_phrase
        || path_carries_token(url)
        || url.query_pairs().any(|(key, value)| {
            names_a_hex_key(&key, &value)
                || query_part_carries_payload(&key)
                || query_part_carries_payload(&value)
        })
        || fragment
            .map(|fragment| decoded(&fragment))
            .is_some_and(|fragment| query_part_carries_payload(&fragment))
}

/// A label of either case that decodes from base32 to readable text, as data
/// spelled into a host name does. An ordinary word-like label decodes to
/// noise.
fn base32_text(label: &str) -> bool {
    if label.len() < 16
        || !label
            .bytes()
            .all(|b| matches!(b.to_ascii_uppercase(), b'A'..=b'Z' | b'2'..=b'7'))
    {
        return false;
    }
    let mut bits = 0u32;
    let mut held = 0u32;
    let mut decoded = Vec::new();
    for byte in label.bytes() {
        let value = match byte.to_ascii_uppercase() {
            letter @ b'A'..=b'Z' => u32::from(letter - b'A'),
            digit => u32::from(digit - b'2') + 26,
        };
        bits = (bits << 5) | value;
        held += 5;
        if held >= 8 {
            held -= 8;
            decoded.push((bits >> held) as u8);
            bits &= (1 << held) - 1;
        }
    }
    decoded
        .iter()
        .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
}

/// Whether a host name, as written, spells data into its labels: more labels
/// than a public host uses, a base32 run written in upper case, or a label
/// that names itself as an exfiltration endpoint.
pub(super) fn host_spells_data(raw_host: &str) -> bool {
    let labels: Vec<&str> = raw_host.trim_end_matches('.').split('.').collect();
    labels.len() > MAX_HOST_LABELS
        || labels.iter().any(|label| {
            (BASE32_LABEL.is_match(label) && label.bytes().any(|b| b.is_ascii_digit()))
                || base32_text(label)
                || label.to_ascii_lowercase().contains("exfil")
        })
}

#[cfg(test)]
#[path = "web_fetch_payloads_tests.rs"]
mod tests;

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
        || (IBAN.is_match(token) && iban_checked(token))
}

fn query_value_carries_payload(value: &str) -> bool {
    TOKEN
        .find_iter(value)
        .any(|token| wallet_or_account_token(token.as_str()))
        || holds_recovery_phrase(value)
        || OPAQUE_RUN.is_match(value)
}

/// Whether the query or fragment carries a wallet key, recovery phrase,
/// wallet address, bank account number or an opaque payload.
pub(super) fn url_carries_payload(url: &Url) -> bool {
    let fragment = url.fragment().map(str::to_owned);
    url.query_pairs().any(|(key, value)| {
        (KEY_NAME.is_match(&key) && HEX_KEY.is_match(&value)) || query_value_carries_payload(&value)
    }) || fragment
        .map(|fragment| {
            percent_encoding::percent_decode_str(&fragment)
                .decode_utf8_lossy()
                .into_owned()
        })
        .is_some_and(|fragment| query_value_carries_payload(&fragment))
}

/// Whether a host name, as written, spells data into its labels: more labels
/// than a public host uses, a base32 run written in upper case, or a label
/// that names itself as an exfiltration endpoint.
pub(super) fn host_spells_data(raw_host: &str) -> bool {
    let labels: Vec<&str> = raw_host.trim_end_matches('.').split('.').collect();
    labels.len() > MAX_HOST_LABELS
        || labels.iter().any(|label| {
            (BASE32_LABEL.is_match(label) && label.bytes().any(|b| b.is_ascii_digit()))
                || label.to_ascii_lowercase().contains("exfil")
        })
}

#[cfg(test)]
#[path = "web_fetch_payloads_tests.rs"]
mod tests;

//! Shared seeded generator and Gmail send entry points for the business
//! parser property suites.
//!
//! Each property runs a fixed number of cases from a deterministic SplitMix64
//! stream, so failures reproduce from the seed and case number without adding
//! a property-testing dependency.
#![allow(dead_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use guard_command::business_gmail_plain::{GmailPlainErrorV1, GmailPlainInputV1};
use guard_command::business_gmail_wire::{GmailSendWireErrorV1, GmailSendWireInputV1};

pub const SEED: u64 = 0x5eed_0fb0_517e_5500;
pub const CASES: u64 = 512;
pub const PARAMS: &str = r#"{"userId":"me"}"#;

pub struct Rng(u64);

impl Rng {
    pub fn for_case(property: u64, case: u64) -> Self {
        Self(SEED ^ property.rotate_left(32) ^ case.wrapping_mul(0x9e37_79b9_7f4a_7c15))
    }

    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    pub fn bytes(&mut self, max: usize) -> Vec<u8> {
        let len = 1 + self.below(max);
        (0..len).map(|_| self.next() as u8).collect()
    }
}

pub fn wire(body: String) -> Result<GmailSendWireInputV1, GmailSendWireErrorV1> {
    GmailSendWireInputV1::from_owned_json(PARAMS.as_bytes().to_vec(), body.into_bytes())
}

pub fn plain(mime: &[u8]) -> Result<GmailPlainInputV1, GmailPlainErrorV1> {
    let wire = wire(format!(r#"{{"raw":"{}"}}"#, URL_SAFE_NO_PAD.encode(mime))).unwrap();
    GmailPlainInputV1::from_owned_wire(wire)
}

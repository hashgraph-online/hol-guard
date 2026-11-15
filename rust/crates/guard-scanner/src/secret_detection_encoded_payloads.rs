//! The decoded payloads of a text, read once, for callers that place several
//! credentials in it.

use zeroize::Zeroizing;

use super::{walk_payloads, MAX_DECODED_BYTES};

/// One base64 payload's span in the text and its decoded UTF-8 text.
pub struct DecodedPayload {
    pub start: usize,
    pub end: usize,
    pub text: Zeroizing<String>,
}

/// The text's decodable payloads, and whether the decoding budget the
/// scanner applies ran out before every payload was read.
pub struct DecodedPayloads {
    pub payloads: Vec<DecodedPayload>,
    pub exhausted: bool,
}

impl DecodedPayloads {
    /// Spans of the payloads whose decoded text holds `candidate`.
    pub fn spans_holding(&self, candidate: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
        let candidate = candidate.to_owned();
        self.payloads
            .iter()
            .filter(move |payload| !candidate.is_empty() && payload.text.contains(&candidate))
            .map(|payload| (payload.start, payload.end))
    }
}

/// Decode every payload in `text` under the same budget the scanner uses, so
/// `exhausted` says exactly when a scan of this text skipped payloads.
pub fn decoded_payloads(text: &str) -> DecodedPayloads {
    let mut budget = MAX_DECODED_BYTES;
    let mut found = DecodedPayloads {
        payloads: Vec::new(),
        exhausted: false,
    };
    walk_payloads(text, &mut |payload| {
        let Some(decoded) = payload.decode() else {
            return true;
        };
        let Some(left) = budget.checked_sub(decoded.len()) else {
            found.exhausted = true;
            return false;
        };
        budget = left;
        if let Ok(plain) = std::str::from_utf8(&decoded) {
            found.payloads.push(DecodedPayload {
                start: payload.at,
                end: payload.end,
                text: Zeroizing::new(plain.to_owned()),
            });
        }
        true
    });
    found
}

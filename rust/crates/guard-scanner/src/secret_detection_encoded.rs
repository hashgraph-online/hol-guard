//! Provider credentials carried inside a base64 payload.
//!
//! A credential does not stop being a credential because something encoded it
//! on the way into a file. A Kubernetes `Secret` manifest holds every value
//! base64-encoded, `base64 < .env > env.b64` writes the same bytes wrapped at a
//! fixed column, and both read as ordinary high-entropy text to a scan that
//! only looks at the characters on the page.
//!
//! This pass decodes the base64 runs in a text and re-reads the decoded bytes
//! with the provider formats alone. A provider format says what it is -- a
//! prefix, an alphabet and a length -- so a match inside decoded bytes is the
//! credential it names, with no surrounding line needed to believe it. The
//! contextual assignment rule is deliberately not run here: its score is built
//! from the line the candidate sits on, and a decoded payload has no line in
//! the file for it to read.
//!
//! The finding is reported at the encoded run, because that is where a reader
//! has to go to remove it, and it carries [`ENCODED_REASON`] among its reasons
//! so nobody is left searching the file for bytes it does not literally hold.
//!
//! Two shapes are decoded: a run standing inside a line, which is how a
//! manifest or a JSON document carries one value, and a block of consecutive
//! whole lines of equal width, which is what every base64 writer produces when
//! it wraps. A run mixing the standard `+/` alphabet with the URL-safe `-_` one
//! is valid base64 in neither, so it is skipped rather than guessed at.

use regex::Regex;
use std::sync::LazyLock;

use base64ct::{Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding};
use zeroize::Zeroizing;

use super::{finding_from_match, LineIndex, RuleMeta, SecretFinding, SECRET_RULES};

/// Named among a finding's reasons when the credential was decoded rather than
/// read off the page.
pub(super) const ENCODED_REASON: &str = "base64-encoded-payload";

/// Folded into `detector_version`, so a stored scan taken before this pass
/// existed is recognisable as one that never looked inside a payload.
pub(super) const ENCODED_PAYLOAD_POLICY_VERSION: &str = "encoded-payload-scan-v1";

/// Shortest run worth decoding. The shortest provider format in the catalog is
/// twenty characters, which no run below this length can carry.
const MIN_RUN: usize = 24;

/// Narrowest wrapped block worth joining. Every base64 writer wraps at 64 or
/// 76 columns; a pair of shorter lines that happen to share a width is prose.
const MIN_WRAP_WIDTH: usize = 40;

/// Longest run decoded, in encoded characters. Past this a run is a payload --
/// an embedded image, an archive -- rather than a credential.
const MAX_RUN: usize = 8 * 1024;

/// Most decoded bytes one text contributes. Decoding is cheap; re-reading the
/// result with every provider format is the cost, and this bounds that to the
/// work of scanning one more file of this size.
const MAX_DECODED_BYTES: usize = 256 * 1024;

static RUN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r"[A-Za-z0-9+/_-]{{{MIN_RUN},}}={{0,2}}"))
        .expect("RUN is built from integer literals")
});

/// Findings for the provider formats carried in this text's base64 payloads,
/// capped at `remaining` so the caller's `max_findings` still holds.
pub(super) fn encoded_payload_findings(
    text: &str,
    path: &str,
    source: &str,
    commit: Option<&str>,
    lines: &LineIndex,
    remaining: usize,
) -> Vec<SecretFinding> {
    let mut scan = EncodedScan {
        text,
        path,
        source,
        commit,
        lines,
        remaining,
        decoded_budget: MAX_DECODED_BYTES,
        findings: Vec::new(),
    };
    if remaining == 0 {
        return scan.findings;
    }
    for run in RUN.find_iter(text) {
        if !scan.consider(run.as_str(), run.start()) {
            return scan.findings;
        }
    }
    for (at, block) in wrapped_blocks(text) {
        if !scan.consider(&block, at) {
            return scan.findings;
        }
    }
    scan.findings
}

struct EncodedScan<'a> {
    text: &'a str,
    path: &'a str,
    source: &'a str,
    commit: Option<&'a str>,
    lines: &'a LineIndex,
    remaining: usize,
    decoded_budget: usize,
    findings: Vec<SecretFinding>,
}

impl EncodedScan<'_> {
    /// Decode one run and read the result. `false` means the scan is finished,
    /// either because the caller's budget is full or because this text has
    /// spent the decoding it is allowed.
    fn consider(&mut self, encoded: &str, at: usize) -> bool {
        if encoded.len() > MAX_RUN {
            return true;
        }
        let Some(decoded) = decode(encoded) else {
            return true;
        };
        let Some(budget) = self.decoded_budget.checked_sub(decoded.len()) else {
            return false;
        };
        self.decoded_budget = budget;
        // Bytes that are not text cannot hold a provider format, and reading
        // them as one would be reading the lossy replacement characters a
        // conversion invented rather than anything the file carries.
        let Ok(plain) = std::str::from_utf8(&decoded) else {
            return true;
        };
        for rule in SECRET_RULES.iter() {
            for captures in rule.pattern.captures_iter(plain) {
                if captures
                    .name("overrun")
                    .is_some_and(|overrun| !overrun.is_empty())
                {
                    continue;
                }
                let matched = captures
                    .name("secret")
                    .unwrap_or_else(|| captures.get(0).expect("whole match always present"));
                let finding = finding_from_match(
                    &RuleMeta::of(rule),
                    matched.as_str(),
                    self.text,
                    at,
                    self.path,
                    self.source,
                    self.commit,
                    Some(rule),
                    self.lines,
                );
                let Some(mut finding) = finding else { continue };
                finding.context_reasons.push(ENCODED_REASON);
                self.findings.push(finding);
                if self.findings.len() >= self.remaining {
                    return false;
                }
            }
        }
        true
    }
}

/// Decode one run, in whichever single alphabet it is written in.
fn decode(run: &str) -> Option<Zeroizing<Vec<u8>>> {
    let standard = run.contains('+') || run.contains('/');
    let url = run.contains('-') || run.contains('_');
    if standard && url {
        return None;
    }
    let padded = run.ends_with('=');
    let decoded = match (url, padded) {
        (false, false) => Base64Unpadded::decode_vec(run),
        (false, true) => Base64::decode_vec(run),
        (true, false) => Base64UrlUnpadded::decode_vec(run),
        (true, true) => Base64Url::decode_vec(run),
    }
    .ok()?;
    Some(Zeroizing::new(decoded))
}

/// The wrapped base64 blocks in a text, each as its offset and joined body.
///
/// A block is two or more consecutive whole lines of base64 where every line
/// but the last has the same width, which is exactly what a writer that wraps
/// at a fixed column produces and what a paragraph of prose never does.
fn wrapped_blocks(text: &str) -> Vec<(usize, Zeroizing<String>)> {
    let mut blocks: Vec<(usize, Zeroizing<String>)> = Vec::new();
    let mut open: Option<OpenBlock> = None;
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        let start = offset;
        offset += line.len();
        let body = line.trim_end_matches(['\n', '\r']);
        if let Some(block) = open.as_mut() {
            if block.extend(body) {
                continue;
            }
            if let Some(block) = open.take().and_then(OpenBlock::close) {
                blocks.push(block);
            }
        }
        if body.len() >= MIN_WRAP_WIDTH && is_body(body) {
            open = Some(OpenBlock {
                at: start,
                width: Some(body.len()),
                lines: 1,
                overflowed: false,
                joined: Zeroizing::new(body.to_string()),
            });
        }
    }
    if let Some(block) = open.and_then(OpenBlock::close) {
        blocks.push(block);
    }
    blocks
}

struct OpenBlock {
    at: usize,
    /// The wrap's column width, until the padded last line closes it.
    width: Option<usize>,
    lines: usize,
    overflowed: bool,
    joined: Zeroizing<String>,
}

impl OpenBlock {
    /// Take one more line, if it continues the wrap. A line of the block's own
    /// width continues it; a shorter one, or one carrying the padding, is the
    /// last line and closes the wrap after being taken.
    fn extend(&mut self, body: &str) -> bool {
        let Some(width) = self.width else {
            return false;
        };
        let continues = body.len() == width && is_body(body);
        let tail = !continues && !body.is_empty() && body.len() <= width && is_tail(body);
        if !continues && !tail {
            return false;
        }
        self.lines += 1;
        if tail {
            self.width = None;
        }
        // A block past the run bound is a payload, not a credential, but its
        // remaining lines still belong to it: keep taking them so they cannot
        // open a block of their own at an offset the wrap never started on.
        if self.overflowed || self.joined.len() + body.len() > MAX_RUN {
            self.overflowed = true;
        } else {
            self.joined.push_str(body);
        }
        true
    }

    /// The block, once it holds more than the single line that opened it. One
    /// line on its own is already covered by the run pass.
    fn close(self) -> Option<(usize, Zeroizing<String>)> {
        (!self.overflowed && self.lines > 1).then_some((self.at, self.joined))
    }
}

fn is_body(body: &str) -> bool {
    body.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/' || byte == b'_' || byte == b'-'
    })
}

fn is_tail(body: &str) -> bool {
    let body = body.trim_end_matches('=');
    !body.is_empty() && is_body(body)
}

#[cfg(test)]
#[path = "secret_detection_encoded_tests.rs"]
mod tests;

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
//! credential it names. What surrounds it is read in the decoded bytes too,
//! because that is where the words saying what the value is were written: a
//! fixture marker beside a sample token still marks it as one after an
//! encoding, and the encoded characters it would otherwise be read against say
//! nothing about anything.
//!
//! The finding is reported at the line of the file holding the start of the
//! encoded match, because that is where a reader has to go to remove it, and it
//! carries [`ENCODED_REASON`] among its reasons so nobody is left searching the
//! file for bytes it does not literally hold. For the same reason the payload
//! itself is what a redaction replaces: [`encoded_payload_spans`] names the
//! spans holding a given credential, since base64 cannot have the bytes taken
//! out of it in place.
//!
//! Two shapes are decoded: a run standing inside a line, which is how a
//! manifest or a JSON document carries one value, and a block of consecutive
//! whole lines of equal width, which is what every base64 writer produces when
//! it wraps. The lines of a wrap are read only as part of it, so a credential
//! that happens to fall inside one of them is one finding rather than two; the
//! one wrap that is read line by line is the one too long to decode whole, and
//! that one is never read as a payload. A
//! run mixing the standard `+/` alphabet with the URL-safe `-_` one is valid
//! base64 in neither, so it is skipped rather than guessed at.

use regex::Regex;
use std::sync::LazyLock;

use base64ct::{Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding};
use zeroize::Zeroizing;

use super::{finding_in_context, LineIndex, RuleMeta, SecretFinding, SECRET_RULES};

/// Named among a finding's reasons when the credential was decoded rather than
/// read off the page.
pub const ENCODED_REASON: &str = "base64-encoded-payload";

/// Folded into `detector_version`, so a stored scan taken before this pass
/// existed is recognisable as one that never looked inside a payload.
pub(super) const ENCODED_PAYLOAD_POLICY_VERSION: &str = "encoded-payload-scan-v1";

/// Shortest run worth decoding. The shortest provider format in the catalog is
/// twenty characters, which no run below this length can carry.
const MIN_RUN: usize = 24;

/// Narrowest wrapped block worth joining. A writer that wraps chooses its own
/// column -- 64 and 76 are the usual ones, but a dump pasted into a document or
/// a commit message is often narrower -- so the floor is simply the shortest
/// run worth decoding at all. Two consecutive lines of equal width written
/// wholly in the base64 alphabet is already a shape prose does not take, and a
/// pair that is prose anyway decodes to bytes no provider format matches.
const MIN_WRAP_WIDTH: usize = MIN_RUN;

/// Longest payload decoded, in encoded characters. Past this a payload is an
/// embedded image or an archive rather than a credential. A wrap that joins to
/// more than this is not decoded whole; it is read as the lines it was written
/// as, which is the only reading of it left that stays inside the bound.
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
    walk_payloads(text, &mut |payload| scan.consider(payload));
    scan.findings
}

/// The spans of the payloads in `text` whose decoded bytes carry `candidate`.
///
/// A credential written into a file only in an encoded form has no literal
/// occurrence for a redaction to replace. Base64 cannot have bytes taken out of
/// it in place either, so what a redaction replaces is the whole payload that
/// holds the credential, and these are the spans of them.
pub fn encoded_payload_spans(text: &str, candidate: &str) -> Vec<(usize, usize)> {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    if candidate.is_empty() {
        return spans;
    }
    let mut budget = MAX_DECODED_BYTES;
    walk_payloads(text, &mut |payload| {
        let Some(decoded) = payload.decode() else {
            return true;
        };
        let Some(left) = budget.checked_sub(decoded.len()) else {
            return false;
        };
        budget = left;
        if std::str::from_utf8(&decoded).is_ok_and(|plain| plain.contains(candidate)) {
            spans.push((payload.at, payload.end));
        }
        true
    });
    spans
}

/// One base64 payload: a run standing inside a line, or a block of wrapped
/// lines joined back into the stream the writer cut up.
struct Payload<'a> {
    /// Where the payload starts in the text it was read from.
    at: usize,
    /// One past where it ends there.
    end: usize,
    /// Its encoded characters, with a wrap's line breaks taken out.
    body: &'a str,
    /// Set for a wrapped block, so a match in the joined stream can be put back
    /// on the line of the file that holds it.
    wrap: Option<Wrap<'a>>,
}

/// The shape of a wrap: the column it was written at, and where each of its
/// lines starts in the file.
struct Wrap<'a> {
    column: usize,
    lines: &'a [usize],
}

impl Payload<'_> {
    fn decode(&self) -> Option<Zeroizing<Vec<u8>>> {
        (self.body.len() <= MAX_RUN)
            .then(|| decode(self.body))
            .flatten()
    }

    /// Where a match `decoded` bytes into this payload is reported.
    ///
    /// Three decoded bytes are written as four encoded characters, so the group
    /// of four holding a given byte starts at a known character of the joined
    /// stream, and the wrap's column says which of its lines that character
    /// was written on. A run is one line already and is reported where it
    /// stands.
    fn line_at(&self, decoded: usize) -> usize {
        let Some(wrap) = self.wrap.as_ref() else {
            return self.at;
        };
        let encoded = 4 * (decoded / 3);
        let line = encoded / wrap.column;
        wrap.lines[line.min(wrap.lines.len() - 1)]
    }
}

/// Read every payload in the text, in the order it is written. Returning
/// `false` from `read` stops the walk.
///
/// Blocks are read as they close rather than collected, and a line already
/// taken by a block is not read as a run of its own, so one credential is one
/// finding and the text is never copied whole.
fn walk_payloads(text: &str, read: &mut impl FnMut(&Payload<'_>) -> bool) {
    let mut open: Option<OpenBlock> = None;
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        let start = offset;
        offset += line.len();
        let body = line.trim_end_matches(['\n', '\r']);
        if let Some(block) = open.as_mut() {
            match block.extend(body, start) {
                Taken::Held => continue,
                Taken::Spilled => {
                    if !spill(block, read) || !runs_in(body, start, read) {
                        return;
                    }
                    continue;
                }
                Taken::Rejected => {
                    if !close(open.take(), read) {
                        return;
                    }
                }
            }
        }
        // A line that could open a wrap is held until the next line says
        // whether it did. One that did not is read as a run then.
        if body.len() >= MIN_WRAP_WIDTH && body.len() <= MAX_RUN && is_body(body) {
            open = Some(OpenBlock::opened(start, body));
            continue;
        }
        if !runs_in(body, start, read) {
            return;
        }
    }
    close(open, read);
}

/// Read a wrap that outgrew the bound as the lines it was written as.
///
/// Nothing joined is reported for it, so reading its lines cannot name the same
/// credential twice, and the lines it was already holding are given up here so
/// that what the block carries stays bounded.
fn spill(block: &mut OpenBlock, read: &mut impl FnMut(&Payload<'_>) -> bool) -> bool {
    let held = std::mem::take(&mut block.lines);
    let joined = std::mem::replace(&mut block.joined, Zeroizing::new(String::new()));
    for (index, at) in held.iter().enumerate() {
        let from = index * block.column;
        let to = (from + block.column).min(joined.len());
        if from >= to {
            break;
        }
        if !runs_in(&joined[from..to], *at, read) {
            return false;
        }
    }
    true
}

/// Read a block that has taken its last line.
fn close(block: Option<OpenBlock>, read: &mut impl FnMut(&Payload<'_>) -> bool) -> bool {
    let Some(block) = block else {
        return true;
    };
    if block.overflowed {
        return true;
    }
    if block.lines.len() == 1 {
        // Never a wrap after all: the line it opened on is an ordinary run.
        return runs_in(&block.joined, block.at, read);
    }
    read(&Payload {
        at: block.at,
        end: block.end,
        body: &block.joined,
        wrap: Some(Wrap {
            column: block.column,
            lines: &block.lines,
        }),
    })
}

/// Read the runs standing inside one line. A run cannot cross a line break, so
/// a line holds whole runs or none.
fn runs_in(line: &str, at: usize, read: &mut impl FnMut(&Payload<'_>) -> bool) -> bool {
    for run in RUN.find_iter(line) {
        let payload = Payload {
            at: at + run.start(),
            end: at + run.end(),
            body: run.as_str(),
            wrap: None,
        };
        if !read(&payload) {
            return false;
        }
    }
    true
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
    /// Decode one payload and read the result. `false` means the scan is
    /// finished, either because the caller's budget is full or because this
    /// text has spent the decoding it is allowed.
    fn consider(&mut self, payload: &Payload<'_>) -> bool {
        let Some(decoded) = payload.decode() else {
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
                let finding = finding_in_context(
                    &RuleMeta::of(rule),
                    matched.as_str(),
                    plain,
                    matched.start(),
                    self.lines
                        .line_of(self.text, payload.line_at(matched.start())),
                    self.path,
                    self.source,
                    self.commit,
                    Some(rule),
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

/// A wrapped block under construction: two or more consecutive whole lines of
/// base64 where every line but the last has the same width, which is exactly
/// what a writer that wraps at a fixed column produces and what a paragraph of
/// prose never does.
/// What an open wrap did with a line offered to it.
enum Taken {
    /// The line does not continue the wrap, which is therefore finished.
    Rejected,
    /// The wrap took the line and is holding it.
    Held,
    /// The line belongs to the wrap, but the wrap has outgrown the bound and
    /// is no longer holding anything: the caller reads the line itself.
    Spilled,
}

struct OpenBlock {
    at: usize,
    end: usize,
    /// The column the wrap was opened at, which does not change.
    column: usize,
    /// That same width while the wrap is still taking lines, and `None` once
    /// the short or padded last line has closed it.
    width: Option<usize>,
    /// Where each taken line starts in the file.
    lines: Vec<usize>,
    overflowed: bool,
    joined: Zeroizing<String>,
}

impl OpenBlock {
    fn opened(at: usize, body: &str) -> Self {
        Self {
            at,
            end: at + body.len(),
            column: body.len(),
            width: Some(body.len()),
            lines: vec![at],
            overflowed: false,
            joined: Zeroizing::new(body.to_string()),
        }
    }

    /// Take one more line, if it continues the wrap. A line of the block's own
    /// width continues it; a shorter one, or one carrying the padding, is the
    /// last line and closes the wrap after being taken.
    ///
    /// A wrap whose join would pass the run bound stops being held: its lines
    /// still belong to it, so that none of them opens a block of its own at an
    /// offset the wrap never started on, but the caller reads them one at a
    /// time rather than as a payload the bound says is too long to decode.
    fn extend(&mut self, body: &str, at: usize) -> Taken {
        let Some(width) = self.width else {
            return Taken::Rejected;
        };
        let continues = body.len() == width && is_body(body);
        let tail = !continues && !body.is_empty() && body.len() <= width && is_tail(body);
        if !continues && !tail {
            return Taken::Rejected;
        }
        self.end = at + body.len();
        if tail {
            self.width = None;
        }
        if self.overflowed || self.joined.len() + body.len() > MAX_RUN {
            self.overflowed = true;
            return Taken::Spilled;
        }
        self.lines.push(at);
        self.joined.push_str(body);
        Taken::Held
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

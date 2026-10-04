#![forbid(unsafe_code)]

//! Private extraction for a deliberately narrow, unencoded plain-text send.
//! Success supplies syntax only: mailbox/group resolution, principal ownership,
//! content inspection, policy, approval and dispatch remain separate authorities.

use crate::business_gmail_wire::GmailSendWireInputV1;
use guard_contracts::{BusinessRecipientKindV1, MAX_BUSINESS_ACTION_ITEMS};
use mailparse::{addrparse_header, parse_headers, MailAddr, MailHeader};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const MAX_HEADERS_BYTES: usize = 32 * 1024;
const MAX_HEADER_LINE_BYTES: usize = 998;
const MAX_HEADERS: usize = 64;

/// Finite extraction errors never include source bytes or recipient details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GmailPlainErrorV1 {
    /// Invalid framing, duplicate fields, empty audience or invalid mailbox.
    Invalid,
    /// A header/audience limit exceeded the explicit profile bounds.
    BoundsExceeded,
    /// Validity is not established for a shape outside this narrow profile.
    Unsupported,
}

/// Private unresolved mailbox entry. Do not export this value to Cloud.
pub struct GmailPlainRecipientV1 {
    address: String,
    kind: BusinessRecipientKindV1,
}

impl GmailPlainRecipientV1 {
    /// Literal mailbox spelling, requiring trusted alias/group resolution.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The original To/Cc/Bcc role, retained even for duplicate addresses.
    pub fn kind(&self) -> BusinessRecipientKindV1 {
        self.kind
    }
}

/// Owns the entire immutable wire input alongside private extracted metadata.
/// No Debug, Serialize, Clone or mutable access; not an enforcing action/grant.
pub struct GmailPlainInputV1 {
    wire: GmailSendWireInputV1,
    sender: String,
    recipients: Vec<GmailPlainRecipientV1>,
    body_offset: usize,
    binding: String,
}

impl GmailPlainInputV1 {
    /// Extract a bounded CRLF message with bare ASCII mailboxes and plain text.
    /// All unsupported headers/MIME forms fail closed; an accepted literal
    /// address is not evidence that it names one person rather than a group.
    pub fn from_owned_wire(wire: GmailSendWireInputV1) -> Result<Self, GmailPlainErrorV1> {
        use GmailPlainErrorV1 as Error;
        if wire.thread_id().is_some() {
            return Err(Error::Unsupported);
        }
        let mime = wire.mime_bytes();
        let delimiter = mime
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or(Error::Invalid)?;
        let body_offset = delimiter + 4;
        if body_offset > MAX_HEADERS_BYTES {
            return Err(Error::BoundsExceeded);
        }
        let header_text = std::str::from_utf8(&mime[..delimiter]).map_err(|_| Error::Invalid)?;
        let mut seen = BTreeSet::new();
        for line in header_text.split("\r\n") {
            if line.len() > MAX_HEADER_LINE_BYTES || seen.len() >= MAX_HEADERS {
                return Err(Error::BoundsExceeded);
            }
            if !line.is_ascii() || line.bytes().any(|b| b < 32 || b == 127) {
                return Err(Error::Unsupported);
            }
            let (key, _) = line.split_once(':').ok_or(Error::Invalid)?;
            if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return Err(Error::Invalid);
            }
            let key = key.to_ascii_lowercase();
            if !seen.insert(key.clone()) {
                return Err(Error::Invalid);
            }
            if !matches!(
                key.as_str(),
                "from"
                    | "to"
                    | "cc"
                    | "bcc"
                    | "subject"
                    | "date"
                    | "message-id"
                    | "mime-version"
                    | "content-type"
                    | "content-transfer-encoding"
            ) {
                return Err(Error::Unsupported);
            }
        }
        // Parse only already-bounded headers. No recursive MIME tree is built,
        // and permissive default decoding cannot turn an unknown CTE into text.
        let (headers, parsed_offset) = parse_headers(mime).map_err(|_| Error::Invalid)?;
        if parsed_offset != body_offset || headers.len() != seen.len() {
            return Err(Error::Invalid);
        }
        let mut sender = None;
        let mut recipients = Vec::new();
        let mut utf8 = false;
        let mut eight_bit = false;
        for header in &headers {
            let key = header.get_key().to_ascii_lowercase();
            let value = std::str::from_utf8(header.get_value_raw())
                .map_err(|_| Error::Invalid)?
                .trim();
            match key.as_str() {
                "from" => {
                    let addresses = bare_mailboxes(header)?;
                    if addresses.len() != 1 {
                        return Err(Error::Invalid);
                    }
                    sender = addresses.into_iter().next();
                }
                "to" | "cc" | "bcc" => {
                    let kind = match key.as_str() {
                        "to" => BusinessRecipientKindV1::To,
                        "cc" => BusinessRecipientKindV1::Cc,
                        _ => BusinessRecipientKindV1::Bcc,
                    };
                    for address in bare_mailboxes(header)? {
                        if recipients.len() >= MAX_BUSINESS_ACTION_ITEMS {
                            return Err(Error::BoundsExceeded);
                        }
                        recipients.push(GmailPlainRecipientV1 { address, kind });
                    }
                }
                "content-type" => {
                    let normalized = value.to_ascii_lowercase();
                    utf8 = matches!(
                        normalized.as_str(),
                        "text/plain; charset=utf-8" | "text/plain; charset=\"utf-8\""
                    );
                    if !utf8
                        && !matches!(
                            normalized.as_str(),
                            "text/plain"
                                | "text/plain; charset=us-ascii"
                                | "text/plain; charset=\"us-ascii\""
                        )
                    {
                        return Err(Error::Unsupported);
                    }
                }
                "content-transfer-encoding" => {
                    eight_bit = value.eq_ignore_ascii_case("8bit");
                    if !eight_bit && !value.eq_ignore_ascii_case("7bit") {
                        return Err(Error::Unsupported);
                    }
                }
                "mime-version" if value != "1.0" => return Err(Error::Unsupported),
                _ => {}
            }
        }
        let sender = sender.ok_or(Error::Invalid)?;
        if recipients.is_empty() {
            return Err(Error::Invalid);
        }
        let body = &mime[body_offset..];
        if body.contains(&0) {
            return Err(Error::Invalid);
        }
        let body_text = std::str::from_utf8(body).map_err(|_| Error::Invalid)?;
        if body_text.chars().any(|ch| {
            (ch.is_control() && !matches!(ch, '\r' | '\n' | '\t'))
                || matches!(ch, '\u{2028}' | '\u{2029}')
        }) {
            return Err(Error::Unsupported);
        }
        for (index, byte) in body.iter().enumerate() {
            if (*byte == b'\r' && body.get(index + 1) != Some(&b'\n'))
                || (*byte == b'\n' && (index == 0 || body[index - 1] != b'\r'))
            {
                return Err(Error::Invalid);
            }
            if (*byte < 32 && !matches!(byte, b'\r' | b'\n' | b'\t')) || *byte == 127 {
                return Err(Error::Unsupported);
            }
        }
        if body
            .split(|b| *b == b'\n')
            .any(|line| line.strip_suffix(b"\r").unwrap_or(line).len() > MAX_HEADER_LINE_BYTES)
        {
            return Err(Error::BoundsExceeded);
        }
        if !(body.is_ascii() || utf8 && eight_bit) {
            return Err(Error::Unsupported);
        }
        let mut hash = Sha256::new();
        hash.update(b"hol-guard.gmail-plain-input.v1\0");
        hash.update(wire.input_binding().as_bytes());
        let binding = hex::encode(hash.finalize());
        Ok(Self {
            wire,
            sender,
            recipients,
            body_offset,
            binding,
        })
    }

    /// Full original private wire/MIME bytes; retain through exact inspection.
    pub fn wire_input(&self) -> &GmailSendWireInputV1 {
        &self.wire
    }

    /// Literal From mailbox, with no authenticated ownership claim.
    pub fn sender(&self) -> &str {
        &self.sender
    }

    /// Every To/Cc/Bcc occurrence; no deduplication or inferred group expansion.
    pub fn recipients(&self) -> &[GmailPlainRecipientV1] {
        &self.recipients
    }

    /// Exact unencoded body bytes. No public/confidential/secret label is inferred.
    pub fn body_bytes(&self) -> &[u8] {
        &self.wire.mime_bytes()[self.body_offset..]
    }

    /// Profile-version commitment to the entire retained wire, not a capability.
    pub fn input_binding(&self) -> &str {
        &self.binding
    }
}

fn bare_mailboxes(header: &MailHeader<'_>) -> Result<Vec<String>, GmailPlainErrorV1> {
    use GmailPlainErrorV1 as Error;
    let raw = std::str::from_utf8(header.get_value_raw()).map_err(|_| Error::Invalid)?;
    let literals: Vec<_> = raw.split(',').map(str::trim).collect();
    if literals.len() > MAX_BUSINESS_ACTION_ITEMS {
        return Err(Error::BoundsExceeded);
    }
    if !literals.iter().all(|s| simple_mailbox(s)) {
        return Err(Error::Unsupported);
    }
    // Cross-check the established RFC parser without decoding a header to a
    // string first (encoded display words must not introduce address delimiters).
    let parsed = addrparse_header(header)
        .map_err(|_| Error::Invalid)?
        .into_inner();
    if parsed.len() != literals.len() {
        return Err(Error::Invalid);
    }
    parsed
        .into_iter()
        .zip(literals)
        .map(|(address, literal)| match address {
            MailAddr::Single(info) if info.display_name.is_none() && info.addr == literal => {
                Ok(info.addr)
            }
            _ => Err(Error::Unsupported),
        })
        .collect()
}

fn simple_mailbox(address: &str) -> bool {
    if address.len() > 254 || !address.is_ascii() {
        return false;
    }
    let Some((local, domain)) = address.split_once('@') else {
        return false;
    };
    if local.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".!#$%&'*+-/=?^_`{|}~".contains(&b))
    {
        return false;
    }
    if domain.len() > 253 || !domain.contains('.') {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

//! Reading a macOS managed-preferences property list into the same document
//! shape the JSON policy parse already accepts.
//!
//! `plistlib.loads` accepts both the XML and the binary serialisation, and a
//! profile delivered through macOS configuration management is written in the
//! binary one, so the native loader has to read both to see the policy Python
//! sees.
//!
//! Two plist types have no place in a policy document and are refused rather
//! than mapped: `data` and `date`. Python turns them into `bytes` and
//! `datetime`, which the typed fields reject and which the canonical hash
//! cannot serialise at all, so a document carrying one has no successful
//! reading under either implementation.

use serde_json::{Map, Number, Value};

/// What a policy document may nest. A profile is a few levels deep; this is a
/// bound on malicious nesting, not on anything an administrator writes.
const MAX_DEPTH: usize = 32;

const BINARY_HEADER: &[u8] = b"bplist00";
const TRAILER_BYTES: usize = 32;

pub(crate) type PlistError = String;

type PlistResult<T> = Result<T, PlistError>;

fn refuse<T>(message: &str) -> PlistResult<T> {
    Err(message.to_owned())
}

/// Read either serialisation. The caller has already bounded the byte count.
pub(crate) fn parse_plist(bytes: &[u8]) -> PlistResult<Value> {
    if bytes.starts_with(BINARY_HEADER) {
        return parse_binary(bytes);
    }
    parse_xml(bytes)
}

// ---------------------------------------------------------------------------
// XML
// ---------------------------------------------------------------------------

fn parse_xml(bytes: &[u8]) -> PlistResult<Value> {
    let text = std::str::from_utf8(bytes).map_err(|_| "managed policy is not valid UTF-8")?;
    // Every XML property list Apple's tools write opens with the PropertyList
    // DOCTYPE, so refusing a document type declaration would refuse the
    // serialisation itself. The declaration is parsed and otherwise unused:
    // the parser resolves no external entity, reads no file and opens no
    // connection, and a reference it cannot resolve from the document itself
    // fails the parse rather than expanding to anything.
    let options = roxmltree::ParsingOptions {
        allow_dtd: true,
        ..roxmltree::ParsingOptions::default()
    };
    let document = roxmltree::Document::parse_with_options(text, options)
        .map_err(|_| "managed policy is not a valid plist")?;
    let root = document.root_element();
    if root.tag_name().name() != "plist" {
        return refuse("managed policy is not a plist document");
    }
    let mut children = root.children().filter(roxmltree::Node::is_element);
    let Some(top) = children.next() else {
        return refuse("managed policy plist is empty");
    };
    if children.next().is_some() {
        return refuse("managed policy plist has more than one value");
    }
    xml_value(top, 0)
}

fn xml_value(node: roxmltree::Node<'_, '_>, depth: usize) -> PlistResult<Value> {
    if depth > MAX_DEPTH {
        return refuse("managed policy plist nests too deeply");
    }
    match node.tag_name().name() {
        "dict" => xml_dict(node, depth),
        "array" => {
            let mut items = Vec::new();
            for child in node.children().filter(roxmltree::Node::is_element) {
                items.push(xml_value(child, depth + 1)?);
            }
            Ok(Value::Array(items))
        }
        "string" => Ok(Value::String(xml_text(node))),
        "true" => Ok(Value::Bool(true)),
        "false" => Ok(Value::Bool(false)),
        "integer" => xml_text(node)
            .trim()
            .parse::<i64>()
            .map(|number| Value::Number(number.into()))
            .or_else(|_| {
                xml_text(node)
                    .trim()
                    .parse::<u64>()
                    .map(|number| Value::Number(number.into()))
            })
            .map_err(|_| "managed policy plist holds an integer Guard cannot read".to_owned()),
        "real" => {
            let parsed: f64 = xml_text(node)
                .trim()
                .parse()
                .map_err(|_| "managed policy plist holds a real Guard cannot read".to_owned())?;
            Number::from_f64(parsed)
                .map(Value::Number)
                .ok_or_else(|| "managed policy plist holds a real Guard cannot read".to_owned())
        }
        "data" => refuse("managed policy plist holds binary data"),
        "date" => refuse("managed policy plist holds a date"),
        other => Err(format!("managed policy plist holds an unsupported {other}")),
    }
}

fn xml_dict(node: roxmltree::Node<'_, '_>, depth: usize) -> PlistResult<Value> {
    let mut map = Map::new();
    let mut pending: Option<String> = None;
    for child in node.children().filter(roxmltree::Node::is_element) {
        match (child.tag_name().name(), pending.take()) {
            ("key", None) => pending = Some(xml_text(child)),
            ("key", Some(_)) => return refuse("managed policy plist has a key without a value"),
            (_, None) => return refuse("managed policy plist has a value without a key"),
            (_, Some(key)) => {
                map.insert(key, xml_value(child, depth + 1)?);
            }
        }
    }
    if pending.is_some() {
        return refuse("managed policy plist has a key without a value");
    }
    Ok(Value::Object(map))
}

/// The concatenated text of an element, which is how `plistlib` reads one.
fn xml_text(node: roxmltree::Node<'_, '_>) -> String {
    node.children()
        .filter(roxmltree::Node::is_text)
        .filter_map(|child| child.text())
        .collect()
}

// ---------------------------------------------------------------------------
// Binary
// ---------------------------------------------------------------------------

/// How many objects one document may decode, as a multiple of the objects it
/// actually holds. `plistlib` decodes each object once and remembers it, so a
/// profile that shares a value reads in one pass there; this reader decodes a
/// reference wherever it appears, and a document whose containers all point at
/// one another describes exponentially more nodes than it holds. The bound is
/// on the whole document rather than on one object, because the blow-up is the
/// product of the fan-out at every level.
const DECODE_FACTOR: usize = 8;
/// The floor under that bound, so a small document with heavily shared strings
/// is read rather than refused for its sharing.
const MIN_DECODE_BUDGET: usize = 256;

/// The trailer fields the object table is read through.
struct BinaryPlist<'a> {
    bytes: &'a [u8],
    reference_size: usize,
    offsets: Vec<usize>,
    /// How many objects are left to decode before the document is refused.
    budget: std::cell::Cell<usize>,
}

fn parse_binary(bytes: &[u8]) -> PlistResult<Value> {
    if bytes.len() < BINARY_HEADER.len() + TRAILER_BYTES {
        return refuse("managed policy is not a valid plist");
    }
    let trailer = &bytes[bytes.len() - TRAILER_BYTES..];
    let offset_size = trailer[6] as usize;
    let reference_size = trailer[7] as usize;
    let count = be_u64(&trailer[8..16]) as usize;
    let top = be_u64(&trailer[16..24]) as usize;
    let table = be_u64(&trailer[24..32]) as usize;
    if offset_size == 0 || offset_size > 8 || reference_size == 0 || reference_size > 8 {
        return refuse("managed policy plist has an unreadable object table");
    }
    let end = table
        .checked_add(count.checked_mul(offset_size).unwrap_or(usize::MAX))
        .unwrap_or(usize::MAX);
    if table < BINARY_HEADER.len() || end > bytes.len() - TRAILER_BYTES || top >= count {
        return refuse("managed policy plist has an unreadable object table");
    }
    let mut offsets = Vec::with_capacity(count);
    for index in 0..count {
        let at = table + index * offset_size;
        offsets.push(be_u64(&bytes[at..at + offset_size]) as usize);
    }
    let budget = count
        .saturating_mul(DECODE_FACTOR)
        .max(MIN_DECODE_BUDGET)
        .into();
    let plist = BinaryPlist {
        bytes,
        reference_size,
        offsets,
        budget,
    };
    plist.object(top, 0)
}

impl BinaryPlist<'_> {
    fn object(&self, index: usize, depth: usize) -> PlistResult<Value> {
        if depth > MAX_DEPTH {
            return refuse("managed policy plist nests too deeply");
        }
        // The depth bound alone leaves the width unbounded: thirty arrays that
        // each hold ten references to the next describe 10^30 nodes in a few
        // hundred bytes. The read has to end in a refusal the fail-closed path
        // can act on, not in a runtime that never answers.
        let Some(left) = self.budget.get().checked_sub(1) else {
            return refuse("managed policy plist describes too many objects");
        };
        self.budget.set(left);
        let start = *self
            .offsets
            .get(index)
            .ok_or("managed policy plist names an object it does not hold")?;
        let marker = *self
            .bytes
            .get(start)
            .ok_or("managed policy plist names an object it does not hold")?;
        let info = (marker & 0x0f) as usize;
        match marker >> 4 {
            0x0 => match marker {
                0x08 => Ok(Value::Bool(false)),
                0x09 => Ok(Value::Bool(true)),
                0x00 => Ok(Value::Null),
                _ => refuse("managed policy plist holds an unsupported value"),
            },
            0x1 => self.integer(start + 1, 1usize << info),
            0x2 => self.real(start + 1, 1usize << info),
            0x3 => refuse("managed policy plist holds a date"),
            0x4 => refuse("managed policy plist holds binary data"),
            0x5 => {
                let (at, length) = self.length(start, info)?;
                let slice = self.slice(at, length)?;
                if !slice.is_ascii() {
                    return refuse("managed policy plist holds an unreadable string");
                }
                Ok(Value::String(String::from_utf8_lossy(slice).into_owned()))
            }
            0x6 => {
                let (at, length) = self.length(start, info)?;
                let slice = self.slice(at, length.checked_mul(2).unwrap_or(usize::MAX))?;
                let units: Vec<u16> = slice
                    .chunks_exact(2)
                    .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                    .collect();
                String::from_utf16(&units)
                    .map(Value::String)
                    .map_err(|_| "managed policy plist holds an unreadable string".to_owned())
            }
            0xa => {
                let (at, length) = self.length(start, info)?;
                let mut items = Vec::with_capacity(length.min(1024));
                for reference in self.references(at, length)? {
                    items.push(self.object(reference, depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            0xd => {
                let (at, length) = self.length(start, info)?;
                let keys = self.references(at, length)?;
                let values = self.references(at + length * self.reference_size, length)?;
                let mut map = Map::new();
                for (key, value) in keys.into_iter().zip(values) {
                    let Value::String(name) = self.object(key, depth + 1)? else {
                        return refuse("managed policy plist has a key that is not a string");
                    };
                    map.insert(name, self.object(value, depth + 1)?);
                }
                Ok(Value::Object(map))
            }
            _ => refuse("managed policy plist holds an unsupported value"),
        }
    }

    /// An object's payload start and element count, following the `0x0f`
    /// escape into a trailing integer.
    fn length(&self, start: usize, info: usize) -> PlistResult<(usize, usize)> {
        if info != 0x0f {
            return Ok((start + 1, info));
        }
        let marker = *self
            .bytes
            .get(start + 1)
            .ok_or("managed policy plist is truncated")?;
        if marker >> 4 != 0x1 {
            return refuse("managed policy plist has an unreadable length");
        }
        let width = 1usize << (marker & 0x0f);
        let slice = self.slice(start + 2, width)?;
        Ok((start + 2 + width, be_u64(slice) as usize))
    }

    fn references(&self, at: usize, count: usize) -> PlistResult<Vec<usize>> {
        let width = self.reference_size;
        let slice = self.slice(at, count.checked_mul(width).unwrap_or(usize::MAX))?;
        Ok(slice
            .chunks_exact(width)
            .map(|chunk| be_u64(chunk) as usize)
            .collect())
    }

    fn integer(&self, at: usize, width: usize) -> PlistResult<Value> {
        let slice = self.slice(at, width)?;
        // A 16-byte integer is the signed 128-bit form; the range a policy can
        // hold is the 64-bit one either way.
        if width > 8 {
            return refuse("managed policy plist holds an integer Guard cannot read");
        }
        let raw = be_u64(slice);
        if width == 8 {
            return Ok(Value::Number((raw as i64).into()));
        }
        Ok(Value::Number(raw.into()))
    }

    fn real(&self, at: usize, width: usize) -> PlistResult<Value> {
        let slice = self.slice(at, width)?;
        let parsed = match width {
            4 => f64::from(f32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]])),
            8 => f64::from_be_bytes([
                slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
            ]),
            _ => return refuse("managed policy plist holds a real Guard cannot read"),
        };
        Number::from_f64(parsed)
            .map(Value::Number)
            .ok_or_else(|| "managed policy plist holds a real Guard cannot read".to_owned())
    }

    fn slice(&self, at: usize, length: usize) -> PlistResult<&[u8]> {
        let end = at.checked_add(length).unwrap_or(usize::MAX);
        if end > self.bytes.len().saturating_sub(TRAILER_BYTES) {
            return refuse("managed policy plist is truncated");
        }
        Ok(&self.bytes[at..end])
    }
}

/// Big-endian read of up to eight bytes, as every binary plist width is.
fn be_u64(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .take(8)
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte))
}

#[cfg(test)]
#[path = "managed_policy_plist_tests.rs"]
mod tests;

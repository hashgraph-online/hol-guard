//! Port of `adapters/remote_mcp_origin.py`: the origin Guard records for a
//! remote MCP server it finds in a harness config. Guard never connects to it.
//!
//! Only `scheme://host[:port]/path` survives. Credentials, query and fragment
//! never persist, and because some hosted servers carry the account key in the
//! path, a path segment that looks like a key is masked before the origin is
//! stored or shown. The parse follows CPython's `urlsplit`, so an origin stays
//! the one earlier releases recorded for the same config.

use std::sync::LazyLock;

use crate::codex_output_py::py_strip;
use crate::local_tool_eligibility::python_digit::python_isdigit_char;
use crate::python_url::{urlsplit, urlunsplit};
use crate::sfrs_encoded_payloads::py_isprintable;

/// What a masked path segment reads as.
const MASKED_PATH_SEGMENT: &str = "[masked]";

const MAX_ORIGIN_CHARS: usize = 512;

/// `str.isalpha` for one code point: the `L*` general categories.
static LETTER: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^\p{L}$").expect("letter class"));

/// Return `scheme://host[:port]/path` for an `http` or `https` URL, or `None`
/// when the URL does not parse, names no host, or the origin would still carry
/// a delimiter, a space or an unprintable character.
pub fn remote_mcp_origin(url: &str) -> Option<String> {
    let parts = urlsplit(py_strip(url)).ok()?;
    let port = parts.port().ok()?;
    let hostname = parts.hostname()?;
    if parts.scheme != "http" && parts.scheme != "https" {
        return None;
    }
    let host = if hostname.contains(':') {
        format!("[{hostname}]")
    } else {
        hostname
    };
    let netloc = match port {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    let path = parts
        .path
        .split('/')
        .map(masked_segment)
        .collect::<Vec<&str>>()
        .join("/");
    let origin = urlunsplit(&parts.scheme, &netloc.to_lowercase(), &path, "", "");
    let refused = origin.chars().count() > MAX_ORIGIN_CHARS
        || origin.contains(['?', '#', '@', ' '])
        || !origin.chars().all(py_isprintable);
    (!refused).then_some(origin)
}

/// A path segment, or the mask when it is long or mixes letters and digits.
fn masked_segment(segment: &str) -> &str {
    let length = segment.chars().count();
    let looks_like_key = length >= 16
        || (length >= 8
            && segment.chars().any(python_isdigit_char)
            && segment.chars().any(is_letter));
    if looks_like_key {
        MASKED_PATH_SEGMENT
    } else {
        segment
    }
}

fn is_letter(c: char) -> bool {
    let mut buffer = [0u8; 4];
    LETTER.is_match(c.encode_utf8(&mut buffer))
}

#[cfg(test)]
#[path = "remote_mcp_origin_tests.rs"]
mod tests;

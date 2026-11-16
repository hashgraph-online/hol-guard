//! Oh My Pi `read` targets spelled as `file://` URLs.
//!
//! Oh My Pi's `read` tool addresses an ordinary local file or directory either
//! by path or by a `file://` URL. The URL is a spelling of the path, not a
//! separate capability, so Guard resolves it to the path it denotes and lets
//! the ordinary read proofs decide. Resolution is deliberately narrow, because
//! a URL parser sits on a trust boundary:
//!
//! * only an empty or `localhost` authority names a file on this host; any
//!   other authority names a remote file and is left unresolved;
//! * percent escapes are decoded before any path rule runs, so an encoded
//!   `..`, dot-directory or credential name is judged as the path it spells
//!   rather than as opaque URL text;
//! * a decoded target that is not valid UTF-8, or that carries a NUL or any
//!   other control character, a backslash or surrounding whitespace, is left
//!   unresolved;
//! * a query or fragment changes what the host opens, so neither resolves;
//! * the host rewrites some spellings before it parses the URL: it replaces a
//!   raw Unicode space with an ASCII one, folds `.` and `..` segments (encoded
//!   or not) lexically, and refuses an encoded `/`. A URL carrying any of those
//!   could name one file to Guard and another to the host, so none resolves.
//!
//! Anything left unresolved keeps the review it has today. Resolution never
//! decides a read on its own: the decoded path goes through exactly the same
//! proofs as the plain spelling, so neither spelling can buy a weaker answer
//! than the other.

/// The longest URL and decoded path the resolver accepts, matching the bound
/// the plain path proofs use.
const MAX_FILE_URL_BYTES: usize = 4096;

/// The local filesystem path a `file://` URL denotes, or `None` when the value
/// is not a `file://` URL or names something other than a plain local path.
pub(in crate::pretool) fn local_file_url_path(value: &str) -> Option<String> {
    if value.len() > MAX_FILE_URL_BYTES
        || value.trim() != value
        || value.contains('\\')
        || value.chars().any(host_rewritten_space)
    {
        return None;
    }
    let rest = after_file_scheme(value)?;
    // A query or a fragment is not part of the path, and both change what the
    // host opens; neither is resolved here.
    if rest.contains(['?', '#']) {
        return None;
    }
    // `file:/path` and `file:path` carry no authority to check, so they stay
    // on the review path together with every other unresolved spelling.
    let after_authority = rest.strip_prefix("//")?;
    let split = after_authority.find('/')?;
    let (authority, encoded) = after_authority.split_at(split);
    // Only this host's own files. `file://host/path` names a remote file and
    // must never be resolved to a local path.
    if !(authority.is_empty() || authority.eq_ignore_ascii_case("localhost")) {
        return None;
    }
    // The host refuses an encoded `/`, so it never opens what Guard would read
    // the decoded text as.
    if encoded.to_ascii_lowercase().contains("%2f") {
        return None;
    }
    let decoded = decoded_path(encoded)?;
    // The host's URL parser folds a `.` or `..` segment, encoded or not,
    // before it reaches the filesystem, while Guard would walk it through any
    // link it crosses. The two can land on different files, so neither
    // spelling resolves.
    if decoded
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return None;
    }
    Some(drive_rooted(&decoded).unwrap_or(decoded))
}

/// A raw Unicode space the host replaces with an ASCII space before it reads
/// the URL: a no-break space, the U+2000 to U+200A run, the narrow no-break
/// space, the medium mathematical space and the ideographic space.
fn host_rewritten_space(character: char) -> bool {
    matches!(
        character,
        '\u{00a0}' | '\u{2000}'..='\u{200a}' | '\u{202f}' | '\u{205f}' | '\u{3000}'
    )
}

/// The part after a `file:` scheme. URL schemes are case-insensitive, so
/// `FILE://` names the same thing; any other scheme, and a bare path, is not
/// a file URL.
fn after_file_scheme(value: &str) -> Option<&str> {
    let (scheme, rest) = value.split_once(':')?;
    scheme.eq_ignore_ascii_case("file").then_some(rest)
}

/// The percent-decoded path. Decoding happens once, which is what the URL
/// denotes: `%252e` spells the three characters `%2e`, a legitimate file name,
/// and must not be read as a second escape.
fn decoded_path(encoded: &str) -> Option<String> {
    let decoded = percent_encoding::percent_decode_str(encoded)
        .decode_utf8()
        .ok()?
        .into_owned();
    if decoded.is_empty()
        || decoded.len() > MAX_FILE_URL_BYTES
        || decoded.trim() != decoded
        || decoded.contains('\\')
        || decoded
            .chars()
            .any(|character| character.is_control() || character == '\u{feff}')
    {
        return None;
    }
    Some(decoded)
}

/// `file:///C:/dir` denotes `C:/dir`: the slash before a drive letter is the
/// URL's root marker, not part of the path. Resolved on every platform so the
/// Windows spelling reaches the same proofs everywhere; on a Unix host the
/// result is a relative path that resolves no file the plain spelling would
/// not. `/C:dir` is a drive-relative spelling this resolver does not model.
fn drive_rooted(path: &str) -> Option<String> {
    let rest = path.strip_prefix('/')?;
    let bytes = rest.as_bytes();
    if !bytes.first().is_some_and(u8::is_ascii_alphabetic) || bytes.get(1) != Some(&b':') {
        return None;
    }
    matches!(bytes.get(2), None | Some(b'/')).then(|| rest.to_owned())
}

#[cfg(test)]
#[path = "omp_file_url_tests.rs"]
mod tests;

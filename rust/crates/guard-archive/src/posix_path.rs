//! Byte-level ports of the CPython `posixpath` helpers the archive policy
//! relies on. Operating on raw bytes preserves tar member names that are not
//! valid UTF-8 exactly the way Python's surrogateescape decoding did: the
//! byte values that carry structural meaning (`/`, `.`) are single ASCII
//! bytes that can never appear inside a multi-byte UTF-8 sequence, so byte
//! and decoded-string traversal are equivalent.

/// CPython `posixpath.normpath`, byte for byte.
pub fn normpath(path: &[u8]) -> Vec<u8> {
    let initial_slashes = if path.starts_with(b"//") && !path.starts_with(b"///") {
        2
    } else if path.starts_with(b"/") {
        1
    } else {
        0
    };
    let mut comps: Vec<&[u8]> = Vec::new();
    for comp in path.split(|b| *b == b'/') {
        if comp.is_empty() || comp == b"." {
            continue;
        }
        if comp != b".."
            || (initial_slashes == 0 && comps.is_empty())
            || comps.last() == Some(&b"..".as_slice())
        {
            comps.push(comp);
        } else if !comps.is_empty() {
            comps.pop();
        }
    }
    let mut out = vec![b'/'; initial_slashes];
    out.extend(comps.join(&b'/'));
    if out.is_empty() {
        out.push(b'.');
    }
    out
}

/// CPython `posixpath.basename`.
pub fn basename(path: &[u8]) -> &[u8] {
    let index = path.iter().rposition(|b| *b == b'/').map_or(0, |i| i + 1);
    &path[index..]
}

/// CPython `posixpath.dirname`.
pub fn dirname(path: &[u8]) -> Vec<u8> {
    let index = path.iter().rposition(|b| *b == b'/').map_or(0, |i| i + 1);
    let head = &path[..index];
    if head.is_empty() || head.iter().all(|b| *b == b'/') {
        head.to_vec()
    } else {
        let mut trimmed = head.to_vec();
        while trimmed.last() == Some(&b'/') {
            trimmed.pop();
        }
        trimmed
    }
}

/// CPython `posixpath.join(a, b)` for the two-argument case.
pub fn join(a: &[u8], b: &[u8]) -> Vec<u8> {
    if b.starts_with(b"/") {
        return b.to_vec();
    }
    let mut out = a.to_vec();
    if out.is_empty() || out.ends_with(b"/") {
        out.extend_from_slice(b);
    } else {
        out.push(b'/');
        out.extend_from_slice(b);
    }
    out
}

/// True when the byte is an ASCII control character the policy rejects.
pub fn has_control_character(path: &[u8]) -> bool {
    path.iter().any(|b| *b <= 0x1f || *b == 0x7f)
}

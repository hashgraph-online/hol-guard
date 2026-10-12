/// The literal-name fallback must refuse this operand. A bracket class can
/// name a leading dot under `dotglob` (a literal `.` or a range such as
/// `[,-0]`), or it uses `]`, `!`, or a POSIX class that this matcher closes
/// at the first `]`.
pub(super) fn bracket_fallback_unsafe(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'[' {
            index += 1;
            continue;
        }
        let Some((unsafe_class, next)) = one_bracket_class(bytes, index) else {
            return true;
        };
        if unsafe_class {
            return true;
        }
        index = next;
    }
    false
}

/// `(unsafe, index after the closing bracket)`. `None` when the class never
/// closes. An unsafe class returns immediately, so its end index is unused.
fn one_bracket_class(bytes: &[u8], open: usize) -> Option<(bool, usize)> {
    let mut cursor = open + 1;
    if cursor < bytes.len() && matches!(bytes[cursor], b'!' | b'^') {
        return Some((true, cursor));
    }
    let mut unsafe_class = false;
    let mut first = true;
    while cursor < bytes.len() {
        if !first && bytes[cursor] == b']' {
            return Some((unsafe_class, cursor + 1));
        }
        let nested = bytes[cursor] == b'['
            && cursor + 1 < bytes.len()
            && matches!(bytes[cursor + 1], b':' | b'.' | b'=');
        if nested || (first && bytes[cursor] == b']') {
            return Some((true, cursor));
        }
        first = false;
        if cursor + 2 < bytes.len() && bytes[cursor + 1] == b'-' && bytes[cursor + 2] != b']' {
            let (start, end) = (bytes[cursor], bytes[cursor + 2]);
            let (lo, hi) = if start <= end {
                (start, end)
            } else {
                (end, start)
            };
            unsafe_class |= (lo..=hi).contains(&b'.');
            cursor += 3;
            continue;
        }
        unsafe_class |= bytes[cursor] == b'.';
        cursor += 1;
    }
    None
}

pub(super) fn glob_class_matches(class: &[u8], value: u8) -> bool {
    let (negated, members) = match class.first() {
        Some(b'!' | b'^') => (true, &class[1..]),
        _ => (false, class),
    };
    let mut matched = false;
    let mut index = 0;
    while index < members.len() {
        if index + 2 < members.len() && members[index + 1] == b'-' {
            matched |= members[index] <= value && value <= members[index + 2];
            index += 3;
        } else {
            matched |= members[index] == value;
            index += 1;
        }
    }
    matched != negated
}

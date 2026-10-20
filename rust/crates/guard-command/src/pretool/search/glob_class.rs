/// The literal-name fallback must refuse this operand. A bracket class can
/// name a leading dot under `dotglob`, it can hold a range, or it uses `]`,
/// `!`, or a POSIX class that this matcher closes at the first `]`.
pub(super) fn bracket_fallback_unsafe(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'[' {
            index += 1;
            continue;
        }
        let Some(next) = one_bracket_class(bytes, index) else {
            return true;
        };
        index = next;
    }
    false
}

/// The index after the closing bracket, or `None` when the class never closes
/// or could stand for a name other than the one it is spelled with.
fn one_bracket_class(bytes: &[u8], open: usize) -> Option<usize> {
    let mut cursor = open + 1;
    if cursor < bytes.len() && matches!(bytes[cursor], b'!' | b'^') {
        return None;
    }
    let mut first = true;
    while cursor < bytes.len() {
        if !first && bytes[cursor] == b']' {
            return Some(cursor + 1);
        }
        let nested = bytes[cursor] == b'['
            && cursor + 1 < bytes.len()
            && matches!(bytes[cursor + 1], b':' | b'.' | b'=');
        if nested || (first && bytes[cursor] == b']') {
            return None;
        }
        first = false;
        // A range is expanded in the locale's collating sequence unless
        // `globasciiranges` is set, so the byte comparison this matcher makes
        // is no proof of what the shell matched: `[a-d]` reaches `B` where the
        // locale sorts the cases together, and a locale this matcher does not
        // model can place more between the two ends. A leading dot would name
        // a hidden entry under `dotglob`.
        if (cursor + 2 < bytes.len() && bytes[cursor + 1] == b'-' && bytes[cursor + 2] != b']')
            || bytes[cursor] == b'.'
        {
            return None;
        }
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

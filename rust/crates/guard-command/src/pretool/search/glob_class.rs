use std::borrow::Cow;

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

/// Whether a bracket expression holds what [`glob_class_matches`] cannot
/// read the way a shell does: a POSIX class, equivalence class or collating
/// symbol (`[[:alpha:]]`, `[[=a=]]`, `[[.a.]]`), a leading `]` member, or an
/// escape. The matcher closes such a class at its first `]`, so it would
/// answer for a different pattern: `[[:alpha:]]d_rsa` would miss `id_rsa`.
pub(super) fn unmodeled_bracket_class(value: &[u8]) -> bool {
    unmodeled_class_start(value).is_some()
}

/// `component` with everything from its first class that
/// [`unmodeled_bracket_class`] finds through its last `]` replaced by `*`.
/// The shell closes that class at one of those `]`, and `*` matches whatever
/// the class and the text after it can, so the result is a superset:
/// `[[:alpha:]]d_rsa` becomes `*d_rsa`, which still names `id_rsa`.
pub(super) fn widen_unmodeled_class(component: &str) -> Cow<'_, str> {
    match (
        unmodeled_class_start(component.as_bytes()),
        component.rfind(']'),
    ) {
        (Some(open), Some(close)) if open < close => Cow::Owned(format!(
            "{}*{}",
            &component[..open],
            &component[close + 1..]
        )),
        _ => Cow::Borrowed(component),
    }
}

fn unmodeled_class_start(value: &[u8]) -> Option<usize> {
    let mut open = None;
    for (index, &byte) in value.iter().enumerate() {
        match open {
            None if byte == b'[' => open = Some(index),
            None => {}
            Some(start) => {
                let leading = index == start + 1
                    || (index == start + 2 && matches!(value[start + 1], b'!' | b'^'));
                // A class that never closes is literal text to the shell.
                let closes = value[index + 1..].contains(&b']');
                if closes
                    && (byte == b'\\'
                        || (byte == b']' && leading)
                        || (byte == b'[' && matches!(value[index + 1], b':' | b'.' | b'=')))
                {
                    return Some(start);
                }
                if byte == b']' {
                    open = None;
                }
            }
        }
    }
    None
}

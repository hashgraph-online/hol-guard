//! Bounded gitignore-style glob matching for native search-scope proofs.
//!
//! Every ambiguity returns `Err`. Callers decide which direction is
//! conservative: an unparsed ignore rule hides nothing, while an unparsed
//! re-include or exclusion rule invalidates the whole proof.

const MAX_PATTERN_BYTES: usize = 256;
const MAX_MATCH_STEPS: usize = 20_000;
const MAX_BRACE_EXPANSIONS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct GlobError;

/// Match `pattern` against a `/`-separated relative path. `*` and `?` never
/// cross a separator; `**` does. Character classes support ranges and `!`/`^`.
pub(super) fn glob_matches(pattern: &str, text: &str) -> Result<bool, GlobError> {
    if pattern.is_empty() || pattern.len() > MAX_PATTERN_BYTES {
        return Err(GlobError);
    }
    let mut steps = 0_usize;
    match_from(pattern.as_bytes(), text.as_bytes(), &mut steps)
}

fn match_from(pattern: &[u8], text: &[u8], steps: &mut usize) -> Result<bool, GlobError> {
    *steps += 1;
    if *steps > MAX_MATCH_STEPS {
        return Err(GlobError);
    }
    let Some(&first) = pattern.first() else {
        return Ok(text.is_empty());
    };
    match first {
        b'*' if pattern.get(1) == Some(&b'*') => {
            let rest = &pattern[2..];
            if let Some(after_slash) = rest.strip_prefix(b"/") {
                // `**/` matches zero or more whole directories.
                if match_from(after_slash, text, steps)? {
                    return Ok(true);
                }
                for (index, byte) in text.iter().enumerate() {
                    if *byte == b'/' && match_from(after_slash, &text[index + 1..], steps)? {
                        return Ok(true);
                    }
                }
                return Ok(false);
            }
            for index in 0..=text.len() {
                if match_from(rest, &text[index..], steps)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        b'*' => {
            let rest = &pattern[1..];
            for index in 0..=text.len() {
                if match_from(rest, &text[index..], steps)? {
                    return Ok(true);
                }
                if text.get(index) == Some(&b'/') {
                    break;
                }
            }
            Ok(false)
        }
        b'?' => match text.first() {
            Some(byte) if *byte != b'/' => match_from(&pattern[1..], &text[1..], steps),
            _ => Ok(false),
        },
        b'[' => {
            let (matched, consumed) = match_class(&pattern[1..], text.first().copied())?;
            if !matched {
                return Ok(false);
            }
            match_from(&pattern[1 + consumed..], &text[1..], steps)
        }
        b'\\' => {
            let Some(&literal) = pattern.get(1) else {
                return Err(GlobError);
            };
            if text.first() != Some(&literal) {
                return Ok(false);
            }
            match_from(&pattern[2..], &text[1..], steps)
        }
        literal => {
            if text.first() != Some(&literal) {
                return Ok(false);
            }
            match_from(&pattern[1..], &text[1..], steps)
        }
    }
}

/// Return whether the class matches and how many pattern bytes it used,
/// including the closing bracket.
fn match_class(class: &[u8], value: Option<u8>) -> Result<(bool, usize), GlobError> {
    let mut index = 0;
    let negated = matches!(class.first(), Some(b'!' | b'^'));
    if negated {
        index += 1;
    }
    let mut matched = false;
    let mut first = true;
    loop {
        let Some(&byte) = class.get(index) else {
            return Err(GlobError);
        };
        if byte == b']' && !first {
            index += 1;
            break;
        }
        first = false;
        let start = if byte == b'\\' {
            index += 1;
            *class.get(index).ok_or(GlobError)?
        } else {
            byte
        };
        index += 1;
        let end = if class.get(index) == Some(&b'-')
            && class.get(index + 1).is_some_and(|b| *b != b']')
        {
            index += 1;
            let mut end = class[index];
            if end == b'\\' {
                index += 1;
                end = *class.get(index).ok_or(GlobError)?;
            }
            index += 1;
            end
        } else {
            start
        };
        if start > end {
            return Err(GlobError);
        }
        if value.is_some_and(|value| value != b'/' && (start..=end).contains(&value)) {
            matched = true;
        }
    }
    let Some(value) = value else {
        return Ok((false, index));
    };
    if value == b'/' {
        return Ok((false, index));
    }
    Ok((matched != negated, index))
}

/// Expand ripgrep-style `{a,b}` alternatives. Nested or unbalanced braces
/// are rejected rather than approximated.
pub(super) fn expand_braces(pattern: &str) -> Result<Vec<String>, GlobError> {
    let mut pending = vec![pattern.to_owned()];
    let mut expanded = Vec::new();
    while let Some(candidate) = pending.pop() {
        let Some(open) = candidate.find('{') else {
            if candidate.contains('}') {
                return Err(GlobError);
            }
            expanded.push(candidate);
            if expanded.len() > MAX_BRACE_EXPANSIONS {
                return Err(GlobError);
            }
            continue;
        };
        let Some(close_offset) = candidate[open + 1..].find('}') else {
            return Err(GlobError);
        };
        let close = open + 1 + close_offset;
        let body = &candidate[open + 1..close];
        if body.contains('{') || candidate[..open].contains('\\') {
            return Err(GlobError);
        }
        for alternative in body.split(',') {
            pending.push(format!(
                "{}{}{}",
                &candidate[..open],
                alternative,
                &candidate[close + 1..]
            ));
            if pending.len() + expanded.len() > MAX_BRACE_EXPANSIONS {
                return Err(GlobError);
            }
        }
    }
    Ok(expanded)
}

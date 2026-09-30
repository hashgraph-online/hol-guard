// Python's isalnum is Unicode Letter or Number, not Rust's broader Alphabetic.
// The category table below is generated from the Python 3.12 reference's UCD
// 15.0.0. ASCII keeps its allocation-free fast path. This pins the semantics of
// otherwise runtime-dependent short-flag classification for native v1.
#[path = "command_option_unicode_ranges_a.rs"]
mod ranges_a;
#[path = "command_option_unicode_ranges_b.rs"]
mod ranges_b;

use ranges_a::PYTHON_ALNUM_RANGES_A;
use ranges_b::PYTHON_ALNUM_RANGES_B;

pub(crate) fn python_is_alphanumeric(character: char) -> bool {
    if character.is_ascii() {
        return character.is_ascii_alphanumeric();
    }
    python_alphanumeric_kind(character).is_some()
}

pub(crate) fn python_is_alphabetic(character: char) -> bool {
    if character.is_ascii() {
        return character.is_ascii_alphabetic();
    }
    python_alphanumeric_kind(character) == Some(1)
}

pub(crate) fn python_is_whitespace(character: char) -> bool {
    matches!(character, '\u{0009}'..='\u{000d}' | '\u{001c}'..='\u{0020}' | '\u{0085}' | '\u{00a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}')
}

fn python_alphanumeric_kind(character: char) -> Option<u8> {
    let codepoint = u32::from(character);
    range_kind(PYTHON_ALNUM_RANGES_A, codepoint)
        .or_else(|| range_kind(PYTHON_ALNUM_RANGES_B, codepoint))
}

fn range_kind(ranges: &[(u32, u32, u8)], codepoint: u32) -> Option<u8> {
    ranges
        .binary_search_by(|(start, end, _)| {
            if codepoint < *start {
                std::cmp::Ordering::Greater
            } else if codepoint > *end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .ok()
        .map(|index| ranges[index].2)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unicode_reference_categories_are_disjoint_sorted_and_python_compatible() {
        let mut previous_end = None;
        for &(start, end, _) in PYTHON_ALNUM_RANGES_A
            .iter()
            .chain(PYTHON_ALNUM_RANGES_B.iter())
        {
            assert!(start <= end);
            if let Some(previous) = previous_end {
                assert!(previous < start);
            }
            previous_end = Some(end);
        }
        assert!(python_is_alphabetic('é'));
        assert!(python_is_alphanumeric('²'));
        assert!(!python_is_alphabetic('²'));
        assert!(python_is_alphanumeric('Ⅻ'));
        assert!(!python_is_alphabetic('Ⅻ'));
        assert!(!python_is_alphanumeric('\u{0345}'));
        assert!(python_is_alphabetic('\u{1e4d0}'));
        assert!(python_is_whitespace('\u{001c}'));
        assert!(python_is_whitespace('\u{0085}'));
        assert!(!python_is_whitespace('\u{200b}'));
        assert!(!python_is_alphanumeric('🦀'));
    }
}

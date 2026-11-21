//! CPython 3.12 lowercase equivalence against an admitted ASCII grammar.
//!
//! Unicode operands need not be converted to full Unicode lowercase when every
//! configured comparison string is ASCII. Only U+0130 and U+212A can introduce
//! ASCII bytes through non-ASCII lowercase mappings in Unicode 15.0.0. Keeping
//! other Unicode characters opaque preserves ASCII equality, prefix and
//! substring results, including contextual Greek sigma. U+0130's combining dot
//! must remain present so a token or short-option cluster cannot collapse.
//! The Python fixture generator exhaustively verifies these mapping assumptions.

use std::collections::BTreeSet;

use crate::CommandSegmentV1;

pub(super) fn lowercase_for_ascii_comparison(value: &str) -> String {
    if value.is_ascii() {
        return value.to_ascii_lowercase();
    }
    let mut normalized = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\u{0130}' => normalized.push_str("i\u{0307}"),
            '\u{212a}' => normalized.push('k'),
            character => normalized.push(character.to_ascii_lowercase()),
        }
    }
    normalized
}

pub(super) fn executable_matches(
    segment: &CommandSegmentV1,
    executables: &BTreeSet<String>,
) -> bool {
    segment.executable.as_deref().is_some_and(|value| {
        let basename = value.rsplit(['/', '\\']).next().unwrap_or(value);
        executables.contains(&lowercase_for_ascii_comparison(basename))
    })
}

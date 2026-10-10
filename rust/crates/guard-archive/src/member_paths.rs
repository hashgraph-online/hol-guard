//! Path and link interpretation for archive members: normalization, the unsafe
//! path/link verdicts, and the case-folded identity used for conflicts.

use std::collections::HashMap;
use std::io::Read;

use tar::EntryType;

use crate::posix_path;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum MemberKind {
    Directory,
    File,
    Symlink,
    Hardlink,
}

pub(crate) fn replace_backslashes(bytes: &[u8]) -> Vec<u8> {
    if bytes.contains(&b'\\') {
        bytes
            .iter()
            .map(|b| if *b == b'\\' { b'/' } else { *b })
            .collect()
    } else {
        bytes.to_vec()
    }
}

/// `_unsafe_member_reason`: returns `Some` when the member is unsafe. The
/// caller collapses every reason to `tarball_zip_slip`, so only presence
/// matters.
pub(crate) fn unsafe_member_reason<R: Read>(
    entry: &tar::Entry<'_, R>,
    raw_name: &[u8],
    normalized_name: &[u8],
) -> Option<&'static str> {
    if posix_path::has_control_character(raw_name)
        || raw_name.starts_with(b"/")
        || normalized_name == b"."
        || normalized_name == b".."
        || normalized_name.starts_with(b"../")
    {
        return Some("unsafe_path");
    }
    let first_component = normalized_name
        .split(|b| *b == b'/')
        .next()
        .unwrap_or_default();
    if first_component.contains(&b':') {
        return Some("unsafe_path");
    }
    let entry_type = entry.header().entry_type();
    if matches!(
        entry_type,
        EntryType::Char | EntryType::Block | EntryType::Fifo
    ) {
        return Some("special_file");
    }
    if matches!(entry_type, EntryType::Symlink | EntryType::Link) {
        let raw_target = entry
            .link_name_bytes()
            .map(|name| replace_backslashes(&name))
            .unwrap_or_default();
        if raw_target.is_empty() || raw_target.starts_with(b"/") {
            return Some("unsafe_link");
        }
        let resolved_target = if entry_type == EntryType::Link {
            posix_path::normpath(&raw_target)
        } else {
            let base = posix_path::dirname(normalized_name);
            posix_path::normpath(&posix_path::join(&base, &raw_target))
        };
        if resolved_target == b".." || resolved_target.starts_with(b"../") {
            return Some("unsafe_link");
        }
        if resolved_target
            .split(|b| *b == b'/')
            .next()
            .unwrap_or_default()
            .contains(&b':')
        {
            return Some("unsafe_link");
        }
    }
    None
}

pub(crate) fn member_kind<R: Read>(entry: &tar::Entry<'_, R>) -> Option<MemberKind> {
    match entry.header().entry_type() {
        EntryType::Directory => Some(MemberKind::Directory),
        EntryType::Regular => Some(MemberKind::File),
        EntryType::Symlink => Some(MemberKind::Symlink),
        EntryType::Link => Some(MemberKind::Hardlink),
        _ => None,
    }
}

/// `_member_path_conflicts` on the case-folded normalized path.
pub(crate) fn member_path_conflicts(
    name: &str,
    kind: MemberKind,
    seen: &HashMap<String, MemberKind>,
) -> bool {
    if seen.contains_key(name) {
        return true;
    }
    let components: Vec<&str> = name.split('/').collect();
    for index in 1..components.len() {
        let ancestor = components[..index].join("/");
        if let Some(ancestor_kind) = seen.get(ancestor.as_str()) {
            if *ancestor_kind != MemberKind::Directory {
                return true;
            }
        }
    }
    if kind != MemberKind::Directory {
        let descendant_prefix = format!("{name}/");
        if seen
            .keys()
            .any(|existing| existing.starts_with(descendant_prefix.as_str()))
        {
            return true;
        }
    }
    false
}

/// `_normalized_link_target`: resolved in-archive link target or `None` when
/// the target is unsafe.
pub(crate) fn normalized_link_target<R: Read>(
    entry: &tar::Entry<'_, R>,
    normalized_name: &[u8],
) -> Option<Vec<u8>> {
    let raw_target = entry
        .link_name_bytes()
        .map(|name| replace_backslashes(&name))
        .unwrap_or_default();
    if raw_target.is_empty()
        || posix_path::has_control_character(&raw_target)
        || raw_target.starts_with(b"/")
    {
        return None;
    }
    let resolved_target = if entry.header().entry_type() == EntryType::Link {
        posix_path::normpath(&raw_target)
    } else {
        let base = posix_path::dirname(normalized_name);
        posix_path::normpath(&posix_path::join(&base, &raw_target))
    };
    if resolved_target == b"." || resolved_target == b".." || resolved_target.starts_with(b"../") {
        return None;
    }
    if resolved_target
        .split(|b| *b == b'/')
        .next()
        .unwrap_or_default()
        .contains(&b':')
    {
        return None;
    }
    Some(resolved_target)
}

/// Case- and normalization-insensitive identity of a member name, the way a
/// case-insensitive, normalization-insensitive filesystem (NTFS, APFS, HFS+)
/// would compare it: NFD, full Unicode case folding, NFD again (Unicode
/// canonical caseless matching, D145). Invalid UTF-8 collapses to U+FFFD, so
/// distinct undecodable names collide and are refused rather than trusted.
pub(crate) fn identity_key(bytes: &[u8]) -> String {
    use unicode_normalization::UnicodeNormalization;
    // ASCII is already NFD and its full case fold is plain lowercasing; this
    // is the overwhelmingly common name and avoids three full-path copies.
    if bytes.is_ascii() {
        return String::from_utf8_lossy(bytes).to_ascii_lowercase();
    }
    let decoded = String::from_utf8_lossy(bytes);
    let decomposed: String = decoded.nfd().collect();
    caseless::default_case_fold_str(&decomposed).nfd().collect()
}

/// Whether the name ends in one of `suffixes` under either the plain
/// lowercase view or the full identity view, so folding can only add matches.
pub(crate) fn name_ends_with_any(bytes: &[u8], suffixes: &[&str]) -> bool {
    let lowered = String::from_utf8_lossy(bytes).to_lowercase();
    let identity = identity_key(bytes);
    suffixes
        .iter()
        .any(|suffix| lowered.ends_with(suffix) || identity.ends_with(suffix))
}

/// The lowercase and identity spellings of a file name, for exact-match
/// recognition of build manifests.
pub(crate) fn name_variants(bytes: &[u8]) -> [String; 2] {
    [
        String::from_utf8_lossy(bytes).to_lowercase(),
        identity_key(bytes),
    ]
}

#[cfg(test)]
mod identity_key_tests {
    use super::identity_key;

    #[test]
    fn ascii_fast_path_equals_the_full_fold() {
        use unicode_normalization::UnicodeNormalization;
        let slow = |bytes: &[u8]| -> String {
            let decoded = String::from_utf8_lossy(bytes);
            let decomposed: String = decoded.nfd().collect();
            caseless::default_case_fold_str(&decomposed).nfd().collect()
        };
        // Every printable ASCII pair plus a seeded run of longer strings.
        for a in 0x20u8..0x7f {
            for b in 0x20u8..0x7f {
                let bytes = [a, b];
                assert_eq!(identity_key(&bytes), slow(&bytes));
            }
        }
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..2000 {
            let mut bytes = Vec::new();
            for _ in 0..(state % 40) {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                bytes.push(((state >> 33) % 0x5f) as u8 + 0x20);
            }
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            assert_eq!(identity_key(&bytes), slow(&bytes));
        }
    }
}

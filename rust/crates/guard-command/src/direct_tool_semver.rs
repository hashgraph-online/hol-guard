//! Conservative Node semver: exact, caret and tilde three-component versions.
use super::*;

fn decimal_integer(text: &str) -> Option<String> {
    // Unicode decimal-zero blocks preserve Python integer parsing without a
    // fixed-width overflow boundary. Version comparison uses normalized digits.
    const ZERO: &[u32] = &[
        0x30, 0x660, 0x6f0, 0x7c0, 0x966, 0x9e6, 0xa66, 0xae6, 0xb66, 0xbe6, 0xc66, 0xce6, 0xd66,
        0xde6, 0xe50, 0xed0, 0xf20, 0x1040, 0x1090, 0x17e0, 0x1810, 0x1946, 0x19d0, 0x1a80, 0x1a90,
        0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0, 0xa9f0, 0xaa50, 0xabf0,
        0xff10, 0x104a0, 0x10d30, 0x10d40, 0x11066, 0x110f0, 0x11136, 0x111d0, 0x112f0, 0x11450,
        0x114d0, 0x11650, 0x116c0, 0x116d0, 0x116da, 0x11730, 0x118e0, 0x11950, 0x11bf0, 0x11c50,
        0x11d50, 0x11da0, 0x11f50, 0x16130, 0x16a60, 0x16ac0, 0x16b50, 0x16d70, 0x1ccf0, 0x1d7ce,
        0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6, 0x1e140, 0x1e2f0, 0x1e4f0, 0x1e5f1, 0x1e950, 0x1fbf0,
    ];
    let mut digits = String::new();
    for character in text.chars() {
        let code = character as u32;
        let zero = ZERO
            .iter()
            .find(|zero| code >= **zero && code - **zero < 10)?;
        digits.push(char::from(b'0' + (code - zero) as u8));
    }
    let trimmed = digits.trim_start_matches('0');
    Some(if trimmed.is_empty() {
        "0".to_owned()
    } else {
        trimmed.to_owned()
    })
}

fn compare_versions(a: &[String; 3], b: &[String; 3]) -> std::cmp::Ordering {
    for (a, b) in a.iter().zip(b) {
        let comparison = a.len().cmp(&b.len()).then_with(|| a.cmp(b));
        if !comparison.is_eq() {
            return comparison;
        }
    }
    std::cmp::Ordering::Equal
}

pub(super) fn semver_spec_matches(specifier: &str, version: &str) -> bool {
    static EXACT: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\A\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\z").unwrap());
    static SPEC: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\A([~^]?)(\d+)\.(\d+)\.(\d+)\z").unwrap());
    static VERSION: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\A(\d+)\.(\d+)\.(\d+)\z").unwrap());
    if specifier == version && EXACT.is_match(version) {
        return version
            .split('-')
            .next()
            .unwrap_or("")
            .split('.')
            .all(|part| decimal_integer(part).is_some());
    }
    let (Some(spec), Some(installed)) = (SPEC.captures(specifier), VERSION.captures(version))
    else {
        return false;
    };
    let requested = [
        decimal_integer(&spec[2]),
        decimal_integer(&spec[3]),
        decimal_integer(&spec[4]),
    ];
    let installed = [
        decimal_integer(&installed[1]),
        decimal_integer(&installed[2]),
        decimal_integer(&installed[3]),
    ];
    let ([Some(a), Some(b), Some(c)], [Some(x), Some(y), Some(z)]) = (requested, installed) else {
        return false;
    };
    let requested = [a, b, c];
    let installed = [x, y, z];
    if compare_versions(&installed, &requested).is_lt() {
        return false;
    }
    match &spec[1] {
        "^" if requested[0] != "0" => installed[0] == requested[0],
        "^" if requested[1] != "0" => installed[..2] == requested[..2],
        "~" => installed[..2] == requested[..2],
        _ => installed == requested,
    }
}

//! Environment authority for attacker-controlled MCP children.

use std::collections::BTreeMap;

const INHERITED_RUNTIME_NAMES: &[&str] = &[
    "COLORTERM",
    "COMSPEC",
    "FORCE_COLOR",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LOGNAME",
    "NO_COLOR",
    "PATH",
    "PATHEXT",
    "SHELL",
    "SYSTEMROOT",
    "TEMP",
    "TERM",
    "TMP",
    "TMPDIR",
    "USER",
    "WINDIR",
];

// Python casefold compatibility for an ASCII target: long-s and Kelvin sign
// are the only non-ASCII characters whose full fold is a character in this name.
fn is_guard_token_name(name: &str) -> bool {
    let mut chars = name.chars();
    for expected in "hermes_guard_token".bytes() {
        let Some(actual) = chars.next() else {
            return false;
        };
        let folded = match actual {
            '\u{017f}' => 's',
            '\u{212a}' => 'k',
            other => other.to_ascii_lowercase(),
        };
        if folded != char::from(expected) {
            return false;
        }
    }
    chars.next().is_none()
}

pub fn build_launch_environment(
    inherited: &BTreeMap<String, String>,
    configured: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut selected = BTreeMap::new();
    for (name, value) in inherited {
        if INHERITED_RUNTIME_NAMES.contains(&name.as_str()) && !configured.contains_key(name) {
            selected.insert(name.clone(), value.clone());
        }
    }
    for (name, value) in configured {
        if !is_guard_token_name(name) {
            selected.insert(name.clone(), value.clone());
        }
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_grants_do_not_reintroduce_guard_credentials() {
        let inherited = BTreeMap::from([
            ("PATH".into(), "/ambient/bin".into()),
            ("AWS_SECRET_ACCESS_KEY".into(), "ambient-secret".into()),
            ("HERMES_GUARD_TOKEN".into(), "internal".into()),
        ]);
        let configured = BTreeMap::from([
            ("PATH".into(), "/configured/bin".into()),
            ("MCP_API_TOKEN".into(), "explicit-grant".into()),
            ("HERMEſ_GUARD_TOKEN".into(), "reinjected".into()),
            ("hermes_guard_token_suffix".into(), "ordinary-grant".into()),
        ]);
        assert_eq!(
            build_launch_environment(&inherited, &configured),
            BTreeMap::from([
                ("PATH".into(), "/configured/bin".into()),
                ("MCP_API_TOKEN".into(), "explicit-grant".into()),
                ("hermes_guard_token_suffix".into(), "ordinary-grant".into()),
            ]),
        );
    }
}

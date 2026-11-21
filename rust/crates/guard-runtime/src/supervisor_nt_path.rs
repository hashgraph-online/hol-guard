//! Windows path and security-descriptor checks for the supervisor task,
//! matching Python's `ntpath` normalization.

use std::sync::LazyLock;

use regex::Regex;

use crate::daemon_lifecycle_text::nt_root_end;

/// `ntpath.normcase(ntpath.normpath(path))`.
pub(super) fn nt_normcase_normpath(path: &str) -> String {
    nt_normpath(path).to_lowercase()
}

/// `ntpath.normpath(path)`.
pub(super) fn nt_normpath(path: &str) -> String {
    let characters: Vec<char> = path
        .chars()
        .map(|character| if character == '/' { '\\' } else { character })
        .collect();
    let end = nt_root_end(&characters);
    let prefix: String = characters[..end].iter().collect();
    let rooted = prefix.ends_with('\\');
    let tail: String = characters[end..].iter().collect();
    let mut parts: Vec<&str> = Vec::new();
    for part in tail.split('\\') {
        match part {
            "" | "." => {}
            ".." if parts.last().is_some_and(|last| *last != "..") => {
                parts.pop();
            }
            ".." if parts.is_empty() && rooted => {}
            part => parts.push(part),
        }
    }
    if prefix.is_empty() && parts.is_empty() {
        ".".to_owned()
    } else {
        format!("{prefix}{}", parts.join("\\"))
    }
}

/// `D:P` with exactly the SYSTEM and Administrators full-control entries, in
/// either order and with either SID spelling, and only those owners/groups.
pub(super) fn security_descriptor_valid(descriptor: &str) -> bool {
    static SDDL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?i)^(?:O:(?:BA|SY|S-1-5-32-544|S-1-5-18))?(?:G:(?:BA|SY|S-1-5-32-544|S-1-5-18))?D:P(?P<aces>(?:\([^()]+\))+)$",
        )
        .expect("static pattern")
    });
    static ACE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\(([^()]+)\)").expect("static pattern"));
    let Some(aces) = SDDL
        .captures(descriptor)
        .and_then(|captures| captures.name("aces"))
    else {
        return false;
    };
    let mut normalized = Vec::new();
    for ace in ACE.captures_iter(aces.as_str()) {
        let mut fields: Vec<String> = ace[1]
            .to_uppercase()
            .split(';')
            .map(str::to_owned)
            .collect();
        if fields.len() != 6 {
            return false;
        }
        fields[5] = match fields[5].as_str() {
            "SY" => "S-1-5-18".to_owned(),
            "BA" => "S-1-5-32-544".to_owned(),
            other => other.to_owned(),
        };
        normalized.push(format!("({})", fields.join(";")));
    }
    let system = "(A;;FA;;;S-1-5-18)";
    let administrators = "(A;;FA;;;S-1-5-32-544)";
    normalized.len() == 2
        && normalized.iter().any(|ace| ace == system)
        && normalized.iter().any(|ace| ace == administrators)
}

//! Compile the pinned public-suffix snapshot (`public-suffix/` in this crate) into a compact rule list.
//!
//! The snapshot file must match the SHA-256 pinned in `snapshot.v1.json`, so a hand edit or a
//! partial refresh fails the build. Each rule is reduced to its ASCII (punycode) form with its `!`
//! or `*.` prefix kept, one per line, sorted and de-duplicated.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path};

pub const MAX_RULES: usize = 20_000;
const MAX_RULE_CHARS: usize = 253;

pub struct Compiled {
    pub rules: Vec<u8>,
    pub snapshot_sha256: String,
    pub version: String,
}

pub fn compile(package: &Path, read: impl Fn(&Path) -> String) -> Compiled {
    let directory = package.join("public-suffix");
    let manifest: Value =
        serde_json::from_str(&read(&directory.join("snapshot.v1.json"))).expect("snapshot JSON");
    assert_eq!(manifest["schema"], "guard.public-suffix-snapshot.v1");
    let file = manifest["file"].as_str().expect("snapshot file name");
    assert!(
        !file.contains('/') && !file.contains('\\') && !file.starts_with('.'),
        "snapshot file must be a plain name"
    );
    let pinned = manifest["sha256"].as_str().expect("snapshot sha256");
    let version = manifest["version"]
        .as_str()
        .expect("snapshot version")
        .to_owned();
    let text = read(&directory.join(file));
    let actual = hex::encode(Sha256::digest(text.as_bytes()));
    assert_eq!(actual, pinned, "public-suffix snapshot digest mismatch");
    let mut rules = BTreeSet::new();
    for line in text.lines() {
        let Some(rule) = line.split_whitespace().next() else {
            continue;
        };
        if rule.starts_with("//") {
            continue;
        }
        rules.insert(ascii_rule(rule));
    }
    assert!(!rules.is_empty(), "public-suffix snapshot has no rules");
    assert!(rules.len() <= MAX_RULES, "public-suffix snapshot too large");
    let mut bytes = Vec::new();
    for rule in rules {
        bytes.extend_from_slice(rule.as_bytes());
        bytes.push(b'\n');
    }
    Compiled {
        rules: bytes,
        snapshot_sha256: actual,
        version,
    }
}

fn ascii_rule(rule: &str) -> String {
    let (prefix, name) = if let Some(rest) = rule.strip_prefix('!') {
        ("!", rest)
    } else if let Some(rest) = rule.strip_prefix("*.") {
        ("*.", rest)
    } else {
        ("", rule)
    };
    assert!(
        !name.is_empty() && !name.contains('*') && !name.contains('!'),
        "unsupported public-suffix rule: {rule}"
    );
    let ascii = idna::domain_to_ascii(name)
        .unwrap_or_else(|_| panic!("public-suffix rule is not a domain: {rule}"));
    assert!(
        !ascii.is_empty()
            && ascii.len() <= MAX_RULE_CHARS
            && ascii.bytes().all(|byte| byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || b"-.".contains(&byte)),
        "public-suffix rule did not normalise: {rule}"
    );
    format!("{prefix}{ascii}")
}

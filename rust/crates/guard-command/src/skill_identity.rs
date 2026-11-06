//! Content-addressed skill identity: the `SkillIdentity` half of
//! `runtime/skill_protection.py`, which Python used to compose itself.
//!
//! A skill's identity is its own SHA-256 plus the digests of the links,
//! template placeholders and shell blocks its text carries. The composed
//! `identity_hash` therefore moves when any of those move, which is what the
//! portal firewall and the install scanner key their snapshots on.
//!
//! Python `re` semantics come from [`crate::persistence_rules::py_regex`];
//! `re.findall` with one group yields that group for each leftmost,
//! non-overlapping match.

use std::sync::LazyLock;

use fancy_regex::Regex;
use sha2::{Digest, Sha256};

use crate::persistence_rules::py_regex;

static REFERENCE: LazyLock<Regex> = LazyLock::new(|| py_regex(r"\[.*?\]\((.*?)\)", ""));
static TEMPLATE: LazyLock<Regex> = LazyLock::new(|| py_regex(r"\{\{(.*?)\}\}", ""));
static SHELL_BLOCK: LazyLock<Regex> =
    LazyLock::new(|| py_regex(r"```(?:bash|sh|shell|zsh)\s(.*?)```", "s"));

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// `re.findall(pattern, text)` for a single-group pattern.
fn findall(re: &Regex, text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for captures in re.captures_iter(text) {
        let Ok(captures) = captures else {
            // A backtrack limit is an unusable extraction, not an empty one;
            // the caller's digest would otherwise silently drop a reference.
            return Vec::new();
        };
        found.push(
            captures
                .get(1)
                .map(|group| group.as_str().to_owned())
                .unwrap_or_default(),
        );
    }
    found
}

fn digests(re: &Regex, text: &str) -> Vec<String> {
    findall(re, text)
        .iter()
        .map(|item| sha256_hex(item.as_bytes()))
        .collect()
}

/// The content-addressed identity of one skill document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillIdentity {
    pub skill_hash: String,
    pub reference_hashes: Vec<String>,
    pub template_hashes: Vec<String>,
    pub script_hashes: Vec<String>,
}

impl SkillIdentity {
    /// `skill_hash|refs|templates|scripts`, each group sorted and comma joined.
    pub fn identity_hash(&self) -> String {
        let group = |hashes: &[String]| {
            let mut sorted = hashes.to_vec();
            sorted.sort();
            sorted.join(",")
        };
        let payload = [
            self.skill_hash.clone(),
            group(&self.reference_hashes),
            group(&self.template_hashes),
            group(&self.script_hashes),
        ]
        .join("|");
        sha256_hex(payload.as_bytes())
    }
}

/// `build_skill_identity(skill_content)`.
pub fn build_skill_identity(content: &str) -> SkillIdentity {
    SkillIdentity {
        skill_hash: sha256_hex(content.as_bytes()),
        reference_hashes: digests(&REFERENCE, content),
        template_hashes: digests(&TEMPLATE, content),
        script_hashes: digests(&SHELL_BLOCK, content),
    }
}

#[cfg(test)]
#[path = "skill_identity_tests.rs"]
mod tests;

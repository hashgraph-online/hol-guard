//! Registered harness ids and their install aliases.
//!
//! Mirrors the harness contract registry read by
//! `guard/harness_posture.py::runtime_harness_key`. This lives in
//! `guard-command` so the risk-action resolver can canonicalize a harness name
//! without a second, partial copy of the table.

/// `(harness id, install aliases)` of every registered harness contract.
const HARNESS_ALIASES: [(&str, &[&str]); 17] = [
    ("codex", &["codex"]),
    ("claude-code", &["claude-code", "claude"]),
    ("opencode", &["opencode"]),
    ("copilot", &["copilot"]),
    ("cursor", &["cursor"]),
    ("cline", &["cline", "cline-cli", "cline-vscode"]),
    ("gemini", &["gemini"]),
    ("hermes", &["hermes"]),
    ("openclaw", &["openclaw"]),
    ("antigravity", &["antigravity"]),
    ("kimi", &["kimi", "kimi-code", "kimi-cli"]),
    (
        "grok",
        &["grok", "grok-build", "grok-build-cli", "xai-grok"],
    ),
    ("pi", &["pi", "pi-agent", "pi-coding-agent"]),
    ("omp", &["omp", "oh-my-pi"]),
    ("zcode", &["zcode", "zai", "z-code", "zai-zcode"]),
    ("devin", &["devin", "devin-cli", "cognition-devin"]),
    ("paseo", &["paseo"]),
];

/// Number of registered harness contracts.
pub const REGISTERED_HARNESS_COUNT: usize = HARNESS_ALIASES.len();

/// `canonical_harness_id`: a registry id or install alias, else `None`.
pub fn canonical_harness_id(value: &str) -> Option<&'static str> {
    let key = value.trim().to_lowercase().replace('_', "-");
    HARNESS_ALIASES
        .iter()
        .find(|(_, aliases)| aliases.contains(&key.as_str()))
        .map(|(harness, _)| *harness)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_ids_aliases_and_spelling() {
        assert_eq!(canonical_harness_id("codex"), Some("codex"));
        assert_eq!(canonical_harness_id("claude"), Some("claude-code"));
        assert_eq!(canonical_harness_id(" PI_Agent "), Some("pi"));
        assert_eq!(canonical_harness_id("oh-my-pi"), Some("omp"));
        assert_eq!(canonical_harness_id("unregistered"), None);
        assert_eq!(canonical_harness_id(""), None);
    }
}

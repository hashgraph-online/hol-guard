//! Encoded-execution patterns and sensitive path labels (`request_models.py`).
//! Generated from the retired Python tables; keep in step with the vectors.

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::sync::LazyLock;

use fancy_regex::Regex as FancyRegex;

use crate::hook_adapter_pytext::compile_fancy;

pub(crate) static ENCODED_EXECUTION_PATTERNS: LazyLock<Vec<FancyRegex>> = LazyLock::new(|| {
    vec![
        compile_fancy(
            r#"(?i)\bbase64\b(?=[^\n|;]*\s(?:--decode|-[A-Za-z]*[dD][A-Za-z]*))[^\n|;]*(?:\|\s*(?:(?:[A-Za-z0-9_./~-]+/)?env(?:(?:\s+--?[A-Za-z][A-Za-z-]*(?:=\S+)?|\s+--|\s+[A-Za-z_][A-Za-z0-9_]*=\S+|\s+\S+))*\s+)?(?:[A-Za-z0-9_./~-]+/)?(?:ash|bash|dash|sh|zsh|python(?:3)?|node|perl|ruby|pwsh|powershell)\b)"#,
        ),
        compile_fancy(
            r#"(?i)\bxxd\s+(?:-r\s+-p|-rp)\b[^\n|;]*(?:\|\s*(?:(?:[A-Za-z0-9_./~-]+/)?env(?:(?:\s+--?[A-Za-z][A-Za-z-]*(?:=\S+)?|\s+--|\s+[A-Za-z_][A-Za-z0-9_]*=\S+|\s+\S+))*\s+)?(?:[A-Za-z0-9_./~-]+/)?(?:ash|bash|dash|sh|zsh|python(?:3)?|node|perl|ruby|pwsh|powershell)\b)"#,
        ),
        compile_fancy(
            r#"(?i)\bopenssl\s+enc\b[^\n|;]*\s-(?:d|decrypt)\b[^\n|;]*(?:\|\s*(?:(?:[A-Za-z0-9_./~-]+/)?env(?:(?:\s+--?[A-Za-z][A-Za-z-]*(?:=\S+)?|\s+--|\s+[A-Za-z_][A-Za-z0-9_]*=\S+|\s+\S+))*\s+)?(?:[A-Za-z0-9_./~-]+/)?(?:ash|bash|dash|sh|zsh|python(?:3)?|node|perl|ruby|pwsh|powershell)\b)"#,
        ),
        compile_fancy(
            r#"(?i)\b(?:gpg|gpg2)\b[^\n|;]*(?:--decrypt|-d)\b[^\n|;]*(?:\|\s*(?:(?:[A-Za-z0-9_./~-]+/)?env(?:(?:\s+--?[A-Za-z][A-Za-z-]*(?:=\S+)?|\s+--|\s+[A-Za-z_][A-Za-z0-9_]*=\S+|\s+\S+))*\s+)?(?:[A-Za-z0-9_./~-]+/)?(?:ash|bash|dash|sh|zsh|python(?:3)?|node|perl|ruby|pwsh|powershell)\b)"#,
        ),
        compile_fancy(r#"(?i)\b(?:powershell|pwsh)\b[^\n;]*\s-(?:e|ec|enc|encodedcommand)\b"#),
        compile_fancy(r#"(?i)\b(?:powershell|pwsh)\b[^\n;]*\bfrombase64string\s*\("#),
    ]
});
pub(crate) static BASE64_LITERAL_PATTERN: LazyLock<FancyRegex> = LazyLock::new(|| {
    compile_fancy(r#"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])"#)
});
pub(crate) static HEX_LITERAL_PATTERN: LazyLock<FancyRegex> =
    LazyLock::new(|| compile_fancy(r#"(?<![A-Fa-f0-9])[A-Fa-f0-9]{24,}(?![A-Fa-f0-9])"#));
pub(crate) const MAX_DECODED_PAYLOAD_BYTES: usize = 32768;
pub(crate) const SENSITIVE_DECODED_PAYLOAD_TOKENS: &[&str] = &[
    ".env",
    ".ssh/",
    ".aws/credentials",
    ".git-credentials",
    "process.env",
    "os.environ",
    "getenv(",
    "curl ",
    "wget ",
    "requests.",
    "fetch(",
    "axios.",
    "approval_policy",
    "hol-guard",
    "guard-bypass",
    ".codex/config.toml",
    "scp ",
];
pub(crate) static SECRET_EXFILTRATION_SECRET_PATTERN: LazyLock<FancyRegex> = LazyLock::new(|| {
    compile_fancy(
        r#"(?i)\b(?:api[_-]?key|auth[_-]?token|credential|credentials|npm[_-]?token|private[_-]?key|secret|token)\b"#,
    )
});
pub(crate) static SECRET_EXFILTRATION_NETWORK_PATTERN: LazyLock<FancyRegex> = LazyLock::new(|| {
    compile_fancy(
        r#"(?i)\b(?:axios\.post|fetch\s*\(|http\.client|requests\.post|urllib\.request|urlopen\s*\()|https?://"#,
    )
});
pub(crate) static SECRET_EXFILTRATION_DESTINATION_PATTERN: LazyLock<FancyRegex> =
    LazyLock::new(|| compile_fancy(r#"(?i)\b(?:collect|exfil|evil|leak|post|upload|webhook)\b"#));
pub(crate) const SENSITIVE_BASENAME_LABELS: &[(&str, &str)] = &[
    (".npmrc", "npm registry credentials"),
    (".pypirc", "Python package credentials"),
    (".netrc", "netrc credentials"),
    (".git-credentials", "Git credential store"),
];
pub(crate) const SENSITIVE_SUFFIX_LABELS: &[(&[&str], &str)] = &[
    (&[".aws", "credentials"], "AWS shared credentials file"),
    (&[".aws", "config"], "AWS shared config file"),
    (&[".docker", "config.json"], "Docker client config"),
    (&[".ssh", "id_rsa"], "SSH private key"),
    (&[".ssh", "id_ed25519"], "SSH private key"),
    (&[".ssh", "id_ecdsa"], "SSH private key"),
    (&[".ssh", "config"], "SSH client config"),
];
pub(crate) const SENSITIVE_PATH_REASONS: &[(&str, &str)] = &[
    (
        "local .env file",
        "Guard treats .env files as sensitive because they commonly store local secrets.",
    ),
    (
        "npm registry credentials",
        "Guard treats .npmrc as sensitive because it may contain registry tokens.",
    ),
    (
        "Python package credentials",
        "Guard treats .pypirc as sensitive because it may contain package credentials.",
    ),
    (
        "netrc credentials",
        "Guard treats .netrc as sensitive because it may contain login secrets.",
    ),
    (
        "Git credential store",
        "Guard treats .git-credentials as sensitive because it may contain repository credentials.",
    ),
    (
        "AWS shared credentials file",
        "Guard treats AWS shared credentials as sensitive because they contain cloud access keys.",
    ),
    (
        "AWS shared config file",
        "Guard treats AWS shared config as sensitive because it may contain credential profiles.",
    ),
    (
        "Docker client config",
        "Guard treats Docker client config as sensitive because it may contain registry auth.",
    ),
    (
        "SSH private key",
        "Guard treats SSH private keys as sensitive because they provide direct host access.",
    ),
    (
        "SSH client config",
        "Guard treats SSH config as sensitive because it may reveal or shape host credentials.",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pattern_compiles() {
        LazyLock::force(&ENCODED_EXECUTION_PATTERNS);
        LazyLock::force(&BASE64_LITERAL_PATTERN);
        LazyLock::force(&HEX_LITERAL_PATTERN);
        LazyLock::force(&SECRET_EXFILTRATION_SECRET_PATTERN);
        LazyLock::force(&SECRET_EXFILTRATION_NETWORK_PATTERN);
        LazyLock::force(&SECRET_EXFILTRATION_DESTINATION_PATTERN);
    }
}

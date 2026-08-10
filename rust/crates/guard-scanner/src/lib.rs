#![forbid(unsafe_code)]

use guard_rules::{CONTEXT_CHARS, MAX_MATCHES, MAX_SCAN_BYTES};
use regex::{Regex, RegexBuilder};
use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanMatch {
    pub classifier: &'static str,
    pub family: &'static str,
    pub sensitivity: &'static str,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    pub matches: Vec<ScanMatch>,
    pub bytes_scanned: usize,
    pub chunks_scanned: usize,
    pub budget_exhausted: bool,
    pub reason_code: &'static str,
}

#[derive(Clone, Copy)]
struct PatternDef {
    classifier: &'static str,
    family: &'static str,
    sensitivity: &'static str,
    reason: &'static str,
    pattern: &'static str,
    case_insensitive: bool,
    multi_line: bool,
}

const PATTERNS: &[PatternDef] = &[
    PatternDef { classifier: "npm-auth-token", family: "npm auth token", sensitivity: "high", reason: "Guard found an npm registry token pattern.", pattern: r#"[\"']?\b[A-Za-z0-9_-]*(?:_authToken|npm[_-]?token)\b[\"']?\s*[:=]\s*(?:\"[^\"\r\n]+\"|'[^'\r\n]+'|[^ \t\r\n\"',}]+)"#, case_insensitive: true, multi_line: true },
    PatternDef { classifier: "github-token", family: "GitHub token", sensitivity: "high", reason: "Guard found a GitHub token pattern.", pattern: concat!(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github", r"_pat_[A-Za-z0-9_]{20,}_[A-Za-z0-9_]{20,})\b"), case_insensitive: false, multi_line: false },
    PatternDef { classifier: "aws-access-key", family: "AWS access key", sensitivity: "high", reason: "Guard found an AWS access key pattern.", pattern: r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", case_insensitive: false, multi_line: false },
    PatternDef { classifier: "openai-api-key", family: "OpenAI API key", sensitivity: "high", reason: "Guard found an OpenAI API key pattern.", pattern: r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b", case_insensitive: false, multi_line: false },
    PatternDef { classifier: "anthropic-api-key", family: "Anthropic API key", sensitivity: "high", reason: "Guard found an Anthropic API key pattern.", pattern: r"\bsk-ant-api03-[A-Za-z0-9_-]{20,}\b", case_insensitive: false, multi_line: false },
    PatternDef { classifier: "hedera-private-key", family: "Hedera private key", sensitivity: "critical", reason: "Guard found a Hedera private-key-like value.", pattern: r#"[\"']?\b[A-Za-z0-9_-]*(?:hedera[_-]?)?(?:operator[_-]?)?private[_-]?key\b[\"']?\s*[:=]\s*(?:\"(?:0x)?[0-9a-f]{64,96}\"|'(?:0x)?[0-9a-f]{64,96}'|(?:0x)?[0-9a-f]{64,96}\b)"#, case_insensitive: true, multi_line: true },
    PatternDef { classifier: "pem-private-key", family: "PEM private key", sensitivity: "critical", reason: "Guard found a PEM private key header.", pattern: r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", case_insensitive: false, multi_line: true },
    PatternDef { classifier: "generic-bearer-token", family: "generic bearer token", sensitivity: "medium", reason: "Guard found a bearer token pattern.", pattern: r"\bbearer\s+[A-Za-z0-9._~+/=-]{16,}\b", case_insensitive: true, multi_line: true },
    PatternDef { classifier: "credential-marker", family: "credential assignment", sensitivity: "medium", reason: "Guard found credential-looking marker text.", pattern: r"(?:^|[^a-z0-9])fake[_-]?(?:credential|secret)\b", case_insensitive: true, multi_line: false },
    PatternDef { classifier: "credential-assignment", family: "credential assignment", sensitivity: "medium", reason: "Guard found credential-looking assignment text.", pattern: r#"[\"']?\b[A-Za-z0-9_-]*(?:api[_-]?key|auth[_-]?token|credential|credentials|npm[_-]?token|private[_-]?key|secret|token|password)\b[\"']?\s*[:=]\s*(?:\"[^\"\r\n]+\"|'[^'\r\n]+'|[^ \t\r\n\"',}]+)"#, case_insensitive: true, multi_line: true },
];

static COMPILED: OnceLock<Vec<Regex>> = OnceLock::new();
static SAMPLE: OnceLock<Regex> = OnceLock::new();
static DOC_SAMPLE: OnceLock<Regex> = OnceLock::new();

fn compiled() -> &'static [Regex] {
    COMPILED.get_or_init(|| {
        PATTERNS
            .iter()
            .map(|def| {
                RegexBuilder::new(def.pattern)
                    .case_insensitive(def.case_insensitive)
                    .multi_line(def.multi_line)
                    .build()
                    .expect("native Guard rule must compile")
            })
            .collect()
    })
}

fn sample_regex() -> &'static Regex {
    SAMPLE.get_or_init(|| {
        RegexBuilder::new(r"\b(?:example|fake|dummy|invalid|test|canary)\b")
            .case_insensitive(true)
            .build()
            .expect("sample rule must compile")
    })
}

fn doc_sample_regex() -> &'static Regex {
    DOC_SAMPLE.get_or_init(|| {
        RegexBuilder::new(r"^(?:fixture|placeholder)(?:[-_.]?(?:only|value|secret|credential|token|key|example|dummy|fake|test|sample|[0-9]{1,4}))*$")
            .case_insensitive(true)
            .build()
            .expect("documentation sample rule must compile")
    })
}

fn suppressible(classifier: &str) -> bool {
    matches!(classifier, "credential-assignment" | "generic-bearer-token")
}

fn has_long_alphanumeric_run(token: &str) -> bool {
    let mut run = 0usize;
    for character in token.chars() {
        if character.is_ascii_alphanumeric() {
            run += 1;
            if run >= 20 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn assignment_value(matched: &str) -> Option<&str> {
    let index = matched.find([':', '='])?;
    Some(matched[index + 1..].trim().trim_matches(|character| character == '\'' || character == '"'))
}

fn is_sample(classifier: &str, matched: &str, documentation_sample_context: bool) -> bool {
    if !suppressible(classifier) {
        return false;
    }
    if classifier == "generic-bearer-token" {
        let token = matched.split_whitespace().last().unwrap_or_default();
        if sample_regex().is_match(token) && !has_long_alphanumeric_run(token) {
            return true;
        }
        return documentation_sample_context && doc_sample_regex().is_match(token);
    }
    if sample_regex().is_match(matched) {
        return true;
    }
    if !documentation_sample_context {
        return false;
    }
    assignment_value(matched).is_some_and(|value| doc_sample_regex().is_match(value))
}

fn classify_window(
    text: &str,
    suppress_samples: bool,
    documentation_sample_context: bool,
    found: &mut BTreeMap<&'static str, ScanMatch>,
) {
    for (index, def) in PATTERNS.iter().enumerate() {
        if found.contains_key(def.classifier) {
            continue;
        }
        let has_match = compiled()[index].find_iter(text).any(|matched| {
            !(suppress_samples && is_sample(def.classifier, matched.as_str(), documentation_sample_context))
        });
        if has_match {
            found.insert(
                def.classifier,
                ScanMatch {
                    classifier: def.classifier,
                    family: def.family,
                    sensitivity: def.sensitivity,
                    reason: def.reason,
                },
            );
        }
    }
}

pub fn scan_text(
    text: &str,
    local_content: bool,
    source_context: bool,
    max_bytes: usize,
    deadline: Option<Instant>,
) -> ScanResult {
    scan_chunks(
        std::iter::once(text),
        local_content,
        source_context,
        max_bytes,
        deadline,
    )
}

pub fn scan_chunks<'a>(
    chunks: impl IntoIterator<Item = &'a str>,
    local_content: bool,
    source_context: bool,
    max_bytes: usize,
    deadline: Option<Instant>,
) -> ScanResult {
    let max_bytes = max_bytes.min(MAX_SCAN_BYTES);
    let mut found = BTreeMap::new();
    let mut tail = String::new();
    let mut bytes_scanned = 0usize;
    let mut chunks_scanned = 0usize;

    for chunk in chunks {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return ScanResult {
                matches: found.into_values().collect(),
                bytes_scanned,
                chunks_scanned,
                budget_exhausted: true,
                reason_code: "deadline_exceeded",
            };
        }
        let remaining = max_bytes.saturating_sub(bytes_scanned);
        if remaining == 0 {
            return ScanResult {
                matches: found.into_values().collect(),
                bytes_scanned,
                chunks_scanned,
                budget_exhausted: true,
                reason_code: "max_bytes_exceeded",
            };
        }
        let mut accepted_end = chunk.len().min(remaining);
        while accepted_end > 0 && !chunk.is_char_boundary(accepted_end) {
            accepted_end -= 1;
        }
        let accepted = &chunk[..accepted_end];
        let truncated = accepted_end < chunk.len();
        bytes_scanned += accepted.len();
        chunks_scanned += 1;
        let mut window = String::with_capacity(tail.len() + accepted.len());
        window.push_str(&tail);
        window.push_str(accepted);
        classify_window(&window, true, !local_content, &mut found);
        if found.is_empty() && local_content {
            classify_window(&window, false, source_context, &mut found);
        }
        if found
            .values()
            .any(|matched| matches!(matched.sensitivity, "high" | "critical"))
        {
            return ScanResult {
                matches: found.into_values().collect(),
                bytes_scanned,
                chunks_scanned,
                budget_exhausted: false,
                reason_code: "secret_match_early_exit",
            };
        }
        if found.len() >= MAX_MATCHES {
            return ScanResult {
                matches: found.into_values().collect(),
                bytes_scanned,
                chunks_scanned,
                budget_exhausted: false,
                reason_code: "max_matches_reached",
            };
        }
        if truncated {
            return ScanResult {
                matches: found.into_values().collect(),
                bytes_scanned,
                chunks_scanned,
                budget_exhausted: true,
                reason_code: "max_bytes_exceeded",
            };
        }
        tail = window
            .chars()
            .rev()
            .take(CONTEXT_CHARS)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
    }

    let reason_code = if found.is_empty() { "clean" } else { "matches" };
    ScanResult {
        matches: found.into_values().collect(),
        bytes_scanned,
        chunks_scanned,
        budget_exhausted: false,
        reason_code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn github_like_token() -> String {
        let prefix = ["gh", "p_"].concat();
        format!("{prefix}{}", "a".repeat(30))
    }

    #[test]
    fn detects_github_token_without_returning_sample() {
        let token = github_like_token();
        let text = format!("token={token}");
        let result = scan_text(&text, true, true, MAX_SCAN_BYTES, None);
        assert!(result.matches.iter().any(|matched| matched.classifier == "github-token"));
        assert!(!format!("{:?}", result.matches).contains(&token));
    }

    #[test]
    fn detects_split_token_across_chunks() {
        let token = github_like_token();
        let split_at = 16.min(token.len());
        let first = format!("prefix {}", &token[..split_at]);
        let second = format!("{} suffix", &token[split_at..]);
        let result = scan_chunks([first.as_str(), second.as_str()], true, true, MAX_SCAN_BYTES, None);
        assert!(result.matches.iter().any(|matched| matched.classifier == "github-token"));
    }

    #[test]
    fn documentation_placeholder_is_suppressed() {
        let result = scan_text("token = placeholder-only", false, true, MAX_SCAN_BYTES, None);
        assert!(result.matches.is_empty());
    }
}

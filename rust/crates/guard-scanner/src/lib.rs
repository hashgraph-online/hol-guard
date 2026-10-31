#![forbid(unsafe_code)]

pub mod git_read;
pub mod precommit;
pub mod repository_scanner;
pub mod secret_detection;
pub mod staged_scanner;

mod code_cursor;
mod code_expression;
mod code_value;
mod continuation;
mod field_copy;
mod guard_link;
mod masked_value;
mod match_spans;
mod prose_answer_value;
mod reference_value;
mod self_named_value;
mod url_credential;

pub use match_spans::scan_match_spans;

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
    PatternDef {
        classifier: "npm-auth-token",
        family: "npm auth token",
        sensitivity: "high",
        reason: "Guard found an npm registry token pattern.",
        pattern: r#"[\"']?\b[A-Za-z0-9_-]*(?:_authToken|npm[_-]?token)\b[\"']?\s*[:=]\s*(?:\"[^\"\r\n]+\"|'[^'\r\n]+'|[^ \t\r\n\"',}]+)"#,
        case_insensitive: true,
        multi_line: true,
    },
    PatternDef {
        classifier: "github-token",
        family: "GitHub token",
        sensitivity: "high",
        reason: "Guard found a GitHub token pattern.",
        pattern: concat!(
            r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github",
            r"_pat_[A-Za-z0-9_]{20,}_[A-Za-z0-9_]{20,})\b"
        ),
        case_insensitive: false,
        multi_line: false,
    },
    PatternDef {
        classifier: "aws-access-key",
        family: "AWS access key",
        sensitivity: "high",
        reason: "Guard found an AWS access key pattern.",
        pattern: r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        case_insensitive: false,
        multi_line: false,
    },
    PatternDef {
        classifier: "openai-api-key",
        family: "OpenAI API key",
        sensitivity: "high",
        reason: "Guard found an OpenAI API key pattern.",
        pattern: r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b",
        case_insensitive: false,
        multi_line: false,
    },
    PatternDef {
        classifier: "anthropic-api-key",
        family: "Anthropic API key",
        sensitivity: "high",
        reason: "Guard found an Anthropic API key pattern.",
        pattern: r"\bsk-ant-api03-[A-Za-z0-9_-]{20,}\b",
        case_insensitive: false,
        multi_line: false,
    },
    PatternDef {
        classifier: "hedera-private-key",
        family: "Hedera private key",
        sensitivity: "critical",
        reason: "Guard found a Hedera private-key-like value.",
        pattern: r#"[\"']?\b[A-Za-z0-9_-]*(?:hedera[_-]?)?(?:operator[_-]?)?private[_-]?key\b[\"']?\s*[:=]\s*(?:\"(?:0x)?[0-9a-f]{64,96}\"|'(?:0x)?[0-9a-f]{64,96}'|(?:0x)?[0-9a-f]{64,96}\b)"#,
        case_insensitive: true,
        multi_line: true,
    },
    PatternDef {
        classifier: "pem-private-key",
        family: "PEM private key",
        sensitivity: "critical",
        reason: "Guard found a PEM private key header.",
        pattern: r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
        case_insensitive: false,
        multi_line: true,
    },
    PatternDef {
        classifier: "generic-bearer-token",
        family: "generic bearer token",
        sensitivity: "medium",
        reason: "Guard found a bearer token pattern.",
        pattern: r"\bbearer\s+[A-Za-z0-9._~+/=-]{16,}\b",
        case_insensitive: true,
        multi_line: true,
    },
    PatternDef {
        classifier: "credential-marker",
        family: "credential assignment",
        sensitivity: "medium",
        reason: "Guard found credential-looking marker text.",
        pattern: r"(?:^|[^a-z0-9])fake[_-]?(?:credential|secret)\b",
        case_insensitive: true,
        multi_line: false,
    },
    PatternDef {
        classifier: "credential-assignment",
        family: "credential assignment",
        sensitivity: "medium",
        reason: "Guard found credential-looking assignment text.",
        // `pass` and `pwd` count only after `_` or `-` (`DB_PASS`, `WEBDAV_PWD`), so
        // `bypass`, `compass`, test tallies (`"pass": 12`) and the shell's
        // `PWD=`/`OLDPWD=` paths stay clean.
        pattern: r#"[\"']?\b[A-Za-z0-9_-]*(?:api[_-]?key|auth[_-]?token|credential|credentials|npm[_-]?token|private[_-]?key|secret|token|password|passwd|passphrase|access[_-]?key|[_-]pass|[_-]pwd)\b[\"']?\s*[:=]\s*(?:(?:get_secret\([^\)\r\n]*\)|\{(?:r|result|response|proc|process)\.(?:stderr|stdout)\}|[fF](?:\"\{[A-Za-z_][A-Za-z0-9_.]*\}\"|'\{[A-Za-z_][A-Za-z0-9_.]*\}'))\s*$|\"[^\"\r\n]+\"|'[^'\r\n]+'|[^ \t\r\n\"',}]+)"#,
        case_insensitive: true,
        multi_line: true,
    },
    PatternDef {
        classifier: "url-credential",
        family: "URL credential",
        sensitivity: "high",
        reason: "Guard found a password inside a URL.",
        // `scheme://user:password@host`, as `git remote -v`, `.git/config`, a
        // database URL or a sync script prints it. `git@host:repo` has no
        // scheme and `ssh://git@host:22/` has no password, so neither matches.
        pattern: r#"\b[a-z][a-z0-9+.-]{1,31}://[^\s:/?#@'"<>]{0,128}:[^\s/?#@"<>]{1,256}@[^\s/?#@'"<>]"#,
        case_insensitive: true,
        multi_line: false,
    },
];

static COMPILED: OnceLock<Vec<Regex>> = OnceLock::new();
static SAMPLE: OnceLock<Regex> = OnceLock::new();
static DOC_SAMPLE: OnceLock<Regex> = OnceLock::new();
static INERT_CODE_EXPRESSION: OnceLock<Regex> = OnceLock::new();
static DECLARED_SAMPLE_VALUE: OnceLock<Regex> = OnceLock::new();
static DEPLOYED_VALUE_MARKER: OnceLock<Regex> = OnceLock::new();

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

/// Values in tests and docs that say outright they are not real, such as
/// `fictional-report-key` or `stub_token`. Delimiters are explicit because
/// `\b` treats `_` as a word character.
fn declared_sample_value_regex() -> &'static Regex {
    DECLARED_SAMPLE_VALUE.get_or_init(|| {
        RegexBuilder::new(
            r"(?:^|[^a-z0-9])(?:fictional|fictitious|bogus|stub|stubbed|mock|mocked|sample|placeholder|fixture|synthetic|redacted|not[-_.]?real)(?:[^a-z0-9]|$)",
        )
        .case_insensitive(true)
        .build()
        .expect("declared sample rule must compile")
    })
}

/// A value that names a deployed environment, such as `fixture-prod-value`,
/// is not treated as inert even when it also carries a sample word.
fn deployed_value_marker_regex() -> &'static Regex {
    DEPLOYED_VALUE_MARKER.get_or_init(|| {
        RegexBuilder::new(r"(?:^|[^a-z0-9])(?:prod|production|live|staging|stage)(?:[^a-z0-9]|$)")
            .case_insensitive(true)
            .build()
            .expect("deployed value rule must compile")
    })
}

fn inert_code_expression_regex() -> &'static Regex {
    INERT_CODE_EXPRESSION.get_or_init(|| {
        Regex::new(
            r#"^(?:get_secret\([^\)\r\n]*\)|\{(?:r|result|response|proc|process)\.(?:stderr|stdout)\}|[fF]"\{[A-Za-z_][A-Za-z0-9_.]*\}"|[fF]'\{[A-Za-z_][A-Za-z0-9_.]*\}')$"#,
        )
        .expect("inert code-expression rule must compile")
    })
}

fn suppressible(classifier: &str) -> bool {
    matches!(
        classifier,
        "credential-assignment" | "generic-bearer-token" | "url-credential"
    )
}

fn has_long_alphanumeric_run(token: &str) -> bool {
    token
        .split(|character: char| !character.is_ascii_alphanumeric())
        .any(|run| run.len() >= 20)
}

fn assignment_value(matched: &str) -> Option<&str> {
    let index = matched.find([':', '='])?;
    let value = matched[index + 1..].trim();
    if value.len() >= 2
        && ((value.starts_with('\'') && value.ends_with('\''))
            || (value.starts_with('"') && value.ends_with('"')))
    {
        return Some(&value[1..value.len() - 1]);
    }
    Some(value)
}

/// Whether a value substitutes something else when it is used, as in
/// `mock-${REAL_SECRET}`, `mock-$REAL`, `mock-$(cat key)`, `f"mock-{key}"`
/// or `` `mock-${key}` ``. Its sample wording then proves nothing.
fn interpolates(value: &str) -> bool {
    value.contains(['{', '`'])
        || value.split('$').skip(1).any(|tail| {
            tail.starts_with(|next: char| next == '(' || next == '_' || next.is_ascii_alphabetic())
        })
}

fn is_sample(
    classifier: &str,
    matched: &str,
    preceding: &str,
    continued: bool,
    rest_of_line: &str,
    suppress_samples: bool,
    documentation_sample_context: bool,
) -> bool {
    if !suppressible(classifier) {
        return false;
    }
    if classifier == "url-credential" {
        // Only a whole-password stand-in carries no secret. Sample wording in
        // the account, host or part of the password (`test:…@`, `@example.com`,
        // `test-Kq7…`) proves nothing.
        return url_credential::password(matched).is_some_and(url_credential::is_placeholder);
    }
    if classifier == "credential-assignment"
        && (field_copy::is_field_copy(matched, rest_of_line)
            || guard_link::is_guard_link(matched, preceding)
            || self_named_value::is_self_named(matched, rest_of_line)
            || assignment_value(matched).is_some_and(|value| {
                inert_code_expression_regex().is_match(value) || masked_value::is_masked(value)
            })
            || reference_value::is_reference(matched, rest_of_line)
            || code_value::is_code_value(matched, rest_of_line)
            || code_expression::is_code_expression(matched, rest_of_line))
    {
        return true;
    }
    if !suppress_samples {
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
    !continued
        && assignment_value(matched).is_some_and(|value| {
            doc_sample_regex().is_match(value)
                || (declared_sample_value_regex().is_match(value)
                    && !interpolates(value)
                    && !deployed_value_marker_regex().is_match(value)
                    && !has_long_alphanumeric_run(value))
        })
}

/// The matches of rule `index` in `text` that are not suppressed as samples.
fn counted_matches<'t>(
    index: usize,
    text: &'t str,
    suppress_samples: bool,
    documentation_sample_context: bool,
) -> impl Iterator<Item = regex::Match<'t>> {
    let classifier = PATTERNS[index].classifier;
    // A prose answer is read here rather than inside `is_sample`, because it
    // needs the line's last credential-shaped token, which this scan resolves
    // once per line.
    let answers = classifier == "credential-assignment";
    let mut line_end = 0;
    let mut last_value = None;
    compiled()[index].find_iter(text).filter(move |matched| {
        if matched.end() > line_end {
            let rest = &text[matched.end()..];
            line_end = matched.end() + rest.find(['\r', '\n']).unwrap_or(rest.len());
            last_value = answers
                .then(|| prose_answer_value::last_value_offset(&text[matched.end()..line_end]))
                .flatten()
                .map(|offset| matched.end() + offset);
        }
        if answers
            && prose_answer_value::is_prose_answer(
                matched.as_str(),
                &text[matched.end()..line_end],
                &text[..matched.start()],
                last_value.is_some_and(|start| start >= matched.end()),
            )
        {
            return false;
        }
        !is_sample(
            classifier,
            matched.as_str(),
            &text[..matched.start()],
            continuation::continues_as_expression(&text[matched.end()..]),
            &text[matched.end()..line_end],
            suppress_samples,
            documentation_sample_context,
        )
    })
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
        let mut matches =
            counted_matches(index, text, suppress_samples, documentation_sample_context);
        if matches.next().is_some() {
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
        assert!(result
            .matches
            .iter()
            .any(|matched| matched.classifier == "github-token"));
        assert!(!format!("{:?}", result.matches).contains(&token));
    }

    #[test]
    fn detects_split_token_across_chunks() {
        let token = github_like_token();
        let split_at = 16.min(token.len());
        let first = format!("prefix {}", &token[..split_at]);
        let second = format!("{} suffix", &token[split_at..]);
        let result = scan_chunks(
            [first.as_str(), second.as_str()],
            true,
            true,
            MAX_SCAN_BYTES,
            None,
        );
        assert!(result
            .matches
            .iter()
            .any(|matched| matched.classifier == "github-token"));
    }

    #[test]
    fn documentation_placeholder_is_suppressed() {
        let result = scan_text(
            "token = placeholder-only",
            false,
            true,
            MAX_SCAN_BYTES,
            None,
        );
        assert!(result.matches.is_empty());
    }

    #[test]
    fn inert_credential_expressions_are_suppressed_during_local_retry() {
        for text in [
            "secret = get_secret('deployment-config')",
            "secret = f\"{config.token}\"",
            "secret: {r.stderr}",
        ] {
            let result = scan_text(text, true, true, MAX_SCAN_BYTES, None);
            assert!(result.matches.is_empty(), "{text:?}");
        }
    }

    #[test]
    fn realistic_medium_credentials_survive_local_retry() {
        for text in [
            "password = example-production-value",
            "password = {user.password}",
            "api_key = {token: \"AIza-realistic-value\"}",
            "password = {r.stdout}real-password",
            "secret = f\"{config.token}\" + \"prod-live-value\"",
            "secret = get_secret(\"deployment-config\") + \"prod-live-value\"",
        ] {
            let result = scan_text(text, true, true, MAX_SCAN_BYTES, None);
            assert!(
                result
                    .matches
                    .iter()
                    .any(|matched| matched.classifier == "credential-assignment"),
                "{text:?}"
            );
        }
    }

    fn credential_assignment(text: &str) -> bool {
        scan_text(text, true, true, MAX_SCAN_BYTES, None)
            .matches
            .iter()
            .any(|matched| matched.classifier == "credential-assignment")
    }

    #[test]
    fn password_names_a_secret_search_looks_for_are_credentials() {
        let value = ["Kq7Xr2", "mWp9Lq4z"].concat();
        for name in [
            "PASSWD",
            "PASSPHRASE",
            "DB_PASS",
            "_PASS",
            "_PWD",
            "SMTP-PASS",
            "WEBDAV_PWD",
            "S3_ACCESS_KEY",
            "accessKey",
        ] {
            for text in [
                format!("{name}={value}"),
                format!("config.env:6:{name}={value}"),
                format!("\"{name}\": \"{value}\""),
            ] {
                assert!(credential_assignment(&text), "{text:?}");
            }
        }
    }

    #[test]
    fn pass_and_pwd_need_a_separator_before_them() {
        for text in [
            "PWD=/home/alice/notes",
            "OLDPWD=/home/alice",
            "bypass=true",
            "compass: north",
            "{\"pass\": 12, \"fail\": 0}",
        ] {
            assert!(!credential_assignment(text), "{text:?}");
        }
    }

    #[test]
    fn declared_sample_values_are_suppressed_in_tests_and_docs() {
        for text in [
            "process.env.EXAMPLE_SERVICE_API_KEY = 'fictional-report-key';",
            "const apiKey = 'stub_token'",
            "password: \"mocked-password\"",
            "secret = synthetic.value.1",
            "token = 'not-real-key'",
        ] {
            let result = scan_text(text, false, true, MAX_SCAN_BYTES, None);
            assert!(result.matches.is_empty(), "{text:?}");
        }
    }

    #[test]
    fn declared_sample_words_do_not_hide_real_looking_values() {
        for text in [
            // Split so repository secret scanners do not read the fixture as a key.
            format!(
                "process.env.EXAMPLE_SERVICE_API_KEY = 'fictional-{}';",
                ["Q9x7Lm2V", "b8Nc4Rt6", "Yp1Zk3"].concat()
            ),
            "const apiKey = 'stubborn-production-key'".to_owned(),
            "password = 'mockingbird-prod-value'".to_owned(),
            "credential = 'fixture-prod-value'".to_owned(),
            "token = 'mock-live-token'".to_owned(),
        ] {
            let result = scan_text(&text, false, true, MAX_SCAN_BYTES, None);
            assert!(
                result
                    .matches
                    .iter()
                    .any(|matched| matched.classifier == "credential-assignment"),
                "{text:?}"
            );
        }
    }

    #[test]
    fn declared_sample_prefixes_of_longer_expressions_are_reported() {
        for text in [
            "password = 'mock-' + real_secret",
            "password = 'mock-' . $real_secret;",
            "password = 'mock-'.$real_secret;",
            "password = \"mock-\"$REAL_SECRET",
            "password = 'mock-' 'real-secret-tail'",
            "password = 'mock-' || real_secret",
            "password = 'fixture-value' + real_secret",
            "const password = 'mock-'\n  + realTail;",
            "const password = 'mock-'\r\n\r\n  .concat(realTail);",
            "api_key = 'mock-' \\\n    'real-secret-tail'",
            "password=\"mock-${REAL_SECRET}\"",
            "password=\"mock-$REAL_SECRET\"",
            "password=\"mock-$(cat key)\"",
        ] {
            let result = scan_text(text, false, true, MAX_SCAN_BYTES, None);
            assert!(
                result
                    .matches
                    .iter()
                    .any(|matched| matched.classifier == "credential-assignment"),
                "{text:?}"
            );
        }
    }

    #[test]
    fn declared_sample_values_ending_a_statement_stay_suppressed() {
        for text in [
            "const apiKey = 'stub_token'.",
            "const apiKey = 'stub_token' && run",
            "call(api_key='stub_token')",
            "{ \"token\": \"mock-token\", \"other\": 1 }",
            "const apiKey = 'stub_token';\nconst other = 1;",
            "api_key: mock-token\n\"next\": 1",
            "password = 'fixture-value'\n",
            "+API_KEY = \"fictional-report-key\"\n+OTHER = 1",
            "password = 'fixture-value'\n...\n",
            "password = 'fixture-value'\n+ next item",
            "password = 'fixture-value'\n  ...",
        ] {
            let result = scan_text(text, false, true, MAX_SCAN_BYTES, None);
            assert!(result.matches.is_empty(), "{text:?}");
        }
    }

    #[test]
    fn declared_sample_words_need_documentation_context() {
        let result = scan_text(
            "process.env.EXAMPLE_SERVICE_API_KEY = 'fictional-report-key';",
            true,
            true,
            MAX_SCAN_BYTES,
            None,
        );
        assert!(result
            .matches
            .iter()
            .any(|matched| matched.classifier == "credential-assignment"));
    }
}

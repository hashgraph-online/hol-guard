//! `redacted_command_tokens` (`local_supply_chain.py` :3267-3268) and its
//! private helper `_redact_command_token` (:4549-4559), including the full
//! `redact_text` pass from `redaction.py` (:194-211 + `_REDACTION_PATTERNS`
//! :40-135) that `local_supply_chain.rs` currently stubs via
//! `redact_text_shim`.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::package_intent_common::redact_package_request_token;

/// `RedactedText` (`redaction.py` :16-34). `original_sha256` is a legacy
/// payload key kept for response-shape compatibility; it stays empty so
/// secret-bearing input never becomes a hash oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedText {
    pub text: String,
    pub count: usize,
    pub classifiers: Vec<String>,
    pub original_sha256: String,
}

impl RedactedText {
    /// `RedactedText.to_dict` (`redaction.py` :29-34). Mirrors the Python
    /// shape: `text` itself is intentionally not part of the dict.
    pub fn to_dict(&self) -> serde_json::Value {
        serde_json::json!({
            "count": self.count,
            "classifiers": self.classifiers,
            "original_sha256": self.original_sha256,
        })
    }
}

// `_REDACTION_PATTERNS` (`redaction.py` :40-135), in application order.
// The `aws-secret-access-key` pattern is handled separately: it uses
// backreferences (`\1`, `\3`) that the `regex` crate cannot express.
static BEARER_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(Bearer)\s+([A-Za-z0-9._\-]{8,})").unwrap());
static OPENAI_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bsk-[A-Za-z0-9_-]{8,}\b").unwrap());
static GITHUB_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bgh[pousr]_[A-Za-z0-9_]{8,}\b").unwrap());
static AWS_ACCESS_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap());
// Relaxed variant of the Python pattern
// r"(?i)(['\"]?)(aws[_-]?secret[_-]?access[_-]?key)\1\s*[:=]\s*(['\"]?)([A-Za-z0-9/+=]{40})\3":
// the `\1`/`\3` backreferences become independent captures and are filtered by
// equality in `subn_aws_secret_access_key`, which is equivalent because the
// relaxed pattern is a strict superset of the original.
static AWS_SECRET_ACCESS_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(['"]?)(aws[_-]?secret[_-]?access[_-]?key)(['"]?)\s*[:=]\s*(['"]?)([A-Za-z0-9/+=]{40})(['"]?)"#,
    )
    .unwrap()
});
static NPM_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?im)\b(_authToken|npm[_ -]?token)\s*[:=]\s*([^\s"',}]+)"#).unwrap()
});
static PYTHON_INDEX_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)\b(index-url|extra-index-url)\s*[:=]\s*(https?://[^@\s]+@[^\s]+)").unwrap()
});
static PRIVATE_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----")
        .unwrap()
});
static SECRET_ENV_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?im)^([ \t]*)([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|KEY|CREDENTIAL)[A-Z0-9_]*)=(.+)$",
    )
    .unwrap()
});
static CONNECTION_ENV_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)^([ \t]*)([A-Z0-9_]*(?:URL|URI|DSN))=([A-Za-z][A-Za-z0-9+.-]*://.+)$")
        .unwrap()
});
static CONNECTION_STRING_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s"',}]+"#)
        .unwrap()
});
static REMOTE_PAIRING_CODE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bHLG-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{6,32}\b").unwrap());

fn apply_pattern(
    text: &mut String,
    classifiers: &mut Vec<&'static str>,
    classifier: &'static str,
    pattern: &Regex,
    replacement: &str,
) {
    let match_count = pattern.find_iter(text).count();
    if match_count == 0 {
        return;
    }
    *text = pattern.replace_all(text, replacement).into_owned();
    classifiers.extend(std::iter::repeat_n(classifier, match_count));
}

/// `pattern.subn` for the `aws-secret-access-key` rule. The original pattern
/// requires the optional quote around the key to pair (`\1`) and the optional
/// quote around the 40-char value to pair (`\3`); the relaxed regex widens
/// each backreference to `(['\"]?)`, and accepted matches are exactly those
/// whose substitute capture groups are equal. A rejected candidate cannot hide
/// a strict match inside its span: its tail is `[A-Za-z0-9/+=]{40}` and the
/// pattern needs `\s*[:=]\s*` plus 40 more value characters, so resuming the
/// scan one char after the rejected start is safe.
fn subn_aws_secret_access_key(input: &str) -> (String, usize) {
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0usize;
    let mut search = 0usize;
    let mut count = 0usize;
    while let Some(caps) = AWS_SECRET_ACCESS_KEY_RE.captures_at(input, search) {
        let m = caps.get(0).unwrap();
        let g4s = caps.get(4).map(|g| g.as_str()).unwrap_or("");
        let g6s = caps.get(6).map(|g| g.as_str()).unwrap_or("");
        let pairs_match = caps.get(1).map(|g| g.as_str()).unwrap_or("")
            == caps.get(3).map(|g| g.as_str()).unwrap_or("")
            && (g4s.is_empty() || g4s == g6s);
        let match_end = if g4s.is_empty() {
            caps.get(5).unwrap().end()
        } else {
            m.end()
        };
        if pairs_match {
            out.push_str(&input[cursor..m.start()]);
            // Python replacement r"\1\2\1=\3*****\3": the separator is
            // normalized to "=" regardless of the matched ":" or "=".
            let g1 = caps.get(1).unwrap().as_str();
            let g2 = caps.get(2).unwrap().as_str();
            let g4 = caps.get(4).unwrap().as_str();
            out.push_str(g1);
            out.push_str(g2);
            out.push_str(g1);
            out.push('=');
            out.push_str(g4);
            out.push_str("*****");
            out.push_str(g4);
            cursor = match_end;
            search = match_end;
            count += 1;
        } else {
            let first_char_len = input[m.start()..]
                .chars()
                .next()
                .map(char::len_utf8)
                .unwrap_or(1);
            search = m.start() + first_char_len;
        }
    }
    out.push_str(&input[cursor..]);
    (out, count)
}

/// `redact_text` (`redaction.py` :194-211): applies every redaction pattern in
/// sequence, tracking the classifiers that fired (ordered, deduplicated like
/// `tuple(dict.fromkeys(classifiers))`) and the total substitution count.
pub fn redact_text(value: &str) -> RedactedText {
    let mut text = value.to_owned();
    let mut classifiers: Vec<&'static str> = Vec::new();

    apply_pattern(
        &mut text,
        &mut classifiers,
        "bearer-token",
        &BEARER_TOKEN_RE,
        "${1} *****",
    );
    apply_pattern(
        &mut text,
        &mut classifiers,
        "openai-token",
        &OPENAI_TOKEN_RE,
        "sk-*****",
    );
    apply_pattern(
        &mut text,
        &mut classifiers,
        "github-token",
        &GITHUB_TOKEN_RE,
        "gh*****",
    );
    apply_pattern(
        &mut text,
        &mut classifiers,
        "aws-access-key",
        &AWS_ACCESS_KEY_RE,
        "AKIA****************",
    );
    {
        let (next, match_count) = subn_aws_secret_access_key(&text);
        if match_count > 0 {
            text = next;
            classifiers.extend(std::iter::repeat_n("aws-secret-access-key", match_count));
        }
    }
    apply_pattern(
        &mut text,
        &mut classifiers,
        "npm-token",
        &NPM_TOKEN_RE,
        "${1}=*****",
    );
    apply_pattern(
        &mut text,
        &mut classifiers,
        "python-index-token",
        &PYTHON_INDEX_TOKEN_RE,
        "${1}=*****",
    );
    apply_pattern(
        &mut text,
        &mut classifiers,
        "private-key",
        &PRIVATE_KEY_RE,
        "*****",
    );
    apply_pattern(
        &mut text,
        &mut classifiers,
        "secret-env",
        &SECRET_ENV_RE,
        "${1}${2}=*****",
    );
    apply_pattern(
        &mut text,
        &mut classifiers,
        "connection-env",
        &CONNECTION_ENV_RE,
        "${1}${2}=*****",
    );
    apply_pattern(
        &mut text,
        &mut classifiers,
        "connection-string",
        &CONNECTION_STRING_RE,
        "*****",
    );
    apply_pattern(
        &mut text,
        &mut classifiers,
        "remote-pairing-code",
        &REMOTE_PAIRING_CODE_RE,
        "HLG-******",
    );

    let count = classifiers.len();
    let mut seen = BTreeSet::new();
    let unique_classifiers: Vec<String> = classifiers
        .into_iter()
        .filter(|classifier| seen.insert(*classifier))
        .map(str::to_owned)
        .collect();
    RedactedText {
        text,
        count,
        classifiers: unique_classifiers,
        original_sha256: String::new(),
    }
}

const SENSITIVE_KEY_FRAGMENTS: [&str; 5] = ["token", "secret", "api_key", "api-key", "password"];

/// `_redact_command_token` (`local_supply_chain.py` :4549-4559).
fn redact_command_token(token: &str) -> String {
    let token = redact_package_request_token(token);
    if let Some(eq) = token.find('=') {
        let key = &token[..eq];
        if SENSITIVE_KEY_FRAGMENTS
            .iter()
            .any(|fragment| key.to_lowercase().contains(fragment))
        {
            return format!("{key}=*****");
        }
    }
    if let Some(colon) = token.find(':') {
        let key = &token[..colon];
        if SENSITIVE_KEY_FRAGMENTS
            .iter()
            .any(|fragment| key.to_lowercase().contains(fragment))
        {
            return format!("{key}: *****");
        }
    }
    redact_text(&token).text
}

/// `redacted_command_tokens` (`local_supply_chain.py` :3267-3268).
pub fn redacted_command_tokens(command: &[String]) -> Vec<String> {
    command
        .iter()
        .map(|token| redact_command_token(token))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(command: &[&str]) -> Vec<String> {
        command.iter().map(|token| token.to_string()).collect()
    }

    /// Oracle: `redacted_command_tokens` from `local_supply_chain.py`.
    #[test]
    fn oracle_vectors() {
        let a40 = "A".repeat(40);
        // Secret-bearing inputs are assembled at runtime so no literal secret
        // exists in the source tree.
        let akia = format!("AKIA{}", "0".repeat(16));
        let pem_begin = concat!("-----BEGIN RSA PRIVATE", " KEY-----");
        let pem_end = concat!("-----END RSA PRIVATE", " KEY-----");
        let pem_one_line = format!("{pem_begin}ZHVtbXk={pem_end}");
        let pem_multi_line = format!("{pem_begin}\nQUJD\n{pem_end}");
        let pem_no_end = "-----BEGIN PRIVATE KEY-----\nno end";
        let pem_wrapped = format!("pre {pem_one_line} post");

        let cases: Vec<(Vec<String>, Vec<String>)> = vec![
            (tokens(&["echo", "hello"]), tokens(&["echo", "hello"])),
            (vec![], vec![]),
            (tokens(&[""]), tokens(&[""])),
            (tokens(&["API_KEY=abc123"]), tokens(&["API_KEY=*****"])),
            (tokens(&["api-key: secretval"]), tokens(&["api-key: *****"])),
            (
                tokens(&["Authorization=Bearer abcdefghij"]),
                tokens(&["Authorization=Bearer *****"]),
            ),
            (
                tokens(&["Authorization: Bearer abcdefghij"]),
                tokens(&["Authorization: Bearer *****"]),
            ),
            (tokens(&["bearer abcdefghij"]), tokens(&["bearer *****"])),
            (tokens(&["bearer abc"]), tokens(&["bearer abc"])),
            (
                tokens(&["https://user:pass@example.com/pkg?x=1#y"]),
                tokens(&["https://example.com/pkg"]),
            ),
            (
                tokens(&["git+https://user:pw@github.com/org/repo.git"]),
                tokens(&["git+https://github.com/org/repo.git"]),
            ),
            (
                tokens(&["git+ssh://git@github.com/org/repo.git?x=1"]),
                tokens(&["git+ssh://github.com/org/repo.git"]),
            ),
            (
                tokens(&["https:example.com"]),
                tokens(&["https:<redacted-source>"]),
            ),
            (
                tokens(&["http:\\evil"]),
                tokens(&["http:<redacted-source>"]),
            ),
            (tokens(&["--token"]), tokens(&["--token"])),
            (tokens(&["password=hunter2"]), tokens(&["password=*****"])),
            (
                tokens(&["AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]),
                tokens(&["AWS_SECRET_ACCESS_KEY=*****"]),
            ),
            (
                tokens(&["aws_secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]),
                tokens(&["aws_secret_access_key: *****"]),
            ),
            (
                tokens(&["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]),
                tokens(&["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]),
            ),
            // The `aws-secret-access-key` pattern only survives the `=`/`:`
            // key branches when the sensitive key is not the first `key`.
            (
                tokens(&[&format!("x=1 \"aws_secret_access_key\"=\"{a40}\"")]),
                tokens(&["x=1 \"aws_secret_access_key\"=\"*****\""]),
            ),
            (
                tokens(&[&format!("x=1 'aws_secret_access_key'='{a40}'")]),
                tokens(&["x=1 'aws_secret_access_key'='*****'"]),
            ),
            // Mismatched quote pairing (\1 != \3) must not redact.
            (
                tokens(&[&format!("x=1 \"aws_secret_access_key\"='{a40}\"")]),
                tokens(&[&format!("x=1 \"aws_secret_access_key\"='{a40}\"")]),
            ),
            // Quote only on the value side still pairs (\3 == \3).
            (
                tokens(&[&format!("x=1 aws_secret_access_key=\"{a40}\"")]),
                tokens(&["x=1 aws_secret_access_key=\"*****\""]),
            ),
            (
                tokens(&[&format!("prefix;aws_secret_access_key={a40}")]),
                tokens(&["prefix;aws_secret_access_key=*****"]),
            ),
            (
                tokens(&["foo sk-abcdefghijklmnop bar"]),
                tokens(&["foo sk-***** bar"]),
            ),
            (tokens(&["SK-ABCDEFGHIJ"]), tokens(&["sk-*****"])),
            (tokens(&["sk-1234567"]), tokens(&["sk-1234567"])),
            (tokens(&["ghp_abcdefghijklmnop"]), tokens(&["gh*****"])),
            (tokens(&["gho_ABCDEFGH"]), tokens(&["gh*****"])),
            (tokens(&[&akia]), tokens(&["AKIA****************"])),
            (
                tokens(&[&format!("x={akia}")]),
                tokens(&["x=AKIA****************"]),
            ),
            (tokens(&[&format!("key={akia}")]), tokens(&["key=*****"])),
            (
                tokens(&["akiaiosfodnn7example"]),
                tokens(&["akiaiosfodnn7example"]),
            ),
            (tokens(&["HLG-ABC234"]), tokens(&["HLG-******"])),
            (tokens(&["hlg-abc234"]), tokens(&["HLG-******"])),
            (tokens(&["HLG-ABC2"]), tokens(&["HLG-ABC2"])),
            (tokens(&["HLG-ABC234I"]), tokens(&["HLG-ABC234I"])),
            (
                tokens(&["DATABASE_URL=postgres://u:p@host/db"]),
                tokens(&["DATABASE_URL=*****"]),
            ),
            (tokens(&["mongodb+srv://u:p@h/d"]), tokens(&["*****"])),
            (
                tokens(&["//registry/:_authToken=abc"]),
                tokens(&["//registry/:_authToken=*****"]),
            ),
            (
                tokens(&["index-url=https://user:pw@pypi.example.com/simple"]),
                tokens(&["index-url=https://pypi.example.com/simple"]),
            ),
            // sanitize_url strips userinfo before the python-index-token
            // pattern can fire: the key branch never matches because the
            // sanitized token keeps the original "extra-index-url" key.
            (
                tokens(&["extra-index-url: https://u:p@h/"]),
                tokens(&["extra-index-url: https://h/"]),
            ),
            (tokens(&[pem_one_line.as_str()]), tokens(&["*****"])),
            (tokens(&[pem_multi_line.as_str()]), tokens(&["*****"])),
            (tokens(&[pem_no_end]), tokens(&[pem_no_end])),
            (tokens(&[pem_wrapped.as_str()]), tokens(&["pre ***** post"])),
            (
                tokens(&["MY_PASSWORD: foo"]),
                tokens(&["MY_PASSWORD: *****"]),
            ),
            (tokens(&["x=1"]), tokens(&["x=1"])),
            (
                tokens(&["https://example.com/path?query=1"]),
                tokens(&["https://example.com/path"]),
            ),
            (tokens(&["x=token: abc"]), tokens(&["x=token: *****"])),
            (
                tokens(&["plain", "SECRET_KEY=abc", "mysql://u:p@h/d", "npm i lodash"]),
                tokens(&["plain", "SECRET_KEY=*****", "*****", "npm i lodash"]),
            ),
            (tokens(&["TOKEN"]), tokens(&["TOKEN"])),
            (
                tokens(&["REDIS_URL: redis://h"]),
                tokens(&["REDIS_URL: *****"]),
            ),
            (tokens(&["a=b:c"]), tokens(&["a=b:c"])),
            (tokens(&["a:b=c"]), tokens(&["a:b=c"])),
            (tokens(&["token=abc"]), tokens(&["token=*****"])),
            (tokens(&["x=1 token=abc"]), tokens(&["x=1 token=abc"])),
            (tokens(&["foo\ntoken=abc"]), tokens(&["foo\ntoken=*****"])),
            (
                tokens(&["FOO_URL=not-a-url"]),
                tokens(&["FOO_URL=not-a-url"]),
            ),
            (tokens(&["FOO_URI=https://h"]), tokens(&["FOO_URI=*****"])),
            (tokens(&["MY_API-KEY: z"]), tokens(&["MY_API-KEY: *****"])),
        ];

        for (input, expected) in cases {
            assert_eq!(
                redacted_command_tokens(&input),
                expected,
                "input: {input:?}"
            );
        }
    }

    /// Oracle: `redact_text` metadata (count/classifiers/original_sha256).
    #[test]
    fn redact_text_metadata() {
        let redacted = redact_text("ghp_aaaaaaaa gho_bbbbbbbb");
        assert_eq!(redacted.text, "gh***** gh*****");
        assert_eq!(redacted.count, 2);
        assert_eq!(redacted.classifiers, vec!["github-token".to_string()]);
        assert_eq!(redacted.original_sha256, "");

        let redacted = redact_text("x");
        assert_eq!(redacted.text, "x");
        assert_eq!(redacted.count, 0);
        assert!(redacted.classifiers.is_empty());
        assert_eq!(redacted.original_sha256, "");

        let redacted = redact_text("sk-aaaaaaaa bearer abcdefgh");
        assert_eq!(redacted.text, "sk-***** bearer *****");
        assert_eq!(redacted.count, 2);
        assert_eq!(
            redacted.classifiers,
            vec!["bearer-token".to_string(), "openai-token".to_string()]
        );

        let redacted = redact_text("AWS_KEY=1\nGH=ghp_aaaaaaaa");
        assert_eq!(redacted.text, "AWS_KEY=*****\nGH=gh*****");
        assert_eq!(redacted.count, 2);
        assert_eq!(
            redacted.classifiers,
            vec!["github-token".to_string(), "secret-env".to_string()]
        );
    }
}

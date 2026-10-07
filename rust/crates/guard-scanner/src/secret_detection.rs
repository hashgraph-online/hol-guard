//! Context-aware leaked-secret detection for HOL Guard.
//!
//! Port of `codex_plugin_scanner.guard.secrets.secret_detection` (RTM-032).
//! The runtime is deliberately local, deterministic, and dependency-free beyond
//! the shared `regex`/`hmac`/`sha2`/`serde` crates. It combines strong provider
//! formats with contextual scoring for generic credentials, entropy/rarity
//! signals, and conservative sample suppression.
//!
//! Security invariants preserved from the Python implementation:
//! - public finding payloads never contain the raw candidate secret;
//! - fingerprints are HMACs and require an explicit caller-owned key;
//! - no network or LLM call is made by detection;
//! - generic findings require contextual evidence and are suppressed in obvious
//!   documentation/test fixtures unless the candidate has a strong provider
//!   format.

use hmac::{Hmac, Mac};
use regex::{Regex, RegexBuilder};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::fmt;
use std::sync::LazyLock;

type HmacSha256 = Hmac<Sha256>;

const DETECTOR_VERSION: &str = "guard-secrets-v1";
const GENERIC_CANDIDATE_POLICY_VERSION: &str = "credential-expression-filter-v2";

/// `max_findings` default mirroring `scan_secret_text(..., max_findings=200)`.
pub const DEFAULT_MAX_FINDINGS: usize = 200;

// Python `re` flag integers captured verbatim for `detector_version` parity:
// plain `re.compile` on a `str` pattern reports UNICODE(32); MULTILINE adds 8;
// IGNORECASE adds 2; the assignment rule compiles with `(?im)` -> 42.
const FLAG_UNICODE: u32 = 32;
const FLAG_MULTILINE_UNICODE: u32 = 40;
const FLAG_IGNORECASE_UNICODE: u32 = 34;
const FLAG_IGNORECASE_MULTILINE_UNICODE: u32 = 42;

/// Python source of `_ASSIGNMENT`, used verbatim in `detector_version` material.
/// The compiled Rust equivalent cannot reuse `(?P=quote)` backreferences, so the
/// compiled pattern below expands the quoted/unquoted arms explicitly.
const ASSIGNMENT_PATTERN_SOURCE: &str = r#"(?im)(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,80})\s*[:=]\s*(?P<quote>[\"']?)(?P<secret>[^\s\"',}{]{12,256})(?P=quote)"#;

static SAMPLE_WORDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)(?:example|sample|dummy|fake|fixture|placeholder|changeme|replace[_-]?me|",
        r"redacted|synthetic|mock(?:ed)?|canary|not[_-]?real|invalid[_-]?",
        r"(?:key|token|secret|password)?|your[_-]?(?:api[_-]?)?",
        r"(?:key|token|secret|password)|test[_-]?(?:key|token|secret|password))",
    ))
    .expect("SAMPLE_WORDS is a static literal")
});
static COMMON_PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)^(?:p@?ssw0rd(?:1234?|[!@#$%^&*]+)?|password(?:1234?|[!@#$%^&*]+)?|",
        r"(?:super|my|your|replace|change|invalid|fake|dummy|sample|test|fixture|not[_-]?real)",
        r"[_-](?:api[_-]?)?(?:secret|token|password|key)(?:[_-].*)?)$",
    ))
    .expect("COMMON_PLACEHOLDER is a static literal")
});
static CREDENTIAL_KEYWORDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)(?:api[_-]?key|access[_-]?key|auth[_-]?token|bearer|credential|password|passwd|",
        r"private[_-]?key|secret|token|webhook|client[_-]?secret)",
    ))
    .expect("CREDENTIAL_KEYWORDS is a static literal")
});
static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    // Equivalent to `(?im)` + the three capture arms of `_ASSIGNMENT`; the
    // `(?P=quote)` backreference is expanded into distinct named groups so the
    // regex crate (no backreference support) can compile it.
    Regex::new(
        r#"(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,80})\s*[:=]\s*(?:(?P<quote>")(?P<secret>[^\s"',}{]{12,256})"|(?P<quote1>')(?P<secret_sq>[^\s"',}{]{12,256})'|(?P<secret_uq>[^\s"',}{]{12,256}))"#,
    )
    .expect("ASSIGNMENT is a static literal")
});

const CODE_REFERENCE_PREFIXES: &[&str] = &[
    "config.",
    "context.",
    "crypto.",
    "data.",
    "deno.env.",
    "env.",
    "headers.",
    "import.meta.env.",
    "local.",
    "module.",
    "os.environ",
    "os.getenv",
    "params.",
    "payload.",
    "process.env.",
    "request.",
    "response.",
    "secret.",
    "secrets.",
    "self.",
    "settings.",
    "this.",
    "values.",
    "var.",
    "vault.",
];

static CODE_MEMBER_REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\??\.[A-Za-z_$][A-Za-z0-9_$]*)+$")
        .expect("CODE_MEMBER_REFERENCE is a static literal")
});
static CODE_CALL_REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\??\.[A-Za-z_$][A-Za-z0-9_$]*)*\s*\(")
        .expect("CODE_CALL_REFERENCE is a static literal")
});
static CODE_IDENTIFIER_REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z_$][A-Za-z0-9_$]*$")
        .expect("CODE_IDENTIFIER_REFERENCE is a static literal")
});
static INTERPOLATED_REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:\$\{|\$\(|\{\{|<%|%\{|@\{)")
        .expect("INTERPOLATED_REFERENCE is a static literal")
});
static SHELL_VARIABLE_REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
    RegexBuilder::new(r"^\$(?:(?:env|global|local|private|script):)?[A-Za-z_][A-Za-z0-9_]*$")
        .case_insensitive(true)
        .build()
        .expect("SHELL_VARIABLE_REFERENCE is a static literal")
});
static CODE_COORDINATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9_.@/+~-]+:[A-Za-z0-9_.@/+~:-]+$")
        .expect("CODE_COORDINATE is a static literal")
});
static TEST_FIXTURE_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)(?:\bdescribe\s*\(|\bit\s*\(|\btest\s*\(|\bexpect\s*\(|\bassert\b|",
        r"\bmock(?:ed)?\b|\bfixture\b|\bsample\b|\bfake\b|\bsynthetic\b|\bcanary\b|",
        r"\bredact(?:ed|ion)?\b|\bsanitiz(?:e|ed|ation)\b|\bmask(?:ed|ing)?\b|",
        r"\bscrub(?:bed|bing)?\b|\bnot[_ -]?real\b|\binvalid\b)",
    ))
    .expect("TEST_FIXTURE_CONTEXT is a static literal")
});
static SAMPLE_PATH_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)(?:^|[._-])(?:test|tests|spec|fixture|fixtures|example|examples|sample|samples|",
        r"mock|mocks|demo|benchmark|scenario|scenarios|proof|canary)(?:[._-]|$)",
    ))
    .expect("SAMPLE_PATH_TOKEN is a static literal")
});

const PUBLIC_CLIENT_CONFIG_BASENAMES: &[&str] =
    &["google-services.json", "googleservice-info.plist"];

const NON_SECRET_NAME_TERMINALS: &[&str] = &[
    "config",
    "configs",
    "count",
    "counts",
    "endpoint",
    "endpoints",
    "event",
    "events",
    "field",
    "fields",
    "header",
    "headers",
    "id",
    "ids",
    "input",
    "inputs",
    "kind",
    "label",
    "labels",
    "limit",
    "limits",
    "mode",
    "name",
    "names",
    "options",
    "output",
    "outputs",
    "path",
    "paths",
    "pattern",
    "payload",
    "prefix",
    "provider",
    "record",
    "records",
    "regex",
    "request",
    "response",
    "result",
    "results",
    "row",
    "rows",
    "schema",
    "schemas",
    "scope",
    "scopes",
    "size",
    "sizes",
    "state",
    "status",
    "suffix",
    "table",
    "tables",
    "type",
    "types",
    "uri",
    "url",
    "version",
    "versions",
];

const SECRET_ASSIGNMENT_SUFFIXES: &[&str] = &[
    "access_key",
    "access_token",
    "api_key",
    "auth_token",
    "bearer_token",
    "client_secret",
    "credential",
    "credentials",
    "database_password",
    "encryption_key",
    "password",
    "passwd",
    "private_key",
    "refresh_token",
    "secret",
    "secret_key",
    "session_token",
    "signing_secret",
    "smtp_password",
    "token",
    "webhook",
    "webhook_secret",
    "webhook_token",
];

const CODE_SUFFIXES: &[&str] = &[
    ".bash", ".cjs", ".cs", ".dart", ".go", ".gradle", ".java", ".js", ".jsx", ".kt", ".kts",
    ".lua", ".mjs", ".php", ".ps1", ".py", ".rb", ".rs", ".scala", ".sh", ".svelte", ".swift",
    ".ts", ".tsx", ".vue", ".zsh",
];

static DATABASE_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://[^\s:/@]{1,128}:(?P<secret>[^\s/@]{6,256})@[^\s]+",
    )
    .expect("DATABASE_URL is a static literal")
});
static BASIC_AUTH_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bhttps?://[^\s:/@]{1,128}:(?P<secret>[^\s/@]{8,256})@[^\s]+")
        .expect("BASIC_AUTH_URL is a static literal")
});
static JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?P<secret>eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b")
        .expect("JWT is a static literal")
});

const DOC_SEGMENTS: &[&str] = &[
    "docs",
    "doc",
    "documentation",
    "examples",
    "example",
    "fixtures",
    "fixture",
    "samples",
    "sample",
    "test",
    "tests",
    "spec",
    "specs",
    "__tests__",
    "__fixtures__",
];
const DOC_SUFFIXES: &[&str] = &[".md", ".mdx", ".rst", ".adoc", ".txt"];
const HIGH_SIGNAL_BASENAMES: &[&str] = &[
    ".env",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    "credentials",
    "secrets.yml",
    "secrets.yaml",
    "terraform.tfvars",
];
const HIGH_SIGNAL_SEGMENTS: &[&str] = &[".aws", ".ssh", ".gnupg"];

/// Ordered secret detection rule. Field order mirrors the Python dataclass;
/// `pattern_source` and `pattern_flags` carry the exact Python pattern text and
/// `re` flag integer needed for byte-identical `detector_version` material.
#[derive(Debug, Clone)]
pub struct SecretRule {
    pub rule_id: &'static str,
    pub family: &'static str,
    pub severity: &'static str,
    pub validation: &'static str,
    pub strong_format: bool,
    pub description: &'static str,
    pub pattern: Regex,
    pub pattern_source: &'static str,
    pub pattern_flags: u32,
}

#[allow(clippy::too_many_arguments)] // Mirrors the Python dataclass constructor field order.
fn secret_rule(
    rule_id: &'static str,
    family: &'static str,
    severity: &'static str,
    pattern_source: &'static str,
    pattern_flags: u32,
    validation: &'static str,
    strong_format: bool,
    description: &'static str,
    pattern: Option<&'static LazyLock<Regex>>,
) -> SecretRule {
    SecretRule {
        rule_id,
        family,
        severity,
        validation,
        strong_format,
        description,
        pattern: pattern.map_or_else(
            || Regex::new(pattern_source).expect("SECRET_RULES patterns are static literals"),
            |shared| (**shared).clone(),
        ),
        pattern_source,
        pattern_flags,
    }
}

/// Provider-format rules in Python tuple order; iteration order drives finding
/// emit order and dedup identity.
pub static SECRET_RULES: LazyLock<Vec<SecretRule>> = LazyLock::new(|| {
    vec![
        secret_rule(
            "github-token",
            "GitHub token",
            "critical",
            r"\b(?P<secret>(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255}))\b",
            FLAG_UNICODE,
            "github",
            true,
            "GitHub personal, OAuth, user, server, refresh, or fine-grained token.",
            None,
        ),
        secret_rule(
            "gitlab-token",
            "GitLab token",
            "critical",
            r"\b(?P<secret>glpat-[A-Za-z0-9_-]{20,255})\b",
            FLAG_UNICODE,
            "gitlab",
            true,
            "GitLab personal/project/group access token.",
            None,
        ),
        secret_rule(
            "aws-access-key",
            "AWS access key ID",
            "high",
            r"\b(?P<secret>(?:AKIA|ASIA)[0-9A-Z]{16})\b",
            FLAG_UNICODE,
            "aws",
            true,
            "AWS long-lived or STS access key identifier.",
            None,
        ),
        secret_rule(
            "slack-token",
            "Slack token",
            "critical",
            r"\b(?P<secret>xox[baprs]-[A-Za-z0-9-]{10,255})\b",
            FLAG_UNICODE,
            "slack",
            true,
            "Slack bot, app, user, refresh, or service token.",
            None,
        ),
        secret_rule(
            "slack-webhook",
            "Slack incoming webhook",
            "critical",
            r"(?P<secret>https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{24,255})",
            FLAG_UNICODE,
            "slack",
            true,
            "Slack incoming webhook URL.",
            None,
        ),
        secret_rule(
            "stripe-secret-key",
            "Stripe secret key",
            "critical",
            r"\b(?P<secret>(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,255})\b",
            FLAG_UNICODE,
            "stripe",
            true,
            "Stripe secret or restricted API key.",
            None,
        ),
        secret_rule(
            "openai-api-key",
            "OpenAI API key",
            "critical",
            r"\b(?P<secret>sk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{20,255})\b",
            FLAG_UNICODE,
            "openai",
            true,
            "OpenAI project/service/account API key.",
            None,
        ),
        secret_rule(
            "anthropic-api-key",
            "Anthropic API key",
            "critical",
            r"\b(?P<secret>sk-ant-[A-Za-z0-9_-]{20,255})\b",
            FLAG_UNICODE,
            "anthropic",
            true,
            "Anthropic API key.",
            None,
        ),
        secret_rule(
            "huggingface-token",
            "Hugging Face token",
            "high",
            r"\b(?P<secret>hf_[A-Za-z0-9]{24,255})\b",
            FLAG_UNICODE,
            "huggingface",
            true,
            "Hugging Face user or organization token.",
            None,
        ),
        secret_rule(
            "npm-token",
            "npm access token",
            "critical",
            r"\b(?P<secret>npm_[A-Za-z0-9]{30,255})\b",
            FLAG_UNICODE,
            "npm",
            true,
            "npm granular or automation access token.",
            None,
        ),
        secret_rule(
            "pypi-token",
            "PyPI API token",
            "critical",
            r"\b(?P<secret>pypi-[A-Za-z0-9_-]{24,255})\b",
            FLAG_UNICODE,
            "pypi",
            true,
            "PyPI scoped API token.",
            None,
        ),
        secret_rule(
            "google-api-key",
            "Google API key",
            "high",
            r"\b(?P<secret>AIza[0-9A-Za-z_-]{35})\b",
            FLAG_UNICODE,
            "google",
            true,
            "Google Cloud/Firebase API key.",
            None,
        ),
        secret_rule(
            "sendgrid-api-key",
            "SendGrid API key",
            "critical",
            r"\b(?P<secret>SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b",
            FLAG_UNICODE,
            "sendgrid",
            true,
            "SendGrid API key.",
            None,
        ),
        secret_rule(
            "pem-private-key",
            "PEM private key",
            "critical",
            r"(?P<secret>-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)",
            FLAG_MULTILINE_UNICODE,
            "none",
            true,
            "Private-key material in PEM/OpenSSH-style form.",
            None,
        ),
        secret_rule(
            "database-url-password",
            "Database URL password",
            "critical",
            r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://[^\s:/@]{1,128}:(?P<secret>[^\s/@]{6,256})@[^\s]+",
            FLAG_IGNORECASE_UNICODE,
            "none",
            false,
            "Password embedded in a database connection URL.",
            Some(&DATABASE_URL),
        ),
        secret_rule(
            "basic-auth-url-password",
            "Basic-auth URL password",
            "high",
            r"(?i)\bhttps?://[^\s:/@]{1,128}:(?P<secret>[^\s/@]{8,256})@[^\s]+",
            FLAG_IGNORECASE_UNICODE,
            "none",
            false,
            "Credential embedded in an HTTP(S) URL.",
            Some(&BASIC_AUTH_URL),
        ),
        secret_rule(
            "jwt-token",
            "JWT bearer token",
            "high",
            r"\b(?P<secret>eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b",
            FLAG_UNICODE,
            "none",
            false,
            "JWT-like bearer token in credential context.",
            Some(&JWT),
        ),
    ]
});

/// Rule metadata for the synthetic `credential-assignment` rule constructed
/// inside `scan_secret_text` (not part of `SECRET_RULES`).
struct RuleMeta {
    rule_id: &'static str,
    family: &'static str,
    severity: &'static str,
    validation: &'static str,
    strong_format: bool,
}

impl RuleMeta {
    fn of(rule: &SecretRule) -> Self {
        RuleMeta {
            rule_id: rule.rule_id,
            family: rule.family,
            severity: rule.severity,
            validation: rule.validation,
            strong_format: rule.strong_format,
        }
    }
}

const GENERIC_RULE_META: RuleMeta = RuleMeta {
    rule_id: "credential-assignment",
    family: "Contextual credential assignment",
    severity: "high",
    validation: "none",
    strong_format: false,
};

/// One detected secret. `candidate` is excluded from `Debug` and `PartialEq`,
/// mirroring `field(repr=False, compare=False)` on the Python dataclass so the
/// raw secret can never leak through formatting or equality.
#[derive(Clone)]
pub struct SecretFinding {
    pub rule_id: &'static str,
    pub family: &'static str,
    pub severity: &'static str,
    pub confidence: &'static str,
    pub confidence_score: f64,
    pub line: usize,
    pub path: String,
    pub source: String,
    pub commit: Option<String>,
    pub validation: &'static str,
    pub entropy: f64,
    pub context_reasons: Vec<&'static str>,
    pub candidate: String,
}

impl fmt::Debug for SecretFinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretFinding")
            .field("rule_id", &self.rule_id)
            .field("family", &self.family)
            .field("severity", &self.severity)
            .field("confidence", &self.confidence)
            .field("confidence_score", &self.confidence_score)
            .field("line", &self.line)
            .field("path", &self.path)
            .field("source", &self.source)
            .field("commit", &self.commit)
            .field("validation", &self.validation)
            .field("entropy", &self.entropy)
            .field("context_reasons", &self.context_reasons)
            .finish_non_exhaustive()
    }
}

impl PartialEq for SecretFinding {
    fn eq(&self, other: &Self) -> bool {
        self.rule_id == other.rule_id
            && self.family == other.family
            && self.severity == other.severity
            && self.confidence == other.confidence
            && self.confidence_score == other.confidence_score
            && self.line == other.line
            && self.path == other.path
            && self.source == other.source
            && self.commit == other.commit
            && self.validation == other.validation
            && self.entropy == other.entropy
            && self.context_reasons == other.context_reasons
    }
}

/// Raised when a fingerprint is requested without a key, mirroring the Python
/// `ValueError("secret fingerprint key must not be empty")`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyFingerprintKeyError;

impl fmt::Display for EmptyFingerprintKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("secret fingerprint key must not be empty")
    }
}

impl Error for EmptyFingerprintKeyError {}

impl SecretFinding {
    /// Tenant/caller-scoped HMAC of the finding, never exposing candidate bytes.
    pub fn fingerprint(&self, key: &[u8]) -> Result<String, EmptyFingerprintKeyError> {
        if key.is_empty() {
            return Err(EmptyFingerprintKeyError);
        }
        let material = format!("{}\u{0}{}", self.rule_id, self.candidate);
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
        mac.update(material.as_bytes());
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    /// Public, non-sensitive payload. Field order matches the Python dict
    /// literal exactly; `fingerprint` is omitted unless a key is supplied.
    pub fn to_public_dict(
        &self,
        fingerprint_key: Option<&[u8]>,
    ) -> Result<PublicFinding, EmptyFingerprintKeyError> {
        let fingerprint = match fingerprint_key {
            Some(key) => Some(self.fingerprint(key)?),
            None => None,
        };
        Ok(PublicFinding {
            rule_id: self.rule_id,
            family: self.family,
            severity: self.severity,
            confidence: self.confidence,
            confidence_score: round4(self.confidence_score),
            line: self.line,
            path: &self.path,
            source: &self.source,
            commit: self.commit.as_deref(),
            validation: self.validation,
            entropy: round4(self.entropy),
            context_reasons: &self.context_reasons,
            fingerprint,
        })
    }
}

/// Serializable form of `SecretFinding.to_public_dict`. Field order is the
/// Python dict insertion order; `serde_json` emits struct fields in
/// declaration order so the JSON key order matches Python's.
#[derive(Debug, Clone, Serialize)]
pub struct PublicFinding<'a> {
    pub rule_id: &'a str,
    pub family: &'a str,
    pub severity: &'a str,
    pub confidence: &'a str,
    pub confidence_score: f64,
    pub line: usize,
    pub path: &'a str,
    pub source: &'a str,
    pub commit: Option<&'a str>,
    pub validation: &'a str,
    pub entropy: f64,
    pub context_reasons: &'a [&'static str],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// Serializable form of `SecretScanSummary.to_public_dict`.
#[derive(Debug, Clone, Serialize)]
pub struct PublicScanSummary<'a> {
    pub schema: &'static str,
    pub detector_version: &'a str,
    pub finding_count: usize,
    pub findings: Vec<PublicFinding<'a>>,
}

/// Scan result: detector version plus findings sorted by
/// `(path, line, rule_id, commit or "")`.
#[derive(Debug, Clone, PartialEq)]
pub struct SecretScanSummary {
    pub detector_version: String,
    pub findings: Vec<SecretFinding>,
}

impl SecretScanSummary {
    /// Public, non-sensitive payload matching Python `to_public_dict`.
    pub fn to_public_dict(
        &self,
        fingerprint_key: Option<&[u8]>,
    ) -> Result<PublicScanSummary<'_>, EmptyFingerprintKeyError> {
        let mut findings = Vec::with_capacity(self.findings.len());
        for finding in &self.findings {
            findings.push(finding.to_public_dict(fingerprint_key)?);
        }
        Ok(PublicScanSummary {
            schema: "guard-secret-scan.v1",
            detector_version: &self.detector_version,
            finding_count: findings.len(),
            findings,
        })
    }
}

/// Public, non-sensitive detector catalog metadata (Python `TypedDict`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecretRuleCatalogEntry {
    pub rule_id: &'static str,
    pub family: &'static str,
    pub severity: &'static str,
    pub validation: &'static str,
    pub strong_format: bool,
    pub description: &'static str,
}

/// `round(x, 4)` parity: Python uses banker's rounding while `f64::round`
/// rounds half away from zero. Formatting to four decimals uses the correctly
/// rounded decimal representation and matches `round()` on all non-tie inputs.
fn round4(value: f64) -> f64 {
    format!("{value:.4}").parse::<f64>().unwrap_or(0.0)
}

/// Detector version digest, byte-identical to the Python implementation: the
/// SHA-256 hex digest of the rule material truncated to 16 hex characters.
pub fn detector_version() -> String {
    let mut material_parts: Vec<String> = SECRET_RULES
        .iter()
        .map(|rule| {
            format!(
                "{}|{}|{}|{}|{}",
                rule.rule_id,
                rule.severity,
                rule.validation,
                rule.pattern_source,
                rule.pattern_flags
            )
        })
        .collect();
    material_parts.push(format!(
        "credential-assignment|{ASSIGNMENT_PATTERN_SOURCE}|{FLAG_IGNORECASE_MULTILINE_UNICODE}|{GENERIC_CANDIDATE_POLICY_VERSION}"
    ));
    let digest = hex::encode(Sha256::digest(material_parts.join("\n").as_bytes()));
    format!("{DETECTOR_VERSION}:{digest:.16}")
}

/// Non-sensitive catalog of every detector rule, with the synthetic
/// `credential-assignment` entry appended last (Python parity).
pub fn secret_rule_catalog() -> Vec<SecretRuleCatalogEntry> {
    let mut entries: Vec<SecretRuleCatalogEntry> = SECRET_RULES
        .iter()
        .map(|rule| SecretRuleCatalogEntry {
            rule_id: rule.rule_id,
            family: rule.family,
            severity: rule.severity,
            validation: rule.validation,
            strong_format: rule.strong_format,
            description: rule.description,
        })
        .collect();
    entries.push(SecretRuleCatalogEntry {
        rule_id: "credential-assignment",
        family: "Contextual credential assignment",
        severity: "high",
        validation: "none",
        strong_format: false,
        description: "High-entropy credential assignment accepted only with contextual evidence.",
    });
    entries
}

/// Compensated summation matching CPython 3.12+ `sum()` over floats
/// (Neumaier variant). Required for bit-parity with `shannon_entropy`.
fn python_sum(terms: impl Iterator<Item = f64>) -> f64 {
    let mut total = 0.0;
    let mut compensation = 0.0;
    for term in terms {
        let next = total + term;
        if total.abs() >= term.abs() {
            compensation += (total - next) + term;
        } else {
            compensation += (term - next) + total;
        }
        total = next;
    }
    total + compensation
}

/// Shannon entropy in bits per character. Matches Python exactly, including
/// `-0.0` for single-character inputs. Counts are kept in first-occurrence
/// order to mirror Python's insertion-ordered dict iteration.
pub fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts: Vec<(char, usize)> = Vec::new();
    let mut length = 0usize;
    for character in value.chars() {
        length += 1;
        match counts.iter_mut().find(|(seen, _)| *seen == character) {
            Some((_, count)) => *count += 1,
            None => counts.push((character, 1)),
        }
    }
    let length = length as f64;
    -python_sum(counts.iter().map(|(_, count)| {
        let share = *count as f64 / length;
        share * share.log2()
    }))
}

fn rarity_score(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let entropy_component = (shannon_entropy(value) / 5.2).min(1.0);
    // Mirrors `re.search(r"[a-z]")` etc.: ASCII classes, not Unicode.
    let classes = usize::from(value.chars().any(|c| c.is_ascii_lowercase()))
        + usize::from(value.chars().any(|c| c.is_ascii_uppercase()))
        + usize::from(value.chars().any(|c| c.is_ascii_digit()))
        + usize::from(value.chars().any(|c| !c.is_ascii_alphanumeric()));
    let class_component = (classes as f64 / 3.0).min(1.0);
    let length_component = (value.chars().count().saturating_sub(12) as f64 / 36.0).min(1.0);
    ((entropy_component * 0.55) + (class_component * 0.2) + (length_component * 0.25)).min(1.0)
}

fn normalized_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    path.replace('\\', "/").trim().to_lowercase()
}

/// `PurePosixPath.parts`: non-empty components, `.` entries collapsed.
fn posix_parts(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect()
}

/// `PurePosixPath.name`: last component, or `""` for empty/`/`/`..`.
fn posix_name(path: &str) -> &str {
    posix_parts(path).last().copied().unwrap_or("")
}

/// `PurePosixPath.suffix`: final `.`-delimited extension, `""` for dotfiles
/// and names without a dot.
fn posix_suffix(path: &str) -> &str {
    let name = posix_name(path);
    match name.rfind('.') {
        Some(index) if index > 0 => &name[index..],
        _ => "",
    }
}

fn path_is_documentation(path: &str) -> bool {
    let normalized = normalized_path(path);
    if normalized.is_empty() {
        return false;
    }
    let parts = posix_parts(&normalized);
    parts.iter().any(|part| DOC_SEGMENTS.contains(part))
        || DOC_SUFFIXES.contains(&posix_suffix(&normalized))
}

fn path_is_sample_fixture(path: &str) -> bool {
    let normalized = normalized_path(path);
    if normalized.is_empty() {
        return false;
    }
    let parts = posix_parts(&normalized);
    if parts.iter().any(|part| DOC_SEGMENTS.contains(part)) {
        return true;
    }
    SAMPLE_PATH_TOKEN.is_match(posix_name(&normalized))
}

fn path_is_public_client_config(path: &str) -> bool {
    PUBLIC_CLIENT_CONFIG_BASENAMES.contains(&posix_name(&normalized_path(path)))
}

fn path_is_high_signal(path: &str) -> bool {
    let normalized = normalized_path(path);
    if normalized.is_empty() {
        return false;
    }
    let basename = posix_name(&normalized);
    if basename == ".env" || basename.starts_with(".env.") {
        return true;
    }
    HIGH_SIGNAL_BASENAMES.contains(&basename)
        || posix_parts(&normalized)
            .iter()
            .any(|part| HIGH_SIGNAL_SEGMENTS.contains(part))
}

/// Mirrors `_character_class_count`: Python `str.islower`/`isupper`/`isdigit`/
/// `isalnum` are Unicode-aware, so this deliberately uses the Unicode variants
/// (unlike `rarity_score`, which mirrors ASCII regex classes).
fn character_class_count(value: &str) -> usize {
    usize::from(value.chars().any(|c| c.is_lowercase()))
        + usize::from(value.chars().any(|c| c.is_uppercase()))
        + usize::from(value.chars().any(|c| c.is_numeric()))
        + usize::from(value.chars().any(|c| !c.is_alphanumeric()))
}

fn largest_character_share(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts: BTreeMap<char, usize> = BTreeMap::new();
    for character in value.chars() {
        *counts.entry(character).or_insert(0) += 1;
    }
    let largest = counts.values().copied().max().unwrap_or(0);
    largest as f64 / value.chars().count() as f64
}

/// `_obvious_sample` (secret_detection.py:641-651): strip the candidate,
/// unwrap bracket placeholders, then apply the Python ordering exactly —
/// `fullmatch` on the unwrapped value, `search` on the *value* (not context),
/// and only then the sample-context gate on `context`/`path`.
fn obvious_sample(candidate: &str, context: &str, path: &str) -> bool {
    let value = candidate.trim();
    let unwrapped = value.trim_matches(|c| "<>[]{}()".contains(c));
    if COMMON_PLACEHOLDER.is_match(unwrapped) || SAMPLE_WORDS.is_match(value) {
        return true;
    }
    let has_sample_context = SAMPLE_WORDS.is_match(context) || path_is_sample_fixture(path);
    if !has_sample_context {
        return false;
    }
    rarity_score(value) < 0.62
        || value.chars().count() < 20
        || largest_character_share(value) >= 0.4
}

fn normalized_assignment_name(name: &str) -> String {
    static LOWER_UPPER: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"([a-z0-9])([A-Z])").expect("static literal"));
    static NON_ALNUM: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"[^A-Za-z0-9]+").expect("static literal"));
    let snake = LOWER_UPPER.replace_all(name, "${1}_${2}");
    NON_ALNUM
        .replace_all(&snake, "_")
        .trim_matches('_')
        .to_lowercase()
}

fn assignment_name_likely_holds_secret(name: &str) -> bool {
    let normalized = normalized_assignment_name(name);
    if normalized.is_empty() {
        return false;
    }
    if ["indexnow_", "next_public_", "public_"]
        .iter()
        .any(|prefix| normalized.starts_with(prefix))
    {
        return false;
    }
    let terminal = normalized.rsplit('_').next().unwrap_or("");
    if NON_SECRET_NAME_TERMINALS.contains(&terminal) {
        return false;
    }
    SECRET_ASSIGNMENT_SUFFIXES.iter().any(|suffix| {
        normalized == *suffix
            || (normalized.len() > suffix.len()
                && normalized.ends_with(suffix)
                && normalized.as_bytes()[normalized.len() - suffix.len() - 1] == b'_')
    })
}

fn candidate_is_indirect_reference(candidate: &str, quoted: bool, path: &str) -> bool {
    let value = candidate.trim();
    if value.is_empty() {
        return true;
    }
    let lowered = value.to_lowercase();
    if ["false", "none", "null", "true", "undefined"].contains(&lowered.as_str()) {
        return true;
    }
    if INTERPOLATED_REFERENCE.is_match(value) {
        return true;
    }
    if SHELL_VARIABLE_REFERENCE.is_match(value) {
        return true;
    }
    if CODE_REFERENCE_PREFIXES
        .iter()
        .any(|prefix| lowered.starts_with(prefix))
    {
        return true;
    }
    if CODE_CALL_REFERENCE.is_match(value) {
        return true;
    }
    if CODE_MEMBER_REFERENCE.is_match(value) {
        return true;
    }
    let normalized = normalized_path(path);
    let suffix = posix_suffix(&normalized);
    if !quoted && CODE_COORDINATE.is_match(value) {
        return true;
    }
    if quoted {
        return false;
    }
    if ["=>", "??", "||", "&&", "::"]
        .iter()
        .any(|operator| value.contains(operator))
    {
        return true;
    }
    if value.chars().any(|c| "()[]{};`<>:".contains(c)) {
        return true;
    }
    if !CODE_SUFFIXES.contains(&suffix) || !CODE_IDENTIFIER_REFERENCE.is_match(value) {
        return false;
    }
    let digit_count = value.chars().filter(|c| c.is_ascii_digit()).count();
    value.chars().next().is_some_and(|c| c.is_lowercase()) && digit_count <= 1
}

fn generic_candidate_is_plausible(
    candidate: &str,
    // Kept for signature parity with the Python helper; unused there and here.
    _quoted: bool,
    path: &str,
    context: &str,
) -> bool {
    static SCHEME_PREFIX: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9+.-]*://").expect("static literal"));
    static HEX_TOKEN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[A-Fa-f0-9]{32,}$").expect("static literal"));
    let value = candidate.trim();
    if value.is_empty() || obvious_sample(value, context, path) {
        return false;
    }
    let lowered = value.to_lowercase();
    if SCHEME_PREFIX.is_match(&lowered) {
        return false;
    }
    if value.contains('/') || value.contains('\\') {
        return false;
    }
    if largest_character_share(value) >= 0.55 {
        return false;
    }
    let entropy = shannon_entropy(value);
    let classes = character_class_count(value);
    let normalized = normalized_path(path);
    let suffix = posix_suffix(&normalized);
    let value_len = value.chars().count();
    if path_is_high_signal(path) {
        return value_len >= 12 && (entropy >= 3.2 || classes >= 3);
    }
    if HEX_TOKEN.is_match(value) {
        return true;
    }
    if CODE_SUFFIXES.contains(&suffix) {
        return value_len >= 20 && ((classes >= 3 && entropy >= 3.65) || entropy >= 4.2);
    }
    value_len >= 16 && rarity_score(value) >= 0.58
}

fn surrounding_context(text: &str, match_start: usize) -> &str {
    // Python slices characters; stay on UTF-8 boundaries.
    let prefix = &text[..match_start];
    let start = prefix
        .char_indices()
        .rev()
        .nth(239)
        .map_or(0, |(index, _)| index);
    let end = text[match_start..]
        .char_indices()
        .nth(240)
        .map_or(text.len(), |(index, _)| match_start + index);
    &text[start..end]
}

fn provider_match_is_fixture(
    rule: &SecretRule,
    candidate: &str,
    text: &str,
    match_start: usize,
    path: &str,
) -> bool {
    if rule.rule_id == "google-api-key" && path_is_public_client_config(path) {
        return true;
    }
    let context = surrounding_context(text, match_start);
    let unwrapped = candidate.trim().trim_matches(|c| "<>[]{}()".contains(c));
    let explicit_placeholder =
        COMMON_PLACEHOLDER.is_match(unwrapped) || SAMPLE_WORDS.is_match(candidate);
    if explicit_placeholder && (path_is_sample_fixture(path) || SAMPLE_WORDS.is_match(context)) {
        return true;
    }
    if path_is_high_signal(path) {
        return false;
    }
    path_is_sample_fixture(path) && TEST_FIXTURE_CONTEXT.is_match(context)
}

fn confidence_label(score: f64) -> &'static str {
    if score >= 0.84 {
        "high"
    } else if score >= 0.64 {
        "medium"
    } else {
        "low"
    }
}

fn context_score(
    candidate: &str,
    path: &str,
    line_text: &str,
    strong_format: bool,
) -> (f64, Vec<&'static str>) {
    let mut score = if strong_format { 0.9 } else { 0.3 };
    let mut reasons: Vec<&'static str> = vec![if strong_format {
        "provider-format"
    } else {
        "contextual-candidate"
    }];
    let rarity = rarity_score(candidate);
    score += rarity * if strong_format { 0.08 } else { 0.34 };
    if rarity >= 0.72 {
        reasons.push("high-token-rarity");
    }
    if CREDENTIAL_KEYWORDS.is_match(line_text) {
        score += 0.22;
        reasons.push("credential-name-context");
    }
    if path_is_high_signal(path) {
        score += 0.14;
        reasons.push("sensitive-file-context");
    }
    if path_is_documentation(path) {
        score -= if strong_format { 0.08 } else { 0.28 };
        reasons.push("documentation-context");
    }
    if SAMPLE_WORDS.is_match(line_text) {
        score -= if strong_format { 0.1 } else { 0.32 };
        reasons.push("sample-marker-context");
    }
    (score.clamp(0.0, 1.0), reasons)
}

fn line_number(text: &str, match_start: usize) -> usize {
    text[..match_start].bytes().filter(|b| *b == b'\n').count() + 1
}

fn line_text(text: &str, match_start: usize) -> String {
    let start = text[..match_start].rfind('\n').map_or(0, |index| index + 1);
    let end = text[match_start..]
        .find('\n')
        .map_or(text.len(), |index| match_start + index);
    text[start..end].chars().take(1024).collect()
}

#[allow(clippy::too_many_arguments)] // Mirrors the Python keyword arguments verbatim.
fn finding_from_match(
    rule: &RuleMeta,
    candidate: &str,
    text: &str,
    match_start: usize,
    path: &str,
    source: &str,
    commit: Option<&str>,
    provider_rule: Option<&SecretRule>,
) -> Option<SecretFinding> {
    let line_text = line_text(text, match_start);
    if rule.strong_format {
        // Provider fixtures need the full SecretRule for `rule_id`-specific
        // suppression; only provider rules take this branch.
        if let Some(rule) = provider_rule {
            if provider_match_is_fixture(rule, candidate, text, match_start, path) {
                return None;
            }
        }
    } else if obvious_sample(candidate, &line_text, path) {
        return None;
    }
    let (score, reasons) = context_score(candidate, path, &line_text, rule.strong_format);
    let minimum_score = if rule.strong_format { 0.56 } else { 0.64 };
    if score < minimum_score {
        return None;
    }
    Some(SecretFinding {
        rule_id: rule.rule_id,
        family: rule.family,
        severity: rule.severity,
        confidence: confidence_label(score),
        confidence_score: score,
        line: line_number(text, match_start),
        path: path.to_string(),
        source: source.to_string(),
        commit: commit.map(str::to_string),
        validation: rule.validation,
        entropy: shannon_entropy(candidate),
        context_reasons: reasons,
        candidate: candidate.to_string(),
    })
}

fn finding_sort_key(finding: &SecretFinding) -> (&str, usize, &str, &str) {
    (
        finding.path.as_str(),
        finding.line,
        finding.rule_id,
        finding.commit.as_deref().unwrap_or(""),
    )
}

/// Scan text for leaked credentials without serializing candidate bytes.
/// Mirrors `scan_secret_text(text, *, path="", source="text", commit=None,
/// max_findings=200)`.
pub fn scan_secret_text(
    text: &str,
    path: &str,
    source: &str,
    commit: Option<&str>,
    max_findings: usize,
) -> SecretScanSummary {
    if text.is_empty() {
        return SecretScanSummary {
            detector_version: detector_version(),
            findings: Vec::new(),
        };
    }
    let bounded_max = max_findings.clamp(1, 10_000);
    let mut findings: Vec<SecretFinding> = Vec::new();
    let mut seen: HashSet<(&'static str, usize, String)> = HashSet::new();

    for rule in SECRET_RULES.iter() {
        for captures in rule.pattern.captures_iter(text) {
            let candidate = captures
                .name("secret")
                .map(|m| m.as_str())
                .unwrap_or_else(|| {
                    captures
                        .get(0)
                        .expect("whole match always present")
                        .as_str()
                });
            let match_start = captures.get(0).expect("whole match always present").start();
            let finding = finding_from_match(
                &RuleMeta::of(rule),
                candidate,
                text,
                match_start,
                path,
                source,
                commit,
                Some(rule),
            );
            let Some(finding) = finding else { continue };
            if !seen.insert((finding.rule_id, finding.line, finding.candidate.clone())) {
                continue;
            }
            findings.push(finding);
            if findings.len() >= bounded_max {
                findings.sort_by(|a, b| finding_sort_key(a).cmp(&finding_sort_key(b)));
                return SecretScanSummary {
                    detector_version: detector_version(),
                    findings,
                };
            }
        }
    }

    // Generic assignments are intentionally evaluated after provider formats so
    // the structured detector wins when both identify the same token.
    let provider_candidates: HashSet<String> = findings
        .iter()
        .map(|finding| finding.candidate.clone())
        .collect();
    for captures in ASSIGNMENT.captures_iter(text) {
        let candidate = captures
            .name("secret")
            .or_else(|| captures.name("secret_sq"))
            .or_else(|| captures.name("secret_uq"))
            .map(|m| m.as_str());
        let Some(candidate) = candidate else { continue };
        if provider_candidates.contains(candidate) {
            continue;
        }
        let name = captures.name("name").map(|m| m.as_str()).unwrap_or("");
        if !assignment_name_likely_holds_secret(name) {
            continue;
        }
        let quoted = captures.name("quote").is_some() || captures.name("quote1").is_some();
        let match_start = captures.get(0).expect("whole match always present").start();
        let whole_match = captures
            .get(0)
            .expect("whole match always present")
            .as_str();
        if candidate_is_indirect_reference(candidate, quoted, path) {
            continue;
        }
        if !generic_candidate_is_plausible(candidate, quoted, path, whole_match) {
            continue;
        }
        let finding = finding_from_match(
            &GENERIC_RULE_META,
            candidate,
            text,
            match_start,
            path,
            source,
            commit,
            None,
        );
        let Some(finding) = finding else { continue };
        if !seen.insert((finding.rule_id, finding.line, finding.candidate.clone())) {
            continue;
        }
        findings.push(finding);
        if findings.len() >= bounded_max {
            break;
        }
    }

    findings.sort_by(|a, b| finding_sort_key(a).cmp(&finding_sort_key(b)));
    SecretScanSummary {
        detector_version: detector_version(),
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Built in parts so a literal JWT never appears in source.
    fn jwt_fixture() -> String {
        let parts = [
            "eyJ",
            "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9",
            "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ",
        ];
        [parts[0], parts[1], ".", parts[2], ".", parts[3]].concat()
    }

    fn fixture_text() -> String {
        [
            "Line one has nothing.",
            "GH_TOKEN = ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345",
            &format!("token = {}", jwt_fixture()),
            "db = postgres://admin:Sup3rSecretPassw0rd99@db.internal:5432/app",
            r#"api_key = "xK9mQ2vL8nP4wR7tY1uI6oP3aS5dFgHj""#,
        ]
        .join("\n")
    }

    #[test]
    fn detector_version_matches_python() {
        // Oracle: python3 detector_version() -> guard-secrets-v1:1d8dc93ef4fc2a04
        assert_eq!(detector_version(), "guard-secrets-v1:1d8dc93ef4fc2a04");
    }

    #[test]
    fn shannon_entropy_matches_python() {
        assert_eq!(shannon_entropy("").to_bits(), 0.0f64.to_bits());
        // Python reports -0.0 for a single repeated character class.
        assert_eq!(shannon_entropy("a").to_bits(), (-0.0f64).to_bits());
        assert_eq!(shannon_entropy("aaaa").to_bits(), (-0.0f64).to_bits());
        assert_eq!(
            shannon_entropy("sk-test-abc123XYZ").to_bits(),
            3.7345216647797512f64.to_bits()
        );
        assert_eq!(
            shannon_entropy("ABCDEFGHIJKLMNOP").to_bits(),
            4.0f64.to_bits()
        );
    }

    #[test]
    fn rarity_score_matches_python() {
        assert_eq!(rarity_score("").to_bits(), 0.0f64.to_bits());
        assert_eq!(
            rarity_score("aaaaaaaaaaaaaaaaaaaaaaaa").to_bits(),
            0.15f64.to_bits()
        );
        assert_eq!(
            rarity_score("Tr0ub4dor&3ExampleKey123").to_bits(),
            0.741838982448071f64.to_bits()
        );
        assert_eq!(
            rarity_score("correcthorsebatterystaple").to_bits(),
            0.5127369260552326f64.to_bits()
        );
        assert_eq!(
            rarity_score("xK9mQ2vL8nP4wR7tY1uI6oP3aS5dFgHj").to_bits(),
            0.8611244658119659f64.to_bits()
        );
    }

    #[test]
    fn catalog_has_18_entries_with_python_order() {
        let catalog = secret_rule_catalog();
        assert_eq!(catalog.len(), 18);
        assert_eq!(
            serde_json::to_value(&catalog[0]).unwrap(),
            serde_json::json!({
                "rule_id": "github-token",
                "family": "GitHub token",
                "severity": "critical",
                "validation": "github",
                "strong_format": true,
                "description": "GitHub personal, OAuth, user, server, refresh, or fine-grained token.",
            })
        );
        assert_eq!(
            serde_json::to_value(&catalog[13]).unwrap(),
            serde_json::json!({
                "rule_id": "pem-private-key",
                "family": "PEM private key",
                "severity": "critical",
                "validation": "none",
                "strong_format": true,
                "description": "Private-key material in PEM/OpenSSH-style form.",
            })
        );
        assert_eq!(
            serde_json::to_value(&catalog[17]).unwrap(),
            serde_json::json!({
                "rule_id": "credential-assignment",
                "family": "Contextual credential assignment",
                "severity": "high",
                "validation": "none",
                "strong_format": false,
                "description": "High-entropy credential assignment accepted only with contextual evidence.",
            })
        );
    }

    #[test]
    fn scan_fixture_matches_python_findings() {
        let summary = scan_secret_text(
            &fixture_text(),
            "config/prod.env",
            "working_tree",
            None,
            200,
        );
        assert_eq!(summary.findings.len(), 4);
        assert_eq!(
            summary.detector_version,
            "guard-secrets-v1:1d8dc93ef4fc2a04"
        );

        let github = &summary.findings[0];
        assert_eq!(github.rule_id, "github-token");
        assert_eq!(github.line, 2);
        assert_eq!(github.confidence, "high");
        assert_eq!(github.confidence_score.to_bits(), 1.0f64.to_bits());
        assert_eq!(github.entropy.to_bits(), 5.0588138903312005f64.to_bits());
        assert_eq!(
            github.context_reasons,
            [
                "provider-format",
                "high-token-rarity",
                "credential-name-context"
            ]
        );
        assert_eq!(
            github.fingerprint(b"oracle-key").unwrap(),
            "b018734dfa08a0099c84c484d37b473f5a14095e14a647584993f1b2c6d9a100"
        );

        let jwt = &summary.findings[1];
        assert_eq!(jwt.rule_id, "jwt-token");
        assert_eq!(jwt.line, 3);
        assert_eq!(jwt.confidence, "high");
        assert_eq!(jwt.confidence_score.to_bits(), 0.86f64.to_bits());
        assert_eq!(jwt.entropy.to_bits(), 5.53607171214771f64.to_bits());
        assert_eq!(
            jwt.fingerprint(b"oracle-key").unwrap(),
            "0d05f8b0554b142fc7af91c080f121b17fdf0c412a39eee0d6cbd1559e981d29"
        );

        let db = &summary.findings[2];
        assert_eq!(db.rule_id, "database-url-password");
        assert_eq!(db.line, 4);
        assert_eq!(db.confidence, "medium");
        assert_eq!(
            db.confidence_score.to_bits(),
            0.7453623311020845f64.to_bits()
        );
        assert_eq!(db.entropy.to_bits(), 3.7849418274376427f64.to_bits());

        let generic = &summary.findings[3];
        assert_eq!(generic.rule_id, "credential-assignment");
        assert_eq!(generic.line, 5);
        assert_eq!(generic.confidence, "medium");
        assert_eq!(
            generic.confidence_score.to_bits(),
            0.8127823183760684f64.to_bits()
        );
        assert_eq!(generic.entropy.to_bits(), 4.9375f64.to_bits());
    }

    #[test]
    fn public_dict_matches_python_key_order_and_rounding() {
        let summary = scan_secret_text(
            &fixture_text(),
            "config/prod.env",
            "working_tree",
            None,
            200,
        );
        let public = summary.to_public_dict(Some(b"oracle-key")).unwrap();
        let json = serde_json::to_string(&public).unwrap();
        let expected = concat!(
            r#"{"schema":"guard-secret-scan.v1","detector_version":"guard-secrets-v1:1d8dc93ef4fc2a04","#,
            r#""finding_count":4,"findings":[{"rule_id":"github-token","family":"GitHub token","#,
            r#""severity":"critical","confidence":"high","confidence_score":1.0,"line":2,"#,
            r#""path":"config/prod.env","source":"working_tree","commit":null,"validation":"github","#,
            r#""entropy":5.0588,"context_reasons":["provider-format","high-token-rarity","#,
            r#""credential-name-context"],"fingerprint":"b018734dfa08a0099c84c484d37b473f5a14095e14a647584993f1b2c6d9a100"},"#,
        );
        assert!(json.starts_with(expected), "mismatch: {json}");
        // Without a key, `fingerprint` is absent (not null).
        let no_key = serde_json::to_string(&summary.to_public_dict(None).unwrap()).unwrap();
        assert!(!no_key.contains("fingerprint"));
        // An explicitly empty key is an error, mirroring the Python ValueError.
        assert_eq!(
            summary.findings[0].fingerprint(b""),
            Err(EmptyFingerprintKeyError)
        );
        assert!(summary.to_public_dict(Some(b"")).is_err());
    }

    #[test]
    fn assignment_name_heuristic_matches_python() {
        let cases: &[(&str, bool)] = &[
            ("api_key", true),
            ("API_SECRET", true),
            ("next_public_token", false),
            ("password_count", false),
            ("TOKEN", true),
            ("public_api_key", false),
            ("secret_key_id", false),
            ("db_password", true),
            ("webhook_url", false),
            ("smtpPassword", true),
            ("authToken", true),
        ];
        for (name, expected) in cases {
            assert_eq!(
                assignment_name_likely_holds_secret(name),
                *expected,
                "name={name}"
            );
        }
        assert_eq!(normalized_assignment_name("myDBPassword"), "my_dbpassword");
        assert_eq!(normalized_assignment_name("weird--name__x"), "weird_name_x");
    }

    #[test]
    fn obvious_sample_matches_python() {
        assert!(obvious_sample(
            "example_token_abc",
            "token = example_token_abc",
            ""
        ));
        assert!(obvious_sample("p@ssw0rd", "password=p@ssw0rd", ""));
        assert!(!obvious_sample(
            "xK9mQ2vL8nP4wR7tY1uI6oP3aS5dFgHj",
            "secret=xK9mQ2vL8nP4wR7tY1uI6oP3aS5dFgHj",
            "config/prod.env"
        ));
        assert!(!obvious_sample(
            "xK9mQ2vL8nP4wR7tY1uI6oP3aS5dFgHj",
            "secret=xK9mQ2vL8nP4wR7tY1uI6oP3aS5dFgHj",
            ""
        ));
        assert!(obvious_sample("short", "key=short", "tests/fixtures/x.env"));
        assert!(obvious_sample(
            "aaaaaaaaaaaaaaaaaaaaaaaa",
            "key=aaaaaaaaaaaaaaaaaaaaaaaa",
            "docs/sample.txt"
        ));
        // Python `_obvious_sample` does NOT early-true on a leading digit or
        // interior whitespace; those were spurious Rust-only suppressions.
        assert!(!obvious_sample(
            "1X9kkkkkkkkkkkkkk",
            "password = 1X9kkkkkkkkkkkkkk",
            "config/prod.env"
        ));
        assert!(!obvious_sample(
            "9digitsLeadingSecret99",
            "token = 9digitsLeadingSecret99",
            ""
        ));
        // SAMPLE_WORDS matches `context` only in the sample-context gate, and
        // `value` only for the early-true search — not swapped.
        assert!(!obvious_sample(
            "xK9mQ2vL8nP4wR7tY1uI6oP3aS5dFgHj",
            "secret = xK9mQ2vL8nP4wR7tY1uI6oP3aS5dFgHj",
            "src/prod.rs"
        ));
        // Bracket-wrapped placeholder still hits the fullmatch-on-unwrapped arm.
        assert!(obvious_sample("<placeholder_secret>", "key = x", ""));
        // Empty candidate: no early-true — falls to the context gate (False here).
        assert!(!obvious_sample("", "key = xK9mQ2vL8nP4wR7", ""));
    }

    #[test]
    fn fixture_suppression_and_high_signal_paths_match_python() {
        let token_line = "expect(x).toBe(ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345)";
        // Test/fixture context suppresses the strong-format finding.
        let suppressed = scan_secret_text(token_line, "tests/x.ts", "working_tree", None, 200);
        assert!(suppressed.findings.is_empty());
        // A high-signal path overrides fixture suppression.
        let kept = scan_secret_text(token_line, ".env", "working_tree", None, 200);
        assert_eq!(kept.findings.len(), 1);
        assert_eq!(kept.findings[0].rule_id, "github-token");
        assert_eq!(
            kept.findings[0].confidence_score.to_bits(),
            1.0f64.to_bits()
        );
        assert_eq!(
            kept.findings[0].context_reasons,
            [
                "provider-format",
                "high-token-rarity",
                "sensitive-file-context"
            ]
        );

        // Generic assignment in a high-signal path survives with oracle score.
        let generic = scan_secret_text(
            r#"api_key = "xK9mQ2vL8nP4wR7tY1uI6oP3aS5dFgHj""#,
            ".env",
            "staged",
            None,
            200,
        );
        assert_eq!(generic.findings.len(), 1);
        let finding = &generic.findings[0];
        assert_eq!(finding.rule_id, "credential-assignment");
        assert_eq!(finding.confidence, "high");
        assert_eq!(
            finding.confidence_score.to_bits(),
            0.9527823183760684f64.to_bits()
        );
        assert_eq!(finding.entropy.to_bits(), 4.9375f64.to_bits());
        assert_eq!(finding.source, "staged");
        assert_eq!(
            finding.context_reasons,
            [
                "contextual-candidate",
                "high-token-rarity",
                "credential-name-context",
                "sensitive-file-context"
            ]
        );

        // Docs/sample path suppresses the generic finding entirely.
        let doc = scan_secret_text(
            r#"api_key = "xK9mQ2vL8nP4wR7tY1uI6oP3aS5dFgHj""#,
            "docs/example.md",
            "working_tree",
            None,
            200,
        );
        assert!(doc.findings.is_empty());

        // Indirect environment-variable references never produce findings.
        let env_var = scan_secret_text(
            "api_key = ${MY_API_KEY_FROM_ENV}",
            ".env",
            "working_tree",
            None,
            200,
        );
        assert!(env_var.findings.is_empty());

        // max_findings bounds the result even mid-scan.
        let many = (0..10)
            .map(|i| format!("k{i} ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0{i:02}45"))
            .collect::<Vec<_>>()
            .join("\n");
        let capped = scan_secret_text(&many, "a.env", "working_tree", None, 3);
        assert_eq!(capped.findings.len(), 3);
    }

    #[test]
    fn empty_text_and_dedup_match_python() {
        let empty = scan_secret_text("", "x.env", "text", None, 200);
        assert!(empty.findings.is_empty());
        let dup =
            "key1 ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345\nkey2 ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345";
        let summary = scan_secret_text(dup, "a.env", "text", None, 200);
        assert_eq!(summary.findings.len(), 2);
        assert_eq!(summary.findings[0].line, 1);
        assert_eq!(summary.findings[1].line, 2);
    }
}

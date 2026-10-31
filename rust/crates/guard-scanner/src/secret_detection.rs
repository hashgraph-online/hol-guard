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
use std::cell::OnceCell;
use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::fmt;
use std::sync::LazyLock;
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

/// How the scan tells two candidates apart without keeping either one.
///
/// Deduplication only ever asks whether it has seen these exact bytes before,
/// and a digest answers that. Keying on the candidate itself would put a second
/// copy of every secret in a set that lives as long as the scan does.
pub(crate) type CandidateDigest = [u8; 32];

pub(crate) fn candidate_digest(candidate: &str) -> CandidateDigest {
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&Sha256::digest(candidate.as_bytes()));
    digest
}

const DETECTOR_VERSION: &str = "guard-secrets-v1";
const GENERIC_CANDIDATE_POLICY_VERSION: &str = "credential-expression-filter-v2";

/// `max_findings` default mirroring `scan_secret_text(..., max_findings=200)`.
pub const DEFAULT_MAX_FINDINGS: usize = 200;

/// Most findings the detector will return from a single text.
///
/// This sits one above `repository_scanner::MAX_FINDINGS_CEILING`, the most a
/// caller's own `max_findings` can be. A scanner that has filled its budget
/// cannot tell a file that ended exactly on the cap from one that held more, so
/// it asks for one finding past its budget and reads the extra as the cut. A
/// caller sitting on the ceiling has to be able to ask for that one too, which
/// is what the headroom here is for; clamping it away is what let a repository
/// scanned at the ceiling report complete coverage over a file that was cut.
pub const MAX_FINDINGS_PER_TEXT: usize = 10_001;

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
/// How many provider rules the retired Python detector published.
///
/// Rules added since then append after these, so the leading slice stays the
/// set Python hashed into `guard-secrets-v1:1d8dc93ef4fc2a04` and the recorded
/// parity vectors stay checkable against it.
pub const PYTHON_ERA_PROVIDER_RULES: usize = 17;

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
        // Rules added after the Python detector was retired. They append
        // after the set Python published so `detector_version` keeps a
        // checkable prefix, and the synthetic `credential-assignment` entry
        // stays last in both the catalog and the digest material.
        //
        // A rule whose token has no fixed length is written open-ended rather
        // than capped. A cap with nothing to close the match against stops
        // part-way through a longer value, and the part it captured is not the
        // value the generic assignment rule sees, so the same credential is
        // reported twice and the provider finding fingerprints a fragment of
        // it. Where the token's length is fixed the cap stays, because the
        // trailing `\b` then refuses the longer value outright instead of
        // cutting it.
        secret_rule(
            "atlassian-api-token",
            "Atlassian API token",
            "critical",
            r"\b(?P<secret>ATATT[A-Za-z0-9_\-=]{20,})",
            FLAG_UNICODE,
            "atlassian",
            true,
            "Atlassian API token for Jira, Confluence, or Bitbucket Cloud.",
            None,
        ),
        secret_rule(
            "telegram-bot-token",
            "Telegram bot token",
            "high",
            r"\b(?P<secret>[0-9]{8,10}:AA[A-Za-z0-9_-]{30,})",
            FLAG_UNICODE,
            "telegram",
            true,
            "Telegram bot token granting full control of the bot.",
            None,
        ),
        secret_rule(
            "discord-webhook",
            "Discord incoming webhook",
            "critical",
            r"(?P<secret>https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,})",
            FLAG_UNICODE,
            "discord",
            true,
            "Discord incoming webhook that posts to a channel without further authentication.",
            None,
        ),
        secret_rule(
            "doppler-token",
            "Doppler token",
            "critical",
            r"\b(?P<secret>dp\.(?:ct|pt|said|sa|scim|audit)\.[A-Za-z0-9]{40,44}|dp\.st\.(?:[a-z0-9_-]{2,35}\.)?[A-Za-z0-9]{40,44})\b",
            FLAG_UNICODE,
            "doppler",
            true,
            "Doppler personal, service, service-account, service-account identity, SCIM, or audit token.",
            None,
        ),
        secret_rule(
            "vault-token",
            "HashiCorp Vault token",
            "critical",
            r"\b(?P<secret>hv[sbr]\.[A-Za-z0-9_-]{20,})",
            FLAG_UNICODE,
            "vault",
            true,
            "HashiCorp Vault service, batch, or recovery token.",
            None,
        ),
        secret_rule(
            "shopify-access-token",
            "Shopify access token",
            "critical",
            r"\b(?P<secret>shp(?:at|ca|pa|ss)_[0-9a-fA-F]{32})\b",
            FLAG_UNICODE,
            "shopify",
            true,
            "Shopify access, custom-app, private-app, or shared-secret token.",
            None,
        ),
        secret_rule(
            "grafana-service-account-token",
            "Grafana service account token",
            "high",
            r"\b(?P<secret>glsa_[A-Za-z0-9]{32}_[0-9a-fA-F]{8})\b",
            FLAG_UNICODE,
            "grafana",
            true,
            "Grafana service account token.",
            None,
        ),
        secret_rule(
            "linear-api-key",
            "Linear API key",
            "high",
            r"\b(?P<secret>lin_api_[A-Za-z0-9]{40,50})\b",
            FLAG_UNICODE,
            "linear",
            true,
            "Linear personal API key.",
            None,
        ),
        secret_rule(
            "dockerhub-pat",
            "Docker Hub access token",
            "critical",
            r"\b(?P<secret>dckr_pat_[A-Za-z0-9_-]{20,})",
            FLAG_UNICODE,
            "dockerhub",
            true,
            "Docker Hub personal access token able to push images.",
            None,
        ),
        secret_rule(
            "postman-api-key",
            "Postman API key",
            "high",
            r"\b(?P<secret>PMAK-[0-9a-fA-F]{24}-[0-9a-fA-F]{34})\b",
            FLAG_UNICODE,
            "postman",
            true,
            "Postman API key.",
            None,
        ),
        secret_rule(
            "databricks-token",
            "Databricks access token",
            "critical",
            r"\b(?P<secret>dapi[0-9a-fA-F]{32}(?:-[0-9]+)?)\b",
            FLAG_UNICODE,
            "databricks",
            true,
            "Databricks personal access token.",
            None,
        ),
        secret_rule(
            "planetscale-token",
            "PlanetScale token",
            "critical",
            r"\b(?P<secret>pscale_(?:tkn|pw)_[A-Za-z0-9_\-]{32,})",
            FLAG_UNICODE,
            "planetscale",
            true,
            "PlanetScale service token or database password.",
            None,
        ),
        secret_rule(
            "figma-token",
            "Figma access token",
            "high",
            r"\b(?P<secret>figd_[A-Za-z0-9_-]{40,})",
            FLAG_UNICODE,
            "figma",
            true,
            "Figma personal access token.",
            None,
        ),
        secret_rule(
            "square-access-token",
            "Square access token",
            "critical",
            r"\b(?P<secret>(?:sq0atp-[A-Za-z0-9_-]{22,}|EAAA[A-Za-z0-9_-]{60,}))",
            FLAG_UNICODE,
            "square",
            true,
            "Square production access token.",
            None,
        ),
        secret_rule(
            "mailgun-api-key",
            "Mailgun API key",
            "critical",
            r"(?:^|[^A-Za-z0-9_-])(?P<secret>key-[0-9a-f]{32})\b",
            FLAG_UNICODE,
            "mailgun",
            true,
            // `key-` before a hex digest also spells a cache key, an
            // idempotency key and half the object keys in a storage bucket, so
            // the match has to start where a word does. Anything carrying its
            // own prefix is somebody else's key, not Mailgun's.
            "Mailgun private API key able to send mail for the domain.",
            None,
        ),
        secret_rule(
            "flyio-token",
            "Fly.io API token",
            "critical",
            r"\b(?P<secret>(?:fm1a|fm1r|fm2)_[A-Za-z0-9+/]{40,}={0,3})",
            FLAG_UNICODE,
            "flyio",
            true,
            "Fly.io deploy or personal access token.",
            None,
        ),
        secret_rule(
            "slack-app-token",
            "Slack app-level token",
            "critical",
            r"(?:^|[^A-Za-z0-9_-])(?P<secret>xapp-[0-9]-[A-Za-z0-9-]{10,})(?P<overrun>_?)",
            FLAG_UNICODE,
            "slack",
            true,
            // `-` is a token character here, so a word boundary would end the
            // match at one and report the head as the whole token. The match
            // runs to the first character the alphabet does not hold, which
            // leaves only `_` able to continue the value, and `overrun` catches
            // that without consuming anything else.
            "Slack app-level token for socket-mode connections.",
            None,
        ),
        secret_rule(
            "discord-bot-token",
            "Discord bot token",
            "critical",
            r"(?:^|[^A-Za-z0-9_.-])(?P<secret>[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38})(?P<overrun>[A-Za-z0-9_.-]*)",
            FLAG_UNICODE,
            "discord",
            true,
            // The segments hold `-` and `_`, and the token is exactly three of
            // them, so `overrun` watches for `.` as well: a fourth segment or a
            // longer third one is some other value, not a bot token with its
            // tail cut off.
            "Discord bot token granting the application its gateway identity.",
            None,
        ),
        secret_rule(
            "digitalocean-token",
            "DigitalOcean access token",
            "critical",
            r"\b(?P<secret>do[opr]_v1_[0-9a-f]{64})\b",
            FLAG_UNICODE,
            "digitalocean",
            true,
            "DigitalOcean personal, OAuth, or refresh access token.",
            None,
        ),
        secret_rule(
            "notion-integration-token",
            "Notion integration token",
            "critical",
            r"\b(?P<secret>ntn_[A-Za-z0-9]{40,60})\b",
            FLAG_UNICODE,
            "notion",
            true,
            "Notion internal integration token.",
            None,
        ),
        secret_rule(
            "sentry-auth-token",
            "Sentry auth token",
            "critical",
            r"(?:^|[^A-Za-z0-9+/=_-])(?P<secret>sntry[su]_[A-Za-z0-9+/=_-]{50,})",
            FLAG_UNICODE,
            "sentry",
            true,
            // Unbounded above, because a ceiling on the quantifier reports the
            // first N characters of anything longer. The class already holds
            // every character that could continue the value, so the greedy run
            // ends the token and no overrun group is needed.
            "Sentry organization or user auth token.",
            None,
        ),
        secret_rule(
            "google-oauth-client-secret",
            "Google OAuth client secret",
            "critical",
            r"(?:^|[^A-Za-z0-9_-])(?P<secret>GOCSPX-[A-Za-z0-9_-]{28})(?P<overrun>[A-Za-z0-9_-]*)",
            FLAG_UNICODE,
            "google",
            true,
            // Exactly 28 characters after the prefix, and `-` is one of them, so
            // anything after the 28 that still comes from the alphabet means
            // those 28 were never the whole secret. `overrun` collects it.
            "Google OAuth 2.0 client secret.",
            None,
        ),
        secret_rule(
            "groq-api-key",
            "Groq API key",
            "critical",
            r"\b(?P<secret>gsk_[A-Za-z0-9]{48,60})\b",
            FLAG_UNICODE,
            "groq",
            true,
            "Groq API key.",
            None,
        ),
        secret_rule(
            "replicate-api-token",
            "Replicate API token",
            "critical",
            r"\b(?P<secret>r8_[A-Za-z0-9]{37,45})\b",
            FLAG_UNICODE,
            "replicate",
            true,
            "Replicate API token.",
            None,
        ),
        secret_rule(
            "perplexity-api-key",
            "Perplexity API key",
            "critical",
            r"\b(?P<secret>pplx-[A-Za-z0-9]{32,60})\b",
            FLAG_UNICODE,
            "perplexity",
            true,
            "Perplexity API key.",
            None,
        ),
        secret_rule(
            "azure-storage-account-key",
            "Azure Storage account key",
            "critical",
            r"(?P<secret>AccountKey=[A-Za-z0-9+/=]{86,})",
            FLAG_UNICODE,
            "azure_storage",
            true,
            "Azure Storage account key in a connection string.",
            None,
        ),
        secret_rule(
            "gcp-oauth-refresh-token",
            "Google Cloud OAuth refresh token",
            "critical",
            r"\b(?P<secret>1//0[A-Za-z0-9_-]{30,255})\b",
            FLAG_UNICODE,
            "gcp_oauth",
            true,
            "Google Cloud OAuth refresh token.",
            None,
        ),
        secret_rule(
            "twilio-api-key",
            "Twilio API key",
            "critical",
            r"\b(?P<secret>SK[0-9a-fA-F]{32})\b",
            FLAG_UNICODE,
            "twilio",
            true,
            "Twilio API key SID.",
            None,
        ),
        secret_rule(
            "new-relic-api-key",
            "New Relic API key",
            "critical",
            r"\b(?P<secret>NR(?:AK|II|JS|IQ)-[A-Za-z0-9]{20,64})\b",
            FLAG_UNICODE,
            "new_relic",
            true,
            "New Relic user, ingest, browser or query key.",
            None,
        ),
        secret_rule(
            "terraform-cloud-token",
            "Terraform Cloud API token",
            "critical",
            r"\b(?P<secret>[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{30,255})\b",
            FLAG_UNICODE,
            "terraform_cloud",
            true,
            "Terraform Cloud or Enterprise API token.",
            None,
        ),
        secret_rule(
            "rubygems-api-key",
            "RubyGems API key",
            "critical",
            r"\b(?P<secret>rubygems_[0-9a-f]{48})\b",
            FLAG_UNICODE,
            "rubygems",
            true,
            "RubyGems API key.",
            None,
        ),
        secret_rule(
            "nuget-api-key",
            "NuGet API key",
            "critical",
            r"\b(?P<secret>oy2[a-z0-9]{43})\b",
            FLAG_UNICODE,
            "nuget",
            true,
            "NuGet gallery API key.",
            None,
        ),
        secret_rule(
            "sonarqube-token",
            "SonarQube token",
            "critical",
            r"\b(?P<secret>sq[apu]_[0-9a-f]{40})\b",
            FLAG_UNICODE,
            "sonarqube",
            true,
            "SonarQube or SonarCloud analysis, user or project token.",
            None,
        ),
        secret_rule(
            "langsmith-api-key",
            "LangSmith API key",
            "critical",
            r"\b(?P<secret>lsv2_(?:pt|sk)_[0-9a-f]{32}_[0-9a-f]{10})\b",
            FLAG_UNICODE,
            "langsmith",
            true,
            "LangSmith personal or service API key.",
            None,
        ),
        secret_rule(
            "tailscale-auth-key",
            "Tailscale auth key",
            "critical",
            r"\b(?P<secret>tskey-(?:auth|api|client|scim|webhook)-[A-Za-z0-9]{8,64}-[A-Za-z0-9]{8,64})\b",
            FLAG_UNICODE,
            "tailscale",
            true,
            "Tailscale auth, API, OAuth client, SCIM or webhook key.",
            None,
        ),
        secret_rule(
            "pulumi-access-token",
            "Pulumi access token",
            "critical",
            r"\b(?P<secret>pul-[0-9a-f]{40})\b",
            FLAG_UNICODE,
            "pulumi",
            true,
            "Pulumi Cloud access token.",
            None,
        ),
        secret_rule(
            "supabase-access-token",
            "Supabase access token",
            "critical",
            r"\b(?P<secret>sb[ps]_[0-9a-f]{40})\b",
            FLAG_UNICODE,
            "supabase",
            true,
            "Supabase personal or service access token.",
            None,
        ),
        secret_rule(
            "jfrog-access-token",
            "JFrog Artifactory access token",
            "critical",
            r"\b(?P<secret>cmVmdGtuOjAx[A-Za-z0-9+/=]{40,255})",
            FLAG_UNICODE,
            "jfrog",
            true,
            "JFrog Artifactory reference or access token.",
            None,
        ),
        secret_rule(
            "asana-pat",
            "Asana personal access token",
            "critical",
            r"\b(?P<secret>[12]/[0-9]{10,20}:[0-9a-f]{32})\b",
            FLAG_UNICODE,
            "asana",
            true,
            "Asana personal access token.",
            None,
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
/// raw secret can never leak through formatting or equality, and it is
/// overwritten when the finding is dropped so it does not sit in a freed
/// allocation for the rest of the process. The detector keeps no second copy of
/// those bytes that outlives the scan: deduplication keys on a digest, the
/// fingerprint hashes the field in place, and the line and context strings the
/// matching path builds are zeroized when they go out of scope. The text handed
/// to the scan is the caller's own allocation and stays the caller's to manage.
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

/// Raised when a finding cannot be fingerprinted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintError {
    /// No key was supplied, mirroring the Python
    /// `ValueError("secret fingerprint key must not be empty")`.
    EmptyKey,
    /// The candidate was already scrubbed. Hashing what is left would bind the
    /// identity to the rule alone, so every scrubbed finding of one rule would
    /// answer to the same fingerprint.
    CandidateScrubbed,
}

impl fmt::Display for FingerprintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyKey => formatter.write_str("secret fingerprint key must not be empty"),
            Self::CandidateScrubbed => formatter
                .write_str("secret fingerprint is unavailable once the candidate is scrubbed"),
        }
    }
}

impl Error for FingerprintError {}

impl Drop for SecretFinding {
    fn drop(&mut self) {
        self.scrub_candidate();
    }
}

impl SecretFinding {
    /// Tenant/caller-scoped HMAC of the finding, never exposing candidate bytes.
    pub fn fingerprint(&self, key: &[u8]) -> Result<String, FingerprintError> {
        if key.is_empty() {
            return Err(FingerprintError::EmptyKey);
        }
        // A detected candidate is never empty, so an empty one here means the
        // caller already scrubbed it. Refuse rather than return the identity of
        // the rule wearing this finding's name.
        if self.candidate.is_empty() {
            return Err(FingerprintError::CandidateScrubbed);
        }
        // Fed in three pieces rather than joined into one string: the bytes
        // the HMAC sees are the same, and the candidate is never copied into a
        // temporary that outlives this call unscrubbed.
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
        mac.update(self.rule_id.as_bytes());
        mac.update(&[0]);
        mac.update(self.candidate.as_bytes());
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    /// Overwrite the raw secret in place.
    ///
    /// `Drop` runs this, so a finding that goes out of scope leaves nothing
    /// behind in the allocation it frees. A caller that holds a finding past
    /// the point where it still needs the raw bytes — to report the family and
    /// the line, say — can run it early and keep the rest of the finding.
    pub fn scrub_candidate(&mut self) {
        self.candidate.zeroize();
    }

    /// Public, non-sensitive payload. Field order matches the Python dict
    /// literal exactly; `fingerprint` is omitted unless a key is supplied.
    pub fn to_public_dict(
        &self,
        fingerprint_key: Option<&[u8]>,
    ) -> Result<PublicFinding, FingerprintError> {
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
    ) -> Result<PublicScanSummary<'_>, FingerprintError> {
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
    let mut material_parts: Vec<String> = SECRET_RULES.iter().map(rule_material_line).collect();
    material_parts.push(assignment_material_line());
    detector_version_over(&material_parts)
}

/// One rule's contribution to the detector digest.
fn rule_material_line(rule: &SecretRule) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        rule.rule_id, rule.severity, rule.validation, rule.pattern_source, rule.pattern_flags
    )
}

/// The synthetic `credential-assignment` contribution, always last.
fn assignment_material_line() -> String {
    format!(
        "credential-assignment|{ASSIGNMENT_PATTERN_SOURCE}|{FLAG_IGNORECASE_MULTILINE_UNICODE}|{GENERIC_CANDIDATE_POLICY_VERSION}"
    )
}

/// Digest over an explicit material list. Hashing a subset is how the rules
/// Python published stay checkable against the version Python published once
/// later rules have been appended.
fn detector_version_over(material_parts: &[String]) -> String {
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
/// Non-ASCII code points for which Python 3.12 (Unicode 15.0) `str.isdigit()`
/// is true: decimal digits plus digit-valued superscripts, subscripts and
/// circled forms. Other numerics (Roman numerals, fractions) are excluded.
const PYTHON_DIGIT_RANGES: &[(u32, u32)] = &[
    (0xB2, 0xB3),
    (0xB9, 0xB9),
    (0x660, 0x669),
    (0x6F0, 0x6F9),
    (0x7C0, 0x7C9),
    (0x966, 0x96F),
    (0x9E6, 0x9EF),
    (0xA66, 0xA6F),
    (0xAE6, 0xAEF),
    (0xB66, 0xB6F),
    (0xBE6, 0xBEF),
    (0xC66, 0xC6F),
    (0xCE6, 0xCEF),
    (0xD66, 0xD6F),
    (0xDE6, 0xDEF),
    (0xE50, 0xE59),
    (0xED0, 0xED9),
    (0xF20, 0xF29),
    (0x1040, 0x1049),
    (0x1090, 0x1099),
    (0x1369, 0x1371),
    (0x17E0, 0x17E9),
    (0x1810, 0x1819),
    (0x1946, 0x194F),
    (0x19D0, 0x19DA),
    (0x1A80, 0x1A89),
    (0x1A90, 0x1A99),
    (0x1B50, 0x1B59),
    (0x1BB0, 0x1BB9),
    (0x1C40, 0x1C49),
    (0x1C50, 0x1C59),
    (0x2070, 0x2070),
    (0x2074, 0x2079),
    (0x2080, 0x2089),
    (0x2460, 0x2468),
    (0x2474, 0x247C),
    (0x2488, 0x2490),
    (0x24EA, 0x24EA),
    (0x24F5, 0x24FD),
    (0x24FF, 0x24FF),
    (0x2776, 0x277E),
    (0x2780, 0x2788),
    (0x278A, 0x2792),
    (0xA620, 0xA629),
    (0xA8D0, 0xA8D9),
    (0xA900, 0xA909),
    (0xA9D0, 0xA9D9),
    (0xA9F0, 0xA9F9),
    (0xAA50, 0xAA59),
    (0xABF0, 0xABF9),
    (0xFF10, 0xFF19),
    (0x104A0, 0x104A9),
    (0x10A40, 0x10A43),
    (0x10D30, 0x10D39),
    (0x10E60, 0x10E68),
    (0x11052, 0x1105A),
    (0x11066, 0x1106F),
    (0x110F0, 0x110F9),
    (0x11136, 0x1113F),
    (0x111D0, 0x111D9),
    (0x112F0, 0x112F9),
    (0x11450, 0x11459),
    (0x114D0, 0x114D9),
    (0x11650, 0x11659),
    (0x116C0, 0x116C9),
    (0x11730, 0x11739),
    (0x118E0, 0x118E9),
    (0x11950, 0x11959),
    (0x11C50, 0x11C59),
    (0x11D50, 0x11D59),
    (0x11DA0, 0x11DA9),
    (0x11F50, 0x11F59),
    (0x16A60, 0x16A69),
    (0x16AC0, 0x16AC9),
    (0x16B50, 0x16B59),
    (0x1D7CE, 0x1D7FF),
    (0x1E140, 0x1E149),
    (0x1E2F0, 0x1E2F9),
    (0x1E4F0, 0x1E4F9),
    (0x1E950, 0x1E959),
    (0x1F100, 0x1F10A),
    (0x1FBF0, 0x1FBF9),
];

/// Python `str.isdigit()` for one character.
fn python_isdigit(c: char) -> bool {
    if c.is_ascii() {
        return c.is_ascii_digit();
    }
    let code = u32::from(c);
    PYTHON_DIGIT_RANGES
        .binary_search_by(|&(low, high)| {
            if high < code {
                std::cmp::Ordering::Less
            } else if low > code {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

fn character_class_count(value: &str) -> usize {
    usize::from(value.chars().any(|c| c.is_lowercase()))
        + usize::from(value.chars().any(|c| c.is_uppercase()))
        + usize::from(value.chars().any(python_isdigit))
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
    let digit_count = value.chars().filter(|c| python_isdigit(*c)).count();
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

/// Python `str.splitlines()`: every Unicode line boundary ends a line, `\r\n`
/// counts once, and a trailing boundary adds no empty line.
fn python_splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        if !matches!(
            ch,
            '\n' | '\r'
                | '\u{0b}'
                | '\u{0c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        ) {
            continue;
        }
        lines.push(&text[start..index]);
        start = index + ch.len_utf8();
        if ch == '\r' && chars.peek().is_some_and(|(_, next)| *next == '\n') {
            chars.next();
            start += 1;
        }
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// Python `_surrounding_context`: the three lines on each side of the match
/// line (counted by `\n`, sliced from `splitlines()`), capped at 4096 chars.
fn surrounding_context(text: &str, match_start: usize) -> Zeroizing<String> {
    let lines = python_splitlines(text);
    let line_index = text.as_bytes()[..match_start]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count();
    let start = line_index.saturating_sub(3);
    let end = (line_index + 4).min(lines.len());
    let joined = Zeroizing::new(if start < end {
        lines[start..end].join("\n")
    } else {
        String::new()
    });
    match joined.char_indices().nth(4096) {
        Some((index, _)) => Zeroizing::new(joined.as_str()[..index].to_string()),
        None => joined,
    }
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
    let context = context.as_str();
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

/// How many lines a scanned text holds before each block of it, so a
/// finding's line is read from one count and a short scan instead of by
/// counting the newlines before it again.
///
/// A scan reports up to ten thousand findings, and counting from the start of
/// the text for each one walks the whole prefix every time: a large file that
/// leaks in many places reads its own bytes once per finding. Holding the
/// offset of every newline would answer that in a single search, but a
/// newline-heavy text would then carry eight bytes of index for every byte of
/// itself, and a repository scan admits files up to 32 MiB while a direct
/// caller of `scan_secret_text` is bounded by nothing at all. One count per
/// block is a five-hundredth of the text instead, and the newlines after the
/// last boundary are counted over at most one block.
///
/// The counts are built on the first finding that survives the filters, so a
/// text that yields none never pays for them, and a scan that stops at its
/// bound has built them once.
const LINE_INDEX_BLOCK: usize = 4096;

#[derive(Default)]
struct LineIndex {
    blocks: OnceCell<Vec<usize>>,
}

impl LineIndex {
    /// The one-based line `match_start` falls on. A match standing on the
    /// newline itself belongs to the line that newline ends, as counting the
    /// newlines strictly before it did.
    fn line_of(&self, text: &str, match_start: usize) -> usize {
        let blocks = self.blocks.get_or_init(|| {
            let bytes = text.as_bytes();
            // One more count than there are blocks, so the boundary at the
            // very end of the text is a block start like any other and an
            // offset standing on it has a count to read.
            let mut counts = Vec::with_capacity(bytes.len() / LINE_INDEX_BLOCK + 2);
            let mut counted = 0usize;
            for block in bytes.chunks(LINE_INDEX_BLOCK) {
                counts.push(counted);
                counted += newlines(block);
            }
            counts.push(counted);
            counts
        });
        let block = match_start / LINE_INDEX_BLOCK;
        let boundary = block * LINE_INDEX_BLOCK;
        blocks[block] + newlines(&text.as_bytes()[boundary..match_start]) + 1
    }
}

fn newlines(bytes: &[u8]) -> usize {
    bytes.iter().filter(|byte| **byte == b'\n').count()
}

fn line_text(text: &str, match_start: usize) -> Zeroizing<String> {
    let start = text[..match_start].rfind('\n').map_or(0, |index| index + 1);
    let end = text[match_start..]
        .find('\n')
        .map_or(text.len(), |index| match_start + index);
    // Collecting the characters would grow the string from a quarter-length
    // guess, and every grow frees a buffer still holding the head of the line,
    // which is where a secret usually sits. Finding the cut first and copying
    // the slice once allocates exactly what the line needs, so the only buffer
    // that ever held the text is the one `Zeroizing` wipes.
    let line = &text[start..end];
    let cut = line
        .char_indices()
        .nth(1024)
        .map_or(line.len(), |(index, _)| index);
    Zeroizing::new(line[..cut].to_string())
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
    lines: &LineIndex,
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
    } else if obvious_sample(candidate, line_text.as_str(), path) {
        return None;
    }
    let (score, reasons) = context_score(candidate, path, line_text.as_str(), rule.strong_format);
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
        line: lines.line_of(text, match_start),
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
    let bounded_max = max_findings.clamp(1, MAX_FINDINGS_PER_TEXT);
    let lines = LineIndex::default();
    let mut findings: Vec<SecretFinding> = Vec::new();
    let mut seen: HashSet<(&'static str, usize, CandidateDigest)> = HashSet::new();

    for rule in SECRET_RULES.iter() {
        for captures in rule.pattern.captures_iter(text) {
            // The finding is anchored on the secret itself, not on the whole
            // match. A rule may consume a character ahead of the secret to
            // prove it starts where a word does, and when that character is
            // the newline ending the line above, the whole match begins on the
            // previous line. Reporting from there would name the wrong line
            // and score the wrong line's text.
            // A rule whose alphabet holds characters a word boundary cannot see
            // has to prove the value ends where the rule says it does. The
            // regex crate has no lookahead, and a guard that consumes the next
            // character would swallow the separator between two neighbouring
            // tokens and miss the second one. Such a rule captures the overrun
            // instead: anything matched there means the value runs past what
            // the rule describes, so the rule does not claim it and the generic
            // assignment rule reports the whole value on its own.
            if captures
                .name("overrun")
                .is_some_and(|overrun| !overrun.is_empty())
            {
                continue;
            }
            let matched = captures
                .name("secret")
                .unwrap_or_else(|| captures.get(0).expect("whole match always present"));
            let candidate = matched.as_str();
            let match_start = matched.start();
            let finding = finding_from_match(
                &RuleMeta::of(rule),
                candidate,
                text,
                match_start,
                path,
                source,
                commit,
                Some(rule),
                &lines,
            );
            let Some(finding) = finding else { continue };
            if !seen.insert((
                finding.rule_id,
                finding.line,
                candidate_digest(&finding.candidate),
            )) {
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
    let provider_candidates: HashSet<CandidateDigest> = findings
        .iter()
        .map(|finding| candidate_digest(&finding.candidate))
        .collect();
    for captures in ASSIGNMENT.captures_iter(text) {
        let candidate = captures
            .name("secret")
            .or_else(|| captures.name("secret_sq"))
            .or_else(|| captures.name("secret_uq"))
            .map(|m| m.as_str());
        let Some(candidate) = candidate else { continue };
        if provider_candidates.contains(&candidate_digest(candidate)) {
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
            &lines,
        );
        let Some(finding) = finding else { continue };
        if !seen.insert((
            finding.rule_id,
            finding.line,
            candidate_digest(&finding.candidate),
        )) {
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

    use guard_alloc_probe::CountingAllocator;

    // Installed for this crate's unit tests so a copy that silently grows is
    // visible as an extra allocation call rather than something a reader has
    // to take on trust.
    #[global_allocator]
    static COUNTING_ALLOCATOR: CountingAllocator = CountingAllocator;

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

    /// The provider rules Python published, in the order it published them.
    const PYTHON_ERA_RULE_IDS: [&str; PYTHON_ERA_PROVIDER_RULES] = [
        "github-token",
        "gitlab-token",
        "aws-access-key",
        "slack-token",
        "slack-webhook",
        "stripe-secret-key",
        "openai-api-key",
        "anthropic-api-key",
        "huggingface-token",
        "npm-token",
        "pypi-token",
        "google-api-key",
        "sendgrid-api-key",
        "pem-private-key",
        "database-url-password",
        "basic-auth-url-password",
        "jwt-token",
    ];

    /// The version string the Python detector published for its own rule set.
    const PYTHON_DETECTOR_VERSION: &str = "guard-secrets-v1:1d8dc93ef4fc2a04";

    #[test]
    fn the_rules_python_published_still_hash_to_the_version_python_published() {
        // Oracle: python3 detector_version() -> guard-secrets-v1:1d8dc93ef4fc2a04
        //
        // Later rules append after the set Python shipped, so the live digest
        // moves with them. Hashing exactly the material Python hashed keeps
        // that oracle checkable: a rule Python published that is renamed,
        // reseverityed or has its pattern edited still breaks this.
        let mut material: Vec<String> = SECRET_RULES
            .iter()
            .take(PYTHON_ERA_PROVIDER_RULES)
            .map(rule_material_line)
            .collect();
        material.push(assignment_material_line());
        assert_eq!(detector_version_over(&material), PYTHON_DETECTOR_VERSION);
    }

    #[test]
    fn a_rule_added_after_python_moves_the_detector_version() {
        // The digest is what a consumer compares to decide whether a cached
        // scan is still current, so appending rules has to change it.
        assert_ne!(detector_version(), PYTHON_DETECTOR_VERSION);
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
    fn catalog_keeps_the_python_entries_in_python_order() {
        let catalog = secret_rule_catalog();
        // The provider rules Python published lead, later ones follow, and the
        // synthetic contextual entry stays last however many are appended.
        assert!(catalog.len() > PYTHON_ERA_PROVIDER_RULES);
        assert_eq!(
            catalog
                .iter()
                .take(PYTHON_ERA_PROVIDER_RULES)
                .map(|rule| rule.rule_id)
                .collect::<Vec<_>>(),
            PYTHON_ERA_RULE_IDS,
        );
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
            serde_json::to_value(catalog.last().unwrap()).unwrap(),
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
        assert_eq!(summary.detector_version, detector_version());

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
        let expected = format!(
            r#"{{"schema":"guard-secret-scan.v1","detector_version":"{}","#,
            detector_version()
        ) + concat!(
            r#""finding_count":4,"findings":[{"rule_id":"github-token","family":"GitHub token","#,
            r#""severity":"critical","confidence":"high","confidence_score":1.0,"line":2,"#,
            r#""path":"config/prod.env","source":"working_tree","commit":null,"validation":"github","#,
            r#""entropy":5.0588,"context_reasons":["provider-format","high-token-rarity","#,
            r#""credential-name-context"],"fingerprint":"b018734dfa08a0099c84c484d37b473f5a14095e14a647584993f1b2c6d9a100"},"#,
        );
        assert!(json.starts_with(&expected), "mismatch: {json}");
        // Without a key, `fingerprint` is absent (not null).
        let no_key = serde_json::to_string(&summary.to_public_dict(None).unwrap()).unwrap();
        assert!(!no_key.contains("fingerprint"));
        // An explicitly empty key is an error, mirroring the Python ValueError.
        assert_eq!(
            summary.findings[0].fingerprint(b""),
            Err(FingerprintError::EmptyKey)
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

    /// The line index answers what counting the newlines before an offset
    /// answered, including at a newline itself, at the first byte and at the
    /// end of the text.
    #[test]
    fn the_line_index_agrees_with_counting_the_newlines_before_an_offset() {
        let text = "\nalpha\n\nbeta\ngamma";
        let index = LineIndex::default();
        for offset in 0..=text.len() {
            let counted = text[..offset].bytes().filter(|byte| *byte == b'\n').count() + 1;
            assert_eq!(index.line_of(text, offset), counted, "offset {offset}");
        }
    }

    /// The block counts answer the same line as counting the newlines does
    /// for a text long enough to hold several blocks, at the boundaries
    /// themselves and on either side of them.
    #[test]
    fn the_line_index_crosses_block_boundaries() {
        let text = "ab\n".repeat(LINE_INDEX_BLOCK);
        let index = LineIndex::default();
        let mut offsets = vec![0, 1, text.len()];
        for block in 0..=text.len() / LINE_INDEX_BLOCK {
            let boundary = block * LINE_INDEX_BLOCK;
            offsets.extend([boundary.saturating_sub(1), boundary, boundary + 1]);
        }
        for offset in offsets {
            if offset > text.len() {
                continue;
            }
            let counted = text[..offset].bytes().filter(|byte| *byte == b'\n').count() + 1;
            assert_eq!(index.line_of(&text, offset), counted, "offset {offset}");
        }
    }

    /// Every finding reads its own line, not the line of the one the index was
    /// first built for.
    #[test]
    fn findings_after_the_first_keep_their_own_lines() {
        let tokens = [
            "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345",
            "ghp_ZyXwVuTsRqPoNmLkJiHgFeDcBa543210",
            "ghp_0123456789AbCdEfGhIjKlMnOpQrStUv",
        ];
        let mut text = String::new();
        for (position, token) in tokens.iter().enumerate() {
            text.push_str(&"filler\n".repeat(position * 40));
            text.push_str(&format!("key{position} {token}\n"));
        }
        let summary = scan_secret_text(&text, "a.env", "text", None, 200);
        assert_eq!(summary.findings.len(), tokens.len());
        let counted: Vec<usize> = tokens
            .iter()
            .map(|token| {
                let start = text.find(token).expect("token present");
                text[..start].bytes().filter(|byte| *byte == b'\n').count() + 1
            })
            .collect();
        let reported: Vec<usize> = summary
            .findings
            .iter()
            .map(|finding| finding.line)
            .collect();
        assert_eq!(reported, counted);
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

    #[test]
    fn scrubbing_a_finding_keeps_everything_but_the_secret() {
        let summary = scan_secret_text(
            &fixture_text(),
            "config/prod.env",
            "working_tree",
            None,
            200,
        );
        let mut finding = summary.findings.into_iter().next().expect("a finding");
        let rule_id = finding.rule_id;
        let line = finding.line;
        assert!(!finding.candidate.is_empty());

        finding.scrub_candidate();

        assert!(finding.candidate.is_empty());
        assert_eq!(finding.rule_id, rule_id);
        assert_eq!(finding.line, line);
        assert_eq!(finding.path, "config/prod.env");
        // The rest of the finding survives, but its identity does not: a
        // fingerprint taken now would name the rule, not the secret.
        assert_eq!(
            finding.fingerprint(b"tenant-key"),
            Err(FingerprintError::CandidateScrubbed)
        );
        assert_eq!(
            finding.to_public_dict(Some(b"tenant-key")).err(),
            Some(FingerprintError::CandidateScrubbed)
        );
        // Without a key the public payload carries no fingerprint, so it is
        // still the honest way to report a scrubbed finding.
        assert!(finding.to_public_dict(None).is_ok());
    }

    #[test]
    fn feeding_the_fingerprint_in_pieces_matches_the_joined_form() {
        let summary = scan_secret_text(
            &fixture_text(),
            "config/prod.env",
            "working_tree",
            None,
            200,
        );
        let finding = summary.findings.first().expect("a finding");
        let key = b"fingerprint-key";

        // What the finding used to build and hash in one allocation.
        let mut joined = HmacSha256::new_from_slice(key).expect("HMAC accepts this key");
        joined.update(format!("{}\u{0}{}", finding.rule_id, finding.candidate).as_bytes());

        assert_eq!(
            finding.fingerprint(key).expect("the key is not empty"),
            hex::encode(joined.finalize().into_bytes())
        );
    }

    #[test]
    fn a_matched_line_reaches_the_zeroizing_buffer_in_one_copy() {
        // Collecting characters starts from a guess of about a quarter of the
        // line's bytes and grows from there, and every grow frees a buffer that
        // still holds the head of the line, which is where the secret sits. The
        // allocator is the only honest witness to that, so measure it: one call
        // is the copy, and anything more is a freed buffer nobody wiped.
        let line = format!("API_KEY=sk_live_{}", "e\u{301}".repeat(400));
        let text = format!("harmless line\n{line}\ntrailing line");
        let match_start = text.find("sk_live_").expect("the fixture carries the line");

        let (copied, measured) = guard_alloc_probe::measure(|| line_text(&text, match_start));

        assert_eq!(copied.as_str(), line);
        assert_eq!(
            measured.alloc_calls, 1,
            "the line was copied through more than one buffer"
        );
    }

    #[test]
    fn a_long_line_is_cut_on_a_character_boundary() {
        let line = format!("API_KEY=sk_live_{}", "e\u{301}".repeat(2000));
        let text = format!("harmless line\n{line}\n");
        let match_start = text.find("sk_live_").expect("the fixture carries the line");

        let copied = line_text(&text, match_start);

        // The cut counts characters, so a multi-byte character is never halved
        // and the kept text is still a prefix of the line it came from.
        assert_eq!(copied.chars().count(), 1024);
        assert!(line.starts_with(copied.as_str()));
    }

    #[test]
    fn the_dedup_digest_tells_candidates_apart() {
        assert_eq!(
            candidate_digest("ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345"),
            candidate_digest("ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345")
        );
        assert_ne!(
            candidate_digest("ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345"),
            candidate_digest("ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012346")
        );
    }

    /// One synthetic credential per rule added after the Python detector was
    /// retired, in the order the rules appear. None of these is a live secret:
    /// each is assembled to satisfy its own pattern and nothing else. Each is
    /// held in two pieces, as `jwt_fixture` is, so no complete provider-shaped
    /// token ever appears as a literal in this file.
    const RULES_ADDED_AFTER_PYTHON: [(&str, &str, &str); 39] = [
        (
            "atlassian-api-token",
            "ATATT3xFfGF0A1b2C3d4E5",
            "f6G7h8I9j0K1l2M",
        ),
        (
            "telegram-bot-token",
            "7645120398:AAH9kQ2vL8nP4wR",
            "7tY1uI6oP3aS5dFgHj",
        ),
        (
            "discord-webhook",
            "https://discord.com/api/webhooks/1298374650192837465/qZ2vL8nP4wR7tY1uI6o",
            "P3aS5dFgHjK9mQ2vL8nP4wR7tY1uI6oP3aS5dFgHjK9mQ2vL8",
        ),
        (
            "doppler-token",
            "dp.pt.a7Kq2VL8nP4wR7tY1uI6oP3",
            "aS5dFgHjK9mQ2vL8nP4w",
        ),
        ("vault-token", "hvs.CAESIJq2VL8nP4wR7t", "Y1uI6oP3aS5dFgHj"),
        (
            "shopify-access-token",
            "shpat_9f3b7c2a1d4e8f60",
            "b5a9c7d3e1f2a4b6",
        ),
        (
            "grafana-service-account-token",
            "glsa_Qq2VL8nP4wR7tY1uI6oP3a",
            "S5dFgHjK9m_3f7b1c9d",
        ),
        (
            "linear-api-key",
            "lin_api_Qq2VL8nP4wR7tY1uI6oP3a",
            "S5dFgHjK9mQ2vL8nP4wR",
        ),
        (
            "dockerhub-pat",
            "dckr_pat_Qq2VL8nP4wR7tY1uI6",
            "oP3aS5dFgHjK9mQ2vL",
        ),
        (
            "postman-api-key",
            "PMAK-6f3b7c2a1d4e8f60b5a9c7d3-e1f2a4b6",
            "9c8d7e5f3a1b2c4d6e8f0a2b4c",
        ),
        (
            "databricks-token",
            "dapi9f3b7c2a1d4e8f60b",
            "5a9c7d3e1f2a4b6",
        ),
        (
            "planetscale-token",
            "pscale_tkn_Qq2VL8nP4wR7tY1uI6o",
            "P3aS5dFgHjK9mQ2vL8nP4",
        ),
        (
            "figma-token",
            "figd_Qq2VL8nP4wR7tY1uI6oP3aS5",
            "dFgHjK9mQ2vL8nP4wR7t",
        ),
        ("square-access-token", "sq0atp-Qq2VL8nP4w", "R7tY1uI6oP3a"),
        (
            "mailgun-api-key",
            "key-9f3b7c2a1d4e8f60b",
            "5a9c7d3e1f2a4b6",
        ),
        (
            "flyio-token",
            "fm2_Qq2VL8nP4wR7tY1uI6oP3aS5dFgHjK9mQ",
            "2vL8nP4wR7tY1uI6oP3aS5dFgH",
        ),
        (
            "slack-app-token",
            "xapp-1-A0K2VL8NP4W-7tY1uI6oP",
            "3aS5dFgHjK9mQ2vL8nP4wR",
        ),
        (
            "discord-bot-token",
            "MTI5ODM3NDY1MDE5MjgzNzQ2N.Gq2VL8.nP4wR7tY1uI6",
            "oP3aS5dFgHjK9mQ",
        ),
        (
            "digitalocean-token",
            "dop_v1_9f3b7c2a1d4e8f60b5a9c7d3e1f2a4b6",
            "9c8d7e5f3a1b2c4d6e8f0a2b4c6d8e0f",
        ),
        (
            "notion-integration-token",
            "ntn_Qq2VL8nP4wR7tY1uI6oP3aS5dFgHjK9m",
            "Q2vL8nP4wR7tY1",
        ),
        (
            "sentry-auth-token",
            "sntrys_Qq2VL8nP4wR7tY1uI6oP3aS5dFgHjK9m",
            "Q2vL8nP4wR7tY1uI6oP3aS5d",
        ),
        (
            "google-oauth-client-secret",
            "GOCSPX-Qq2VL8nP4wR7tY1",
            "uI6oP3aS5dFgH",
        ),
        (
            "groq-api-key",
            "gsk_Qq2VL8nP4wR7tY1uI6oP3aS5dFgHjK9m",
            "Q2vL8nP4wR7tY1uI6oP3",
        ),
        (
            "replicate-api-token",
            "r8_Qq2VL8nP4wR7tY1uI6oP3aS5dFgHjK9m",
            "Q2vL8nP4",
        ),
        (
            "perplexity-api-key",
            "pplx-Qq2VL8nP4wR7tY1uI6oP3aS5dFgHjK9m",
            "Q2vL8nP4",
        ),
        (
            "azure-storage-account-key",
            "AccountKey=",
            "Qq2VL8nP4wR7tY1uI6oP3aS5dFgHjK9mQq2VL8nP4wR7tY1uI6oP3aS5dFgHjK9mQ2vL8nP4wR7tY1uI6oP3aS==",
        ),
        (
            "gcp-oauth-refresh-token",
            "1//0gQq2VL8nP4wR7tY1uI6oP3aS5dFgHjK9mQ2",
            "vL8nP4wR",
        ),
        (
            "twilio-api-key",
            "SK9f3b7c2a1d4e8f60b5a9c7d3",
            "e1f2a4b6",
        ),
        (
            "new-relic-api-key",
            "NRAK-QQ2VL8NP4WR7TY1UI6O",
            "P3AS5DFG",
        ),
        (
            "terraform-cloud-token",
            "Qq2VL8nP4wR7tY.atlasv1.K9mQ2vL8nP4wR7tY1uI6oP3",
            "aS5dFgHj",
        ),
        (
            "rubygems-api-key",
            "rubygems_9f3b7c2a1d4e8f60b5a9c7d3e1f2a4b69c8d7e5f",
            "3a1b2c4d",
        ),
        (
            "nuget-api-key",
            "oy2a9f3b7c2a1d4e8f60b5a9c7d3e1f2a4b69c",
            "8d7e5f3a",
        ),
        (
            "sonarqube-token",
            "squ_9f3b7c2a1d4e8f60b5a9c7d3e1f2a4b6",
            "9c8d7e5f",
        ),
        (
            "langsmith-api-key",
            "lsv2_pt_9f3b7c2a1d4e8f60b5a9c7d3e1f2a4b6_9c",
            "8d7e5f3a",
        ),
        (
            "tailscale-auth-key",
            "tskey-auth-kQ2vL8nP4w-R7tY1uI6oP3aS5dF",
            "gHjK9mQ2",
        ),
        (
            "pulumi-access-token",
            "pul-9f3b7c2a1d4e8f60b5a9c7d3e1f2a4b6",
            "9c8d7e5f",
        ),
        (
            "supabase-access-token",
            "sbp_9f3b7c2a1d4e8f60b5a9c7d3e1f2a4b6",
            "9c8d7e5f",
        ),
        (
            "jfrog-access-token",
            "cmVmdGtuOjAxQq2VL8nP4wR7tY1uI6oP3aS5dFgHjK9mQ2",
            "vL8nP4wR",
        ),
        (
            "asana-pat",
            "1/1201234567890123:9f3b7c2a1d4e8f60b5a9c7d3",
            "e1f2a4b6",
        ),
    ];

    #[test]
    fn the_sample_set_covers_every_rule_added_after_python() {
        // A rule appended without a sample would be a pattern nothing ever
        // runs, so the list above has to track the table.
        assert_eq!(
            SECRET_RULES
                .iter()
                .skip(PYTHON_ERA_PROVIDER_RULES)
                .map(|rule| rule.rule_id)
                .collect::<Vec<_>>(),
            RULES_ADDED_AFTER_PYTHON
                .iter()
                .map(|(rule_id, _, _)| *rule_id)
                .collect::<Vec<_>>(),
        );
    }

    #[test]
    fn every_rule_added_after_python_finds_its_own_credential() {
        for (rule_id, head, tail) in RULES_ADDED_AFTER_PYTHON {
            let text = format!("SERVICE_CREDENTIAL = \"{head}{tail}\"");
            let summary = scan_secret_text(&text, "config/prod.env", "working_tree", None, 200);
            let found: Vec<&str> = summary
                .findings
                .iter()
                .map(|finding| finding.rule_id)
                .collect();
            assert!(found.contains(&rule_id), "{rule_id}: {found:?}");
        }
    }

    #[test]
    fn an_overlong_value_is_never_reported_as_a_fragment_of_itself() {
        // A value longer than the provider's own token must not come back as
        // the provider's token with its tail cut off: the fragment carries a
        // fingerprint of something that was never a credential, and the
        // generic rule reports the whole value alongside it as a second
        // finding for the same secret. Either the provider claims the whole
        // value or it claims nothing and the generic rule speaks for it, so
        // one line holds one finding.
        for (rule_id, head, tail) in RULES_ADDED_AFTER_PYTHON {
            let value = format!("{head}{tail}Zz9Qq2Vv");
            let text = format!("SERVICE_CREDENTIAL = \"{value}\"");
            let summary = scan_secret_text(&text, "config/prod.env", "working_tree", None, 200);
            for finding in &summary.findings {
                if finding.rule_id != rule_id {
                    continue;
                }
                assert_eq!(
                    finding.candidate, value,
                    "{rule_id} reported a fragment of the value"
                );
            }
            // The fragment is what splits one credential into two findings:
            // the provider rule fingerprints the part it took and the generic
            // rule reports the whole value it did not recognise.
            let claimed: Vec<&str> = summary
                .findings
                .iter()
                .map(|finding| finding.rule_id)
                .collect();
            assert!(
                !(claimed.contains(&rule_id) && claimed.contains(&"credential-assignment")),
                "{rule_id}: {claimed:?}"
            );
        }
    }

    #[test]
    fn a_value_that_runs_past_a_rule_in_its_own_alphabet_is_not_claimed() {
        // The sibling test above appends letters and digits, which a word
        // boundary already stops. These are the continuations it cannot see:
        // `-` is not a word character, so `\b` is satisfied between a letter
        // and a `-` and a rule whose alphabet holds `-` would report the head
        // of the value as the whole token. A ceiling on the quantifier does
        // the same to anything longer than the ceiling.
        //
        // Every sample is held in two pieces, as the rest of this file is.
        let discord_segment = format!("{}{}", "N2k8vQ4rT7yU1iO3pA5sD", "9fG6hJ0kL2zX4cV8bN1m");
        let google_tail = format!("{}{}", "Qq2VvL8nP4wR7tY1uI", "6oP3aS5dFg");
        let slack_tail = format!("{}{}", "Zz9Qq2VvL8nP4wR7tY", "1uI6oP3aS5dFgHjK9m");
        let sentry_tail = format!("{}{}", "Rr4TtY7uI1oP3aS5dF", "gH9jK2lZ6xC8vB4nM0");
        for (rule_id, value) in [
            // A third segment of 40 characters with a `-` at offset 30: a
            // boundary stops the match at the `-` and reports the first 30.
            (
                "discord-bot-token",
                format!(
                    "{}.{}.{}-{}",
                    &discord_segment[..24],
                    "Qq2VvL",
                    &discord_segment[..30],
                    "9fG6hJ0kL"
                ),
            ),
            // A 29th character that is a `-`, where the rule takes 28.
            (
                "google-oauth-client-secret",
                format!("GOCSPX-{google_tail}-{}", "9fG6hJ0kL"),
            ),
            // Longer than the 255 characters the rule used to cap at.
            (
                "slack-app-token",
                format!("xapp-1-{}", slack_tail.repeat(10)),
            ),
            (
                "sentry-auth-token",
                format!("sntrys_{}", sentry_tail.repeat(10)),
            ),
        ] {
            let text = format!("SERVICE_CREDENTIAL = \"{value}\"");
            let summary = scan_secret_text(&text, "config/prod.env", "working_tree", None, 200);
            for finding in &summary.findings {
                if finding.rule_id != rule_id {
                    continue;
                }
                assert_eq!(
                    finding.candidate, value,
                    "{rule_id} reported a fragment of the value"
                );
            }
            let claimed: Vec<&str> = summary
                .findings
                .iter()
                .map(|finding| finding.rule_id)
                .collect();
            assert!(
                !(claimed.contains(&rule_id) && claimed.contains(&"credential-assignment")),
                "{rule_id}: {claimed:?}"
            );
        }
    }

    #[test]
    fn two_neighbouring_values_of_one_rule_are_both_reported() {
        // A rule with no lookahead available proves its tail by capturing the
        // overrun. A guard that consumed the next character instead would eat
        // the separator between two values, and the second value's leading
        // guard would then find nothing before it, so only the first of a pair
        // would ever be reported. One space is the tightest such separator.
        //
        // Every sample is held in two pieces, as the rest of this file is.
        let slack = [
            format!("{}{}", "xapp-1-Zz9Qq2VvL8nP4wR7tY", "1uI6oP3aS5dFgHjK9m"),
            format!("{}{}", "xapp-1-Rr4TtY7uI1oP3aS5dF", "gH9jK2lZ6xC8vB4nM0"),
        ];
        let google = [
            format!("{}{}", "GOCSPX-Qq2VvL8nP4wR7tY1u", "I6oP3aS5dFg"),
            format!("{}{}", "GOCSPX-Rr4TtY7uI1oP3aS5d", "FgH9jK2lZ6x"),
        ];
        let sentry = [
            format!(
                "{}{}",
                "sntrys_Rr4TtY7uI1oP3aS5dFgH9jK2lZ6xC8vB4nM0", "Qq2VvL8nP4wR7tY1uI6oP3aS5dFg"
            ),
            format!(
                "{}{}",
                "sntryu_Zz9Qq2VvL8nP4wR7tY1uI6oP3aS5dFgHjK9m", "Rr4TtY7uI1oP3aS5dFgH9jK2l"
            ),
        ];
        let discord = [
            format!(
                "{}{}",
                "N2k8vQ4rT7yU1iO3pA5sD9fG.Qq2VvL.", "6hJ0kL2zX4cV8bN1mZz9Qq2VvL8nP4wR"
            ),
            format!(
                "{}{}",
                "M1a2B3c4D5e6F7g8H9i0J1k2.Rr4TtY.", "7uI1oP3aS5dFgH9jK2lZ6xC8vB4nM0Q"
            ),
        ];
        for (rule_id, pair) in [
            ("slack-app-token", &slack),
            ("google-oauth-client-secret", &google),
            ("sentry-auth-token", &sentry),
            ("discord-bot-token", &discord),
        ] {
            let text = format!("SERVICE_CREDENTIALS = \"{} {}\"", pair[0], pair[1]);
            let summary = scan_secret_text(&text, "config/prod.env", "working_tree", None, 200);
            let claimed: Vec<&str> = summary
                .findings
                .iter()
                .filter(|finding| finding.rule_id == rule_id)
                .map(|finding| finding.candidate.as_str())
                .collect();
            assert_eq!(
                claimed,
                vec![pair[0].as_str(), pair[1].as_str()],
                "{rule_id} did not report both neighbours"
            );
        }
    }

    #[test]
    fn the_mailgun_rule_leaves_an_ordinary_cache_key_alone() {
        // `key-` with a hex digest after it is a common shape for keys that
        // open nothing.
        // Held in two pieces, as every other sample in this file is.
        let digest = format!("{}{}", "9f3b7c2a1d4e8f60b", "5a9c7d3e1f2a4b6");
        for name in ["cache-key-", "idempotency-key-", "object_key-"] {
            let text = format!("entry = \"{name}{digest}\"");
            let summary = scan_secret_text(&text, "src/cache.rs", "working_tree", None, 200);
            let claimed: Vec<&str> = summary
                .findings
                .iter()
                .map(|finding| finding.rule_id)
                .collect();
            assert!(!claimed.contains(&"mailgun-api-key"), "{name}: {claimed:?}");
        }
    }

    #[test]
    fn a_mailgun_key_opening_a_line_is_reported_on_its_own_line() {
        // The rule consumes the character before the key to prove the key
        // starts where a word does. On every line but the first that
        // character is the newline that ended the line above, so a finding
        // anchored on the whole match would name the previous line and score
        // that line's text.
        // The line above carries a sample marker and the key's own line carries
        // a credential name, so the scoring reasons say which line was read.
        let digest = format!("{}{}", "9f3b7c2a1d4e8f60b", "5a9c7d3e1f2a4b6");
        let text = format!("# example configuration\nMAILGUN_API_KEY = key-{digest}\n");
        let summary = scan_secret_text(&text, "config/prod.env", "working_tree", None, 200);
        let finding = summary
            .findings
            .iter()
            .find(|finding| finding.rule_id == "mailgun-api-key")
            .expect("the key on the second line is still a finding");
        assert_eq!(finding.line, 2);
        assert!(
            finding.context_reasons.contains(&"credential-name-context"),
            "{:?}",
            finding.context_reasons
        );
        assert!(
            !finding.context_reasons.contains(&"sample-marker-context"),
            "{:?}",
            finding.context_reasons
        );
    }

    #[test]
    fn the_doppler_rule_reads_cli_and_config_scoped_tokens() {
        // A Doppler service token carries the config it was cut for, a CLI
        // token uses its own `ct` kind, and a service account identity token
        // uses `said`, which the `sa` kind does not cover. All three were
        // missed while only the shorter kinds were listed.
        for (head, tail) in [
            ("dp.ct.a7Kq2VL8nP4wR7tY1uI6oP3", "aS5dFgHjK9mQ2vL8nP4w"),
            ("dp.st.dev.a7Kq2VL8nP4wR7tY1uI6oP3", "aS5dFgHjK9mQ2vL8nP4w"),
            ("dp.said.a7Kq2VL8nP4wR7tY1uI6oP3", "aS5dFgHjK9mQ2vL8nP4w"),
        ] {
            let text = format!("SERVICE_CREDENTIAL = \"{head}{tail}\"");
            let summary = scan_secret_text(&text, "config/prod.env", "working_tree", None, 200);
            let claimed: Vec<&str> = summary
                .findings
                .iter()
                .map(|finding| finding.rule_id)
                .collect();
            assert!(claimed.contains(&"doppler-token"), "{head}: {claimed:?}");
        }
    }

    #[test]
    fn a_doppler_identity_token_is_read_without_a_credential_name_beside_it() {
        // A token pasted on its own, with no assignment to name it, is the
        // shape a leaked credential most often takes. The rule's format is
        // specific enough to stand alone, so the finding must not depend on
        // surrounding text.
        let head = "dp.said.a7Kq2VL8nP4wR7tY1uI6oP3";
        let tail = "aS5dFgHjK9mQ2vL8nP4w";
        let text = format!("{head}{tail}\n");
        let summary = scan_secret_text(&text, "notes/scratch.txt", "working_tree", None, 200);
        let claimed: Vec<&str> = summary
            .findings
            .iter()
            .map(|finding| finding.rule_id)
            .collect();
        assert!(claimed.contains(&"doppler-token"), "{claimed:?}");
    }

    #[test]
    fn a_rule_added_after_python_does_not_claim_another_rules_credential() {
        // Each sample belongs to exactly one provider. A pattern loose enough
        // to swallow a neighbour's token would mislabel a real finding.
        for (rule_id, head, tail) in RULES_ADDED_AFTER_PYTHON {
            let text = format!("SERVICE_CREDENTIAL = \"{head}{tail}\"");
            let summary = scan_secret_text(&text, "config/prod.env", "working_tree", None, 200);
            for finding in &summary.findings {
                let claimed = finding.rule_id;
                let is_own = claimed == rule_id;
                let is_python_era = PYTHON_ERA_RULE_IDS.contains(&claimed);
                let is_contextual = claimed == "credential-assignment";
                assert!(
                    is_own || is_python_era || is_contextual,
                    "{rule_id} also matched {claimed}"
                );
            }
        }
    }
}

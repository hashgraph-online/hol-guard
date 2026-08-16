"""Context-aware leaked-secret detection for HOL Guard.

The runtime in this module is deliberately local, deterministic, and dependency-free.
It combines strong provider formats with contextual scoring for generic credentials,
entropy/rarity signals, and conservative sample suppression.

Security invariants:
- public finding payloads never contain the raw candidate secret;
- fingerprints are HMACs and require an explicit caller-owned key;
- no network or LLM call is made by detection;
- generic findings require contextual evidence and are suppressed in obvious
  documentation/test fixtures unless the candidate has a strong provider format.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Literal, TypedDict

SecretSeverity = Literal["medium", "high", "critical"]
SecretConfidence = Literal["low", "medium", "high"]
SecretScanSource = Literal["working_tree", "git_history", "text", "staged"]
SecretValidationKind = Literal[
    "none",
    "github",
    "gitlab",
    "aws",
    "slack",
    "stripe",
    "openai",
    "anthropic",
    "huggingface",
    "npm",
    "pypi",
    "google",
    "sendgrid",
]


class SecretRuleCatalogEntry(TypedDict):
    """Public, non-sensitive detector catalog metadata."""

    rule_id: str
    family: str
    severity: SecretSeverity
    validation: SecretValidationKind
    strong_format: bool
    description: str


_DETECTOR_VERSION = "guard-secrets-v1"

_SAMPLE_WORDS = re.compile(
    r"(?i)(?:example|sample|dummy|fake|fixture|placeholder|changeme|replace[_-]?me|"
    r"redacted|synthetic|mock(?:ed)?|canary|not[_-]?real|invalid[_-]?"
    r"(?:key|token|secret|password)?|your[_-]?(?:api[_-]?)?"
    r"(?:key|token|secret|password)|test[_-]?(?:key|token|secret|password))"
)
_COMMON_PLACEHOLDER = re.compile(
    r"(?i)^(?:p@?ssw0rd(?:1234?|[!@#$%^&*]+)?|password(?:1234?|[!@#$%^&*]+)?|"
    r"(?:super|my|your|replace|change|invalid|fake|dummy|sample|test|fixture|not[_-]?real)"
    r"[_-](?:api[_-]?)?(?:secret|token|password|key)(?:[_-].*)?)$"
)
_CREDENTIAL_KEYWORDS = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?key|auth[_-]?token|bearer|credential|password|passwd|"
    r"private[_-]?key|secret|token|webhook|client[_-]?secret)"
)
_ASSIGNMENT = re.compile(
    r"(?im)(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,80})\s*[:=]\s*"
    r"(?P<quote>[\"']?)(?P<secret>[^\s\"',}{]{12,256})(?P=quote)"
)
_GENERIC_CANDIDATE_POLICY_VERSION = "credential-expression-filter-v2"
_CODE_REFERENCE_PREFIXES = (
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
)
_CODE_MEMBER_REFERENCE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\??\.[A-Za-z_$][A-Za-z0-9_$]*)+$")
_CODE_CALL_REFERENCE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\??\.[A-Za-z_$][A-Za-z0-9_$]*)*\s*\(")
_CODE_IDENTIFIER_REFERENCE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")
_INTERPOLATED_REFERENCE = re.compile(r"^(?:\$\{|\$\(|\{\{|<%|%\{|@\{)")
_SHELL_VARIABLE_REFERENCE = re.compile(
    r"^\$(?:(?:env|global|local|private|script):)?[A-Za-z_][A-Za-z0-9_]*$",
    re.IGNORECASE,
)
_CODE_COORDINATE = re.compile(r"^[A-Za-z0-9_.@/+~-]+:[A-Za-z0-9_.@/+~:-]+$")
_TEST_FIXTURE_CONTEXT = re.compile(
    r"(?i)(?:\bdescribe\s*\(|\bit\s*\(|\btest\s*\(|\bexpect\s*\(|\bassert\b|"
    r"\bmock(?:ed)?\b|\bfixture\b|\bsample\b|\bfake\b|\bsynthetic\b|\bcanary\b|"
    r"\bredact(?:ed|ion)?\b|\bsanitiz(?:e|ed|ation)\b|\bmask(?:ed|ing)?\b|"
    r"\bscrub(?:bed|bing)?\b|\bnot[_ -]?real\b|\binvalid\b)"
)
_SAMPLE_PATH_TOKEN = re.compile(
    r"(?i)(?:^|[._-])(?:test|tests|spec|fixture|fixtures|example|examples|sample|samples|"
    r"mock|mocks|demo|benchmark|scenario|scenarios|proof|canary)(?:[._-]|$)"
)
_PUBLIC_CLIENT_CONFIG_BASENAMES = frozenset({"google-services.json", "googleservice-info.plist"})
_NON_SECRET_NAME_TERMINALS = frozenset(
    {
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
    }
)
_SECRET_ASSIGNMENT_SUFFIXES = (
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
)
_CODE_SUFFIXES = frozenset(
    {
        ".bash",
        ".cjs",
        ".cs",
        ".dart",
        ".go",
        ".gradle",
        ".java",
        ".js",
        ".jsx",
        ".kt",
        ".kts",
        ".lua",
        ".mjs",
        ".php",
        ".ps1",
        ".py",
        ".rb",
        ".rs",
        ".scala",
        ".sh",
        ".svelte",
        ".swift",
        ".ts",
        ".tsx",
        ".vue",
        ".zsh",
    }
)
_SHELL_SUFFIXES = frozenset({".bash", ".ps1", ".sh", ".zsh"})
_DATABASE_URL = re.compile(
    r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://"
    r"[^\s:/@]{1,128}:(?P<secret>[^\s/@]{6,256})@[^\s]+"
)
_BASIC_AUTH_URL = re.compile(r"(?i)\bhttps?://[^\s:/@]{1,128}:(?P<secret>[^\s/@]{8,256})@[^\s]+")
_JWT = re.compile(r"\b(?P<secret>eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b")

_DOC_SEGMENTS = frozenset(
    {
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
    }
)
_DOC_SUFFIXES = frozenset({".md", ".mdx", ".rst", ".adoc", ".txt"})
_HIGH_SIGNAL_BASENAMES = frozenset(
    {
        ".env",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".git-credentials",
        "credentials",
        "secrets.yml",
        "secrets.yaml",
        "terraform.tfvars",
    }
)


@dataclass(frozen=True, slots=True)
class SecretRule:
    rule_id: str
    family: str
    severity: SecretSeverity
    pattern: re.Pattern[str]
    validation: SecretValidationKind = "none"
    strong_format: bool = True
    description: str = ""


@dataclass(frozen=True, slots=True)
class SecretFinding:
    rule_id: str
    family: str
    severity: SecretSeverity
    confidence: SecretConfidence
    confidence_score: float
    line: int
    path: str
    source: SecretScanSource
    commit: str | None
    validation: SecretValidationKind
    entropy: float
    context_reasons: tuple[str, ...]
    candidate: str = field(repr=False, compare=False)

    def fingerprint(self, key: bytes) -> str:
        """Return a tenant/caller-scoped HMAC without exposing candidate bytes."""

        if not key:
            raise ValueError("secret fingerprint key must not be empty")
        material = f"{self.rule_id}\0{self.candidate}".encode("utf-8", errors="strict")
        return hmac.new(key, material, hashlib.sha256).hexdigest()

    def to_public_dict(self, *, fingerprint_key: bytes | None = None) -> dict[str, object]:
        payload: dict[str, object] = {
            "rule_id": self.rule_id,
            "family": self.family,
            "severity": self.severity,
            "confidence": self.confidence,
            "confidence_score": round(self.confidence_score, 4),
            "line": self.line,
            "path": self.path,
            "source": self.source,
            "commit": self.commit,
            "validation": self.validation,
            "entropy": round(self.entropy, 4),
            "context_reasons": list(self.context_reasons),
        }
        if fingerprint_key is not None:
            payload["fingerprint"] = self.fingerprint(fingerprint_key)
        return payload


@dataclass(frozen=True, slots=True)
class SecretScanSummary:
    detector_version: str
    findings: tuple[SecretFinding, ...]

    def to_public_dict(self, *, fingerprint_key: bytes | None = None) -> dict[str, object]:
        return {
            "schema": "guard-secret-scan.v1",
            "detector_version": self.detector_version,
            "finding_count": len(self.findings),
            "findings": [finding.to_public_dict(fingerprint_key=fingerprint_key) for finding in self.findings],
        }


def _compile(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


SECRET_RULES: tuple[SecretRule, ...] = (
    SecretRule(
        "github-token",
        "GitHub token",
        "critical",
        _compile(r"\b(?P<secret>(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255}))\b"),
        "github",
        description="GitHub personal, OAuth, user, server, refresh, or fine-grained token.",
    ),
    SecretRule(
        "gitlab-token",
        "GitLab token",
        "critical",
        _compile(r"\b(?P<secret>glpat-[A-Za-z0-9_-]{20,255})\b"),
        "gitlab",
        description="GitLab personal/project/group access token.",
    ),
    SecretRule(
        "aws-access-key",
        "AWS access key ID",
        "high",
        _compile(r"\b(?P<secret>(?:AKIA|ASIA)[0-9A-Z]{16})\b"),
        "aws",
        description="AWS long-lived or STS access key identifier.",
    ),
    SecretRule(
        "slack-token",
        "Slack token",
        "critical",
        _compile(r"\b(?P<secret>xox[baprs]-[A-Za-z0-9-]{10,255})\b"),
        "slack",
        description="Slack bot, app, user, refresh, or service token.",
    ),
    SecretRule(
        "slack-webhook",
        "Slack incoming webhook",
        "critical",
        _compile(r"(?P<secret>https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{24,255})"),
        "slack",
        description="Slack incoming webhook URL.",
    ),
    SecretRule(
        "stripe-secret-key",
        "Stripe secret key",
        "critical",
        _compile(r"\b(?P<secret>(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,255})\b"),
        "stripe",
        description="Stripe secret or restricted API key.",
    ),
    SecretRule(
        "openai-api-key",
        "OpenAI API key",
        "critical",
        _compile(r"\b(?P<secret>sk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{20,255})\b"),
        "openai",
        description="OpenAI project/service/account API key.",
    ),
    SecretRule(
        "anthropic-api-key",
        "Anthropic API key",
        "critical",
        _compile(r"\b(?P<secret>sk-ant-[A-Za-z0-9_-]{20,255})\b"),
        "anthropic",
        description="Anthropic API key.",
    ),
    SecretRule(
        "huggingface-token",
        "Hugging Face token",
        "high",
        _compile(r"\b(?P<secret>hf_[A-Za-z0-9]{24,255})\b"),
        "huggingface",
        description="Hugging Face user or organization token.",
    ),
    SecretRule(
        "npm-token",
        "npm access token",
        "critical",
        _compile(r"\b(?P<secret>npm_[A-Za-z0-9]{30,255})\b"),
        "npm",
        description="npm granular or automation access token.",
    ),
    SecretRule(
        "pypi-token",
        "PyPI API token",
        "critical",
        _compile(r"\b(?P<secret>pypi-[A-Za-z0-9_-]{24,255})\b"),
        "pypi",
        description="PyPI scoped API token.",
    ),
    SecretRule(
        "google-api-key",
        "Google API key",
        "high",
        _compile(r"\b(?P<secret>AIza[0-9A-Za-z_-]{35})\b"),
        "google",
        description="Google Cloud/Firebase API key.",
    ),
    SecretRule(
        "sendgrid-api-key",
        "SendGrid API key",
        "critical",
        _compile(r"\b(?P<secret>SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b"),
        "sendgrid",
        description="SendGrid API key.",
    ),
    SecretRule(
        "pem-private-key",
        "PEM private key",
        "critical",
        _compile(
            r"(?P<secret>-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)",
            re.MULTILINE,
        ),
        description="Private-key material in PEM/OpenSSH-style form.",
    ),
    SecretRule(
        "database-url-password",
        "Database URL password",
        "critical",
        _DATABASE_URL,
        strong_format=False,
        description="Password embedded in a database connection URL.",
    ),
    SecretRule(
        "basic-auth-url-password",
        "Basic-auth URL password",
        "high",
        _BASIC_AUTH_URL,
        strong_format=False,
        description="Credential embedded in an HTTP(S) URL.",
    ),
    SecretRule(
        "jwt-token",
        "JWT bearer token",
        "high",
        _JWT,
        strong_format=False,
        description="JWT-like bearer token in credential context.",
    ),
)


def detector_version() -> str:
    material_parts = [
        f"{rule.rule_id}|{rule.severity}|{rule.validation}|{rule.pattern.pattern}|{rule.pattern.flags}"
        for rule in SECRET_RULES
    ]
    material_parts.append(
        "|".join(
            (
                "credential-assignment",
                _ASSIGNMENT.pattern,
                str(_ASSIGNMENT.flags),
                _GENERIC_CANDIDATE_POLICY_VERSION,
            )
        )
    )
    digest = hashlib.sha256("\n".join(material_parts).encode("utf-8")).hexdigest()[:16]
    return f"{_DETECTOR_VERSION}:{digest}"


def secret_rule_catalog() -> list[SecretRuleCatalogEntry]:
    entries = [
        SecretRuleCatalogEntry(
            rule_id=rule.rule_id,
            family=rule.family,
            severity=rule.severity,
            validation=rule.validation,
            strong_format=rule.strong_format,
            description=rule.description,
        )
        for rule in SECRET_RULES
    ]
    entries.append(
        SecretRuleCatalogEntry(
            rule_id="credential-assignment",
            family="Contextual credential assignment",
            severity="high",
            validation="none",
            strong_format=False,
            description="High-entropy credential assignment accepted only with contextual evidence.",
        )
    )
    return entries


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for character in value:
        counts[character] = counts.get(character, 0) + 1
    length = float(len(value))
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _rarity_score(value: str) -> float:
    if not value:
        return 0.0
    entropy_component = min(shannon_entropy(value) / 5.2, 1.0)
    classes = sum(
        int(bool(pattern.search(value)))
        for pattern in (
            re.compile(r"[a-z]"),
            re.compile(r"[A-Z]"),
            re.compile(r"[0-9]"),
            re.compile(r"[^A-Za-z0-9]"),
        )
    )
    class_component = min(classes / 3.0, 1.0)
    length_component = min(max(len(value) - 12, 0) / 36.0, 1.0)
    return min((entropy_component * 0.55) + (class_component * 0.2) + (length_component * 0.25), 1.0)


def _normalized_path(path: str | None) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").strip().lower()


def _path_is_documentation(path: str) -> bool:
    normalized = _normalized_path(path)
    if not normalized:
        return False
    pure = PurePosixPath(normalized)
    parts = set(pure.parts)
    return bool(parts & _DOC_SEGMENTS) or pure.suffix in _DOC_SUFFIXES


def _path_is_sample_fixture(path: str) -> bool:
    normalized = _normalized_path(path)
    if not normalized:
        return False
    pure = PurePosixPath(normalized)
    if set(pure.parts) & _DOC_SEGMENTS:
        return True
    return _SAMPLE_PATH_TOKEN.search(pure.name) is not None


def _path_is_public_client_config(path: str) -> bool:
    return PurePosixPath(_normalized_path(path)).name in _PUBLIC_CLIENT_CONFIG_BASENAMES


def _path_is_high_signal(path: str) -> bool:
    normalized = _normalized_path(path)
    if not normalized:
        return False
    pure = PurePosixPath(normalized)
    basename = pure.name
    if basename == ".env" or basename.startswith(".env."):
        return True
    return basename in _HIGH_SIGNAL_BASENAMES or any(part in {".aws", ".ssh", ".gnupg"} for part in pure.parts)


def _character_class_count(value: str) -> int:
    return sum(
        (
            any(character.islower() for character in value),
            any(character.isupper() for character in value),
            any(character.isdigit() for character in value),
            any(not character.isalnum() for character in value),
        )
    )


def _largest_character_share(value: str) -> float:
    if not value:
        return 1.0
    counts: dict[str, int] = {}
    for character in value:
        counts[character] = counts.get(character, 0) + 1
    return max(counts.values()) / len(value)


def _surrounding_context(text: str, match_start: int, *, radius: int = 3) -> str:
    lines = text.splitlines()
    line_index = text.count("\n", 0, match_start)
    start = max(0, line_index - radius)
    end = min(len(lines), line_index + radius + 1)
    return "\n".join(lines[start:end])[:4096]


def _obvious_sample(candidate: str, context: str, *, path: str = "") -> bool:
    value = candidate.strip()
    unwrapped = value.strip("<>[]{}()")
    if _COMMON_PLACEHOLDER.fullmatch(unwrapped) is not None:
        return True
    if _SAMPLE_WORDS.search(value) is not None:
        return True
    has_sample_context = _SAMPLE_WORDS.search(context) is not None or _path_is_sample_fixture(path)
    if not has_sample_context:
        return False
    return _rarity_score(value) < 0.62 or len(value) < 20 or _largest_character_share(value) >= 0.4


def _normalized_assignment_name(name: str) -> str:
    snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return re.sub(r"[^A-Za-z0-9]+", "_", snake).strip("_").lower()


def _assignment_name_likely_holds_secret(name: str) -> bool:
    normalized = _normalized_assignment_name(name)
    if not normalized:
        return False
    if normalized.startswith(("indexnow_", "next_public_", "public_")):
        return False
    terminal = normalized.rsplit("_", maxsplit=1)[-1]
    if terminal in _NON_SECRET_NAME_TERMINALS:
        return False
    return any(normalized == suffix or normalized.endswith(f"_{suffix}") for suffix in _SECRET_ASSIGNMENT_SUFFIXES)


def _candidate_is_indirect_reference(
    candidate: str,
    *,
    quoted: bool,
    path: str,
) -> bool:
    """Reject code/config expressions that name a secret without containing it."""

    value = candidate.strip()
    if not value:
        return True
    lowered = value.lower()
    if lowered in {"false", "none", "null", "true", "undefined"}:
        return True
    if _INTERPOLATED_REFERENCE.match(value) is not None:
        return True
    if _SHELL_VARIABLE_REFERENCE.fullmatch(value) is not None:
        return True
    if lowered.startswith(_CODE_REFERENCE_PREFIXES):
        return True
    if _CODE_CALL_REFERENCE.match(value) is not None:
        return True
    if _CODE_MEMBER_REFERENCE.fullmatch(value) is not None:
        return True
    suffix = PurePosixPath(_normalized_path(path)).suffix
    if not quoted and _CODE_COORDINATE.fullmatch(value) is not None:
        return True
    if quoted:
        return False
    if any(operator in value for operator in ("=>", "??", "||", "&&", "::")):
        return True
    if any(character in value for character in "()[]{};`<>:"):
        return True
    if suffix not in _CODE_SUFFIXES or _CODE_IDENTIFIER_REFERENCE.fullmatch(value) is None:
        return False
    digit_count = sum(character.isdigit() for character in value)
    return value[0].islower() and digit_count <= 1


def _generic_candidate_is_plausible(
    candidate: str,
    *,
    quoted: bool,
    path: str,
    context: str,
) -> bool:
    value = candidate.strip()
    if not value or _obvious_sample(value, context, path=path):
        return False
    lowered = value.lower()
    if re.match(r"^[a-z][a-z0-9+.-]*://", lowered) is not None:
        return False
    if "/" in value or "\\" in value:
        return False
    if _largest_character_share(value) >= 0.55:
        return False
    entropy = shannon_entropy(value)
    classes = _character_class_count(value)
    suffix = PurePosixPath(_normalized_path(path)).suffix
    if _path_is_high_signal(path):
        return len(value) >= 12 and (entropy >= 3.2 or classes >= 3)
    if re.fullmatch(r"[A-Fa-f0-9]{32,}", value) is not None:
        return True
    if suffix in _CODE_SUFFIXES:
        return len(value) >= 20 and ((classes >= 3 and entropy >= 3.65) or entropy >= 4.2)
    return len(value) >= 16 and _rarity_score(value) >= 0.58


def _provider_match_is_fixture(
    *,
    rule: SecretRule,
    candidate: str,
    text: str,
    match_start: int,
    path: str,
) -> bool:
    if rule.rule_id == "google-api-key" and _path_is_public_client_config(path):
        return True
    context = _surrounding_context(text, match_start)
    unwrapped = candidate.strip().strip("<>[]{}()")
    explicit_placeholder = (
        _COMMON_PLACEHOLDER.fullmatch(unwrapped) is not None or _SAMPLE_WORDS.search(candidate) is not None
    )
    if explicit_placeholder and (_path_is_sample_fixture(path) or _SAMPLE_WORDS.search(context) is not None):
        return True
    if _path_is_high_signal(path):
        return False
    return _path_is_sample_fixture(path) and _TEST_FIXTURE_CONTEXT.search(context) is not None


def _confidence_label(score: float) -> SecretConfidence:
    if score >= 0.84:
        return "high"
    if score >= 0.64:
        return "medium"
    return "low"


def _context_score(
    candidate: str,
    *,
    path: str,
    line_text: str,
    strong_format: bool,
) -> tuple[float, tuple[str, ...]]:
    score = 0.9 if strong_format else 0.3
    reasons: list[str] = ["provider-format" if strong_format else "contextual-candidate"]
    rarity = _rarity_score(candidate)
    score += rarity * (0.08 if strong_format else 0.34)
    if rarity >= 0.72:
        reasons.append("high-token-rarity")
    if _CREDENTIAL_KEYWORDS.search(line_text) is not None:
        score += 0.22
        reasons.append("credential-name-context")
    if _path_is_high_signal(path):
        score += 0.14
        reasons.append("sensitive-file-context")
    if _path_is_documentation(path):
        score -= 0.28 if not strong_format else 0.08
        reasons.append("documentation-context")
    if _SAMPLE_WORDS.search(line_text) is not None:
        score -= 0.32 if not strong_format else 0.1
        reasons.append("sample-marker-context")
    return max(0.0, min(score, 1.0)), tuple(reasons)


def _line_number(text: str, match_start: int) -> int:
    return text.count("\n", 0, match_start) + 1


def _line_text(text: str, match_start: int) -> str:
    start = text.rfind("\n", 0, match_start) + 1
    end = text.find("\n", match_start)
    if end < 0:
        end = len(text)
    return text[start:end][:1024]


def _finding_from_match(
    *,
    rule: SecretRule,
    candidate: str,
    text: str,
    match_start: int,
    path: str,
    source: SecretScanSource,
    commit: str | None,
) -> SecretFinding | None:
    line_text = _line_text(text, match_start)
    if rule.strong_format:
        if _provider_match_is_fixture(
            rule=rule,
            candidate=candidate,
            text=text,
            match_start=match_start,
            path=path,
        ):
            return None
    elif _obvious_sample(candidate, line_text, path=path):
        return None
    score, reasons = _context_score(
        candidate,
        path=path,
        line_text=line_text,
        strong_format=rule.strong_format,
    )
    minimum_score = 0.56 if rule.strong_format else 0.64
    if score < minimum_score:
        return None
    return SecretFinding(
        rule_id=rule.rule_id,
        family=rule.family,
        severity=rule.severity,
        confidence=_confidence_label(score),
        confidence_score=score,
        line=_line_number(text, match_start),
        path=path,
        source=source,
        commit=commit,
        validation=rule.validation,
        entropy=shannon_entropy(candidate),
        context_reasons=reasons,
        candidate=candidate,
    )


def scan_secret_text(
    text: str,
    *,
    path: str = "",
    source: SecretScanSource = "text",
    commit: str | None = None,
    max_findings: int = 200,
) -> SecretScanSummary:
    """Scan text for leaked credentials without serializing candidate bytes."""

    if not isinstance(text, str) or not text:
        return SecretScanSummary(detector_version=detector_version(), findings=())
    bounded_max = max(1, min(int(max_findings), 10_000))
    findings: list[SecretFinding] = []
    seen: set[tuple[str, int, str]] = set()

    for rule in SECRET_RULES:
        for match in rule.pattern.finditer(text):
            candidate = match.groupdict().get("secret") or match.group(0)
            finding = _finding_from_match(
                rule=rule,
                candidate=candidate,
                text=text,
                match_start=match.start(),
                path=path,
                source=source,
                commit=commit,
            )
            if finding is None:
                continue
            identity = (finding.rule_id, finding.line, candidate)
            if identity in seen:
                continue
            seen.add(identity)
            findings.append(finding)
            if len(findings) >= bounded_max:
                findings.sort(key=lambda item: (item.path, item.line, item.rule_id, item.commit or ""))
                return SecretScanSummary(detector_version=detector_version(), findings=tuple(findings))

    # Generic assignments are intentionally evaluated after provider formats so
    # the structured detector wins when both identify the same token.
    provider_candidates = {finding.candidate for finding in findings}
    generic_rule = SecretRule(
        rule_id="credential-assignment",
        family="Contextual credential assignment",
        severity="high",
        pattern=_ASSIGNMENT,
        strong_format=False,
        description="Contextual high-entropy credential assignment.",
    )
    for match in _ASSIGNMENT.finditer(text):
        candidate = match.group("secret")
        if candidate in provider_candidates:
            continue
        name = match.group("name")
        if not _assignment_name_likely_holds_secret(name):
            continue
        quoted = bool(match.group("quote"))
        if _candidate_is_indirect_reference(
            candidate,
            quoted=quoted,
            path=path,
        ):
            continue
        if not _generic_candidate_is_plausible(
            candidate,
            quoted=quoted,
            path=path,
            context=match.group(0),
        ):
            continue
        finding = _finding_from_match(
            rule=generic_rule,
            candidate=candidate,
            text=text,
            match_start=match.start(),
            path=path,
            source=source,
            commit=commit,
        )
        if finding is None:
            continue
        identity = (finding.rule_id, finding.line, candidate)
        if identity in seen:
            continue
        seen.add(identity)
        findings.append(finding)
        if len(findings) >= bounded_max:
            break

    findings.sort(key=lambda item: (item.path, item.line, item.rule_id, item.commit or ""))
    return SecretScanSummary(detector_version=detector_version(), findings=tuple(findings))


__all__ = [
    "SECRET_RULES",
    "SecretConfidence",
    "SecretFinding",
    "SecretRule",
    "SecretRuleCatalogEntry",
    "SecretScanSource",
    "SecretScanSummary",
    "SecretSeverity",
    "SecretValidationKind",
    "detector_version",
    "scan_secret_text",
    "secret_rule_catalog",
    "shannon_entropy",
]

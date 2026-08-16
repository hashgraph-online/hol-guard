"""Versioned cross-surface contracts for HOL Guard Secrets.

The contracts in this module are dependency-free so the same semantics can be
used by the local CLI, hooks, IDE bridge, isolated workers, and release evidence
tooling. Serializable forms are strict and explicitly exclude raw credential
material and arbitrary source context.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Final, cast


class SecretContractError(ValueError):
    """Raised when an external Secrets contract is invalid or unsafe."""


class ParityState(str, Enum):
    """Evidence state for one public capability claim."""

    UNMAPPED = "unmapped"
    DESIGNED = "designed"
    IMPLEMENTED = "implemented"
    TESTED = "tested"
    VERIFIED_ON_RELEASE_CANDIDATE = "verified_on_release_candidate"
    GENERALLY_AVAILABLE = "generally_available"


class PreventionOutcome(str, Enum):
    """Canonical cross-surface prevention outcomes."""

    CLEAN = "clean"
    WARN = "warn"
    SOFT_BLOCK = "soft_block"
    POLICY_BLOCK = "policy_block"
    PARTIAL = "partial"
    DEGRADED = "degraded"
    ERROR = "error"


class SecretClass(str, Enum):
    """Canonical candidate classification labels."""

    REAL = "real"
    PLACEHOLDER_OR_EXAMPLE = "placeholder_or_example"
    WEAK_OR_AMBIGUOUS = "weak_or_ambiguous"
    UNKNOWN = "unknown"


class SecretValidity(str, Enum):
    """Safe normalized result of optional credential validation."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"
    UNSUPPORTED = "unsupported"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"


class SecretExposure(str, Enum):
    """Normalized exposure surface for one occurrence."""

    LOCAL_ONLY = "local_only"
    PRIVATE_REPOSITORY = "private_repository"
    PUBLIC_REPOSITORY = "public_repository"
    PUBLIC_EXTERNAL_SURFACE = "public_external_surface"
    UNKNOWN = "unknown"


class SecretLifecycle(str, Enum):
    """Canonical logical-finding lifecycle."""

    NEW = "new"
    TRIAGED = "triaged"
    REMEDIATING = "remediating"
    AWAITING_REVERIFICATION = "awaiting_reverification"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    REOPENED = "reopened"


class SecretIgnoreScope(str, Enum):
    """Supported exact suppression scopes."""

    OCCURRENCE = "occurrence"
    SECRET_IDENTITY = "secret_identity"
    PATH_HASH = "path_hash"
    DETECTOR = "detector"
    FIXTURE = "fixture"
    REPOSITORY = "repository"
    LOCAL_WORKSPACE = "local_workspace"


class SecretIgnoreState(str, Enum):
    """Lifecycle states for an ignore decision."""

    REQUESTED = "requested"
    APPROVED = "approved"
    DENIED = "denied"
    CHANGES_REQUESTED = "changes_requested"
    REVOKED = "revoked"
    EXPIRED = "expired"


class SecretRuleMatcherKind(str, Enum):
    """Bounded declarative custom-rule matcher kinds."""

    PREFIX = "prefix"
    REGEX = "regex"
    ASSIGNMENT = "assignment"
    STRUCTURED = "structured"


class SecretRuleCompileState(str, Enum):
    """Safe custom-rule compilation states."""

    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"
    TOO_COMPLEX = "too_complex"


class SecretRolloutState(str, Enum):
    """Versioned custom-rule rollout states."""

    DRAFT = "draft"
    SHADOW = "shadow"
    CANARY = "canary"
    ACTIVE = "active"
    REVOKED = "revoked"


class SourceCapabilityStatus(str, Enum):
    """Stable support states used by the source-capability manifest."""

    SUPPORTED = "supported"
    PARTIAL = "partial"
    PLANNED = "planned"
    UNSUPPORTED = "unsupported"


_ACTIVE_IGNORE_STATES: Final = frozenset(
    {
        SecretIgnoreState.REQUESTED,
        SecretIgnoreState.APPROVED,
        SecretIgnoreState.CHANGES_REQUESTED,
    }
)
_PROHIBITED_KEY = re.compile(
    r"(?:^|_)(?:raw_value|raw_?secret|candidate(?:_value)?|credential(?:_value)?|"
    r"secret_?value|token_?value|source_(?:line|content|excerpt)|prompt|"
    r"tool_(?:output|result)|environment_?value|auth(?:orization)?_?header|"
    r"provider_?response(?:_body)?|absolute_?path)(?:$|_)",
    re.IGNORECASE,
)
_SECRET_LIKE_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,255}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,255}\b"),
    re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{24,255}"),
    re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,255}\b"),
    re.compile(r"\bsk-(?:(?:proj|svcacct|ant)-)?[A-Za-z0-9_-]{20,255}\b"),
    re.compile(r"\bhf_[A-Za-z0-9]{24,255}\b"),
    re.compile(r"\bnpm_[A-Za-z0-9]{30,255}\b"),
    re.compile(r"\bpypi-[A-Za-z0-9_-]{24,255}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|https?)://[^\s:/@]+:[^\s/@]{6,}@"),
    re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|"
        r"private[_-]?key|secret|token)\s*[:=]\s*[\"']?[^\s\"']{16,}"
    ),
)
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_COMMIT_SHA = re.compile(r"^[a-f0-9]{40}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:@/-]{1,160}$")
_SCHEMA_COVERAGE: Final = "guard-secret-coverage.v2"
_SCHEMA_IGNORE: Final = "guard-secret-ignore-decision.v2"
_SCHEMA_RULE: Final = "guard-secret-custom-rule.v2"
_SCHEMA_CAPABILITY_EVIDENCE: Final = "guard-secrets-capability-evidence.v2"
_SCHEMA_PRODUCT_BOUNDARIES: Final = "guard-secrets-product-boundaries.v2"
_SCHEMA_SOURCE_CAPABILITIES: Final = "guard-secrets-source-capabilities.v2"
_SCHEMA_REASON_CODES: Final = "guard-secrets-reason-codes.v2"

PARITY_STATES_V2: Final[tuple[str, ...]] = tuple(state.value for state in ParityState)
SOURCE_CAPABILITY_STATUS_VALUES_V2: Final[tuple[str, ...]] = tuple(state.value for state in SourceCapabilityStatus)
_RELEASE_STATES: Final = frozenset(
    {
        ParityState.VERIFIED_ON_RELEASE_CANDIDATE,
        ParityState.GENERALLY_AVAILABLE,
    }
)
_PARITY_STATE_RANK: Final = {state: index for index, state in enumerate(ParityState)}

_REASON_CODE_CATEGORIES_MUTABLE: dict[str, tuple[str, ...]] = {
    "coverage": (
        "archive_budget_exceeded",
        "binary_skipped",
        "encoding_unsupported",
        "file_changed_during_scan",
        "git_object_missing",
        "history_shallow",
        "lfs_object_missing",
        "max_bytes",
        "max_commits",
        "max_files",
        "max_findings",
        "source_unreadable",
    ),
    "detector": (
        "detector_bundle_invalid",
        "detector_unavailable",
        "model_bundle_invalid",
        "model_degraded",
    ),
    "validation": (
        "validation_error",
        "validation_rate_limited",
        "validation_unknown",
        "validation_unsupported",
    ),
    "policy": ("policy_block", "policy_refresh_required"),
    "worker": ("cleanup_failed", "worker_cancelled", "worker_timeout"),
    "cache": ("cache_stale",),
}
REASON_CODE_CATEGORIES_V2: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    dict(_REASON_CODE_CATEGORIES_MUTABLE)
)
REASON_CODE_RULES_V2: Final[Mapping[str, bool]] = MappingProxyType(
    {
        "stable": True,
        "non_sensitive": True,
        "unknown_codes_fail_closed": True,
        "raw_exception_text_forbidden": True,
    }
)
REASON_CODES_V2: Final[frozenset[str]] = frozenset(
    code for codes in _REASON_CODE_CATEGORIES_MUTABLE.values() for code in codes
)
IGNORE_REASON_CODES_V2: Final[frozenset[str]] = frozenset(
    {
        "approved_fixture",
        "duplicate_finding",
        "false_positive",
        "historical_decision",
        "known_public_value",
        "non_secret_identifier",
        "pending_review",
        "policy_exception",
        "revoked_credential",
        "test_fixture",
    }
)
FIXTURE_JUSTIFICATION_CODES_V2: Final[frozenset[str]] = frozenset(
    {
        "fixture_is_public_example",
        "fixture_is_redacted",
        "fixture_is_revoked",
        "fixture_is_synthetic",
    }
)

_PLAN_POLICIES_MUTABLE: dict[str, dict[str, object]] = {
    "free": {
        "local_scan": True,
        "staged_precommit": True,
        "agent_runtime": True,
        "public_aggregate": True,
        "private_repositories": 0,
        "private_repositories_mode": "fixed",
        "external_routing": False,
        "governed_ignores": False,
        "governed_ignores_enforced": False,
    },
    "solo": {
        "local_scan": True,
        "staged_precommit": True,
        "agent_runtime": True,
        "public_aggregate": True,
        "private_repositories": 5,
        "private_repositories_mode": "fixed",
        "external_routing": False,
        "governed_ignores": False,
        "governed_ignores_enforced": False,
    },
    "pro": {
        "local_scan": True,
        "staged_precommit": True,
        "agent_runtime": True,
        "public_aggregate": True,
        "private_repositories": 5,
        "private_repositories_mode": "configurable_above_solo",
        "external_routing": True,
        "governed_ignores": True,
        "governed_ignores_enforced": False,
    },
    "team": {
        "local_scan": True,
        "staged_precommit": True,
        "agent_runtime": True,
        "public_aggregate": True,
        "private_repositories": 5,
        "private_repositories_mode": "policy",
        "external_routing": True,
        "governed_ignores": True,
        "governed_ignores_enforced": True,
    },
}
PLAN_POLICIES_V2: Final[Mapping[str, Mapping[str, object]]] = MappingProxyType(
    {plan: MappingProxyType(dict(policy)) for plan, policy in _PLAN_POLICIES_MUTABLE.items()}
)

_PRODUCT_BOUNDARIES_MUTABLE: dict[str, dict[str, tuple[str, ...]]] = {
    "shared-detection": {
        "allowed_plans": ("free", "solo", "pro", "team"),
        "allowed_surfaces": (
            "cli",
            "github",
            "history",
            "ide",
            "local",
            "pre_commit",
            "staged",
            "working_tree",
        ),
    },
    "individual-plus": {
        "allowed_plans": ("free", "solo", "pro", "team"),
        "allowed_surfaces": ("github", "local"),
    },
    "free-local": {
        "allowed_plans": ("free", "solo", "pro", "team"),
        "allowed_surfaces": ("cli", "pre_commit"),
    },
    "cloud-monitoring": {
        "allowed_plans": ("solo", "pro", "team"),
        "allowed_surfaces": ("github", "github_check", "github_push", "pull_request", "scheduler"),
    },
    "cloud-reporting": {
        "allowed_plans": ("solo", "pro", "team"),
        "allowed_surfaces": ("api", "export", "portal"),
    },
    "organization-operations": {
        "allowed_plans": ("pro", "team"),
        "allowed_surfaces": ("api", "jira", "notion", "pagerduty", "portal", "slack", "webhook"),
    },
    "organization-governance": {
        "allowed_plans": ("pro", "team"),
        "allowed_surfaces": ("policy", "portal"),
    },
    "exposure-intelligence": {
        "allowed_plans": ("pro", "team"),
        "allowed_surfaces": ("public_intelligence",),
    },
    "public-funnel": {
        "allowed_plans": ("free", "solo", "pro", "team"),
        "allowed_surfaces": ("public_leak_check",),
    },
}
PRODUCT_BOUNDARIES_V2: Final[Mapping[str, Mapping[str, tuple[str, ...]]]] = MappingProxyType(
    {boundary: MappingProxyType(dict(policy)) for boundary, policy in _PRODUCT_BOUNDARIES_MUTABLE.items()}
)
PRODUCT_SURFACES_V2: Final[tuple[str, ...]] = tuple(
    sorted({surface for policy in _PRODUCT_BOUNDARIES_MUTABLE.values() for surface in policy["allowed_surfaces"]})
)
PRODUCT_INVARIANTS_V2: Final[tuple[str, ...]] = (
    "local_detection_unmetered",
    "cloud_outage_does_not_disable_local",
    "solo_does_not_receive_general_external_routing",
    "team_governance_remains_server_authoritative",
)

_SOURCE_CAPABILITY_SECTIONS_MUTABLE: dict[str, dict[str, str]] = {
    "file_classes": {
        "source_code": "supported",
        "environment_files": "supported",
        "configuration_files": "supported",
        "property_files": "supported",
        "documentation": "partial",
        "generated_code": "partial",
        "lockfiles": "partial",
        "archives": "planned",
        "binary_executables": "planned",
        "mobile_bundles": "planned",
        "container_layers": "planned",
        "notebooks": "planned",
    },
    "encodings": {
        "utf8": "supported",
        "utf8_bom": "supported",
        "ascii": "supported",
        "utf16": "planned",
        "base64_literals": "planned",
        "hex_literals": "planned",
        "url_encoding": "planned",
        "escaped_strings": "partial",
        "nested_encoding": "planned",
    },
    "archives": {
        "zip": "planned",
        "tar": "planned",
        "gzip": "planned",
        "jar": "planned",
        "wheel": "planned",
        "npm_package": "planned",
    },
    "git_modes": {
        "working_tree": "supported",
        "staged_index": "supported",
        "bounded_history": "supported",
        "commit_range": "partial",
        "all_reachable_refs": "planned",
        "shallow_clone_detection": "partial",
        "lfs_pointer_detection": "planned",
        "submodule_metadata": "planned",
        "worktrees": "partial",
        "alternates": "planned",
        "replace_refs": "planned",
    },
    "scm_events": {
        "github_push": "supported",
        "github_pull_request": "supported",
        "github_scheduled": "partial",
        "gitlab_push": "planned",
        "gitlab_merge_request": "planned",
        "bitbucket_push": "planned",
        "azure_devops_push": "planned",
    },
    "editors": {"vscode": "planned", "jetbrains": "planned", "lsp": "planned"},
    "operating_systems": {"linux": "supported", "macos": "supported", "windows": "supported"},
    "validators": {
        "github": "supported",
        "gitlab": "supported",
        "aws": "supported",
        "slack": "supported",
        "stripe": "supported",
        "openai": "supported",
        "anthropic": "supported",
        "huggingface": "supported",
        "npm": "supported",
        "pypi": "supported",
        "google": "supported",
        "sendgrid": "supported",
    },
    "notification_providers": {
        "github_checks": "supported",
        "email_safety_notice": "partial",
        "slack": "planned",
        "pagerduty": "planned",
        "jira": "planned",
        "notion": "planned",
        "signed_webhook": "planned",
    },
}
SOURCE_CAPABILITY_SECTIONS_V2: Final[Mapping[str, Mapping[str, str]]] = MappingProxyType(
    {section: MappingProxyType(dict(entries)) for section, entries in _SOURCE_CAPABILITY_SECTIONS_MUTABLE.items()}
)


def _normalized_key(value: str) -> str:
    """Normalize a field name before prohibited-field matching."""

    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return re.sub(r"[^A-Za-z0-9]+", "_", value).lower().strip("_")


def is_exact_commit_sha(value: str) -> bool:
    """Return whether *value* is a full lowercase Git commit SHA."""

    return _COMMIT_SHA.fullmatch(value) is not None


def _assert_safe_public_text(value: str, *, field_name: str) -> None:
    """Reject credential-shaped or control-bearing text before persistence."""

    if _CONTROL_CHARACTERS.search(value):
        raise SecretContractError(f"{field_name}: control characters are prohibited")
    if any(pattern.search(value) for pattern in _SECRET_LIKE_PATTERNS):
        raise SecretContractError(f"{field_name}: secret-like text is prohibited")


def reject_prohibited_fields(value: object, *, path: str = "$") -> None:
    """Reject raw-value-shaped fields and credential-shaped values recursively."""

    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise SecretContractError(f"{path}: mapping keys must be strings")
            if _PROHIBITED_KEY.search(_normalized_key(key)):
                raise SecretContractError(f"{path}.{key}: prohibited Secrets field")
            reject_prohibited_fields(nested, path=f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, nested in enumerate(value):
            reject_prohibited_fields(nested, path=f"{path}[{index}]")
    elif isinstance(value, str):
        _assert_safe_public_text(value, field_name=path)


def _strict_keys(payload: Mapping[str, object], allowed: set[str], *, schema: str) -> None:
    """Reject undeclared and prohibited keys for a versioned contract."""

    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise SecretContractError(f"{schema}: unknown fields: {', '.join(unknown)}")
    reject_prohibited_fields(payload)


def _mapping(value: object, *, field_name: str) -> Mapping[str, object]:
    """Return a mapping or raise a stable contract error."""

    if not isinstance(value, Mapping):
        raise SecretContractError(f"{field_name}: expected an object")
    return cast(Mapping[str, object], value)


def _str_tuple(value: object, *, field_name: str, allow_empty: bool = True) -> tuple[str, ...]:
    """Parse an array of strings into an immutable tuple."""

    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise SecretContractError(f"{field_name}: expected an array of strings")
    result = tuple(cast(list[str], value))
    if not allow_empty and not result:
        raise SecretContractError(f"{field_name}: must not be empty")
    for item in result:
        _assert_safe_public_text(item, field_name=field_name)
    return result


def _non_negative_int(value: object, *, field_name: str) -> int:
    """Parse a non-negative integer without accepting booleans."""

    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SecretContractError(f"{field_name}: expected a non-negative integer")
    return value


def _required_text(value: object, *, field_name: str, limit: int = 200) -> str:
    """Parse bounded non-empty privacy-safe text."""

    if not isinstance(value, str):
        raise SecretContractError(f"{field_name}: expected text")
    normalized = value.strip()
    if not normalized or len(normalized) > limit:
        raise SecretContractError(f"{field_name}: invalid length")
    _assert_safe_public_text(normalized, field_name=field_name)
    return normalized


def _optional_text(value: object, *, field_name: str, limit: int = 200) -> str | None:
    """Parse optional bounded privacy-safe text."""

    if value is None:
        return None
    return _required_text(value, field_name=field_name, limit=limit)


def _required_bool(value: object, *, field_name: str) -> bool:
    """Parse a required boolean without truthy coercion."""

    if not isinstance(value, bool):
        raise SecretContractError(f"{field_name}: expected a boolean")
    return value


def _enum_value(enum_type: type[Enum], value: object, *, field_name: str) -> Enum:
    text = _required_text(value, field_name=field_name)
    try:
        return enum_type(text)
    except ValueError as error:
        raise SecretContractError(f"{field_name}: invalid value") from error


def _require_enum_instance(value: object, enum_type: type[Enum], *, field_name: str) -> None:
    """Reject raw strings and unrelated enums on direct construction."""

    if not isinstance(value, enum_type):
        raise SecretContractError(f"{field_name}: expected {enum_type.__name__}")


def _require_string_tuple(
    value: object,
    *,
    field_name: str,
    allow_empty: bool = True,
) -> None:
    """Validate immutable, unique, non-blank privacy-safe direct sequences."""

    if not isinstance(value, tuple) or any(not isinstance(item, str) for item in value):
        raise SecretContractError(f"{field_name}: expected a tuple of strings")
    values = cast(tuple[str, ...], value)
    if not allow_empty and not values:
        raise SecretContractError(f"{field_name}: must not be empty")
    if len(set(values)) != len(values):
        raise SecretContractError(f"{field_name}: values must be unique")
    for item in values:
        if not item.strip():
            raise SecretContractError(f"{field_name}: values must not be blank")
        if item != item.strip():
            raise SecretContractError(f"{field_name}: surrounding whitespace is prohibited")
        _assert_safe_public_text(item, field_name=field_name)


def _iso_datetime(value: object, *, field_name: str) -> datetime | None:
    if value is None:
        return None
    text = _required_text(value, field_name=field_name, limit=40)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise SecretContractError(f"{field_name}: invalid timestamp") from error
    if parsed.tzinfo is None:
        raise SecretContractError(f"{field_name}: timestamp must be timezone-aware")
    return parsed


@dataclass(frozen=True, slots=True)
class SecretScanCoverageV2:
    """Fail-honest source coverage for one Secrets scan."""

    source_set: tuple[str, ...]
    requested_refs: tuple[str, ...]
    completed_refs: tuple[str, ...]
    files_scanned: int
    bytes_scanned: int
    commits_visited: int
    blobs_scanned: int
    skipped_codes: tuple[str, ...]
    truncation_codes: tuple[str, ...]
    detector_version: str
    model_version: str | None = None
    cache_hits: int = 0
    cache_misses: int = 0
    partial: bool = False
    degraded: bool = False
    error_code: str | None = None

    def __post_init__(self) -> None:
        tuple_fields = {
            "source_set": self.source_set,
            "requested_refs": self.requested_refs,
            "completed_refs": self.completed_refs,
            "skipped_codes": self.skipped_codes,
            "truncation_codes": self.truncation_codes,
        }
        for field_name, values in tuple_fields.items():
            if not isinstance(values, tuple) or any(not isinstance(item, str) for item in values):
                raise SecretContractError(f"{field_name}: expected a tuple of strings")
            if len(set(values)) != len(values):
                raise SecretContractError(f"{field_name}: values must be unique")
            for item in values:
                if not item.strip():
                    raise SecretContractError(f"{field_name}: values must not be blank")
                _assert_safe_public_text(item, field_name=field_name)
        for field_name, value in {
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "commits_visited": self.commits_visited,
            "blobs_scanned": self.blobs_scanned,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
        }.items():
            _non_negative_int(value, field_name=field_name)
        _required_bool(self.partial, field_name="partial")
        _required_bool(self.degraded, field_name="degraded")
        detector_version = _required_text(self.detector_version, field_name="detector_version")
        if detector_version != self.detector_version:
            raise SecretContractError("detector_version: surrounding whitespace is prohibited")
        model_version = _optional_text(self.model_version, field_name="model_version")
        if model_version != self.model_version:
            raise SecretContractError("model_version: surrounding whitespace is prohibited")
        error_code = _optional_text(self.error_code, field_name="error_code")
        if error_code != self.error_code:
            raise SecretContractError("error_code: surrounding whitespace is prohibited")
        if not self.source_set:
            raise SecretContractError("source_set must not be empty")
        if self.skipped_codes and not self.partial:
            raise SecretContractError("skipped work requires partial=true")
        if self.truncation_codes and not self.partial:
            raise SecretContractError("truncation requires partial=true")
        if not self.requested_refs and not self.partial:
            raise SecretContractError("empty requested_refs requires partial=true")
        if set(self.completed_refs) - set(self.requested_refs):
            raise SecretContractError("completed_refs must be a subset of requested_refs")
        if not self.partial and set(self.completed_refs) != set(self.requested_refs):
            raise SecretContractError("complete coverage must complete every requested ref")
        reason_codes = {*self.skipped_codes, *self.truncation_codes}
        if self.error_code is not None:
            reason_codes.add(self.error_code)
        unknown = sorted(reason_codes - REASON_CODES_V2)
        if unknown:
            raise SecretContractError(f"unknown reason codes: {', '.join(unknown)}")
        reject_prohibited_fields(
            {
                "source_set": self.source_set,
                "requested_refs": self.requested_refs,
                "completed_refs": self.completed_refs,
                "detector_version": self.detector_version,
                "model_version": self.model_version,
            }
        )

    @property
    def clean_eligible(self) -> bool:
        return (
            bool(self.source_set)
            and bool(self.requested_refs)
            and not self.partial
            and not self.degraded
            and self.error_code is None
            and not self.skipped_codes
            and not self.truncation_codes
            and set(self.requested_refs).issubset(self.completed_refs)
        )

    def assert_outcome(self, outcome: PreventionOutcome) -> None:
        if outcome is PreventionOutcome.CLEAN and not self.clean_eligible:
            raise SecretContractError("incomplete coverage cannot produce a clean outcome")
        if self.error_code is not None and outcome not in {PreventionOutcome.ERROR, PreventionOutcome.PARTIAL}:
            raise SecretContractError("coverage with an error must be error or partial")
        if self.degraded and outcome is PreventionOutcome.CLEAN:
            raise SecretContractError("degraded coverage cannot produce a clean outcome")

    def to_public_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema": _SCHEMA_COVERAGE,
            "source_set": list(self.source_set),
            "requested_refs": list(self.requested_refs),
            "completed_refs": list(self.completed_refs),
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "commits_visited": self.commits_visited,
            "blobs_scanned": self.blobs_scanned,
            "skipped_codes": list(self.skipped_codes),
            "truncation_codes": list(self.truncation_codes),
            "detector_version": self.detector_version,
            "model_version": self.model_version,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "partial": self.partial,
            "degraded": self.degraded,
            "error_code": self.error_code,
            "clean_eligible": self.clean_eligible,
        }
        reject_prohibited_fields(payload)
        return payload

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> SecretScanCoverageV2:
        allowed = {
            "schema",
            "source_set",
            "requested_refs",
            "completed_refs",
            "files_scanned",
            "bytes_scanned",
            "commits_visited",
            "blobs_scanned",
            "skipped_codes",
            "truncation_codes",
            "detector_version",
            "model_version",
            "cache_hits",
            "cache_misses",
            "partial",
            "degraded",
            "error_code",
        }
        _strict_keys(payload, allowed, schema=_SCHEMA_COVERAGE)
        if payload.get("schema") != _SCHEMA_COVERAGE:
            raise SecretContractError("unsupported SecretScanCoverage schema")
        partial = payload.get("partial", False)
        degraded = payload.get("degraded", False)
        if not isinstance(partial, bool) or not isinstance(degraded, bool):
            raise SecretContractError("coverage partial/degraded flags must be boolean")
        return cls(
            source_set=_str_tuple(payload.get("source_set"), field_name="source_set", allow_empty=False),
            requested_refs=_str_tuple(payload.get("requested_refs"), field_name="requested_refs"),
            completed_refs=_str_tuple(payload.get("completed_refs"), field_name="completed_refs"),
            files_scanned=_non_negative_int(payload.get("files_scanned"), field_name="files_scanned"),
            bytes_scanned=_non_negative_int(payload.get("bytes_scanned"), field_name="bytes_scanned"),
            commits_visited=_non_negative_int(payload.get("commits_visited"), field_name="commits_visited"),
            blobs_scanned=_non_negative_int(payload.get("blobs_scanned"), field_name="blobs_scanned"),
            skipped_codes=_str_tuple(payload.get("skipped_codes"), field_name="skipped_codes"),
            truncation_codes=_str_tuple(payload.get("truncation_codes"), field_name="truncation_codes"),
            detector_version=_required_text(payload.get("detector_version"), field_name="detector_version"),
            model_version=_optional_text(payload.get("model_version"), field_name="model_version"),
            cache_hits=_non_negative_int(payload.get("cache_hits", 0), field_name="cache_hits"),
            cache_misses=_non_negative_int(payload.get("cache_misses", 0), field_name="cache_misses"),
            partial=partial,
            degraded=degraded,
            error_code=_optional_text(payload.get("error_code"), field_name="error_code"),
        )


@dataclass(frozen=True, slots=True)
class SecretIgnoreDecisionV2:
    """Privacy-safe, durable ignore-decision contract."""

    decision_id: str
    state: SecretIgnoreState
    requested_scope: SecretIgnoreScope
    durable_match_key: str
    reason: str
    expires_at: datetime | None
    detector_version: str
    model_version: str | None
    requester_id: str
    approver_id: str | None
    policy_source: str
    propagation: tuple[str, ...]
    permanent_fixture_justification: str | None = None

    def __post_init__(self) -> None:
        _require_enum_instance(self.state, SecretIgnoreState, field_name="state")
        _require_enum_instance(
            self.requested_scope,
            SecretIgnoreScope,
            field_name="requested_scope",
        )
        _require_string_tuple(
            self.propagation,
            field_name="propagation",
            allow_empty=False,
        )
        for field_name, value in {
            "decision_id": self.decision_id,
            "requester_id": self.requester_id,
            "policy_source": self.policy_source,
        }.items():
            if not _IDENTIFIER.fullmatch(value):
                raise SecretContractError(f"{field_name}: invalid identifier")
        if self.approver_id is not None and not _IDENTIFIER.fullmatch(self.approver_id):
            raise SecretContractError("approver_id: invalid identifier")
        if not _DIGEST.fullmatch(self.durable_match_key):
            raise SecretContractError("durable_match_key must be an opaque SHA-256 digest")
        if self.reason not in IGNORE_REASON_CODES_V2:
            raise SecretContractError("ignore reason must be a registered reason code")
        if self.permanent_fixture_justification is not None and (
            self.permanent_fixture_justification not in FIXTURE_JUSTIFICATION_CODES_V2
        ):
            raise SecretContractError("permanent fixture justification must be a registered code")
        if self.expires_at is None and not self.permanent_fixture_justification:
            raise SecretContractError("non-expiring decisions require permanent fixture justification")
        if self.expires_at is not None:
            if self.expires_at.tzinfo is None:
                raise SecretContractError("expires_at must be timezone-aware")
            if self.state in _ACTIVE_IGNORE_STATES and self.expires_at.astimezone(timezone.utc) <= datetime.now(
                timezone.utc
            ):
                raise SecretContractError("expires_at must be in the future")
        if self.state is SecretIgnoreState.APPROVED and not self.approver_id:
            raise SecretContractError("approved ignore decisions require an approver")
        if not self.propagation or len(set(self.propagation)) != len(self.propagation):
            raise SecretContractError("propagation surfaces must be non-empty and unique")
        for field_name, value in {
            "detector_version": self.detector_version,
            "model_version": self.model_version,
        }.items():
            if value is not None:
                _assert_safe_public_text(value, field_name=field_name)
        for surface in self.propagation:
            if not _IDENTIFIER.fullmatch(surface):
                raise SecretContractError("propagation surface is invalid")

    def to_public_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema": _SCHEMA_IGNORE,
            "decision_id": self.decision_id,
            "state": self.state.value,
            "requested_scope": self.requested_scope.value,
            "durable_match_key": self.durable_match_key,
            "reason": self.reason,
            "expires_at": self.expires_at.astimezone(timezone.utc).isoformat() if self.expires_at else None,
            "detector_version": self.detector_version,
            "model_version": self.model_version,
            "requester_id": self.requester_id,
            "approver_id": self.approver_id,
            "policy_source": self.policy_source,
            "propagation": list(self.propagation),
            "permanent_fixture_justification": self.permanent_fixture_justification,
        }
        reject_prohibited_fields(payload)
        return payload

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> SecretIgnoreDecisionV2:
        allowed = {
            "schema",
            "decision_id",
            "state",
            "requested_scope",
            "durable_match_key",
            "reason",
            "expires_at",
            "detector_version",
            "model_version",
            "requester_id",
            "approver_id",
            "policy_source",
            "propagation",
            "permanent_fixture_justification",
        }
        _strict_keys(payload, allowed, schema=_SCHEMA_IGNORE)
        if payload.get("schema") != _SCHEMA_IGNORE:
            raise SecretContractError("unsupported SecretIgnoreDecision schema")
        state = cast(
            SecretIgnoreState,
            _enum_value(SecretIgnoreState, payload.get("state"), field_name="state"),
        )
        scope = cast(
            SecretIgnoreScope,
            _enum_value(SecretIgnoreScope, payload.get("requested_scope"), field_name="requested_scope"),
        )
        return cls(
            decision_id=_required_text(payload.get("decision_id"), field_name="decision_id"),
            state=state,
            requested_scope=scope,
            durable_match_key=_required_text(payload.get("durable_match_key"), field_name="durable_match_key"),
            reason=_required_text(payload.get("reason"), field_name="reason"),
            expires_at=_iso_datetime(payload.get("expires_at"), field_name="expires_at"),
            detector_version=_required_text(payload.get("detector_version"), field_name="detector_version"),
            model_version=_optional_text(payload.get("model_version"), field_name="model_version"),
            requester_id=_required_text(payload.get("requester_id"), field_name="requester_id"),
            approver_id=_optional_text(payload.get("approver_id"), field_name="approver_id"),
            policy_source=_required_text(payload.get("policy_source"), field_name="policy_source"),
            propagation=_str_tuple(payload.get("propagation"), field_name="propagation", allow_empty=False),
            permanent_fixture_justification=_optional_text(
                payload.get("permanent_fixture_justification"),
                field_name="permanent_fixture_justification",
            ),
        )


@dataclass(frozen=True, slots=True)
class SecretCustomRuleV2:
    """Versioned declarative custom-rule contract."""

    rule_id: str
    version: str
    matcher_kind: SecretRuleMatcherKind
    matcher_digest: str
    safe_fixture_digest: str
    provenance_digest: str
    compile_state: SecretRuleCompileState
    complexity_budget: int
    rollout_state: SecretRolloutState
    surfaces: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_enum_instance(
            self.matcher_kind,
            SecretRuleMatcherKind,
            field_name="matcher_kind",
        )
        _require_enum_instance(
            self.compile_state,
            SecretRuleCompileState,
            field_name="compile_state",
        )
        _require_enum_instance(
            self.rollout_state,
            SecretRolloutState,
            field_name="rollout_state",
        )
        _require_string_tuple(
            self.surfaces,
            field_name="surfaces",
            allow_empty=False,
        )
        if not _IDENTIFIER.fullmatch(self.rule_id):
            raise SecretContractError("rule_id is invalid")
        if not _IDENTIFIER.fullmatch(self.version):
            raise SecretContractError("version is invalid")
        for field_name, digest in {
            "matcher_digest": self.matcher_digest,
            "safe_fixture_digest": self.safe_fixture_digest,
            "provenance_digest": self.provenance_digest,
        }.items():
            if not _DIGEST.fullmatch(digest):
                raise SecretContractError(f"{field_name} must be SHA-256")
        if not 1 <= self.complexity_budget <= 100_000:
            raise SecretContractError("complexity_budget is outside the supported bound")
        if not self.surfaces or len(set(self.surfaces)) != len(self.surfaces):
            raise SecretContractError("rule surfaces must be non-empty and unique")
        for surface in self.surfaces:
            if surface not in PRODUCT_SURFACES_V2:
                raise SecretContractError(f"unknown rule surface: {surface}")
        if self.rollout_state in {SecretRolloutState.CANARY, SecretRolloutState.ACTIVE} and (
            self.compile_state is not SecretRuleCompileState.VALID
        ):
            raise SecretContractError("only valid compiled rules may be canary or active")

    def to_public_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema": _SCHEMA_RULE,
            "rule_id": self.rule_id,
            "version": self.version,
            "matcher_kind": self.matcher_kind.value,
            "matcher_digest": self.matcher_digest,
            "safe_fixture_digest": self.safe_fixture_digest,
            "provenance_digest": self.provenance_digest,
            "compile_state": self.compile_state.value,
            "complexity_budget": self.complexity_budget,
            "rollout_state": self.rollout_state.value,
            "surfaces": list(self.surfaces),
        }
        reject_prohibited_fields(payload)
        return payload


@dataclass(frozen=True, slots=True)
class CapabilityEvidenceV2:
    """One capability row bound to tests, evidence, and rollout state."""

    capability_id: str
    product_boundary: str
    surfaces: tuple[str, ...]
    plans: tuple[str, ...]
    state: ParityState
    acceptance_tests: tuple[str, ...]
    evidence_artifacts: tuple[str, ...]
    release_commit: str | None = None
    owner: str | None = None
    gap_label: str | None = None

    def __post_init__(self) -> None:
        _require_enum_instance(self.state, ParityState, field_name="state")
        for field_name, values, allow_empty in (
            ("surfaces", self.surfaces, False),
            ("plans", self.plans, False),
            ("acceptance_tests", self.acceptance_tests, True),
            ("evidence_artifacts", self.evidence_artifacts, True),
        ):
            _require_string_tuple(
                values,
                field_name=field_name,
                allow_empty=allow_empty,
            )
        if not _IDENTIFIER.fullmatch(self.capability_id):
            raise SecretContractError("capability_id is invalid")
        boundary = PRODUCT_BOUNDARIES_V2.get(self.product_boundary)
        if boundary is None:
            raise SecretContractError(f"unknown product boundary: {self.product_boundary}")
        if not self.surfaces or len(set(self.surfaces)) != len(self.surfaces):
            raise SecretContractError("capability surfaces must be non-empty and unique")
        if not self.plans or len(set(self.plans)) != len(self.plans):
            raise SecretContractError("capability plans must be non-empty and unique")
        allowed_surfaces = frozenset(boundary["allowed_surfaces"])
        unknown_surfaces = sorted(set(self.surfaces) - allowed_surfaces)
        if unknown_surfaces:
            raise SecretContractError(
                f"{self.capability_id}: surfaces outside product boundary: {', '.join(unknown_surfaces)}"
            )
        allowed_plans = frozenset(boundary["allowed_plans"])
        unknown_plans = sorted(set(self.plans) - allowed_plans)
        if unknown_plans:
            raise SecretContractError(
                f"{self.capability_id}: plans outside product boundary: {', '.join(unknown_plans)}"
            )
        if self.owner is not None and not _IDENTIFIER.fullmatch(self.owner):
            raise SecretContractError("owner is invalid")
        if self.gap_label is not None:
            if not self.gap_label.strip():
                raise SecretContractError("gap_label must not be blank")
            _assert_safe_public_text(self.gap_label, field_name="gap_label")
        for field_name, values in {
            "acceptance_tests": self.acceptance_tests,
            "evidence_artifacts": self.evidence_artifacts,
        }.items():
            for value in values:
                _assert_safe_public_text(value, field_name=field_name)
        if (
            self.state
            in {
                ParityState.TESTED,
                ParityState.VERIFIED_ON_RELEASE_CANDIDATE,
                ParityState.GENERALLY_AVAILABLE,
            }
            and not self.acceptance_tests
        ):
            raise SecretContractError("tested capability requires acceptance tests")
        if self.state in _RELEASE_STATES:
            if not self.release_commit or not is_exact_commit_sha(self.release_commit):
                raise SecretContractError("release-candidate capability requires an exact commit SHA")
            if not self.evidence_artifacts:
                raise SecretContractError("release-candidate capability requires evidence artifacts")

    @classmethod
    def from_mapping(
        cls,
        payload: Mapping[str, object],
        *,
        label: str,
        require_gap_label: bool,
    ) -> CapabilityEvidenceV2:
        allowed = {
            "capability_id",
            "product_boundary",
            "surfaces",
            "plans",
            "owner",
            "state",
            "acceptance_tests",
            "evidence_artifacts",
            "release_commit",
            "gap_label",
        }
        _strict_keys(payload, allowed, schema=label)
        capability_id = _required_text(payload.get("capability_id"), field_name=f"{label}.capability_id")
        try:
            state = ParityState(_required_text(payload.get("state"), field_name=f"{capability_id}.state"))
        except ValueError as error:
            raise SecretContractError(f"{capability_id}: invalid parity state") from error
        gap_label = _optional_text(
            payload.get("gap_label"),
            field_name=f"{capability_id}.gap_label",
            limit=500,
        )
        if require_gap_label and state not in _RELEASE_STATES and gap_label is None:
            raise SecretContractError(f"{capability_id}: non-release state requires an explicit gap label")
        return cls(
            capability_id=capability_id,
            product_boundary=_required_text(
                payload.get("product_boundary"),
                field_name=f"{capability_id}.product_boundary",
            ),
            surfaces=_str_tuple(
                payload.get("surfaces"),
                field_name=f"{capability_id}.surfaces",
                allow_empty=False,
            ),
            plans=_str_tuple(
                payload.get("plans"),
                field_name=f"{capability_id}.plans",
                allow_empty=False,
            ),
            state=state,
            acceptance_tests=_str_tuple(
                payload.get("acceptance_tests"),
                field_name=f"{capability_id}.acceptance_tests",
            ),
            evidence_artifacts=_str_tuple(
                payload.get("evidence_artifacts"),
                field_name=f"{capability_id}.evidence_artifacts",
            ),
            release_commit=_optional_text(
                payload.get("release_commit"),
                field_name=f"{capability_id}.release_commit",
            ),
            owner=_required_text(payload.get("owner"), field_name=f"{capability_id}.owner"),
            gap_label=gap_label,
        )


@dataclass(frozen=True, slots=True)
class CapabilityManifestV2:
    """Parsed capability manifest and its policy-declared validation result."""

    capabilities: tuple[CapabilityEvidenceV2, ...]
    row_errors: tuple[str, ...]
    public_parity_requires: ParityState
    exact_release_commit_required: bool
    remaining_gaps_must_be_labeled: bool
    public_parity_claim_enabled: bool
    required_capability_ids: frozenset[str]


@dataclass(frozen=True, slots=True)
class ProductBoundaryManifestV2:
    """Runtime-validated product plan, boundary, surface, and invariant registry."""

    plan_ids: frozenset[str]
    boundary_ids: frozenset[str]
    surface_ids: frozenset[str]
    invariants: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SourceCapabilityManifestV2:
    """Runtime-validated source support matrix."""

    status_values: tuple[str, ...]
    sections: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReasonCodeManifestV2:
    """Runtime-validated reason-code categories and fail-closed rules."""

    category_ids: tuple[str, ...]
    codes: frozenset[str]
    rule_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OrganizationMetricDefinitionV2:
    """Unambiguous organization-level reporting metric definition."""

    metric_id: str
    numerator: str
    denominator: str
    censored_open_handling: str
    recurrence_handling: str
    incomplete_scan_handling: str

    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.metric_id):
            raise SecretContractError("metric_id is invalid")
        for field_name, value in {
            "numerator": self.numerator,
            "denominator": self.denominator,
            "censored_open_handling": self.censored_open_handling,
            "recurrence_handling": self.recurrence_handling,
            "incomplete_scan_handling": self.incomplete_scan_handling,
        }.items():
            if not value.strip():
                raise SecretContractError("metric definition fields must not be empty")
            _assert_safe_public_text(value, field_name=field_name)


OUTCOME_SURFACE_MAPPING: Final[dict[PreventionOutcome, dict[str, str]]] = {
    PreventionOutcome.CLEAN: {"cli": "0", "check": "success", "ide": "none", "agent": "allow"},
    PreventionOutcome.WARN: {"cli": "0", "check": "neutral", "ide": "warning", "agent": "notice"},
    PreventionOutcome.SOFT_BLOCK: {"cli": "3", "check": "failure", "ide": "error", "agent": "pause"},
    PreventionOutcome.POLICY_BLOCK: {"cli": "4", "check": "failure", "ide": "error", "agent": "deny"},
    PreventionOutcome.PARTIAL: {"cli": "2", "check": "neutral", "ide": "degraded", "agent": "pause"},
    PreventionOutcome.DEGRADED: {"cli": "2", "check": "neutral", "ide": "degraded", "agent": "pause"},
    PreventionOutcome.ERROR: {"cli": "2", "check": "failure", "ide": "error", "agent": "pause"},
}


def _plain_mapping(value: Mapping[str, object], *, field_name: str) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, nested in value.items():
        if not isinstance(key, str):
            raise SecretContractError(f"{field_name}: mapping keys must be strings")
        result[key] = nested
    return result


def parse_product_boundaries_manifest(payload: Mapping[str, object]) -> ProductBoundaryManifestV2:
    """Parse and compare the product boundary manifest to runtime authority."""

    allowed = {"schema", "plans", "surface_values", "product_boundaries", "invariants"}
    _strict_keys(payload, allowed, schema=_SCHEMA_PRODUCT_BOUNDARIES)
    if payload.get("schema") != _SCHEMA_PRODUCT_BOUNDARIES:
        raise SecretContractError("unsupported product-boundary manifest schema")

    plans = _mapping(payload.get("plans"), field_name="plans")
    if set(plans) != set(PLAN_POLICIES_V2):
        raise SecretContractError("plan registry does not match the runtime contract")
    for plan_id, expected_policy in PLAN_POLICIES_V2.items():
        declared_policy = _plain_mapping(
            _mapping(plans.get(plan_id), field_name=f"plans.{plan_id}"),
            field_name=f"plans.{plan_id}",
        )
        if declared_policy != dict(expected_policy):
            raise SecretContractError(f"plans.{plan_id}: policy does not match the runtime contract")

    surfaces = _str_tuple(payload.get("surface_values"), field_name="surface_values", allow_empty=False)
    if surfaces != PRODUCT_SURFACES_V2:
        raise SecretContractError("surface_values do not match the runtime contract")

    boundaries = _mapping(payload.get("product_boundaries"), field_name="product_boundaries")
    if set(boundaries) != set(PRODUCT_BOUNDARIES_V2):
        raise SecretContractError("product boundary registry does not match the runtime contract")
    for boundary_id, expected_policy in PRODUCT_BOUNDARIES_V2.items():
        declared = _mapping(
            boundaries.get(boundary_id),
            field_name=f"product_boundaries.{boundary_id}",
        )
        _strict_keys(
            declared,
            {"allowed_plans", "allowed_surfaces"},
            schema=f"product_boundaries.{boundary_id}",
        )
        declared_plans = _str_tuple(
            declared.get("allowed_plans"),
            field_name=f"product_boundaries.{boundary_id}.allowed_plans",
            allow_empty=False,
        )
        declared_surfaces = _str_tuple(
            declared.get("allowed_surfaces"),
            field_name=f"product_boundaries.{boundary_id}.allowed_surfaces",
            allow_empty=False,
        )
        if declared_plans != expected_policy["allowed_plans"]:
            raise SecretContractError(f"{boundary_id}: allowed plans do not match the runtime contract")
        if declared_surfaces != expected_policy["allowed_surfaces"]:
            raise SecretContractError(f"{boundary_id}: allowed surfaces do not match the runtime contract")

    invariants = _str_tuple(payload.get("invariants"), field_name="invariants", allow_empty=False)
    if invariants != PRODUCT_INVARIANTS_V2:
        raise SecretContractError("product invariants do not match the runtime contract")
    return ProductBoundaryManifestV2(
        plan_ids=frozenset(plans),
        boundary_ids=frozenset(boundaries),
        surface_ids=frozenset(surfaces),
        invariants=invariants,
    )


def parse_source_capabilities_manifest(payload: Mapping[str, object]) -> SourceCapabilityManifestV2:
    """Parse and compare the source-capability manifest to runtime authority."""

    allowed = {"schema", "status_values", *SOURCE_CAPABILITY_SECTIONS_V2}
    _strict_keys(payload, allowed, schema=_SCHEMA_SOURCE_CAPABILITIES)
    if payload.get("schema") != _SCHEMA_SOURCE_CAPABILITIES:
        raise SecretContractError("unsupported source-capability manifest schema")
    statuses = _str_tuple(payload.get("status_values"), field_name="status_values", allow_empty=False)
    if statuses != SOURCE_CAPABILITY_STATUS_VALUES_V2:
        raise SecretContractError("status_values do not match the runtime contract")

    for section, expected_entries in SOURCE_CAPABILITY_SECTIONS_V2.items():
        declared_entries = _mapping(payload.get(section), field_name=section)
        if set(declared_entries) != set(expected_entries):
            raise SecretContractError(f"{section}: capability keys do not match the runtime contract")
        normalized: dict[str, str] = {}
        for capability_id, raw_status in declared_entries.items():
            if not isinstance(capability_id, str):
                raise SecretContractError(f"{section}: capability IDs must be strings")
            status_text = _required_text(raw_status, field_name=f"{section}.{capability_id}")
            try:
                status = SourceCapabilityStatus(status_text)
            except ValueError as error:
                raise SecretContractError(f"{section}.{capability_id}: invalid status") from error
            normalized[capability_id] = status.value
        if normalized != dict(expected_entries):
            raise SecretContractError(f"{section}: statuses do not match the runtime contract")

    return SourceCapabilityManifestV2(
        status_values=statuses,
        sections=tuple(SOURCE_CAPABILITY_SECTIONS_V2),
    )


def parse_reason_codes_manifest(payload: Mapping[str, object]) -> ReasonCodeManifestV2:
    """Parse and compare the reason-code manifest to runtime authority."""

    allowed = {"schema", "categories", "rules"}
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise SecretContractError(f"{_SCHEMA_REASON_CODES}: unknown fields: {', '.join(unknown)}")
    if payload.get("schema") != _SCHEMA_REASON_CODES:
        raise SecretContractError("unsupported reason-code manifest schema")

    categories = _mapping(payload.get("categories"), field_name="categories")
    expected_category_ids = tuple(REASON_CODE_CATEGORIES_V2)
    if tuple(categories) != expected_category_ids:
        raise SecretContractError("reason-code category registry does not match the runtime contract")

    seen: set[str] = set()
    for category_id, expected_codes in REASON_CODE_CATEGORIES_V2.items():
        declared_codes = _str_tuple(
            categories.get(category_id),
            field_name=f"categories.{category_id}",
            allow_empty=False,
        )
        if len(set(declared_codes)) != len(declared_codes):
            raise SecretContractError(f"categories.{category_id}: reason codes must be unique")
        duplicates = sorted(seen.intersection(declared_codes))
        if duplicates:
            raise SecretContractError("reason codes must belong to exactly one category: " + ", ".join(duplicates))
        if declared_codes != expected_codes:
            raise SecretContractError(f"categories.{category_id}: codes do not match the runtime contract")
        seen.update(declared_codes)
    if frozenset(seen) != REASON_CODES_V2:
        raise SecretContractError("reason-code registry does not match the runtime contract")

    rules = _mapping(payload.get("rules"), field_name="rules")
    if tuple(rules) != tuple(REASON_CODE_RULES_V2):
        raise SecretContractError("reason-code rule registry does not match the runtime contract")
    for rule_id, expected_value in REASON_CODE_RULES_V2.items():
        declared_value = _required_bool(
            rules.get(rule_id),
            field_name=f"rules.{rule_id}",
        )
        if declared_value is not expected_value:
            raise SecretContractError(f"rules.{rule_id}: policy does not match the runtime contract")

    return ReasonCodeManifestV2(
        category_ids=expected_category_ids,
        codes=frozenset(seen),
        rule_ids=tuple(REASON_CODE_RULES_V2),
    )


def parse_capability_evidence_manifest(payload: Mapping[str, object]) -> CapabilityManifestV2:
    """Parse the v2 capability manifest and surface row-level errors safely."""

    allowed = {"schema", "generated_at", "parity_states", "claim_policy", "capabilities"}
    _strict_keys(payload, allowed, schema=_SCHEMA_CAPABILITY_EVIDENCE)
    if payload.get("schema") != _SCHEMA_CAPABILITY_EVIDENCE:
        raise SecretContractError("unsupported capability manifest schema")
    _required_text(payload.get("generated_at"), field_name="generated_at", limit=40)
    declared_states = _str_tuple(payload.get("parity_states"), field_name="parity_states", allow_empty=False)
    if declared_states != PARITY_STATES_V2:
        raise SecretContractError("parity_states do not match the runtime contract")

    claim_policy = _mapping(payload.get("claim_policy"), field_name="claim_policy")
    _strict_keys(
        claim_policy,
        {
            "public_parity_requires",
            "exact_release_commit_required",
            "remaining_gaps_must_be_labeled",
            "public_parity_claim_enabled",
            "required_capabilities",
        },
        schema="claim_policy",
    )
    try:
        public_parity_requires = ParityState(
            _required_text(
                claim_policy.get("public_parity_requires"),
                field_name="claim_policy.public_parity_requires",
            )
        )
    except ValueError as error:
        raise SecretContractError("claim_policy.public_parity_requires is not a parity state") from error
    if public_parity_requires not in _RELEASE_STATES:
        raise SecretContractError("claim_policy.public_parity_requires must be release-candidate verified or GA")
    exact_release_commit_required = _required_bool(
        claim_policy.get("exact_release_commit_required"),
        field_name="claim_policy.exact_release_commit_required",
    )
    if not exact_release_commit_required:
        raise SecretContractError("claim_policy must require an exact release commit")
    remaining_gaps_must_be_labeled = _required_bool(
        claim_policy.get("remaining_gaps_must_be_labeled"),
        field_name="claim_policy.remaining_gaps_must_be_labeled",
    )
    if not remaining_gaps_must_be_labeled:
        raise SecretContractError("claim_policy must require labels for remaining gaps")
    public_parity_claim_enabled = _required_bool(
        claim_policy.get("public_parity_claim_enabled"),
        field_name="claim_policy.public_parity_claim_enabled",
    )
    required_capability_list = _str_tuple(
        claim_policy.get("required_capabilities"),
        field_name="claim_policy.required_capabilities",
        allow_empty=False,
    )
    if len(set(required_capability_list)) != len(required_capability_list):
        raise SecretContractError("claim_policy.required_capabilities must be unique")
    required_capability_ids = frozenset(required_capability_list)

    raw_capabilities = payload.get("capabilities")
    if not isinstance(raw_capabilities, list):
        raise SecretContractError("capabilities: expected an array")

    capabilities: list[CapabilityEvidenceV2] = []
    errors: list[str] = []
    declared_ids: set[str] = set()
    for index, raw_capability in enumerate(raw_capabilities):
        label = f"capabilities[{index}]"
        try:
            capability_mapping = _mapping(raw_capability, field_name=label)
            raw_capability_id = capability_mapping.get("capability_id")
            if isinstance(raw_capability_id, str) and raw_capability_id.strip():
                capability_id = raw_capability_id.strip()
                if capability_id in declared_ids:
                    errors.append(f"{capability_id}: duplicate capability")
                    continue
                declared_ids.add(capability_id)
            capability = CapabilityEvidenceV2.from_mapping(
                capability_mapping,
                label=label,
                require_gap_label=remaining_gaps_must_be_labeled,
            )
        except SecretContractError as error:
            errors.append(str(error))
            continue
        capabilities.append(capability)

    missing_required = sorted(required_capability_ids - declared_ids)
    if missing_required:
        errors.append(f"claim policy capabilities are unmapped: {', '.join(missing_required)}")

    return CapabilityManifestV2(
        capabilities=tuple(capabilities),
        row_errors=tuple(errors),
        public_parity_requires=public_parity_requires,
        exact_release_commit_required=exact_release_commit_required,
        remaining_gaps_must_be_labeled=remaining_gaps_must_be_labeled,
        public_parity_claim_enabled=public_parity_claim_enabled,
        required_capability_ids=required_capability_ids,
    )


def validate_capability_manifest(
    capabilities: Sequence[CapabilityEvidenceV2],
    *,
    required_capability_ids: frozenset[str],
    exact_release_commit: str,
    minimum_state: ParityState = ParityState.VERIFIED_ON_RELEASE_CANDIDATE,
) -> None:
    """Fail unless every claimed row has exact release-candidate evidence."""

    if not is_exact_commit_sha(exact_release_commit):
        raise SecretContractError("exact_release_commit must be a full commit SHA")
    if minimum_state not in _RELEASE_STATES:
        raise SecretContractError("minimum parity state must be release-candidate verified or GA")
    by_id = {capability.capability_id: capability for capability in capabilities}
    if len(by_id) != len(capabilities):
        raise SecretContractError("capability IDs must be unique")
    missing = sorted(required_capability_ids - set(by_id))
    if missing:
        raise SecretContractError(f"required capabilities are unmapped: {', '.join(missing)}")
    minimum_rank = _PARITY_STATE_RANK[minimum_state]
    for capability_id in sorted(required_capability_ids):
        capability = by_id[capability_id]
        if _PARITY_STATE_RANK[capability.state] < minimum_rank:
            raise SecretContractError(f"{capability_id}: not verified at the required release state")
        if capability.release_commit != exact_release_commit:
            raise SecretContractError(f"{capability_id}: evidence is bound to a different commit")


__all__ = [
    "FIXTURE_JUSTIFICATION_CODES_V2",
    "IGNORE_REASON_CODES_V2",
    "OUTCOME_SURFACE_MAPPING",
    "PARITY_STATES_V2",
    "PLAN_POLICIES_V2",
    "PRODUCT_BOUNDARIES_V2",
    "PRODUCT_INVARIANTS_V2",
    "PRODUCT_SURFACES_V2",
    "REASON_CODES_V2",
    "REASON_CODE_CATEGORIES_V2",
    "REASON_CODE_RULES_V2",
    "SOURCE_CAPABILITY_SECTIONS_V2",
    "SOURCE_CAPABILITY_STATUS_VALUES_V2",
    "CapabilityEvidenceV2",
    "CapabilityManifestV2",
    "OrganizationMetricDefinitionV2",
    "ParityState",
    "PreventionOutcome",
    "ProductBoundaryManifestV2",
    "ReasonCodeManifestV2",
    "SecretClass",
    "SecretContractError",
    "SecretCustomRuleV2",
    "SecretExposure",
    "SecretIgnoreDecisionV2",
    "SecretIgnoreScope",
    "SecretIgnoreState",
    "SecretLifecycle",
    "SecretRolloutState",
    "SecretRuleCompileState",
    "SecretRuleMatcherKind",
    "SecretScanCoverageV2",
    "SecretValidity",
    "SourceCapabilityManifestV2",
    "SourceCapabilityStatus",
    "is_exact_commit_sha",
    "parse_capability_evidence_manifest",
    "parse_product_boundaries_manifest",
    "parse_reason_codes_manifest",
    "parse_source_capabilities_manifest",
    "reject_prohibited_fields",
    "validate_capability_manifest",
]

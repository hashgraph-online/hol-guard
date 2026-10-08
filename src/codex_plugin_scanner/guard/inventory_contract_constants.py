"""Shared inventory redaction, capability, and wire-format constants."""

from __future__ import annotations

import re

from .path_security import path_has_symlink_component

_SENSITIVE_KEY_RE = re.compile(
    r"(auth|authorization|bearer|token|secret|password|credential|api[^a-z0-9]?key)",
    re.IGNORECASE,
)


_SENSITIVE_VALUE_RE = re.compile(r"(?i)(gh[pousr]_[a-z0-9_]+|sk-[a-z0-9_-]+|guard_live_[a-z0-9_-]+|bearer\s+\S+)")


_UNSAFE_PATH_MARKERS = (
    "".join(("/", "Users", "/")),
    "".join(("/", "home", "/")),
    "".join(("/", "root", "/")),
    "".join(("\\", "Users", "\\")),
    "".join(("/", "var", "/", "folders", "/")),
    "".join(("/", "workspace", "/")),
    "".join(("/", "tmp", "/")),
    "".join(("/", "etc", "/")),
    "".join(("/", "mnt", "/")),
)


_SERIALIZER_UNSAFE_PATH_PATTERN = (
    r"(?:^|[\s\"'=:({])(?:" + "|".join(re.escape(marker) for marker in _UNSAFE_PATH_MARKERS) + ")"
)


_SERIALIZER_UNSAFE_PATH_RE = re.compile(_SERIALIZER_UNSAFE_PATH_PATTERN, re.IGNORECASE)


_SERIALIZER_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|authorization|password|secret|token|access[_-]?token|refresh[_-]?token)\b\s*[:=]\s*(?!redacted\b)\S+",
)


_SERIALIZER_REDACTED_VALUE = "[REDACTED]"


_SAFE_SERIALIZED_MARKERS = frozenset(
    {
        _SERIALIZER_REDACTED_VALUE,
        "present_redacted",
        "present",
        "redacted",
        "malformed_url_redacted",
    }
)


_WHITESPACE_RE = re.compile(r"\s+")


_MCP_READ_RE = re.compile(
    r"(?<![a-z0-9])(read|reads|reading|search|searches|list|lists)(?![a-z0-9])",
    re.IGNORECASE,
)


_MCP_DELETE_RE = re.compile(
    r"(?<![a-z0-9])(delete|deletes|remove|removes|destroy|destroys)(?![a-z0-9])",
    re.IGNORECASE,
)


_MCP_WRITE_RE = re.compile(
    r"(?<![a-z0-9])(write|writes|update|updates|create|creates|modify|modifies)(?![a-z0-9])",
    re.IGNORECASE,
)


_MCP_SHELL_RE = re.compile(
    r"(?<![a-z0-9])(shell|command|commands|execute|exec|subprocess)(?![a-z0-9])",
    re.IGNORECASE,
)


_MCP_SECRET_RE = re.compile(
    r"(?<![a-z0-9])(secret|secrets|token|tokens|password|passwords|credential|credentials|api[_\-\s]?key)(?![a-z0-9])",
    re.IGNORECASE,
)


_MCP_NETWORK_RE = re.compile(
    r"(?<![a-z0-9])(http|url|urls|network|fetch|webhook|webhooks)(?![a-z0-9])",
    re.IGNORECASE,
)


_MCP_MODEL_RE = re.compile(r"(?<![a-z0-9])(sampling|model|models|llm)(?![a-z0-9])", re.IGNORECASE)


_MCP_PERMISSION_RE = re.compile(
    r"(?<![a-z0-9])(permission|permissions|chmod)(?![a-z0-9])",
    re.IGNORECASE,
)


_IGNORED_TREE_DIR_NAMES = {".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".ruff_cache", ".venv", "node_modules"}


_MAX_FINGERPRINT_FILE_BYTES = 1024 * 1024


_AIBOM_METADATA_KEYS = (
    "instructionRole",
    "localSecurity",
    "registryIdentity",
    "skillDirectoryIdentity",
    "sourceLinks",
    "sourceOfTruth",
    "trustLayers",
    "trustResolution",
    "unverifiedAdapterEvidence",
    "versionInfo",
)


_INVENTORY_DATETIME_KEYS = frozenset(
    {
        "capturedAt",
        "completedAt",
        "firstSeenAt",
        "generatedAt",
        "lastSeenAt",
        "startedAt",
    }
)


_FREE_FORM_RECORD_KEYS = frozenset({"metadata", "evidence"})


_OPTIONAL_ONLY_CONTRACT_KEYS = frozenset({"summary"})


_path_has_symlink_component = path_has_symlink_component

"""Fresh presentation constants for each Guard renderer import."""

from __future__ import annotations

import re
from types import ModuleType
from typing import NamedTuple


class RenderConstants(NamedTuple):
    mode_acronyms: frozenset[str]
    severity_colors: dict[str, str]
    known_managed_install_modes: dict[str, str]
    sensitive_key_tokens: tuple[str, ...]
    non_secret_structured_keys: frozenset[str]
    non_secret_diagnostic_keys: frozenset[str]
    safe_policy_literals: frozenset[str]
    sensitive_string_patterns: tuple[tuple[re.Pattern[str], str], ...]
    trust_sensitive_string_patterns: tuple[tuple[re.Pattern[str], str], ...]


def build_render_constants(patterns: ModuleType) -> RenderConstants:
    _mode_acronyms = frozenset({"mcp", "api", "cli"})
    _severity_colors: dict[str, str] = {
        "critical": "red",
        "high": "yellow",
        "medium": "cyan",
        "low": "dim",
        "info": "dim",
    }
    _known_managed_install_modes = {
        "codex-mcp-proxy": "Codex MCP proxy",
    }
    _sensitive_key_tokens = ("key", "token", "auth", "secret", "password", "credential")
    _non_secret_structured_keys = frozenset({"oauth_storage_health"})
    _non_secret_diagnostic_keys = frozenset({"authority_error", "authority_error_message"})
    _safe_policy_literals = frozenset(
        {"allow", "warn", "review", "block", "require-reapproval", "sandbox-required", "strict", "balanced", "custom"}
    )
    _sensitive_string_patterns: tuple[tuple[re.Pattern[str], str], ...] = (
        (
            patterns.compile(
                r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
                patterns.DOTALL,
            ),
            "*****",
        ),
        (patterns.compile(r"(?i)(authorization:\s*)(bearer\s+)?[^\s,;]+"), r"\1*****"),
        (patterns.compile(r"(?i)(api[-_ ]?key:\s*)[^\s,;]+"), r"\1*****"),
        (patterns.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"), "*****"),
        (patterns.compile(r"(?i)(bearer\s+)[^\s,;]+"), r"\1*****"),
        (patterns.compile(r"(?im)\b(?:_authToken|npm[_ -]?token)\s*[:=]\s*[^\s]+"), "npm token redacted"),
        (
            patterns.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s]+", patterns.IGNORECASE),
            "*****",
        ),
        (
            patterns.compile(
                r"(?i)([a-z0-9_-]*(?:token|secret|api[-_]?key|password|credential)[a-z0-9_-]*=)"
                r"(?:'[^']*'|\"[^\"]*\"|[^&\s]+)"
            ),
            r"\1*****",
        ),
    )
    _trust_sensitive_string_patterns: tuple[tuple[re.Pattern[str], str], ...] = tuple(
        item for item in _sensitive_string_patterns if item[0].pattern != r"(?i)(api[-_ ]?key:\s*)[^\s,;]+"
    )
    return RenderConstants(
        _mode_acronyms,
        _severity_colors,
        _known_managed_install_modes,
        _sensitive_key_tokens,
        _non_secret_structured_keys,
        _non_secret_diagnostic_keys,
        _safe_policy_literals,
        _sensitive_string_patterns,
        _trust_sensitive_string_patterns,
    )
